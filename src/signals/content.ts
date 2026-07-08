/**
 * Content signal (M3a, deterministic) — the contamination / taint model.
 *
 * Two halves (see brainstorms/m3-content-signal.md):
 *   • inspect()  — PostToolUse: OBSERVE a tool result, never modify it. Detect secrets in the
 *                  returned content and mark the session *content-confirmed* tainted.
 *   • evaluate() — PreToolUse: the ENFORCEMENT read. Records *path-risk* for sensitive-path calls,
 *                  and escalates an EGRESS call to HITL when the session is content-confirmed.
 *
 * Asymmetric decay (D5): content-confirmed taint persists for the whole session (the secret is
 * still in the agent's context — a TTL here would be a trivial "wait it out" bypass); path-risk is
 * a softer heuristic that decays via a TTL.
 *
 * Enforcement is ALWAYS pre-flight (D2): this never withholds or rewrites a result. The hard stop is
 * the PreToolUse decision on the *next* action. In-memory per process; the interface lets a
 * Redis-backed monitor drop in for the multi-instance paid tier.
 */
import { createHash } from 'node:crypto';
import { classify } from '../taxonomy/index.js';
import { SECRET_PATTERNS } from './secrets.js';
import type { MCPToolCall } from '../contract/types.js';

export interface ContentConfig {
  pathRiskTtlMs: number;    // path-risk heuristic decays after this
  scanLimitBytes: number;   // only scan the first N bytes of a tool result (latency cap)
  entropyThreshold: number; // Shannon bits/char above which a long unstructured token is "secret-like"
  entropyMinLen: number;    // minimum token length to bother entropy-checking
}

export const DEFAULT_CONTENT_CONFIG: ContentConfig = {
  pathRiskTtlMs: 300_000, // 5 min
  scanLimitBytes: 65_536, // first 64 KB
  entropyThreshold: 4.0,
  entropyMinLen: 24,
};

/** What evaluate() contributes to the PreToolUse decision. Content only ever escalates to HITL (D4). */
export interface ContentVerdict {
  action: 'HITL' | null; // content's own action hint; the RiskEngine reads `kind` to weight it
  reason: string | null;
  kind: 'content-exfil-match' | 'content-exfil' | 'content-injection' | 'path-risk' | null;
}

/**
 * A secret captured from a tool result, kept ONLY in session memory for egress content-matching (M6).
 * `value` is the raw secret — NEVER logged or persisted; only `hash`/`type`/`source` ever leave memory.
 */
interface SecretRef {
  value: string; //   raw, in-memory only (dropped on reset/session-end)
  type: string;
  source: string; //  e.g. "Read /path/.env:4" — for provenance in the verdict reason
  hash: string; //    sha256 prefix — the only form that may appear in audit
  confidence: number;
}

const NO_VERDICT: ContentVerdict = { action: null, reason: null, kind: null };

/** What inspect() found in a tool result. */
export interface InspectOutcome {
  secretTypes: string[];
  tainted: boolean;
}

export interface ContaminationMonitor {
  /** PostToolUse: observe a tool result and update session contamination state. Never mutates the result. */
  inspect(call: MCPToolCall, result: string): InspectOutcome;
  /** PostToolUse: record that a tool result was flagged as prompt-injection (M3b posture escalation, D12). */
  flagInjection(sessionId: string, score: number, tool: string): void;
  /** PreToolUse: record path-risk for sensitive-path calls and return content's contribution to the decision. */
  evaluate(call: MCPToolCall): ContentVerdict;
  /** Forget a session's contamination (e.g. when the session ends). */
  reset(sessionId: string): void;
}

interface SessionState {
  // `structured` is TRUE once a real structured secret (SECRET_PATTERNS, not the entropy heuristic) has
  // been loaded — only that arms the generic `content-exfil` suspicion gate (FP1a). `secrets` still holds
  // ALL captured values (structured + entropy) so the precise M6 exact-match path stays fully covered.
  content: { types: Set<string>; secrets: SecretRef[]; structured: boolean; ts: number } | null; // persistent for the session (D5)
  path: { paths: Set<string>; lastTs: number } | null; // heuristic, decays via TTL (D5)
  injection: { score: number; ts: number; tool: string } | null; // heuristic, decays via TTL (D12)
}

// (Structured secret patterns live in ./secrets — shared with the MITM proxy's outbound redaction.)

// Paths that, when read, are an early warning the session may be loading secrets. Kept in sync with the
// policy's sensitive-path token (rules/default_policy.yaml: hitl-sensitive-path / -cmd) — see M7.
const SENSITIVE_PATH =
  /(^|[\s/\\'"=])\.(ssh|aws|gnupg|kube|docker|azure)([/\\]|$)|(^|[\s/\\'"=])\.config[/\\](gcloud|gh|rclone|openai|anthropic|Code|JetBrains|hub)[/\\]|(^|[/\\])\.env(\.[^/\\]*)?($|[/\\])|(^|[\s/\\'"=])(\.pgpass|pgpass\.conf|rclone\.conf|\.dockercfg|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.terraformrc|credentials\.tfrc\.json|credentials\.db|application_default_credentials\.json|access_tokens\.db|logins\.json|key[34]\.db|cookies\.sqlite|WinSCP\.ini)(\b|$)|[/\\](Login Data|Local State|Cookies)\b|(^|[\s/\\'"=])id_(rsa|dsa|ecdsa|ed25519)\b|\.(pem|key|p12|pfx|pkcs12|keystore|jks|ppk)\b|[/\\]etc[/\\](passwd|shadow|sudoers|gshadow)\b|[/\\]etc[/\\]ssl[/\\]private[/\\]|[/\\]proc[/\\]([^/\\]+[/\\])?(environ|cmdline|mem|maps|stack|auxv|kcore)\b|[/\\]dev[/\\](mem|kmem|kcore|port)\b|[/\\](var[/\\])?run[/\\]secrets[/\\]|(^|[\s/\\'"=])\.[a-z]*_history\b|(^|[\s/\\'"=])(wallet\.dat|\.wallet|mnemonic|seed[_-]?phrase|UTC--[0-9])|[/\\](keystore|wallets?)[/\\]|(^|[/\\])(credentials|secrets?\.(?:ya?ml|json|txt))(\/|\\|$)|\.(tfstate|tfvars|gpg|pgp|asc|kdbx|kdb|ovpn|p8)\b|(^|[\s/\\'"=])\.password-store([/\\]|$)|(service[_-]?account|gcp[_-]?key)[^\s/\\]*\.json\b|(^|[\s/\\'"=])credentials?\.(json|ya?ml|xml|ini|toml|properties)\b/i;

export class InMemoryContaminationMonitor implements ContaminationMonitor {
  private readonly sessions = new Map<string, SessionState>();

  constructor(private readonly cfg: ContentConfig = DEFAULT_CONTENT_CONFIG) {}

  inspect(call: MCPToolCall, result: string): InspectOutcome {
    const text = typeof result === 'string' ? result : '';
    const found = detectSecretValues(text, this.cfg);
    if (found.length === 0) return { secretTypes: [], tainted: false };

    const st = this.get(call.sessionId ?? 'default');
    const types = st.content?.types ?? new Set<string>();
    const secrets = st.content?.secrets ?? [];
    const base = `${call.tool}${pathOf(call) ? ` ${pathOf(call)}` : ''}`;
    // Only a STRUCTURED secret arms the generic `content-exfil` suspicion gate (FP1a): a high-entropy
    // token alone (lockfile digest, base64 asset, build id) is too weak to hold every later egress. The
    // entropy value is still STORED below so the precise exact-match path (content-exfil-match) covers it.
    let structured = st.content?.structured ?? false;
    for (const f of found) {
      types.add(f.type);
      if (f.type !== 'high-entropy') structured = true;
      // Keep the raw value in memory for egress matching; store provenance + hash only (M6).
      if (!secrets.some((s) => s.value === f.value)) {
        secrets.push({ value: f.value, type: f.type, source: `${base}:${f.line}`, hash: hash12(f.value), confidence: f.confidence });
      }
    }
    if (secrets.length > 50) secrets.splice(0, secrets.length - 50); // bound memory
    st.content = { types, secrets, structured, ts: Date.now() };
    // `tainted` (audit/notify) reflects any capture; the ENFORCEMENT arming is gated on `structured` in evaluate().
    return { secretTypes: [...new Set(found.map((f) => f.type))], tainted: true };
  }

  flagInjection(sessionId: string, score: number, tool: string): void {
    this.get(sessionId).injection = { score, ts: Date.now(), tool };
  }

  evaluate(call: MCPToolCall): ContentVerdict {
    const sessionId = call.sessionId ?? 'default';
    const now = Date.now();
    const st = this.get(sessionId);

    // heuristic signals decay (D5/D12)
    if (st.path && now - st.path.lastTs > this.cfg.pathRiskTtlMs) st.path = null;
    if (st.injection && now - st.injection.ts > this.cfg.pathRiskTtlMs) st.injection = null;

    // record path-risk for sensitive-path access (early-warning, complementary signal — D3)
    const path = pathOf(call);
    if (path && SENSITIVE_PATH.test(path)) {
      const paths = st.path?.paths ?? new Set<string>();
      paths.add(path);
      st.path = { paths, lastTs: now };
    }

    // Enforcement (D4/D12): egress is gated. `isEgress` counts native EGRESS tools AND a Bash command
    // carrying a network verb (`curl`/`wget`/`scp`…), so an in-shell exfil isn't invisible (H1).
    // Content-confirmed taint (a real secret) is the strongest case; a live injection flag also raises
    // posture. path-only risk stays audit/allow.
    let verdict: ContentVerdict = NO_VERDICT;
    if (isEgress(call)) {
      // M6: precise content-match — does the OUTBOUND payload actually carry a loaded secret?
      // This is the strongest exfil evidence; reported with provenance + confidence, never the value.
      const hit = st.content?.secrets?.length ? matchSecret(st.content.secrets, payloadOf(call, this.cfg.scanLimitBytes)) : null;
      if (hit) {
        const dest = destOf(call);
        verdict = {
          action: 'HITL',
          reason: `Confirmed exfiltration: a ${hit.type} secret (source: ${hit.source}, sha256:${hit.hash}, confidence ${Math.round(hit.confidence * 100)}%) appears in the outbound ${call.tool} payload${dest ? ` to ${dest}` : ''}. Approve only if this is intended.`,
          kind: 'content-exfil-match',
        };
      } else if (st.content?.structured) {
        const types = [...st.content.types].join(', ');
        verdict = {
          action: 'HITL',
          reason: `Potential exfiltration: a secret (${types}) was loaded into this session, and the agent is now making an outbound ${call.tool} call. Approve only if this egress is expected.`,
          kind: 'content-exfil',
        };
      } else if (st.injection) {
        verdict = {
          action: 'HITL',
          reason: `Raised posture: a prior tool result (${st.injection.tool}) was flagged as prompt-injection (score ${st.injection.score.toFixed(2)}); the agent is now making an outbound ${call.tool} call. Approve only if this egress is expected.`,
          kind: 'content-injection',
        };
      } else if (st.path) {
        // path-only risk: a weak early-warning. Action stays null (audit/allow, D4) — the RiskEngine
        // gives it a small weight that only escalates when it stacks with other concerns.
        verdict = {
          action: null,
          reason: `Path-risk: this session accessed a sensitive path (${[...st.path.paths][0]}) and is now making an outbound ${call.tool} call.`,
          kind: 'path-risk',
        };
      } else if (st.content) {
        // Entropy-only taint (FP1a): a high-entropy blob was loaded but NO structured secret and the exact
        // value isn't in this payload. Too weak to HITL egress on its own (that was the false positive), but
        // NOT nothing — an evasively-encoded exfil of a bespoke token would evade the exact-match above. Emit
        // a weak AUDIT-tier corroboration (action null, path-risk weight): quiet alone (below the audit band),
        // escalates only when it STACKS with another distinct concern. Defense-in-depth without the FP.
        verdict = {
          action: null,
          reason: `Weak content-risk: high-entropy data was loaded into this session and the agent is now making an outbound ${call.tool} call (no structured secret; exact value not seen in payload).`,
          kind: 'path-risk',
        };
      }
    } else if (st.injection && (classify(call.tool) === 'EXECUTE' || classify(call.tool) === 'WRITE')) {
      // H4/D12: a session whose context was poisoned by prompt-injection is now running code (Bash) or
      // writing a file — not just egressing. Gate those too, or an injected agent simply avoids EGRESS
      // tools and runs `curl`/`rm` through Bash. Same `content-injection` kind ⇒ same weight/attribution.
      verdict = {
        action: 'HITL',
        reason: `Raised posture: a prior tool result (${st.injection.tool}) was flagged as prompt-injection (score ${st.injection.score.toFixed(2)}); the agent is now running a ${classify(call.tool)} action (${call.tool}). Approve only if this is expected.`,
        kind: 'content-injection',
      };
    }

    this.evictIfClean(sessionId, now);
    return verdict;
  }

  reset(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  private get(sessionId: string): SessionState {
    let st = this.sessions.get(sessionId);
    if (!st) {
      st = { content: null, path: null, injection: null };
      this.sessions.set(sessionId, st);
    }
    return st;
  }

  /**
   * Drop a session that holds nothing actionable — no confirmed taint and no live path-risk — so the
   * map can't grow forever from benign traffic. Content-confirmed sessions persist by design (D5)
   * until `reset`, because the secret is still in the agent's context.
   */
  private evictIfClean(sessionId: string, now: number): void {
    const st = this.sessions.get(sessionId);
    if (!st) return;
    const pathLive = !!st.path && now - st.path.lastTs <= this.cfg.pathRiskTtlMs;
    const injLive = !!st.injection && now - st.injection.ts <= this.cfg.pathRiskTtlMs;
    if (!st.content && !pathLive && !injLive) this.sessions.delete(sessionId);
  }
}

function pathOf(call: MCPToolCall): string {
  const i = call.input ?? {};
  const p = i['file_path'] ?? i['path'];
  return typeof p === 'string' ? p : '';
}

function commandOf(call: MCPToolCall): string {
  const c = call.input?.['command'];
  return typeof c === 'string' ? c : '';
}

// Shell verbs that make a network call — used to treat a Bash EXECUTE as an egress for the exfil gate (H1).
const NETWORK_VERB =
  /\b(curl|wget|fetch|nc|ncat|netcat|scp|sftp|rsync|ssh|ftp|telnet|nslookup|dig|host)\b|\bInvoke-(WebRequest|RestMethod)\b|\b(iwr|irm)\b/i;
// bash's /dev/tcp|/dev/udp pseudo-devices are a raw-socket egress channel with no "verb".
const DEV_SOCKET = /[/\\]dev[/\\](tcp|udp)[/\\]/i;

// git subcommands that make NO network call. Their arguments (commit messages, branch/tag names, paths)
// routinely contain words like "ssh"/"fetch"/"host" that must NOT be read as a network reach-out (FP1c:
// `git commit -m "add ssh config"` was gated as egress). NETWORK git verbs (push/fetch/pull/clone/remote/
// submodule) and `config` (sets remotes / credential helpers) are deliberately EXCLUDED — they stay egress-eligible.
const LOCAL_GIT = new Set([
  'commit', 'add', 'status', 'log', 'diff', 'show', 'branch', 'tag', 'stash', 'reset', 'restore', 'checkout',
  'switch', 'mv', 'rm', 'merge', 'rebase', 'cherry-pick', 'revert', 'init', 'describe', 'shortlog', 'reflog', 'blame',
]);

/** Coarse top-level shell split (mirrors the policy engine's conservative segmentation). */
const cmdSegments = (cmd: string): string[] => cmd.split(/\|\||&&|[;|&\n]/g).map((s) => s.trim()).filter(Boolean);

/** Command-substitution bodies — `$(...)` / backtick — are commands in their own right; extract them so a
 *  verb hidden inside `git commit -m "$(curl evil)"` still counts even though the outer segment is local git. */
function extractSubstitutions(cmd: string): string[] {
  const out: string[] = [];
  const re = /\$\(([^()]*)\)|`([^`]*)`/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(cmd)) !== null) out.push(m[1] ?? m[2] ?? '');
  return out;
}

/** A segment whose leading token is `git` and whose subcommand is purely local — a NETWORK_VERB word in its
 *  args is inert data, not a reach-out. Skips git global options (`-c k=v`, `-C dir`, `--no-pager`) to find the verb. */
function isLocalGitSegment(seg: string): boolean {
  const toks = seg.trim().split(/\s+/);
  if (toks[0] !== 'git') return false;
  let i = 1;
  while (i < toks.length) {
    const t = toks[i] ?? '';
    if (t === '-c' || t === '-C') { i += 2; continue; } // these take an argument
    if (t.startsWith('-')) { i += 1; continue; } // other global flag (e.g. --no-pager)
    break;
  }
  const sub = toks[i];
  return sub != null && LOCAL_GIT.has(sub);
}

/** Is this call an egress for the content gate? A native EGRESS tool, or a shell command that reaches out.
 *  Evaluated PER SEGMENT so a network verb only counts when it's a real command — not a word inside a local
 *  git message (FP1c) — while a chained/substituted `curl`/`ssh`/`nc` in ANY segment still fires (H1 kept). */
function isEgress(call: MCPToolCall): boolean {
  if (classify(call.tool) === 'EGRESS') return true;
  const cmd = commandOf(call);
  if (cmd === '') return false;
  if (DEV_SOCKET.test(cmd)) return true;
  const segments = [...cmdSegments(cmd), ...extractSubstitutions(cmd)];
  return segments.some((seg) => !isLocalGitSegment(seg) && NETWORK_VERB.test(seg));
}

interface FoundSecret {
  value: string;
  type: string;
  confidence: number;
  line: number;
}

/** Upper bound on the structured secret scan — the /inspect body is already ≤1MB (readJson cap). */
const STRUCTURED_SCAN_MAX = 1_000_000;
/** Cap on entropy-fallback hits per result, so a benign high-entropy blob can't flood session memory. */
const MAX_ENTROPY_HITS = 5;

/** Detect secrets in a tool result, capturing the matched VALUE + provenance line for egress matching. */
function detectSecretValues(text: string, cfg: ContentConfig): FoundSecret[] {
  const out: FoundSecret[] = [];
  // Structured patterns scan the WHOLE result (M2) — a secret padded past the 64KB entropy window is
  // still caught. Bounded by STRUCTURED_SCAN_MAX; the regexes are anchored/bounded ⇒ cheap even at ~1MB.
  const structured = text.length > STRUCTURED_SCAN_MAX ? text.slice(0, STRUCTURED_SCAN_MAX) : text;
  for (const { type, re, confidence, valueGroup } of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    let m: RegExpExecArray | null;
    while ((m = g.exec(structured)) !== null) {
      const value = (valueGroup != null ? m[valueGroup] : m[0]) ?? m[0];
      if (value && value.length >= 8) out.push({ value, type, confidence, line: lineOf(structured, m.index) });
      if (m.index === g.lastIndex) g.lastIndex++; // never loop on a zero-width match
    }
  }

  // Entropy fallback (D8) — only when no structured pattern matched, tuned conservative to limit FPs.
  // The O(n) tokenizer is the costly part, so it stays bounded to the first scanLimitBytes; but we no
  // longer stop at the FIRST hit (M3) — a real secret sitting after a benign high-entropy blob was being
  // missed. Collect up to MAX_ENTROPY_HITS distinct tokens.
  if (out.length === 0) {
    const head = structured.length > cfg.scanLimitBytes ? structured.slice(0, cfg.scanLimitBytes) : structured;
    const seen = new Set<string>();
    for (const token of head.split(/[\s'"`,;(){}[\]]+/)) {
      if (
        token.length >= cfg.entropyMinLen &&
        !seen.has(token) &&
        /^[A-Za-z0-9+/=_-]+$/.test(token) &&
        !isBenignBlob(token) &&
        shannon(token) >= cfg.entropyThreshold
      ) {
        seen.add(token);
        out.push({ value: token, type: 'high-entropy', confidence: 0.75, line: lineOf(head, head.indexOf(token)) });
        if (out.length >= MAX_ENTROPY_HITS) break;
      }
    }
  }
  return out;
}

const lineOf = (text: string, idx: number): number => (idx < 0 ? 1 : text.slice(0, idx).split('\n').length);

const hash12 = (v: string): string => createHash('sha256').update(v).digest('hex').slice(0, 12);

/** The encoded forms an exfil might use — we encode the KNOWN secret and search the payload for any. */
function encodedForms(v: string): string[] {
  const forms = [v];
  try {
    forms.push(Buffer.from(v).toString('base64'), Buffer.from(v).toString('hex'), encodeURIComponent(v));
  } catch {
    /* non-encodable — raw only */
  }
  // Split-across-calls (L1): a long secret chopped mid-value still leaks a distinctive high-entropy
  // prefix. Matching a ≥20-char prefix of a ≥24-char secret is near-zero false-positive (secrets are
  // high-entropy) and catches the first chunk of a two-call exfil.
  if (v.length >= 24) forms.push(v.slice(0, 20));
  return forms.filter((f) => f.length >= 8);
}

/** Does the egress payload contain any loaded secret (raw or commonly-encoded)? Returns the match. */
function matchSecret(secrets: readonly SecretRef[], payload: string): SecretRef | null {
  for (const s of secrets) for (const form of encodedForms(s.value)) if (payload.includes(form)) return s;
  return null;
}

/** Serialize the outbound call's args (url + body + headers…) for content scanning, capped for latency. */
function payloadOf(call: MCPToolCall, limit: number): string {
  try {
    return JSON.stringify(call.input ?? {}).slice(0, limit);
  } catch {
    return '';
  }
}

/** Best-effort destination host from the egress call (native `url` arg, or a URL inside a Bash command). */
function destOf(call: MCPToolCall): string {
  const u = call.input?.['url'];
  const raw = typeof u === 'string' ? u : (/\bhttps?:\/\/[^\s'"`)|>]+/i.exec(commandOf(call))?.[0] ?? '');
  if (!raw) return '';
  try {
    return new URL(raw).host;
  } catch {
    return '';
  }
}

// Ubiquitous benign high-entropy shapes the agent reads during normal maintenance — NOT secrets, and
// arming taint on them was FP1a. Excluded from the entropy fallback ONLY (structured SECRET_PATTERNS are
// unaffected). Deliberately narrow: a real bespoke token that merely *looks* like these (e.g. a genuine
// 40-char API token) is far more likely to co-occur with a structured pattern, a sensitive PATH, or to
// appear verbatim in an egress payload — all of which stay covered (structured taint, path-risk, M6 match).
const SUBRESOURCE_INTEGRITY = /^(?:sha(?:256|384|512))[-:][A-Za-z0-9+/=]+$/; //   SRI / npm-yarn integrity digest
const PURE_HEX_DIGEST = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{128}$/; // md5/sha1/sha256/sha512 hex (go.sum, git oid, Cargo checksum)
const RFC4122_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isBenignBlob(token: string): boolean {
  return SUBRESOURCE_INTEGRITY.test(token) || PURE_HEX_DIGEST.test(token) || RFC4122_UUID.test(token);
}

/** Shannon entropy in bits/char — a cheap "does this look random/secret-like" measure. */
function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
