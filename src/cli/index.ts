/**
 * Cerberus CLI — two subcommands:
 *   cerberus engine   start the long-running Engine (HTTP hold + WS dashboard feed)
 *   cerberus hook      run the PreToolUse hook (Claude Code spawns this per tool call)
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { Engine } from '../engine/server.js';
import { DEFAULT_ANOMALY_CONFIG } from '../signals/behavioral.js';
import { DEFAULT_CONTENT_CONFIG } from '../signals/content.js';
import { DEFAULT_INJECTION_CONFIG } from '../signals/injection.js';
import { rawEnv, strEnv, numEnv, flagEnv } from '../config/env.js';

const HERE = dirname(fileURLToPath(import.meta.url));
// CB_HOME / AG_HOME (set by bin/cerberus.mjs) is the package root, so bundled resources resolve whether
// the CLI runs from src/ (tsx dev) or dist/ (published). Fall back to two-up from this file for direct runs.
const PROJECT_ROOT = rawEnv('HOME') ?? resolve(HERE, '..', '..');
/** Writable per-project runtime-state dir (audit log / IOC cache / MITM CA). CB_STATE_DIR overrides. */
const stateDir = (): string => strEnv('STATE_DIR', join(process.cwd(), '.cerberus'));

async function runEngine(): Promise<void> {
  const port = numEnv('ENGINE_PORT', 9000);
  const rulesPath = strEnv('RULES', join(PROJECT_ROOT, 'rules', 'default_policy.yaml'));
  const weightsPath = strEnv('RISK_WEIGHTS', join(PROJECT_ROOT, 'rules', 'risk_weights.yaml'));
  // Runtime state (audit log, IOC feed cache, MITM CA) lives in a WRITABLE per-project dir, not under the
  // package install root (which is read-only on a global install). `cerberus feeds` writes to the same dir.
  const auditFile = strEnv('AUDIT', join(stateDir(), 'audit.jsonl'));
  const ttlMs = numEnv('TTL_MS', 300_000); // 5 min default — NOT 60s
  const behavioral = {
    windowMs: numEnv('WINDOW_MS', DEFAULT_ANOMALY_CONFIG.windowMs),
    maxRate: numEnv('MAX_RATE', DEFAULT_ANOMALY_CONFIG.maxRate),
    maxRepeat: numEnv('MAX_REPEAT', DEFAULT_ANOMALY_CONFIG.maxRepeat),
    hardMultiplier: numEnv('HARD_MULT', DEFAULT_ANOMALY_CONFIG.hardMultiplier),
  };

  const content = {
    pathRiskTtlMs: numEnv('PATH_TTL_MS', DEFAULT_CONTENT_CONFIG.pathRiskTtlMs),
    scanLimitBytes: numEnv('SCAN_BYTES', DEFAULT_CONTENT_CONFIG.scanLimitBytes),
    entropyThreshold: numEnv('ENTROPY', DEFAULT_CONTENT_CONFIG.entropyThreshold),
    entropyMinLen: numEnv('ENTROPY_MINLEN', DEFAULT_CONTENT_CONFIG.entropyMinLen),
  };

  const injection = {
    enabled: flagEnv('INJECTION', DEFAULT_INJECTION_CONFIG.enabled),
    threshold: numEnv('INJECTION_THRESHOLD', DEFAULT_INJECTION_CONFIG.threshold),
  };

  // Serve the built dashboard if it's present (run `npm run build` to produce it).
  const dashboardDist = join(PROJECT_ROOT, 'dashboard', 'dist');
  const staticDir = existsSync(join(dashboardDist, 'index.html')) ? dashboardDist : undefined;

  const autoOpen = strEnv('AUTO_OPEN', 'off') === 'block' ? 'block' : 'off'; // M4-C D39 — default off
  // M4-C: terminal approval (HITL → Claude's native in-terminal prompt) by default; dashboard-hold opt-in.
  const approvalSurface = strEnv('APPROVAL_SURFACE', 'terminal') === 'dashboard' ? 'dashboard' : 'terminal';

  const engine = new Engine({ port, rulesPath, auditFile, ttlMs, behavioral, content, injection, weightsPath, staticDir, autoOpen, approvalSurface });
  await engine.listen();
  process.stderr.write(
    `Cerberus engine listening on :${port}\n` +
      `  rules: ${rulesPath}\n  audit: ${auditFile}\n  HITL TTL: ${ttlMs}ms\n` +
      `  anomaly: ${behavioral.maxRate} calls / ${behavioral.maxRepeat} repeats per ${behavioral.windowMs}ms (×${behavioral.hardMultiplier} = block)\n` +
      `  content: secret-scan ${content.scanLimitBytes}B/result, path-risk TTL ${content.pathRiskTtlMs}ms → exfil HITL\n` +
      `  injection: classifier=${engine.injectionClassifier} (threshold ${injection.threshold}) → posture HITL on egress\n` +
      `  risk: ${weightsPath} (${engine.riskVersion}) → ALLOW/AUDIT/HITL/BLOCK bands\n` +
      `  approval: ${approvalSurface === 'terminal' ? "terminal — HITL → Claude's native prompt (ASK)" : 'dashboard — socket hold + Approve/Deny'}\n` +
      `  auto-open: ${autoOpen === 'block' ? 'on BLOCK/EXFIL' : 'off (set CB_AUTO_OPEN=block)'}\n` +
      `  dashboard: ${staticDir ? `http://127.0.0.1:${port}/` : '(not built — run `npm run build`)'}  ·  WS ws://127.0.0.1:${port}/ws\n`,
  );
}

/** `cerberus proxy` — the network-layer egress gate (outside the agent's trust boundary). */
async function runProxy(): Promise<void> {
  const { EgressProxy } = await import('../proxy/server.js');
  const port = numEnv('PROXY_PORT', 9100);
  const enginePort = numEnv('ENGINE_PORT', 9000);
  const mitm = process.argv.includes('--mitm') || flagEnv('PROXY_MITM', false);
  const mitmDir = strEnv('MITM_DIR', stateDir());
  const proxy = new EgressProxy({ port, engineHost: strEnv('ENGINE_HOST', '127.0.0.1'), enginePort, failOpen: flagEnv('FAIL_OPEN', false), mitm, mitmDir, redact: flagEnv('REDACT', true) });
  try {
    await proxy.listen();
  } catch (err) {
    process.stderr.write(`Cerberus proxy: ${(err as Error).message}\n`);
    process.exit(1);
  }
  process.stderr.write(
    `Cerberus egress proxy on http://127.0.0.1:${port} → engine :${enginePort}\n` +
      `  point your agent/shell at it:  export HTTPS_PROXY=http://127.0.0.1:${port} HTTP_PROXY=http://127.0.0.1:${port}\n` +
      (mitm
        ? `  MITM ON: HTTPS decrypted → RESPONSE scanned for injected payloads + secrets REDACTED from the\n` +
        `           outbound prompt to LLM providers (Layer 2; disable redaction with CB_REDACT=0).\n` +
          `  ⚠ Trust the CA so clients accept it:  ${join(mitmDir, 'ca.crt')}\n` +
          `     (e.g. export NODE_EXTRA_CA_CERTS=${join(mitmDir, 'ca.crt')}  ·  or add to your OS/browser trust store)\n`
        : `  HTTPS gated by destination host (no MITM); plain HTTP also body-scanned for loaded secrets.\n` +
          `  For response-body scanning of HTTPS, run:  cerberus proxy --mitm\n`),
  );
}

/** Fetch against the local engine using the same host/port env the hook uses. */
function engineFetch(path: string, init?: RequestInit): Promise<Response> {
  const host = strEnv('ENGINE_HOST', '127.0.0.1');
  const port = numEnv('ENGINE_PORT', 9000);
  return fetch(`http://${host}:${port}${path}`, { headers: { 'content-type': 'application/json' }, ...init });
}

/** `cerberus approve|deny <id>` — the terminal approval channel (M4-C, D34). */
async function runDecision(action: 'ALLOW' | 'BLOCK', id: string | undefined): Promise<void> {
  if (!id) {
    process.stderr.write(`usage: cerberus ${action === 'ALLOW' ? 'approve' : 'deny'} <violation-id>   (list ids with \`cerberus pending\`)\n`);
    process.exit(1);
  }
  const r = await engineFetch('/decision', { method: 'POST', body: JSON.stringify({ type: 'decision', violationId: id, action }) });
  if (r.ok) process.stdout.write(`${action === 'ALLOW' ? '✓ approved' : '⛔ denied'} ${id}\n`);
  else {
    process.stderr.write(`Cerberus: decision failed (${r.status}). Is the engine running, and is the id still pending?\n`);
    process.exit(1);
  }
}

/** `cerberus pending` — list calls currently held for review, with their ids (M4-C, D41). */
async function runPending(): Promise<void> {
  let r: Response;
  try {
    r = await engineFetch('/pending');
  } catch {
    process.stderr.write('Cerberus: cannot reach the engine. Start it with `cerberus engine`.\n');
    process.exit(1);
  }
  if (!r.ok) { process.stderr.write(`Cerberus: /pending returned ${r.status}.\n`); process.exit(1); }
  const { pending } = (await r.json()) as {
    pending: { id: string; toolCall: { tool: string }; reason: string; risk?: { score: number } }[];
  };
  if (pending.length === 0) { process.stdout.write('No calls awaiting approval.\n'); return; }
  process.stdout.write(`${pending.length} awaiting approval:\n`);
  for (const v of pending) {
    process.stdout.write(
      `  ${v.id}  ${v.toolCall.tool}${v.risk ? ` · risk=${v.risk.score}` : ''}\n    ${v.reason}\n` +
        `    → cerberus approve ${v.id}    ·    cerberus deny ${v.id}\n`,
    );
  }
}

async function main(): Promise<void> {
  const cmd = process.argv[2];
  if (cmd === 'engine') return runEngine();
  if (cmd === 'proxy') return runProxy();
  if (cmd === 'hook') {
    await import('../hook/index.js');
    return;
  }
  if (cmd === 'init') {
    const { runInit } = await import('./init.js');
    return runInit(process.argv.slice(3));
  }
  if (cmd === 'approve') return runDecision('ALLOW', process.argv[3]);
  if (cmd === 'deny') return runDecision('BLOCK', process.argv[3]);
  if (cmd === 'pending') return runPending();
  if (cmd === 'rules' && process.argv[3] === 'validate') {
    const { runValidate } = await import('./validate.js');
    return runValidate(process.argv.slice(4));
  }
  if (cmd === 'scan') {
    const { runScan } = await import('./scan.js');
    return runScan(process.argv.slice(3), Date.now());
  }
  if (cmd === 'deps') {
    const { runDeps } = await import('./deps.js');
    return runDeps(process.argv.slice(3), PROJECT_ROOT);
  }
  if (cmd === 'feeds') {
    const { runFeeds } = await import('./feeds.js');
    return runFeeds(process.argv.slice(3), PROJECT_ROOT);
  }
  process.stderr.write(
    'usage: cerberus <command>\n\n' +
      '  init [--agent claude|codex|cursor|cline] [--global] [--print]   wire the hooks into the agent\n' +
      '  engine                      start the gateway (HTTP hold + WS) and serve the dashboard\n' +
      '  proxy                       start the network-layer egress proxy (HTTPS_PROXY target)\n' +
      '  hook                        the Claude Code hook entry (spawned per tool call)\n' +
      '  pending                     list calls held for review (with their ids)\n' +
      '  approve <id> | deny <id>    resolve a held call from the terminal\n' +
      '  rules validate [--file <path>]  lint rule YAML files before engine load\n' +
      '  scan [--file <tools.json>] [--pin] [--no-connect]  scan MCP tool defs (auto-discovers servers) for\n' +
      '                              poisoning + rug-pull (tool-pinning)\n' +
      '  proxy --mitm                egress proxy that also decrypts+scans HTTPS response bodies\n' +
      '  deps [--dir <path>] [--osv]  offline supply-chain audit of lockfiles (malicious/vuln/url-deps/hash-pin)\n' +
      '  feeds refresh | status      refresh the local IOC destination feed (cerberus feeds refresh)\n',
  );
  process.exit(1);
}

main().catch((err: unknown) => {
  process.stderr.write(`Cerberus: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
