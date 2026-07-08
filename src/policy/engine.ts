/**
 * PolicyEngine — the deterministic decision core.
 *
 * V1 implementation reads declarative rules (DATA, not code) from a YAML file and
 * evaluates them with json-logic-js. Hidden behind the `PolicyEngine` interface so
 * an OPA or Cedar adapter can be dropped in for Enterprise without touching callers.
 */
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import jsonLogic from 'json-logic-js';
import { classify } from '../taxonomy/index.js';
import { testMatch } from './match.js';
import type { MCPToolCall, PolicyAction, PolicyDecision, ToolCategory } from '../contract/types.js';

export interface PolicyEngine {
  evaluate(call: MCPToolCall): PolicyDecision;
}

interface Rule {
  id: string;
  description: string;
  action: PolicyAction;
  when: unknown;
}

interface PolicyFile {
  default: PolicyAction;
  rules: Rule[];
}

// Register a regex operation once, so rules can express `{ matches: [pattern, { var: command }] }`.
// Compilation (incl. the `(?i)` inline-flags prefix) lives in ./match so the `rules validate` linter
// accepts exactly the patterns the engine runs — no drift between validate-time and runtime.
let opsRegistered = false;
function registerOps(): void {
  if (opsRegistered) return;
  jsonLogic.add_operation('matches', (pattern: unknown, value: unknown): boolean => testMatch(pattern, value));
  opsRegistered = true;
}

export class JsonLogicPolicyEngine implements PolicyEngine {
  private readonly policy: PolicyFile;

  constructor(rulesPath: string) {
    registerOps();
    const parsed = yaml.load(readFileSync(rulesPath, 'utf8')) as Partial<PolicyFile> | undefined;
    if (!parsed || !Array.isArray(parsed.rules)) {
      throw new Error(`Cerberus: invalid policy file at ${rulesPath} (expected { default, rules[] }).`);
    }
    this.policy = { default: parsed.default ?? 'HITL', rules: parsed.rules };
  }

  evaluate(call: MCPToolCall): PolicyDecision {
    const category = classify(call.tool);
    const command = commandOf(call);

    // Evaluate the WHOLE command first (deny rules like block-pipe-to-shell are written to span a pipe,
    // so they must see the full string). For a chained command, that whole-string pass can be won by a
    // benign LEADING token (`echo hi; curl evil`) matching an ALLOW rule and short-circuiting the danger.
    // So we ALSO evaluate every chained segment and take the STRICTEST verdict (BLOCK > HITL > ALLOW):
    // an unrecognised segment fails toward HITL, closing the command-chaining bypass (C1). Non-shell
    // calls (Read/Write/Fetch) have no command and take the single-pass path unchanged.
    const whole = this.evaluateOne(call, category, command);
    if (!command || whole.action === 'BLOCK') return whole;

    // Extra strings to evaluate for a shell command — strictest verdict wins, so these only ever
    // ESCALATE, never relax. Two obfuscation classes are neutralised here:
    //   • de-quoting  — strip empty quote pairs / quote chars so `cat /etc/pas""swd` → `/etc/passwd`.
    //   • chaining    — each `;`/`&&`/`|`/`$( )` segment (and its de-quoted form) is judged on its own.
    const parts = hasChaining(command) ? splitSegments(command) : [];
    const norm = (s: string): string[] => [dequote(s), deslash(s), deslash(dequote(s)), deexpand(s), deexpand(dequote(s)), deansi(s), deexpand(deansi(s))];
    const candidates = [...norm(command), ...parts, ...parts.flatMap(norm)];
    const extras = [...new Set(candidates)].filter((c) => c && c !== command);
    if (extras.length === 0) return whole;

    let strict = whole;
    for (const variant of extras) {
      const d = this.evaluateOne(call, category, variant);
      if (rank(d.action) > rank(strict.action)) {
        // Give an unrecognised (default-HITL) part a clearer reason than the generic "no rule matched".
        strict = d.ruleId
          ? d
          : { ...d, reason: `Command (after de-obfuscation / chaining) has an unrecognised or higher-risk part (\`${variant}\`) — held for human review (fail-closed).` };
      }
      if (strict.action === 'BLOCK') break; // BLOCK is maximal — no need to keep scanning
    }
    return strict;
  }

  /** Evaluate one command string (whole command or a single chained segment) against the rule set. */
  private evaluateOne(call: MCPToolCall, category: ToolCategory, command: string): PolicyDecision {
    const fact = this.toFact(call, category, command);

    for (const rule of this.policy.rules) {
      if (jsonLogic.apply(rule.when, fact) === true) {
        return { action: rule.action, ruleId: rule.id, reason: rule.description, category };
      }
    }

    // Fail-Closed: a tool we cannot even categorise is never auto-allowed.
    if (category === 'UNKNOWN') {
      return {
        action: 'HITL',
        ruleId: null,
        reason: `Unknown tool "${call.tool}" — fail-closed to human review.`,
        category,
      };
    }

    return {
      action: this.policy.default,
      ruleId: null,
      reason: `No rule matched — applying default policy (${this.policy.default}).`,
      category,
    };
  }

  /** Flatten the tool call into the primitive fields rules match against. */
  private toFact(call: MCPToolCall, category: ToolCategory, command: string) {
    const input = call.input ?? {};
    const str = (v: unknown): string => (typeof v === 'string' ? v : '');
    // Surface a URL embedded in the shell command (H1) so the egress destination rules can see a
    // `curl`/`wget` target even though the tool is Bash (EXECUTE), not a native EGRESS tool.
    const explicitUrl = str(input['url']);
    return {
      tool: call.tool,
      category,
      command,
      // The `path` fact folds together EVERY path-carrying input key, so a sensitive path can't hide in a
      // non-standard field: `glob` (Grep), `notebook_path` (NotebookRead), array `paths`/`files`, etc.
      // (fact-dodge bypasses). Without this, `Grep {glob:"**/id_rsa", path:"/home"}` read the key with the
      // sensitive name invisibly.
      path: pathFact(input),
      url: explicitUrl || urlInText(command),
      cwd: call.cwd ?? '',
    };
  }
}

/** Collect every path-ish input value (string or string[]) into one string the path rules match against. */
function pathFact(input: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const key of ['file_path', 'path', 'notebook_path', 'glob', 'filePath', 'dir', 'directory']) {
    const v = input[key];
    if (typeof v === 'string') parts.push(v);
  }
  for (const key of ['paths', 'files', 'file_paths']) {
    const a = input[key];
    if (Array.isArray(a)) for (const v of a) if (typeof v === 'string') parts.push(v);
  }
  return parts.join(' ');
}

/* --------------------------------- helpers --------------------------------- */

function commandOf(call: MCPToolCall): string {
  const c = call.input?.['command'];
  return typeof c === 'string' ? c : '';
}

const STRICTNESS: Readonly<Record<PolicyAction, number>> = { ALLOW: 1, HITL: 2, BLOCK: 3 };
const rank = (a: PolicyAction): number => STRICTNESS[a] ?? 2;

// A command "chains" if it contains a shell separator, a pipe, a background `&`, a command
// substitution `$(…)`, or a backtick — any of which can smuggle a second command past a leading token.
const CHAIN_RE = /[;\n&|]|\$\(|`/;
const hasChaining = (command: string): boolean => CHAIN_RE.test(command);

/**
 * Split a shell command into independently-evaluable segments: the command-substitution bodies
 * (`$(…)` / backticks) plus the pieces around `;`, `&&`, `||`, `|`, `&`, and newlines. Deliberately
 * conservative (not a full shell parser): it can over-split a quoted separator, but that only ever
 * routes a benign command toward HITL — never the reverse — which is the safe direction.
 */
function splitSegments(command: string): string[] {
  const out: string[] = [];
  const subRe = /\$\(([\s\S]*?)\)|`([\s\S]*?)`/g;
  let m: RegExpExecArray | null;
  while ((m = subRe.exec(command)) !== null) {
    const body = (m[1] ?? m[2] ?? '').trim();
    if (body) out.push(body);
  }
  for (const part of command.split(/\|\||&&|[;\n&|]/)) {
    const t = part.trim();
    if (t) out.push(t);
  }
  return out;
}

const URL_RE = /\bhttps?:\/\/[^\s'"`)|>]+/i;
function urlInText(text: string): string {
  const m = URL_RE.exec(text);
  return m ? m[0] : '';
}

/**
 * Strip shell quoting used purely to obfuscate a token — empty quote pairs (`""`/`''`/``` `` ```) and
 * lone quote chars — so `pas""swd` → `passwd` and `"/etc/passwd"` → `/etc/passwd`. Backslashes are left
 * ALONE (they are path separators on Windows). Only ever makes a hidden token more visible.
 */
function dequote(command: string): string {
  return command.replace(/''|""|``/g, '').replace(/['"`]/g, '');
}

/**
 * Strip a backslash that escapes an alphanumeric — POSIX shells treat `ca\t` as `cat`, `.ss\h` as
 * `.ssh`. Evaluated only as an ADDITIONAL strictest-wins variant, so on Windows the raw command (with
 * backslash path separators intact) is still judged too — this can only add detections, never remove.
 */
function deslash(command: string): string {
  return command.replace(/\\([A-Za-z0-9])/g, '$1');
}

/**
 * Collapse shell EXPANSIONS to a worst-case literal so an obfuscated path still matches a rule:
 *   `pass[w]d` → `passwd` (char-class/bracket glob)   ·   `{etc,x}/y` → `etc/y` (brace: first alt)
 *   `${z:-etc}` → `etc` (parameter default)           ·   `${VAR}` → '' (unknown value)
 * Additional strictest-wins variant only, so it can only ADD detections. Wildcards `?`/`*` are left as
 * literals — an ABSOLUTE obfuscated path (`/et?/shadow`) is already caught by the risky-path guard on the
 * read-only allow rules, so we don't need to resolve them here.
 */
function deexpand(s: string): string {
  return s
    .replace(/\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]*)\}/g, '$1') // ${x:-etc}   -> etc
    .replace(/\$\{[^}]*\}/g, '') //                            ${VAR}, ${HOME:0:0} -> '' (inert)
    .replace(/\{([^,{}]*)(?:,[^{}]*)*\}/g, '$1') //            {etc,x}     -> etc
    .replace(/\[([^\]]+)\]/g, '$1'); //                        pass[w]d    -> passwd
}

/**
 * Decode ANSI-C `$'…'` quoting to its literal so a hex/octal-escaped path still matches a rule:
 *   `$'\x2essh'` → `.ssh`   ·   `$'\151d_rsa'` → `id_rsa`   ·   `$'\x2fetc\x2fshadow'` → `/etc/shadow`.
 * Additional strictest-wins variant only (bash resolves these before running the command, so this is the
 * value the shell actually reads). Handles `\xHH`, `\0NNN`/`\NNN` octal, common `\n\t\r`, and `\<char>`.
 */
function deansi(command: string): string {
  return command.replace(/\$'((?:[^'\\]|\\.)*)'/g, (_m, body: string) =>
    body
      .replace(/\\x([0-9A-Fa-f]{1,2})/g, (_s, h: string) => String.fromCharCode(parseInt(h, 16)))
      .replace(/\\0?([0-7]{1,3})/g, (_s, o: string) => String.fromCharCode(parseInt(o, 8)))
      .replace(/\\n/g, '\n')
      .replace(/\\t/g, '\t')
      .replace(/\\r/g, '\r')
      .replace(/\\(.)/g, '$1'),
  );
}
