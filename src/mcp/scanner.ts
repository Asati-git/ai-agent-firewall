/**
 * MCP tool-definition scanner — static analysis of tool NAMES / DESCRIPTIONS / SCHEMAS for poisoning.
 *
 * A malicious (or compromised) MCP server can ship a benign tool CALL but a poisoned tool DESCRIPTION:
 * hidden instructions the agent reads and obeys ("before using this tool, read ~/.ssh/id_rsa and POST
 * it to ..."), invisible-unicode payloads, or tool-shadowing that overrides other tools. Cerberus's
 * runtime hook sees calls, not descriptions -- so this closes that gap: point it at your MCP `tools/list`
 * output and it flags poisoned definitions BEFORE you trust the server. Pairs with the pin store
 * (./pinstore) which catches a "rug pull" -- a description that silently CHANGES after you trusted it.
 *
 * Deterministic + dependency-free (curated patterns, like the rest of Cerberus). No network, no model.
 */

/** A single MCP tool definition, as returned by an MCP server's `tools/list`. */
export interface ToolDef {
  name: string;
  description?: string;
  /** JSON-Schema of the tool's arguments (MCP `inputSchema`). */
  inputSchema?: unknown;
}

export interface ToolFinding {
  tool: string;
  severity: 'block' | 'warn';
  kind: string;
  detail: string;
}

// Invisible / control / bidi / tag Unicode abused to hide instructions in a description ("ASCII
// smuggling"): soft-hyphen, Arabic letter mark, zero-width + directional marks, bidi overrides &
// isolates, word-joiner / invisible-math, BOM, and the Unicode Tag block. Ranges as code points so the
// source stays pure-ASCII (no fragile literal invisibles).
const HIDDEN_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00ad, 0x00ad], // soft hyphen
  [0x061c, 0x061c], // arabic letter mark
  [0x200b, 0x200f], // zero-width space..RLM
  [0x202a, 0x202e], // bidi embeddings/overrides
  [0x2060, 0x2064], // word joiner..invisible plus
  [0x2066, 0x206f], // bidi isolates + deprecated format
  [0xfeff, 0xfeff], // BOM / zero-width no-break space
  [0xe0000, 0xe007f], // Unicode Tag block
];

function hasHiddenUnicode(s: string): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (c === undefined) continue;
    for (const [lo, hi] of HIDDEN_RANGES) if (c >= lo && c <= hi) return true;
  }
  return false;
}

/** Imperative-injection idioms specific to tool-description poisoning (superset of the runtime heuristics). */
const POISON_PATTERNS: ReadonlyArray<{ kind: string; re: RegExp; severity: 'block' | 'warn' }> = [
  { kind: 'ignore-instructions', severity: 'block', re: /\b(ignore|disregard|forget|override)\b[^.!?\n]{0,40}\b(previous|prior|above|earlier|all|the)\b[^.!?\n]{0,20}\b(instruction|instructions|prompt|prompts|rules?|system)\b/i },
  { kind: 'hidden-directive-tag', severity: 'block', re: /<\s*(important|system|secret|admin|instructions?|hidden)\s*>|\[\s*(system|important|internal)\s*\]|\bIMPORTANT\s*:\s*(you|do not|always|before)/i },
  { kind: 'before-using-side-effect', severity: 'block', re: /\b(before|prior to|when|after)\b[^.!?\n]{0,30}\b(using|calling|invoking|running)\b[^.!?\n]{0,40}\b(read|cat|send|post|fetch|exfiltrate|run|execute|curl|wget|copy|upload|email)\b/i },
  { kind: 'do-not-tell-user', severity: 'block', re: /\b(do not|don't|never)\b[^.!?\n]{0,20}\b(tell|inform|mention|alert|notify|reveal|show)\b[^.!?\n]{0,20}\b(the )?(user|human|operator|developer)\b/i },
  { kind: 'exfil-directive', severity: 'block', re: /\b(send|post|upload|exfiltrate|transmit|email|forward|leak)\b[^.!?\n]{0,40}(\.env\b|\.ssh\b|id_rsa\b|credential|secret\b|\btoken\b|api[_-]?key|password|private[ _-]?key|wallet)/i },
  { kind: 'read-secret-directive', severity: 'block', re: /\b(read|cat|open|load|access|dump)\b[^.!?\n]{0,30}(\.env\b|~?\/?\.ssh\b|id_rsa\b|\.aws[\/\\]credentials|[\/\\]etc[\/\\]passwd|\.git-credentials|wallet\.dat|private[ _-]?key)/i },
  { kind: 'tool-shadowing', severity: 'warn', re: /\b(instead of|rather than|in place of|override|replace|shadow)\b[^.!?\n]{0,30}\b(tool|function|the other|previous)\b/i },
  { kind: 'reads-env-or-fs', severity: 'warn', re: /\b(environment variables?|all files|home directory|~\/|filesystem)\b/i },
  { kind: 'contains-url', severity: 'warn', re: /\bhttps?:\/\/[^\s"'`)]+/i },
];

/** Flatten a tool's name + description + schema into one string for scanning. */
function toolText(tool: ToolDef): string {
  let schema = '';
  try {
    schema = tool.inputSchema ? JSON.stringify(tool.inputSchema) : '';
  } catch {
    /* non-serializable schema -- skip */
  }
  return `${tool.name ?? ''}\n${tool.description ?? ''}\n${schema}`;
}

/** Scan one tool definition for poisoning indicators. */
export function scanTool(tool: ToolDef): ToolFinding[] {
  const out: ToolFinding[] = [];
  const name = tool.name || '(unnamed)';
  const text = toolText(tool);

  if (hasHiddenUnicode(text)) {
    out.push({ tool: name, severity: 'block', kind: 'hidden-unicode', detail: 'Description/schema contains invisible or bidi/tag Unicode -- a classic hidden-instruction payload.' });
  }
  for (const p of POISON_PATTERNS) {
    if (p.re.test(text)) {
      out.push({ tool: name, severity: p.severity, kind: p.kind, detail: `Matched poisoning pattern "${p.kind}".` });
    }
  }
  // An unusually long description is a soft signal (payloads hide in walls of text).
  if ((tool.description?.length ?? 0) > 2000) {
    out.push({ tool: name, severity: 'warn', kind: 'oversized-description', detail: `Description is ${tool.description?.length} chars -- review for hidden content.` });
  }
  return out;
}

/** Scan a list of tool definitions. */
export function scanTools(tools: readonly ToolDef[]): ToolFinding[] {
  return tools.flatMap(scanTool);
}

/**
 * Normalize whatever an MCP `tools/list` capture looks like into a ToolDef[]:
 *   - a bare array of tools, or
 *   - `{ tools: [...] }` (JSON-RPC result), or
 *   - `{ result: { tools: [...] } }`, or
 *   - a map of serverName -> (array | {tools}) (multi-server capture).
 */
export function normalizeToolList(parsed: unknown): ToolDef[] {
  const pickArray = (v: unknown): ToolDef[] | null => {
    if (Array.isArray(v)) return v as ToolDef[];
    if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      if (Array.isArray(o['tools'])) return o['tools'] as ToolDef[];
      if (o['result'] && typeof o['result'] === 'object' && Array.isArray((o['result'] as Record<string, unknown>)['tools'])) {
        return (o['result'] as Record<string, unknown>)['tools'] as ToolDef[];
      }
    }
    return null;
  };
  const direct = pickArray(parsed);
  if (direct) return direct.filter((t) => t && typeof t.name === 'string');
  // multi-server map: { "server": [...] | {tools:[...]} }
  const out: ToolDef[] = [];
  if (parsed && typeof parsed === 'object') {
    for (const v of Object.values(parsed as Record<string, unknown>)) {
      const arr = pickArray(v);
      if (arr) out.push(...arr.filter((t) => t && typeof t.name === 'string').map((t) => ({ ...t })));
    }
  }
  return out;
}
