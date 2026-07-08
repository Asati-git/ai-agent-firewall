/**
 * Tool-pinning store — the rug-pull defense.
 *
 * The first time you trust an MCP server, we record a SHA-256 of each tool's definition (name +
 * description + schema). On every later scan we re-hash and compare: a tool whose hash CHANGED had its
 * definition silently rewritten AFTER you trusted it — the classic "rug pull" / tool-mutation attack
 * (a benign tool ships for weeks, then quietly adds an exfil instruction to its description). New tools
 * are surfaced as unpinned; removed tools are noted. Pins persist as JSON under the audit dir.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { ToolDef } from './scanner.js';

export interface Pin {
  name: string;
  hash: string;
  firstSeen: number;
  lastSeen: number;
}

export interface Reconciliation {
  unchanged: string[];
  added: ToolDef[];
  changed: { tool: ToolDef; oldHash: string; newHash: string }[]; // rug-pull
  removed: string[];
}

/** Canonical SHA-256 of a tool definition — stable across key ordering in the schema. */
export function hashTool(tool: ToolDef): string {
  const canonical = JSON.stringify({ name: tool.name, description: tool.description ?? '', inputSchema: canon(tool.inputSchema) });
  return createHash('sha256').update(canonical).digest('hex');
}

/** Recursively sort object keys so a re-serialized schema hashes identically regardless of key order. */
function canon(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) out[k] = canon(o[k]);
    return out;
  }
  return v;
}

export class ToolPinStore {
  private pins = new Map<string, Pin>();

  constructor(private readonly file: string) {
    this.load();
  }

  private load(): void {
    if (!existsSync(this.file)) return;
    try {
      const arr = JSON.parse(readFileSync(this.file, 'utf8')) as Pin[];
      for (const p of arr) if (p && typeof p.name === 'string') this.pins.set(p.name, p);
    } catch {
      /* corrupt pin file — treat as empty (a fresh scan re-pins everything) */
    }
  }

  /** Compare `tools` against the stored pins WITHOUT writing. (`_now` unused; kept for API symmetry with commit.) */
  reconcile(tools: readonly ToolDef[], _now?: number): Reconciliation {
    const r: Reconciliation = { unchanged: [], added: [], changed: [], removed: [] };
    const seen = new Set<string>();
    for (const tool of tools) {
      seen.add(tool.name);
      const pin = this.pins.get(tool.name);
      const hash = hashTool(tool);
      if (!pin) r.added.push(tool);
      else if (pin.hash !== hash) r.changed.push({ tool, oldHash: pin.hash, newHash: hash });
      else r.unchanged.push(tool.name);
    }
    for (const name of this.pins.keys()) if (!seen.has(name)) r.removed.push(name);
    return r;
  }

  /** Persist the current tool set as the trusted baseline (call after review). */
  commit(tools: readonly ToolDef[], now: number): void {
    for (const tool of tools) {
      const existing = this.pins.get(tool.name);
      this.pins.set(tool.name, { name: tool.name, hash: hashTool(tool), firstSeen: existing?.firstSeen ?? now, lastSeen: now });
    }
    mkdirSync(dirname(this.file), { recursive: true });
    writeFileSync(this.file, JSON.stringify([...this.pins.values()], null, 2) + '\n');
  }

  get size(): number {
    return this.pins.size;
  }
}
