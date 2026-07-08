/**
 * `cerberus scan [--file <tools.json>] [--pin] [--no-connect] [--timeout <ms>]`
 *
 * Two modes:
 *   • default (no --file) — AUTO-DISCOVER MCP servers from the agent config files (.mcp.json,
 *     ~/.claude.json, .cursor/mcp.json, VS Code, Claude Desktop, Windsurf…), connect to each, and pull
 *     its live `tools/list`. Tool names are namespaced `server::tool` so pins don't collide across servers.
 *   • --file <tools.json> — scan a hand-captured `tools/list` dump (array / {tools:[…]} / JSON-RPC / map).
 *
 * Then: static poisoning scan + rug-pull check (SHA-256 pins). `--pin` records the trusted baseline.
 * `--no-connect` only lists the discovered servers (spawns nothing). Exit 1 on any block finding / rug-pull.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { normalizeToolList, scanTools, type ToolDef } from '../mcp/scanner.js';
import { ToolPinStore } from '../mcp/pinstore.js';
import { discoverServers } from '../mcp/discover.js';
import { listTools } from '../mcp/client.js';
import { rawEnv, strEnv } from '../config/env.js';

export async function runScan(argv: string[], now: number): Promise<void> {
  const fileIdx = argv.indexOf('--file');
  const file = fileIdx >= 0 ? argv[fileIdx + 1] : undefined;
  const doPin = argv.includes('--pin');
  const noConnect = argv.includes('--no-connect');
  const timeoutIdx = argv.indexOf('--timeout');
  const timeoutMs = timeoutIdx >= 0 ? Number(argv[timeoutIdx + 1]) || 8000 : 8000;
  const home = rawEnv('HOME') ?? process.cwd();
  const pinsIdx = argv.indexOf('--pins');
  const pinsFile = pinsIdx >= 0 ? (argv[pinsIdx + 1] as string) : strEnv('TOOL_PINS', join(home, '.cerberus', 'tool_pins.json'));

  const tools = file ? readFileMode(file) : await discoverMode(noConnect, timeoutMs);
  if (tools === null) return; // discoverMode already printed (e.g. --no-connect listing)
  if (tools.length === 0) {
    process.stderr.write('cerberus scan: no tool definitions to scan.\n');
    process.exit(file ? 2 : 0);
  }

  const findings = scanTools(tools);
  const store = new ToolPinStore(pinsFile);
  const rec = store.reconcile(tools, now);

  process.stdout.write(`\nScanned ${tools.length} tool(s)\n`);
  const blocks = findings.filter((f) => f.severity === 'block');
  const warns = findings.filter((f) => f.severity === 'warn');
  if (findings.length === 0) process.stdout.write('  ✓ no poisoning indicators\n');
  for (const f of blocks) process.stdout.write(`  ⛔ [${f.tool}] ${f.kind} — ${f.detail}\n`);
  for (const f of warns) process.stdout.write(`  ⚠ [${f.tool}] ${f.kind} — ${f.detail}\n`);

  process.stdout.write('\nPin reconciliation:\n');
  for (const c of rec.changed) process.stdout.write(`  🔁 RUG-PULL [${c.tool.name}] definition changed since pinned (${c.oldHash.slice(0, 12)} → ${c.newHash.slice(0, 12)})\n`);
  if (rec.added.length) process.stdout.write(`  ＋ ${rec.added.length} new (unpinned): ${rec.added.map((t) => t.name).join(', ')}\n`);
  if (rec.removed.length) process.stdout.write(`  － ${rec.removed.length} removed: ${rec.removed.join(', ')}\n`);
  if (rec.unchanged.length) process.stdout.write(`  ✓ ${rec.unchanged.length} unchanged (pinned)\n`);

  if (doPin) {
    store.commit(tools, now);
    process.stdout.write(`\nPinned ${tools.length} tool(s) as trusted baseline → ${pinsFile}\n`);
    process.exit(0);
  }
  const failed = blocks.length > 0 || rec.changed.length > 0;
  process.stdout.write(failed ? `\n✗ ${blocks.length} poisoning finding(s), ${rec.changed.length} rug-pull(s). Review before trusting; re-run with --pin to accept.\n` : '\n✓ clean (no block findings, no rug-pulls).\n');
  process.exit(failed ? 1 : 0);
}

/** --file mode: read + normalize a captured tools/list JSON. */
function readFileMode(file: string): ToolDef[] {
  if (!existsSync(file)) {
    process.stderr.write(`cerberus scan: file not found: ${file}\n`);
    process.exit(2);
  }
  try {
    return normalizeToolList(JSON.parse(readFileSync(file, 'utf8')));
  } catch (err) {
    process.stderr.write(`cerberus scan: cannot parse ${file}: ${(err as Error).message}\n`);
    process.exit(2);
  }
}

/** default mode: discover servers from agent configs, then connect + list (unless --no-connect). */
async function discoverMode(noConnect: boolean, timeoutMs: number): Promise<ToolDef[] | null> {
  const servers = discoverServers();
  if (servers.length === 0) {
    process.stdout.write('No MCP servers found in the usual agent configs. Pass --file <tools.json> to scan a captured list.\n');
    return null;
  }
  process.stdout.write(`Discovered ${servers.length} MCP server(s):\n`);
  for (const s of servers) process.stdout.write(`  • ${s.name} [${s.transport}] ${s.url ?? `${s.command} ${(s.args ?? []).join(' ')}`}  (${s.source})\n`);
  if (noConnect) {
    process.stdout.write('\n--no-connect: not spawning/contacting any server. Re-run without it to fetch tools/list.\n');
    return null;
  }
  process.stdout.write('\n⚠ Connecting spawns/contacts each server to read its tools/list — scan only servers you intend to run.\n');
  const all: ToolDef[] = [];
  for (const s of servers) {
    const r = await listTools(s, timeoutMs);
    if (r.error) process.stdout.write(`  ✗ ${s.name}: ${r.error}\n`);
    else process.stdout.write(`  ✓ ${s.name}: ${r.tools.length} tool(s)\n`);
    for (const t of r.tools) all.push({ ...t, name: `${s.name}::${t.name}` }); // namespace to avoid cross-server pin collisions
  }
  return all;
}
