/**
 * `cerberus feeds refresh` / `cerberus feeds status` — the OPT-IN, offline-friendly L1 IOC feed.
 *
 * refresh: download the hostfile feeds listed in rules/feeds.yaml (http(s) or file://), parse them to a
 * domain set, and write `.cerberus/ioc.json`. The engine loads it at startup and matches every egress
 * destination LOCALLY — no per-request network call, so local-first/no-telemetry is preserved (the fetch
 * is a periodic bulk download to a config-listed set of hosts). status: show the last refresh + counts.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import yaml from 'js-yaml';
import { IocStore, type IocCache } from '../signals/ioc.js';
import { strEnv } from '../config/env.js';

interface Feed {
  name: string;
  url: string;
  severity: 'block' | 'hitl';
}

export async function runFeeds(argv: string[], projectRoot: string): Promise<void> {
  const sub = argv.find((a) => !a.startsWith('-')) ?? 'status';
  const cfgIdx = argv.indexOf('--config');
  const cfgPath = cfgIdx >= 0 ? (argv[cfgIdx + 1] as string) : join(projectRoot, 'rules', 'feeds.yaml');
  // Write the IOC cache to the SAME dir the engine reads it from — dirname(auditFile) — so a CB_AUDIT /
  // CB_STATE_DIR override keeps refresh and engine aligned (default: <cwd>/.cerberus).
  const cachePath = join(dirname(strEnv('AUDIT', join(strEnv('STATE_DIR', join(process.cwd(), '.cerberus')), 'audit.jsonl'))), 'ioc.json');

  if (sub === 'status') return status(cachePath);
  if (sub !== 'refresh') {
    process.stderr.write('usage: cerberus feeds [refresh|status] [--config <feeds.yaml>]\n');
    process.exit(2);
  }

  if (!existsSync(cfgPath)) {
    process.stderr.write(`cerberus feeds: no feed config at ${cfgPath}. Add feeds there (see rules/feeds.yaml).\n`);
    process.exit(2);
  }
  const doc = yaml.load(readFileSync(cfgPath, 'utf8')) as { feeds?: Feed[] } | undefined;
  const feeds = (doc?.feeds ?? []).filter((f) => f && f.url && f.name);
  if (feeds.length === 0) {
    process.stderr.write('cerberus feeds: no feeds configured.\n');
    process.exit(2);
  }

  const block = new Set<string>();
  const hitl = new Set<string>();
  const sources: { name: string; count: number }[] = [];
  process.stdout.write(`Refreshing ${feeds.length} feed(s) → ${cachePath}\n`);
  for (const f of feeds) {
    let text: string;
    try {
      text = await fetchFeed(f.url);
    } catch (e) {
      process.stdout.write(`  ✗ ${f.name}: ${(e as Error).message} (skipped)\n`);
      continue;
    }
    const domains = parseHostfile(text);
    const set = f.severity === 'block' ? block : hitl;
    for (const d of domains) set.add(d);
    sources.push({ name: f.name, count: domains.length });
    process.stdout.write(`  ✓ ${f.name}: ${domains.length} domain(s) [${f.severity}]\n`);
  }

  const cache: IocCache = { block: [...block], hitl: [...hitl], refreshedAt: Date.now(), sources };
  mkdirSync(dirname(cachePath), { recursive: true });
  writeFileSync(cachePath, JSON.stringify(cache));
  process.stdout.write(`\nWrote ${block.size} block + ${hitl.size} hitl domain(s) → ${cachePath}. Restart \`cerberus engine\` to load.\n`);
  process.exit(0);
}

function status(cachePath: string): void {
  const store = new IocStore(cachePath);
  if (!store.loaded) {
    process.stdout.write('No IOC feed loaded. Run `cerberus feeds refresh`.\n');
    return;
  }
  const when = store.refreshedAt ? new Date(store.refreshedAt).toISOString() : 'unknown';
  process.stdout.write(`IOC feed: ${store.size} domain(s), refreshed ${when}\n`);
  for (const s of store.sources) process.stdout.write(`  • ${s.name}: ${s.count}\n`);
}

/** Fetch a feed over http(s) or read a file:// (or bare path) — the latter for air-gapped mirrors + tests. */
async function fetchFeed(url: string): Promise<string> {
  if (url.startsWith('file://')) return readFile(fileURLToPath(url), 'utf8');
  if (!/^https?:\/\//i.test(url)) return readFile(url, 'utf8'); // bare path
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

/** Parse a hostfile / domain list into normalized domains (handles `0.0.0.0 d`, adblock `||d^`, plain d). */
export function parseHostfile(text: string): string[] {
  const out = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.replace(/[#!].*$/, '').trim();
    if (!line) continue;
    // hosts format: "0.0.0.0 evil.com" / "127.0.0.1 evil.com" / "::1 evil.com"
    const parts = line.split(/\s+/);
    if (parts.length >= 2 && /^(0\.0\.0\.0|127\.0\.0\.1|::1?|::ffff:0\.0\.0\.0)$/.test(parts[0] as string)) line = parts[1] as string;
    // adblock: ||evil.com^
    line = line.replace(/^\|\|/, '').replace(/\^.*$/, '').replace(/^\*\./, '');
    line = line.toLowerCase().replace(/\.$/, '');
    if (/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(line)) out.add(line);
  }
  return [...out];
}
