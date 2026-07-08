/**
 * Lockfile parsing for `cerberus deps` — turn a project's lockfiles into a flat dependency list with two
 * integrity signals: `integrity` (is the install tamper-evident — a pinned hash?) and `urlDep` (is it
 * pulled from a URL/git, i.e. unpinned + can run arbitrary build/postinstall = RCE surface).
 *
 * Supported: npm (package-lock.json / npm-shrinkwrap.json), pnpm (pnpm-lock.yaml), yarn (yarn.lock),
 * pip (requirements*.txt). Others (poetry/cargo/go) are discovered + reported as "unparsed" for now.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';

export interface Dependency {
  ecosystem: string; // npm | PyPI | ...
  name: string;
  version: string; //   '' when not pinned to an exact version
  source: string; //    lockfile it came from
  integrity: boolean; // tamper-evident (pinned hash present)?
  urlDep: boolean; //   installed from a URL / git ref (unpinned, build-script RCE surface)?
}

const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'poetry.lock', 'Pipfile.lock', 'Cargo.lock', 'go.sum'];

/** Find lockfiles + requirements*.txt in `dir`. */
export function findLockfiles(dir: string): string[] {
  const out: string[] = [];
  for (const f of LOCKFILES) if (existsSync(join(dir, f))) out.push(join(dir, f));
  try {
    for (const f of readdirSync(dir)) if (/^requirements.*\.txt$/i.test(f)) out.push(join(dir, f));
  } catch {
    /* unreadable dir */
  }
  return out;
}

/** Parse one lockfile into dependencies (best-effort; unknown formats return []). */
export function parseLockfile(path: string): Dependency[] {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return [];
  }
  const base = path.replace(/\\/g, '/').split('/').pop() ?? path;
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return parsePackageLock(text, path);
  if (base === 'pnpm-lock.yaml') return parsePnpmLock(text, path);
  if (base === 'yarn.lock') return parseYarnLock(text, path);
  if (/^requirements.*\.txt$/i.test(base)) return parseRequirements(text, path);
  return []; // poetry/cargo/go — discovered but unparsed
}

/** Parse every lockfile in `dir`. */
export function parseProject(dir: string): { deps: Dependency[]; files: string[]; unparsed: string[] } {
  const files = findLockfiles(dir);
  const deps: Dependency[] = [];
  const unparsed: string[] = [];
  for (const f of files) {
    const d = parseLockfile(f);
    if (d.length === 0 && !/package-lock|shrinkwrap|pnpm-lock|yarn\.lock|requirements/i.test(f)) unparsed.push(f);
    deps.push(...d);
  }
  return { deps, files, unparsed };
}

/* --------------------------------- npm --------------------------------- */

function parsePackageLock(text: string, source: string): Dependency[] {
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return [];
  }
  const out: Dependency[] = [];
  const packages = json['packages'] as Record<string, Record<string, unknown>> | undefined;
  if (packages) {
    // v2/v3 lockfileVersion
    for (const [key, meta] of Object.entries(packages)) {
      if (!key || !key.includes('node_modules/')) continue; // skip the root ("") + workspace roots
      const name = key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const version = typeof meta['version'] === 'string' ? (meta['version'] as string) : '';
      const resolved = typeof meta['resolved'] === 'string' ? (meta['resolved'] as string) : '';
      out.push({ ecosystem: 'npm', name, version, source, integrity: typeof meta['integrity'] === 'string', urlDep: isUrl(resolved) || isUrl(version) });
    }
  }
  const deps = json['dependencies'] as Record<string, Record<string, unknown>> | undefined;
  if (deps) walkV1(deps, source, out); // v1 lockfileVersion (nested)
  return dedupe(out);
}

function walkV1(deps: Record<string, Record<string, unknown>>, source: string, out: Dependency[]): void {
  for (const [name, meta] of Object.entries(deps)) {
    const version = typeof meta['version'] === 'string' ? (meta['version'] as string) : '';
    const resolved = typeof meta['resolved'] === 'string' ? (meta['resolved'] as string) : '';
    out.push({ ecosystem: 'npm', name, version, source, integrity: typeof meta['integrity'] === 'string', urlDep: isUrl(resolved) || isUrl(version) });
    const nested = meta['dependencies'] as Record<string, Record<string, unknown>> | undefined;
    if (nested) walkV1(nested, source, out);
  }
}

/* --------------------------------- pnpm --------------------------------- */

function parsePnpmLock(text: string, source: string): Dependency[] {
  let doc: Record<string, unknown>;
  try {
    doc = (yaml.load(text) as Record<string, unknown>) ?? {};
  } catch {
    return [];
  }
  const out: Dependency[] = [];
  const packages = (doc['packages'] ?? doc['snapshots']) as Record<string, Record<string, unknown>> | undefined;
  if (!packages) return out;
  for (const [key, meta] of Object.entries(packages)) {
    const parsed = splitNameVersion(key.startsWith('/') ? key.slice(1) : key);
    if (!parsed) continue;
    const resolution = (meta?.['resolution'] as Record<string, unknown>) ?? {};
    const tarball = typeof resolution['tarball'] === 'string' ? (resolution['tarball'] as string) : '';
    out.push({ ecosystem: 'npm', name: parsed.name, version: parsed.version, source, integrity: typeof resolution['integrity'] === 'string', urlDep: isUrl(tarball) });
  }
  return dedupe(out);
}

/** `@scope/name@1.2.3` / `name@1.2.3(react@18.2.0)` → {name, version}. Strip the pnpm peer-suffix `(…)`
 *  from the KEY FIRST — a modern pnpm peer-suffix itself contains `@`-versions, so splitting on the last
 *  `@` before stripping mangles both fields (e.g. `react-dom@18.2.0(react@18.2.0)`). */
function splitNameVersion(key: string): { name: string; version: string } | null {
  const paren = key.indexOf('(');
  const bare = paren >= 0 ? key.slice(0, paren) : key;
  const at = bare.lastIndexOf('@');
  if (at <= 0) return null;
  return { name: bare.slice(0, at), version: bare.slice(at + 1) };
}

/* --------------------------------- yarn --------------------------------- */

function parseYarnLock(text: string, source: string): Dependency[] {
  const out: Dependency[] = [];
  const blocks = text.split(/\n(?=\S)/); // a new block starts at column 0
  for (const block of blocks) {
    const header = block.split('\n')[0] ?? '';
    if (!header.trim().endsWith(':') || header.startsWith('#')) continue;
    const firstSpec = header.replace(/:$/, '').split(',')[0]?.trim().replace(/^"|"$/g, '') ?? '';
    const nv = splitNameVersion(firstSpec.replace(/@(\^|~|>=|<=|>|<|\*).*$/, '@RANGE')); // spec = name@range
    const name = nv ? nv.name : firstSpec.replace(/@[^@]*$/, '');
    const version = /^\s+version:?\s+"?([^"\n]+)"?/m.exec(block)?.[1] ?? '';
    const resolved = /^\s+resolved:?\s+"?([^"\n]+)"?/m.exec(block)?.[1] ?? '';
    const integrity = /^\s+integrity[:\s]/m.test(block);
    if (name) out.push({ ecosystem: 'npm', name, version, source, integrity, urlDep: isUrl(resolved) });
  }
  return dedupe(out);
}

/* --------------------------------- pip --------------------------------- */

function parseRequirements(text: string, source: string): Dependency[] {
  const out: Dependency[] = [];
  const lines = text.split(/\r?\n/);
  for (let raw of lines) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('-r') || line.startsWith('-c')) continue;
    // url / git dependency (unpinned, runs setup.py at install)
    if (/(^| )(-e |git\+|https?:\/\/)/.test(line) || /@\s*(git\+|https?:\/\/)/.test(line)) {
      const nm = /^([A-Za-z0-9._-]+)\s*@/.exec(line)?.[1] ?? /#egg=([A-Za-z0-9._-]+)/.exec(line)?.[1] ?? '(url)';
      out.push({ ecosystem: 'PyPI', name: nm, version: '', source, integrity: false, urlDep: true });
      continue;
    }
    const m = /^([A-Za-z0-9._-]+)\s*(==|===)\s*([A-Za-z0-9._+!-]+)/.exec(line);
    if (m) {
      out.push({ ecosystem: 'PyPI', name: m[1] as string, version: m[3] as string, source, integrity: /--hash=/.test(raw), urlDep: false });
      continue;
    }
    const nm = /^([A-Za-z0-9._-]+)\b/.exec(line)?.[1]; // unpinned (>=, ~=, no version)
    if (nm) out.push({ ecosystem: 'PyPI', name: nm, version: '', source, integrity: false, urlDep: false });
  }
  return out;
}

/* --------------------------------- helpers --------------------------------- */

function isUrl(s: string): boolean {
  return /^(git\+|https?:|ssh:|file:|link:|github:)/i.test(s) || /\/\/[^/]+\/.+#/.test(s);
}
function dedupe(deps: Dependency[]): Dependency[] {
  const seen = new Set<string>();
  const out: Dependency[] = [];
  for (const d of deps) {
    const k = `${d.ecosystem}|${d.name}|${d.version}`;
    if (!seen.has(k)) (seen.add(k), out.push(d));
  }
  return out;
}
