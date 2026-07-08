/**
 * OPT-IN OSV.dev lookup for `cerberus deps --osv`. This is the ONLY online path in `deps`: it POSTs your
 * resolved (name, version) set to OSV's batch API and maps the returned vuln/malware IDs into advisories.
 * It is off by default and prints a privacy notice because it transmits your dependency list to OSV (Google).
 * For fully-offline use, rely on the curated seed + `deps sync` cache instead.
 */
import type { Advisory } from './advisories.js';
import type { Dependency } from './lockfiles.js';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';

/** OSV ecosystem name for one of our lockfile ecosystems. */
function osvEcosystem(e: string): string | null {
  const m: Record<string, string> = { npm: 'npm', pypi: 'PyPI', 'crates.io': 'crates.io', go: 'Go' };
  return m[e.toLowerCase()] ?? null;
}

export interface OsvResult {
  advisories: Advisory[];
  queried: number;
  error?: string;
}

/** Query OSV for the exact-versioned deps; returns one advisory per (dep, vuln-id). */
export async function queryOsv(deps: readonly Dependency[], timeoutMs = 20000): Promise<OsvResult> {
  const indexed = deps.map((d) => ({ d, eco: osvEcosystem(d.ecosystem) })).filter((x) => x.eco && x.d.version);
  if (indexed.length === 0) return { advisories: [], queried: 0 };

  const advisories: Advisory[] = [];
  const seen = new Set<string>();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    for (let i = 0; i < indexed.length; i += 500) {
      const chunk = indexed.slice(i, i + 500);
      const body = { queries: chunk.map((x) => ({ package: { name: x.d.name, ecosystem: x.eco }, version: x.d.version })) };
      const res = await fetch(OSV_BATCH, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: ctrl.signal });
      if (!res.ok) return { advisories, queried: indexed.length, error: `OSV HTTP ${res.status}` };
      const json = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
      json.results?.forEach((r, j) => {
        const dep = chunk[j]?.d;
        if (!dep || !r?.vulns) return;
        for (const v of r.vulns) {
          const key = `${v.id}|${dep.name}|${dep.version}`;
          if (seen.has(key)) continue;
          seen.add(key);
          advisories.push({
            id: v.id,
            ecosystem: dep.ecosystem,
            name: dep.name,
            versions: [dep.version],
            severity: /^MAL-/i.test(v.id) ? 'malicious' : 'high',
            summary: `OSV ${v.id} — https://osv.dev/vulnerability/${v.id}`,
          });
        }
      });
    }
    return { advisories, queried: indexed.length };
  } catch (e) {
    return { advisories, queried: indexed.length, error: (e as Error).message };
  } finally {
    clearTimeout(timer);
  }
}
