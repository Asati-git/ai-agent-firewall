/**
 * Advisory database for `cerberus deps` — load the curated seed (rules/advisories.yaml) plus any synced
 * OSV cache (.cerberus/advisories.json), and match a project's dependencies against them. Fully offline.
 */
import { existsSync, readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import type { Dependency } from './lockfiles.js';

export type Severity = 'malicious' | 'critical' | 'high' | 'medium' | 'low';

export interface Advisory {
  id: string;
  ecosystem?: string; // undefined or '*' = any ecosystem
  name: string;
  versions?: string[]; // exact affected versions
  range?: { introduced?: string; fixed?: string }; // introduced <= v < fixed
  severity: Severity;
  summary: string;
}

export interface Match {
  dep: Dependency;
  advisory: Advisory;
  affected: 'yes' | 'unknown'; // 'unknown' = dep is unpinned so we can't confirm the exact version
}

/** Load advisories from the YAML seed + an optional JSON cache (OSV sync). */
export function loadAdvisories(seedPath: string, cachePath?: string): Advisory[] {
  const out: Advisory[] = [];
  if (existsSync(seedPath)) {
    try {
      const doc = yaml.load(readFileSync(seedPath, 'utf8')) as { advisories?: Advisory[] } | undefined;
      if (Array.isArray(doc?.advisories)) out.push(...doc.advisories.filter((a) => a && a.name && a.id));
    } catch {
      /* malformed seed — ignore */
    }
  }
  if (cachePath && existsSync(cachePath)) {
    try {
      const arr = JSON.parse(readFileSync(cachePath, 'utf8')) as Advisory[];
      if (Array.isArray(arr)) out.push(...arr.filter((a) => a && a.name && a.id));
    } catch {
      /* malformed cache — ignore */
    }
  }
  return out;
}

/** Match dependencies against advisories. Name is exact (case-insensitive); ecosystem '*'/absent = any. */
export function matchAdvisories(deps: readonly Dependency[], advisories: readonly Advisory[]): Match[] {
  const byName = new Map<string, Advisory[]>();
  for (const a of advisories) {
    const k = a.name.toLowerCase();
    (byName.get(k) ?? byName.set(k, []).get(k)!).push(a);
  }
  const out: Match[] = [];
  for (const dep of deps) {
    for (const a of byName.get(dep.name.toLowerCase()) ?? []) {
      if (a.ecosystem && a.ecosystem !== '*' && a.ecosystem.toLowerCase() !== dep.ecosystem.toLowerCase()) continue;
      const aff = affected(dep.version, a);
      if (aff !== 'no') out.push({ dep, advisory: a, affected: aff });
    }
  }
  return out;
}

function affected(version: string, a: Advisory): 'yes' | 'unknown' | 'no' {
  if (!a.versions && !a.range) return 'yes'; // whole package flagged
  if (!version) return 'unknown'; //          unpinned — can't confirm the exact version
  if (a.versions) return a.versions.includes(version) ? 'yes' : 'no';
  if (a.range) {
    if (a.range.introduced && semverCmp(version, a.range.introduced) < 0) return 'no';
    if (a.range.fixed && semverCmp(version, a.range.fixed) >= 0) return 'no';
    return 'yes';
  }
  return 'no';
}

/** Compare two dotted versions numerically (major.minor.patch…); pre-release suffixes are ignored. */
export function semverCmp(a: string, b: string): number {
  const parts = (v: string): number[] => v.replace(/[+-].*$/, '').split('.').map((n) => parseInt(n, 10) || 0);
  const pa = parts(a);
  const pb = parts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}
