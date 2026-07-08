/**
 * IOC feed store (L1) — the REFRESHABLE destination blocklist, complementing the frozen curated IOC rule.
 *
 * `cerberus feeds refresh` downloads hostfile threat-intel feeds into `.cerberus/ioc.json`; the engine
 * loads it at startup and, on every egress decision, matches the destination host (and its parent domains)
 * against it — 100% local at decision time (Pi-hole "gravity" model). Two tiers: `block` (known-malware
 * URL/C2 feeds) forces BLOCK; `hitl` (e.g. a newly-registered-domain list) escalates to human review.
 */
import { existsSync, readFileSync } from 'node:fs';

export interface IocCache {
  block: string[];
  hitl: string[];
  refreshedAt?: number;
  sources?: { name: string; count: number }[];
}

export class IocStore {
  private block = new Set<string>();
  private hitl = new Set<string>();
  refreshedAt = 0;
  sources: { name: string; count: number }[] = [];

  constructor(private readonly file: string) {
    this.load();
  }

  private load(): void {
    if (!existsSync(this.file)) return;
    try {
      const c = JSON.parse(readFileSync(this.file, 'utf8')) as IocCache;
      for (const d of c.block ?? []) this.block.add(d.toLowerCase());
      for (const d of c.hitl ?? []) this.hitl.add(d.toLowerCase());
      this.refreshedAt = c.refreshedAt ?? 0;
      this.sources = c.sources ?? [];
    } catch {
      /* corrupt cache — treat as empty (a refresh rewrites it) */
    }
  }

  get size(): number {
    return this.block.size + this.hitl.size;
  }
  get loaded(): boolean {
    return this.size > 0;
  }

  /** Match a host (and its parent domains / exact IP) against the feed. block > hitl > null. */
  check(host: string | undefined): 'block' | 'hitl' | null {
    if (!host) return null;
    const h = host.toLowerCase().replace(/\.$/, '');
    if (!h) return null;
    const labels = h.split('.');
    // walk suffixes: a.b.evil.com -> a.b.evil.com, b.evil.com, evil.com (stop before a bare TLD)
    for (let i = 0; i <= labels.length - 2; i++) {
      const cand = labels.slice(i).join('.');
      if (this.block.has(cand)) return 'block';
      if (this.hitl.has(cand)) return 'hitl';
    }
    // exact match (covers raw IPs, which have no meaningful suffix)
    if (this.block.has(h)) return 'block';
    if (this.hitl.has(h)) return 'hitl';
    return null;
  }
}

/** Extract the destination host from a raw string (full URL, or a bare host[:port] / IP authority). */
export function hostOf(urlOrHost: string): string {
  if (!urlOrHost) return '';
  if (/:\/\//.test(urlOrHost)) {
    try {
      return new URL(urlOrHost).hostname.replace(/^\[|\]$/g, '');
    } catch {
      /* fall through to bare-host parse */
    }
  }
  const m = /^([A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\])(?::\d+)?/.exec(urlOrHost.trim());
  return m ? (m[1] as string).replace(/^\[|\]$/g, '') : '';
}
