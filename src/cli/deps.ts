/**
 * `cerberus deps [--dir <path>] [--osv]` — offline supply-chain audit of a project's LOCKFILES.
 *
 *   • flags KNOWN-MALICIOUS / vulnerable packages (curated seed rules/advisories.yaml + optional OSV cache);
 *   • flags URL/git dependencies (unpinned + run build/postinstall = RCE surface);
 *   • hash-pin audit — how many installs are NOT tamper-evident (no integrity hash).
 *
 * Fully offline by default. `--osv` additionally queries OSV.dev for your resolved deps (online, opt-in,
 * transmits your dependency list to OSV). Exit 1 if any malicious/critical/high match is found.
 */
import { join } from 'node:path';
import { parseProject } from '../deps/lockfiles.js';
import { loadAdvisories, matchAdvisories, type Match } from '../deps/advisories.js';
import { rawEnv } from '../config/env.js';

export async function runDeps(argv: string[], projectRoot: string): Promise<void> {
  const dirIdx = argv.indexOf('--dir');
  const dir = dirIdx >= 0 ? (argv[dirIdx + 1] as string) : process.cwd();
  const doOsv = argv.includes('--osv');
  const home = rawEnv('HOME') ?? process.cwd();
  const seedPath = join(projectRoot, 'rules', 'advisories.yaml');
  const cachePath = join(home, '.cerberus', 'advisories.json');

  const { deps, files, unparsed } = parseProject(dir);
  if (files.length === 0) {
    process.stdout.write(`No lockfiles found under ${dir}. (looked for package-lock.json / pnpm-lock.yaml / yarn.lock / requirements*.txt / …)\n`);
    process.exit(0);
  }
  process.stdout.write(`Scanned ${deps.length} dependenc(ies) from ${files.length} lockfile(s):\n`);
  for (const f of files) process.stdout.write(`  • ${f}\n`);
  if (unparsed.length) process.stdout.write(`  (unparsed — reported only: ${unparsed.join(', ')})\n`);

  let advisories = loadAdvisories(seedPath, cachePath);
  if (doOsv) {
    process.stdout.write(`\n⚠ --osv: querying OSV.dev for ${deps.length} deps — this SENDS your dependency list to OSV (Google).\n`);
    const { queryOsv } = await import('../deps/osv.js');
    const r = await queryOsv(deps);
    if (r.error) process.stdout.write(`  OSV query error: ${r.error} (falling back to offline advisories)\n`);
    advisories = advisories.concat(r.advisories);
  }

  const matches = matchAdvisories(deps, advisories);
  const malicious = matches.filter((m) => m.advisory.severity === 'malicious');
  const vulns = matches.filter((m) => m.advisory.severity !== 'malicious' && m.affected === 'yes');
  const unknowns = matches.filter((m) => m.affected === 'unknown');
  const urlDeps = deps.filter((d) => d.urlDep);

  process.stdout.write('\n');
  if (malicious.length === 0 && vulns.length === 0) process.stdout.write('  ✓ no known-malicious or vulnerable packages\n');
  for (const m of malicious) process.stdout.write(`  ⛔ MALICIOUS  ${label(m)} — ${m.advisory.summary} [${m.advisory.id}]\n`);
  for (const m of vulns) process.stdout.write(`  ⚠ ${m.advisory.severity.toUpperCase().padEnd(8)} ${label(m)} — ${m.advisory.summary} [${m.advisory.id}]\n`);
  for (const m of unknowns) process.stdout.write(`  ? unpinned — ${m.dep.name} (advisory ${m.advisory.id} affects ${(m.advisory.versions ?? []).join(',')}; pin the version to confirm)\n`);

  // supply-chain hygiene
  if (urlDeps.length) {
    process.stdout.write(`\n  ⚠ ${urlDeps.length} URL/git dependenc(ies) (unpinned, run build/postinstall — RCE surface):\n`);
    for (const d of urlDeps.slice(0, 20)) process.stdout.write(`      ${d.ecosystem}:${d.name}${d.version ? `@${d.version}` : ''}  (${d.source.split(/[/\\]/).pop()})\n`);
  }
  const npm = deps.filter((d) => d.ecosystem === 'npm');
  const pip = deps.filter((d) => d.ecosystem === 'PyPI');
  const npmNoHash = npm.filter((d) => !d.integrity).length;
  const pipNoHash = pip.filter((d) => !d.integrity).length;
  process.stdout.write('\nHash-pin audit (tamper-evidence):\n');
  if (npm.length) process.stdout.write(`  npm:  ${npm.length - npmNoHash}/${npm.length} have an integrity hash${npmNoHash ? '  — run `npm ci` (enforces the lockfile)' : ' ✓'}\n`);
  if (pip.length) process.stdout.write(`  pip:  ${pip.length - pipNoHash}/${pip.length} are hash-pinned${pipNoHash ? '  — use `pip install --require-hashes` (pip-compile --generate-hashes)' : ' ✓'}\n`);

  const gate = malicious.length > 0 || matches.some((m) => ['critical', 'high'].includes(m.advisory.severity) && m.affected === 'yes');
  process.stdout.write(gate ? `\n✗ ${malicious.length} malicious, ${vulns.length} vulnerable. Remove/upgrade before installing.\n` : '\n✓ clean (no malicious/critical/high matches).\n');
  process.exit(gate ? 1 : 0);
}

function label(m: Match): string {
  return `${m.dep.ecosystem}:${m.dep.name}@${m.dep.version || '(unpinned)'}`;
}
