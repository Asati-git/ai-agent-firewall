// Unit test for `cerberus deps` — lockfile parsing + advisory matching + semver (run: npx tsx scripts/deps.test.ts).
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parseProject, type Dependency } from '../src/deps/lockfiles.js';
import { loadAdvisories, matchAdvisories, semverCmp, type Advisory } from '../src/deps/advisories.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}
const seedPath = join(resolve(import.meta.dirname, '..'), 'rules', 'advisories.yaml');

// ── semver compare ──
check('semverCmp basic ordering', semverCmp('1.82.7', '1.82.8') < 0 && semverCmp('2.0.0', '1.9.9') > 0 && semverCmp('1.2.3', '1.2.3') === 0);
check('semverCmp ignores prerelease', semverCmp('5.6.1-rc1', '5.6.1') === 0);

// ── advisory matching (constructed) ──
{
  const advs: Advisory[] = [
    { id: 'A1', ecosystem: 'PyPI', name: 'litellm', versions: ['1.82.7', '1.82.8'], severity: 'malicious', summary: 'x' },
    { id: 'A2', ecosystem: '*', name: 'xz', versions: ['5.6.0', '5.6.1'], severity: 'malicious', summary: 'x' },
    { id: 'A3', ecosystem: 'npm', name: 'evilall', severity: 'malicious', summary: 'x' }, // all versions
    { id: 'A4', ecosystem: 'npm', name: 'vulnrange', range: { introduced: '1.0.0', fixed: '1.5.0' }, severity: 'high', summary: 'x' },
  ];
  const dep = (ecosystem: string, name: string, version: string): Dependency => ({ ecosystem, name, version, source: 't', integrity: false, urlDep: false });
  const m = (d: Dependency) => matchAdvisories([d], advs);
  check('exact version match', m(dep('PyPI', 'litellm', '1.82.8')).length === 1);
  check('non-affected version → no match', m(dep('PyPI', 'litellm', '1.83.0')).length === 0);
  check('ecosystem * matches any', m(dep('crates.io', 'xz', '5.6.1')).length === 1);
  check('wrong ecosystem → no match', m(dep('PyPI', 'evilall', '1.0.0')).length === 0);
  check('all-versions advisory matches any version', m(dep('npm', 'evilall', '9.9.9')).length === 1);
  check('range match (introduced<=v<fixed)', m(dep('npm', 'vulnrange', '1.2.0')).length === 1 && m(dep('npm', 'vulnrange', '1.5.0')).length === 0);
  check('unpinned + versioned advisory → affected:unknown', m(dep('PyPI', 'litellm', '')).some((x) => x.affected === 'unknown'));
}

// ── lockfile parsing (inline fixtures) ──
{
  const dir = mkdtempSync(join(tmpdir(), 'cb-deps-'));
  writeFileSync(
    join(dir, 'package-lock.json'),
    JSON.stringify({
      name: 'x',
      lockfileVersion: 3,
      packages: {
        '': { name: 'x' },
        'node_modules/left-pad': { version: '1.3.0', resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz', integrity: 'sha512-aaa' },
        'node_modules/event-stream': { version: '3.3.6', resolved: 'https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz', integrity: 'sha512-bbb' },
        'node_modules/evilpkg': { version: '1.0.0', resolved: 'git+https://github.com/attacker/evil.git#abc' },
      },
    }),
  );
  writeFileSync(join(dir, 'requirements.txt'), ['litellm==1.82.8', 'requests==2.31.0 --hash=sha256:deadbeef', 'somepkg @ git+https://github.com/x/y', 'flask>=2.0', '# a comment'].join('\n'));
  writeFileSync(join(dir, 'pnpm-lock.yaml'), "lockfileVersion: '6.0'\npackages:\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-aaa}\n  '@scope/tool@2.1.0':\n    resolution: {integrity: sha512-ccc}\n  'react-dom@18.2.0(react@18.2.0)':\n    resolution: {integrity: sha512-ddd}\n");

  const { deps, files } = parseProject(dir);
  const find = (name: string, eco = 'npm') => deps.find((d) => d.name === name && d.ecosystem === eco);
  check('found all three lockfiles', files.length === 3, files.join(','));
  check('npm: event-stream@3.3.6 parsed with integrity', !!find('event-stream') && find('event-stream')!.version === '3.3.6' && find('event-stream')!.integrity === true);
  check('npm: git dep flagged urlDep + no integrity', !!find('evilpkg') && find('evilpkg')!.urlDep === true && find('evilpkg')!.integrity === false);
  check('pnpm: scoped name parsed', !!find('@scope/tool'), JSON.stringify(deps.filter((d) => d.name.includes('scope'))));
  check('pnpm: peer-suffix key with @ parsed correctly (H-1)', !!find('react-dom') && find('react-dom').version === '18.2.0', JSON.stringify(deps.filter((d) => d.name.includes('react'))));
  check('pip: litellm==1.82.8 (not hash-pinned)', !!find('litellm', 'PyPI') && find('litellm', 'PyPI')!.integrity === false);
  check('pip: hash-pinned dep → integrity true', !!find('requests', 'PyPI') && find('requests', 'PyPI')!.integrity === true);
  check('pip: git url dep flagged', deps.some((d) => d.ecosystem === 'PyPI' && d.urlDep));
  check('pip: unpinned (>=) → version empty', !!find('flask', 'PyPI') && find('flask', 'PyPI')!.version === '');

  // ── end-to-end against the REAL seed advisories ──
  const advisories = loadAdvisories(seedPath);
  check('seed advisories loaded', advisories.length >= 8, `${advisories.length}`);
  const matches = matchAdvisories(deps, advisories);
  const malNames = new Set(matches.filter((m) => m.advisory.severity === 'malicious').map((m) => m.dep.name));
  check('e2e: event-stream flagged malicious from seed', malNames.has('event-stream'));
  check('e2e: litellm 1.82.8 flagged malicious from seed', malNames.has('litellm'));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
