// Unit test for the IOC feed store + hostfile parsing (run: npx tsx scripts/ioc.test.ts).
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { IocStore, hostOf } from '../src/signals/ioc.js';
import { parseHostfile } from '../src/cli/feeds.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}

// ── IocStore matching ──
{
  const dir = mkdtempSync(join(tmpdir(), 'cb-ioc-'));
  const f = join(dir, 'ioc.json');
  writeFileSync(f, JSON.stringify({ block: ['evil.com', '45.9.148.99'], hitl: ['young.example'], refreshedAt: 123, sources: [] }));
  const s = new IocStore(f);
  check('loaded + size', s.loaded && s.size === 3);
  check('exact domain → block', s.check('evil.com') === 'block');
  check('subdomain suffix → block', s.check('a.b.evil.com') === 'block');
  check('exact IP → block', s.check('45.9.148.99') === 'block');
  check('hitl tier match', s.check('young.example') === 'hitl');
  check('unrelated host → null', s.check('good-host.org') === null);
  check('bare TLD not matched', s.check('other.com') === null);
  check('empty host → null', s.check('') === null && s.check(undefined) === null);

  const empty = new IocStore(join(dir, 'missing.json'));
  check('missing cache → not loaded (inert)', !empty.loaded && empty.check('evil.com') === null);
}

// ── hostOf ──
check('hostOf: full URL', hostOf('https://a.b.com/x?y=1') === 'a.b.com');
check('hostOf: bare host:port', hostOf('evil.com:443') === 'evil.com');
check('hostOf: raw ip:port', hostOf('45.9.148.99:1080') === '45.9.148.99');
check('hostOf: empty', hostOf('') === '');

// ── hostfile parsing ──
{
  const txt = ['# a comment', '0.0.0.0 evil.com', '127.0.0.1 bad.net', '||adblock.io^', '*.wild.org', 'plain.org', '! adblock comment', 'not a domain', '   ', 'UPPER.CASE'].join('\n');
  const d = new Set(parseHostfile(txt));
  check('hosts-format domain parsed', d.has('evil.com') && d.has('bad.net'));
  check('adblock ||d^ parsed', d.has('adblock.io'));
  check('wildcard *. stripped', d.has('wild.org'));
  check('plain domain parsed', d.has('plain.org'));
  check('lowercased', d.has('upper.case'));
  check('junk/comments excluded', !d.has('not a domain') && ![...d].some((x) => x.includes('comment')));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
