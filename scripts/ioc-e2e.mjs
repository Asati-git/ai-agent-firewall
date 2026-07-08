// End-to-end: `cerberus feeds refresh` (file:// mirror) → engine loads the IOC feed → egress decisions.
// Proves a feed-listed destination is BLOCKED, a hitl-tier host escalates an otherwise-ALLOW egress to
// review, and a clean host is unaffected. Run: node scripts/ioc-e2e.mjs
import { spawn, spawnSync } from 'node:child_process';
import { request } from 'node:http';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const PORT = 9130;
const cwd = process.cwd();
const root = mkdtempSync(join(tmpdir(), 'cb-ioc-e2e-'));
mkdirSync(join(root, 'rules'), { recursive: true });
writeFileSync(join(root, 'block.txt'), '# block feed\nevil-feed.example\nsub.evil-feed.example\n');
writeFileSync(join(root, 'hitl.txt'), '# young/soft feed\napi.github.com\n'); // trusted host → should escalate to HITL
writeFileSync(
  join(root, 'rules', 'feeds.yaml'),
  `feeds:\n  - name: block-feed\n    url: ${pathToFileURL(join(root, 'block.txt')).href}\n    severity: block\n  - name: hitl-feed\n    url: ${pathToFileURL(join(root, 'hitl.txt')).href}\n    severity: hitl\n`,
);

let pass = 0,
  fail = 0;
const check = (name, cond, detail = '') => {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function http(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = request({ host: '127.0.0.1', port: PORT, path, method, headers: payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {} }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode, json: d ? JSON.parse(d) : null }));
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}
async function up(t = 8000) { const s = Date.now(); while (Date.now() - s < t) { try { const r = await http('GET', '/health'); if (r.status < 500) return true; } catch {} await sleep(100); } return false; }
const fetch = (url) => http('POST', '/intercept', { tool: 'WebFetch', input: { url }, sessionId: 'ioc' });

console.log('Cerberus IOC-feed e2e — refresh → engine block/escalate\n');
// 1) refresh the feed into <root>/.cerberus/ioc.json
const ref = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'feeds', 'refresh'], { cwd, env: { ...process.env, AG_HOME: root, CB_STATE_DIR: join(root, '.cerberus'), AG_NOTIFY: '0' }, encoding: 'utf8' });
check('feeds refresh wrote block+hitl domains', /Wrote \d+ block \+ \d+ hitl/.test(ref.stdout ?? ''), (ref.stdout ?? '') + (ref.stderr ?? ''));

// 2) engine with AG_HOME=<root> (loads that ioc.json); real repo rules/weights.
const engine = spawn(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'engine'], {
  cwd,
  env: { ...process.env, AG_ENGINE_PORT: String(PORT), AG_HOME: root, CB_STATE_DIR: join(root, '.cerberus'), AG_RULES: join(cwd, 'rules', 'default_policy.yaml'), AG_RISK_WEIGHTS: join(cwd, 'rules', 'risk_weights.yaml'), AG_NOTIFY: '0' },
  stdio: ['ignore', 'ignore', 'inherit'],
});
let exitCode = 1;
try {
  if (!(await up())) throw new Error('engine did not come up');
  const blocked = await fetch('https://evil-feed.example/x');
  check('feed-listed destination → BLOCK', blocked.json?.action === 'BLOCK' && /IOC feed/.test(blocked.json?.reason ?? ''), JSON.stringify(blocked.json));
  const sub = await fetch('https://deep.sub.evil-feed.example/x');
  check('subdomain of feed entry → BLOCK', sub.json?.action === 'BLOCK', JSON.stringify(sub.json));
  const escalated = await fetch('https://api.github.com/repos/x'); // trusted → normally ALLOW; hitl feed escalates
  check('hitl-feed host escalates trusted ALLOW → ASK', escalated.json?.action === 'ASK' && /young-domain|IOC/.test(escalated.json?.reason ?? ''), JSON.stringify(escalated.json));
  const clean = await fetch('https://github.com/anthropics/x'); // trusted, not in any feed
  check('clean trusted host unaffected → ALLOW', clean.json?.action === 'ALLOW', JSON.stringify(clean.json));
  exitCode = fail ? 1 : 0;
} catch (e) {
  console.error('  ❌ harness error —', e?.message ?? e);
} finally {
  engine.kill('SIGTERM');
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(exitCode);
}
