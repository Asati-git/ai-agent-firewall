// Runs red-team-generated payloads against the LIVE engine and reports which got ALLOW (potential leaks).
// Usage: node scripts/redteam-run.mjs <payloads.json>   (json = [{tool, input, danger, rationale, angle}])
import { spawn } from 'node:child_process';
import { request } from 'node:http';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = 9092;
const file = process.argv[2] ?? new URL('./fixtures/redteam-corpus.json', import.meta.url);
const payloads = JSON.parse(readFileSync(file, 'utf8'));
const auditFile = join(mkdtempSync(join(tmpdir(), 'ag-rt-')), 'audit.jsonl');

function http(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = request({ host: '127.0.0.1', port: PORT, path, method, headers: payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {} },
      (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve({ status: res.statusCode, json: d ? JSON.parse(d) : null })); });
    req.on('error', reject); if (payload) req.write(payload); req.end();
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function up(t = 8000) { const s = Date.now(); while (Date.now() - s < t) { try { const r = await http('GET', '/health'); if (r.status < 500) return true; } catch {} await sleep(100); } return false; }

const engine = spawn(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'engine'], {
  env: { ...process.env, AG_ENGINE_PORT: String(PORT), AG_AUDIT: auditFile, AG_NOTIFY: '0' }, stdio: ['ignore', 'ignore', 'inherit'],
});
try {
  if (!(await up())) throw new Error('engine did not start');
  const leaks = [];
  let sid = 0;
  for (const p of payloads) {
    const r = await http('POST', '/intercept', { tool: p.tool, input: p.input, sessionId: `rt-${sid++}` });
    const action = r.json?.action ?? 'ERR';
    const flag = action === 'ALLOW' ? '🔓 ALLOW' : action === 'BLOCK' ? '🔴 BLOCK' : action === 'ASK' ? '🟡 ASK  ' : '⚠️ ' + action;
    console.log(`  ${flag}  [${p.angle}] ${p.danger}  ::  ${JSON.stringify(p.input).slice(0, 90)}`);
    if (action === 'ALLOW') leaks.push(p);
  }
  console.log(`\n${'═'.repeat(70)}\nALLOW leaks: ${leaks.length} / ${payloads.length} payloads`);
  for (const l of leaks) console.log(`  🔓 [${l.angle}] ${l.danger}\n     input: ${JSON.stringify(l.input)}\n     claim: ${l.rationale}`);
  process.exitCode = leaks.length ? 2 : 0;
} catch (e) { console.error('harness error', e?.message ?? e); process.exitCode = 1; }
finally { engine.kill('SIGTERM'); }
