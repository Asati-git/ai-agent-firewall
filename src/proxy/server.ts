/**
 * Egress proxy (M-proxy) — a network-LAYER enforcement point, complementing the tool-boundary hook.
 *
 * The hook runs INSIDE the agent's trust boundary, so a fully-owned agent could in principle route around
 * it. This proxy runs OUTSIDE that boundary: point the agent (or the whole shell) at it via
 * `HTTPS_PROXY=http://127.0.0.1:9100`, and every outbound connection is gated by the SAME engine decision
 * pipeline (destination allowlist, paste-site / raw-IP holds, and — for plain HTTP — secret-in-body
 * content matching), with the same audit trail and dashboard.
 *
 *   • CONNECT host:port  (HTTPS tunnels) — gated by DESTINATION HOST only (no MITM, no cert install).
 *   • absolute-URI GET/POST/… (plain HTTP) — gated by URL + (capped) request body for exfil matching.
 *
 * A held (HITL) egress uses the engine's dashboard-hold surface, so it pauses on the socket until a human
 * approves/denies (or the TTL fires → fail-closed BLOCK). Engine unreachable ⇒ fail closed unless failOpen.
 */
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse, type Server } from 'node:http';
import { createServer as httpsServer, request as httpsRequest, type Server as HttpsServer } from 'node:https';
import { createSecureContext, type TLSSocket } from 'node:tls';
import { connect as netConnect, type Socket } from 'node:net';
import { loadOrCreateCA, mintLeaf, scanResponse } from './mitm.js';
import { redactSecrets, detectStructuredSecrets } from '../signals/secrets.js';
import type { PipelineResult } from '../contract/types.js';

export interface ProxyOptions {
  port: number;
  engineHost: string;
  enginePort: number;
  failOpen: boolean;
  /** MITM mode — terminate TLS and scan decrypted response bodies (Layer 2). Requires node-forge + a
   *  trusted CA. Off by default: HTTPS is then gated by destination host only. */
  mitm?: boolean;
  mitmDir?: string;
  now?: number;
  /** Max response bytes to buffer for scanning; larger responses stream through UNSCANNED (default 8MB). */
  mitmScanCapBytes?: number;
  /** Redact structured secrets from an OUTBOUND prompt before it reaches the model/router (MITM, L2).
   *  Default on. `redactHost` decides which hosts get redacted (default: the official LLM providers). */
  redact?: boolean;
  redactHost?: (host: string) => boolean;
  /** injected for tests — decide an egress destination via the engine (default: POST /intercept). */
  decide?: (url: string, body?: string) => Promise<PipelineResult>;
}

export class EgressProxy {
  private readonly http: Server;
  private tls?: HttpsServer;
  /** CA cert PEM (MITM mode) — surfaced so the CLI can print the "trust this CA" instructions. */
  caCertPem?: string;
  constructor(private readonly opts: ProxyOptions) {
    this.http = createServer((req, res) => void this.onRequest(req, res));
    this.http.on('connect', (req, socket, head) => void this.onConnect(req, socket as Socket, head));
  }

  async listen(): Promise<void> {
    if (this.opts.mitm) await this.setupMitm();
    return new Promise((resolve, reject) => {
      this.http.once('error', reject);
      this.http.listen(this.opts.port, '127.0.0.1', () => {
        this.http.removeListener('error', reject);
        resolve();
      });
    });
  }

  /** Stand up the TLS-terminating server used to decrypt CONNECT tunnels (MITM). */
  private async setupMitm(): Promise<void> {
    const now = this.opts.now ?? Date.now();
    const ca = await loadOrCreateCA(this.opts.mitmDir ?? '.cerberus', now);
    this.caCertPem = ca.certPem;
    const def = await mintLeaf('localhost', ca, now);
    this.tls = httpsServer(
      {
        key: def.key,
        cert: def.cert,
        SNICallback: (host, cb) => {
          mintLeaf(host, ca, now)
            .then((l) => cb(null, createSecureContext({ key: l.key, cert: l.cert })))
            .catch((e) => cb(e as Error));
        },
      },
      (req, res) => void this.onMitmRequest(req, res),
    );
    this.tls.on('clientError', () => {});
  }
  close(): Promise<void> {
    return new Promise((resolve) => this.http.close(() => resolve()));
  }

  private decide(url: string, body?: string): Promise<PipelineResult> {
    if (this.opts.decide) return this.opts.decide(url, body);
    return askEngine(this.opts, url, body);
  }

  /** HTTPS tunnels: gate by destination host, then blind-pipe (no decryption). */
  private async onConnect(req: IncomingMessage, clientSocket: Socket, head: Buffer): Promise<void> {
    const [host, portStr] = (req.url ?? '').split(':');
    const port = Number(portStr) || 443;
    if (!host) return void clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');

    let verdict: PipelineResult;
    try {
      verdict = await this.decide(`https://${host}:${port}/`);
    } catch (err) {
      if (!this.opts.failOpen) return void deny(clientSocket, `Cerberus proxy: engine unreachable — fail closed. (${(err as Error).message})`);
      verdict = { action: 'ALLOW', reason: 'fail-open' };
    }
    if (verdict.action !== 'ALLOW') return void deny(clientSocket, `Cerberus proxy: egress to ${host} ${verdict.action} — ${verdict.reason}`);

    // MITM: terminate TLS locally (per-host leaf via SNI) so onMitmRequest can scan the RESPONSE body.
    if (this.opts.mitm && this.tls) {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      this.tls.emit('connection', clientSocket);
      if (head?.length) clientSocket.unshift(head);
      return;
    }

    const upstream = netConnect(port, host, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  }

  /** A decrypted request inside an MITM'd tunnel: gate on URL + credential, forward, SCAN the response. */
  private async onMitmRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const authority = req.headers.host ?? (req.socket as TLSSocket).servername ?? '';
    const host = String(authority).split(':')[0] ?? '';
    const port = Number(String(authority).split(':')[1]) || 443;
    const url = `https://${authority}${req.url ?? '/'}`;

    const cred = credentialIn(req.headers);
    if (cred && !PROVIDER_HOSTS.test(host)) return void mitmError(res, 403, `BLOCKED — ${cred} credential to non-provider host ${host}.`);

    let body = await readCappedBody(req);
    // L2 outbound-prompt redaction: strip structured secrets before the model/router sees them. This must
    // cover the GRAY-ROUTER threat (a base_url pointed at cheap-llm-router.io is BY DEFINITION not an
    // official provider), so we redact for EVERY host EXCEPT the trusted dev endpoints where a token in the
    // body is legitimate (github/gitlab/npm/pypi/…). redactSecrets is structured-only ⇒ FP-safe.
    const redactHost = this.opts.redactHost ?? ((h: string) => !TRUSTED_DEV_HOSTS.test(h));
    if (this.opts.redact !== false && body && redactHost(host)) {
      const r = redactSecrets(body);
      if (r.count > 0) {
        process.stderr.write(`Cerberus proxy: redacted ${r.count} secret(s) from outbound prompt to ${host} (${r.types.join(', ')})\n`);
        body = r.text;
      }
    }

    let verdict: PipelineResult;
    try {
      verdict = await this.decide(url, body);
    } catch (err) {
      if (!this.opts.failOpen) return void mitmError(res, 502, `engine unreachable — fail closed. (${(err as Error).message})`);
      verdict = { action: 'ALLOW', reason: 'fail-open' };
    }
    if (verdict.action !== 'ALLOW') return void mitmError(res, 403, `egress ${verdict.action} — ${verdict.reason}`);

    const upHeaders = stripProxyHeaders(req.headers);
    if (body) upHeaders['content-length'] = String(Buffer.byteLength(body)); // redaction changed the length
    const cap = this.opts.mitmScanCapBytes ?? 8_000_000;
    const up = httpsRequest({ hostname: host, port, method: req.method, path: req.url, headers: upHeaders }, (upRes) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let streaming = false; // switched to unscanned passthrough once the body exceeds the scan cap
      upRes.on('data', (c: Buffer) => {
        if (streaming) return; // pipe (below) is delivering the remainder
        size += c.length;
        chunks.push(c);
        if (size > cap) {
          // Too large to hold + scan — deliver EVERYTHING unscanned (never a truncated body under the
          // original content-length): flush what we buffered, then pipe the rest. Full body = full length.
          streaming = true;
          res.writeHead(upRes.statusCode ?? 502, upRes.headers);
          for (const ch of chunks) res.write(ch);
          upRes.pipe(res);
        }
      });
      upRes.on('end', () => {
        if (streaming) return; // already ended via pipe
        const buf = Buffer.concat(chunks);
        const findings = scanResponse(buf.toString('utf8'));
        // A large base64 blob alone is a weak signal (data-URIs, images, source maps) — don't hard-block
        // on it; only an executable/exfil pattern blocks the response.
        const blocking = findings.filter((f) => f.kind !== 'oversized-base64');
        if (blocking.length) {
          process.stderr.write(`Cerberus proxy: BLOCKED injected response from ${host} — ${blocking.map((f) => f.kind).join(', ')}\n`);
          return void mitmError(res, 502, `RESPONSE BLOCKED — router injected a payload (${blocking.map((f) => f.kind).join(', ')}).`);
        }
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        res.end(buf);
      });
    });
    up.on('error', (e) => mitmError(res, 502, `upstream error — ${e.message}`));
    if (body) up.write(body);
    up.end();
  }

  /** Plain-HTTP forward proxy: absolute-URI request → credential guard + gate on URL/body → forward. */
  private async onRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? '';
    if (!/^https?:\/\//i.test(url)) return void send(res, 400, 'Cerberus proxy: expected an absolute-URI proxied request.');
    let target: URL;
    try {
      target = new URL(url);
    } catch {
      return void send(res, 400, 'Cerberus proxy: bad target URL.');
    }

    // Credential guard (Layer 3): an API key must never leave over plaintext HTTP, or to a host that
    // isn't an official model provider — the exact "gray provider / fake endpoint key theft" vector.
    const cred = credentialIn(req.headers);
    if (cred) {
      if (target.protocol === 'http:') return void send(res, 403, `Cerberus proxy: BLOCKED — ${cred} credential over plaintext HTTP to ${target.host}.`);
      if (!PROVIDER_HOSTS.test(target.hostname)) return void send(res, 403, `Cerberus proxy: BLOCKED — ${cred} credential sent to non-provider host ${target.hostname}. Only official provider endpoints should receive your key.`);
    }

    const body = await readCappedBody(req);
    let verdict: PipelineResult;
    try {
      verdict = await this.decide(url, body);
    } catch (err) {
      if (!this.opts.failOpen) return void send(res, 502, `Cerberus proxy: engine unreachable — fail closed. (${(err as Error).message})`);
      verdict = { action: 'ALLOW', reason: 'fail-open' };
    }
    if (verdict.action !== 'ALLOW') return void send(res, 403, `Cerberus proxy: egress ${verdict.action} — ${verdict.reason}`);

    const headers = { ...req.headers };
    delete headers['proxy-connection'];
    const up = httpRequest(
      { protocol: target.protocol, hostname: target.hostname, port: target.port || 80, method: req.method, path: target.pathname + target.search, headers },
      (upRes) => {
        res.writeHead(upRes.statusCode ?? 502, upRes.headers);
        upRes.pipe(res);
      },
    );
    up.on('error', (e) => send(res, 502, `Cerberus proxy: upstream error — ${e.message}`));
    if (body) up.write(body);
    up.end();
  }
}

/* --------------------------------- helpers --------------------------------- */

/** Official LLM-provider API hosts that may legitimately receive an API key (extend for your stack). */
const PROVIDER_HOSTS =
  /(^|\.)(anthropic\.com|openai\.com|azure\.com|mistral\.ai|groq\.com|together\.(xyz|ai)|deepseek\.com|googleapis\.com|cohere\.(ai|com)|openrouter\.ai|x\.ai|perplexity\.ai|fireworks\.ai|anyscale\.com|bedrock[a-z0-9.-]*\.amazonaws\.com)$/i;

/** Trusted dev endpoints where a token in the request body is legitimate (so prompt-redaction skips them). */
const TRUSTED_DEV_HOSTS =
  /(^|\.)(github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org|npmjs\.(org|com)|pypi\.org|pythonhosted\.org|crates\.io|(sum|proxy)\.golang\.org)$/i;

/** Does this request carry an API credential in ANY header? Returns the header name, or '' if none. */
function credentialIn(headers: IncomingMessage['headers']): string {
  for (const name of ['authorization', 'proxy-authorization']) {
    if (/\bbearer\s+\S|\b(sk-(ant-|proj-)?[A-Za-z0-9-]{10,}|xox[baprs]-|gh[pousr]_|AKIA)/i.test(String(headers[name] ?? ''))) return name;
  }
  if (headers['x-api-key'] || headers['api-key'] || headers['x-goog-api-key']) return 'x-api-key';
  // A structured secret hiding in any other header value (cookie, custom X-*, etc.) — the fixed-name
  // allowlist above misses these, so scan every header value with the shared secret detector.
  for (const [name, val] of Object.entries(headers)) {
    if (name === 'authorization' || name === 'proxy-authorization') continue;
    const s = Array.isArray(val) ? val.join(' ') : String(val ?? '');
    if (s && detectStructuredSecrets(s).length > 0) return name;
  }
  return '';
}

/** Ask the running engine to decide an egress. Held (HITL) calls block on the socket until resolved. */
function askEngine(opts: ProxyOptions, url: string, body?: string): Promise<PipelineResult> {
  const payload = JSON.stringify({ tool: 'WebFetch', input: body ? { url, body } : { url }, approvalMode: 'hold' });
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: opts.engineHost, port: opts.enginePort, path: '/intercept', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } },
      (r) => {
        let d = '';
        r.setEncoding('utf8');
        r.on('data', (c) => (d += c));
        r.on('end', () => {
          try {
            resolve(JSON.parse(d) as PipelineResult);
          } catch {
            reject(new Error('invalid engine response'));
          }
        });
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

function readCappedBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 1_000_000) req.destroy();
    });
    req.on('end', () => resolve(data));
    req.on('error', () => resolve(data));
  });
}

function deny(socket: Socket, reason: string): void {
  socket.end(`HTTP/1.1 403 Forbidden\r\ncontent-type: text/plain\r\n\r\n${reason}\n`);
}
function mitmError(res: ServerResponse, status: number, msg: string): void {
  if (!res.headersSent) res.writeHead(status, { 'content-type': 'text/plain' });
  res.end(`Cerberus proxy: ${msg}\n`);
}
/** Drop hop-by-hop / proxy headers before re-originating upstream. */
function stripProxyHeaders(headers: IncomingMessage['headers']): IncomingMessage['headers'] {
  const h = { ...headers };
  delete h['proxy-connection'];
  delete h['proxy-authorization'];
  return h;
}
function send(res: ServerResponse, status: number, msg: string): void {
  if (!res.headersSent) res.writeHead(status, { 'content-type': 'text/plain' });
  res.end(msg + '\n');
}
