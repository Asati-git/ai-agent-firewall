/**
 * MITM support for the egress proxy (opt-in `--mitm`) — the ONLY way to reach the report's "Layer 2"
 * (inspect the decrypted HTTPS RESPONSE body, not just the destination). We mint a local CA once, sign a
 * per-host leaf on the fly, terminate TLS, and scan the response for INJECTED payloads (a malicious LLM
 * router rewriting `content`/`tool_calls` with `curl|sh`, install-from-URL, IOC domains, secret reads…).
 *
 * Requires `node-forge` (dynamic import; core stays dependency-free). The user must trust the generated
 * CA (.cerberus/ca.crt) for their client to accept the minted leaves — printed on first run.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface CA {
  certPem: string;
  keyPem: string;
  cert: any;
  key: any;
}

let forge: any = null;
export async function loadForge(): Promise<any> {
  if (forge) return forge;
  try {
    const mod: any = await import('node-forge');
    forge = mod.default ?? mod;
    return forge;
  } catch {
    throw new Error("MITM mode requires 'node-forge' (an optionalDependency). If it wasn't installed, run:  npm i -g node-forge  (or reinstall @cerberussec/core without --omit=optional)");
  }
}

const YEAR = 365 * 24 * 60 * 60 * 1000;

/** Load the CA from `dir`, or generate + persist a new one. */
export async function loadOrCreateCA(dir: string, now: number): Promise<CA> {
  const f = await loadForge();
  const certPath = join(dir, 'ca.crt');
  const keyPath = join(dir, 'ca.key');
  if (existsSync(certPath) && existsSync(keyPath)) {
    const certPem = readFileSync(certPath, 'utf8');
    const keyPem = readFileSync(keyPath, 'utf8');
    return { certPem, keyPem, cert: f.pki.certificateFromPem(certPem), key: f.pki.privateKeyFromPem(keyPem) };
  }
  const keys = f.pki.rsa.generateKeyPair(2048);
  const cert = f.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(now - YEAR);
  cert.validity.notAfter = new Date(now + 10 * YEAR);
  const attrs = [{ name: 'commonName', value: 'Cerberus Egress CA' }, { name: 'organizationName', value: 'Cerberus' }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true, cRLSign: true }]);
  cert.sign(keys.privateKey, f.md.sha256.create());
  const certPem = f.pki.certificateToPem(cert);
  const keyPem = f.pki.privateKeyToPem(keys.privateKey);
  mkdirSync(dir, { recursive: true });
  writeFileSync(certPath, certPem);
  writeFileSync(keyPath, keyPem);
  return { certPem, keyPem, cert, key: keys.privateKey };
}

/** One leaf keypair reused across hosts (only the per-host cert differs) — keeps handshakes fast. */
let leafKeys: any = null;
const leafCache = new Map<string, { key: string; cert: string }>();

/** Mint (and cache) a leaf cert for `host`, signed by the CA. Cache is keyed per-CA (not just host). */
export async function mintLeaf(host: string, ca: CA, now: number): Promise<{ key: string; cert: string }> {
  const cacheKey = `${createHash('sha1').update(ca.certPem).digest('hex').slice(0, 8)}:${host}`;
  const cached = leafCache.get(cacheKey);
  if (cached) return cached;
  const f = await loadForge();
  leafKeys ??= f.pki.rsa.generateKeyPair(2048);
  const cert = f.pki.createCertificate();
  cert.publicKey = leafKeys.publicKey;
  cert.serialNumber = Buffer.from(host).toString('hex').slice(0, 16) || '02';
  cert.validity.notBefore = new Date(now - 24 * 60 * 60 * 1000);
  cert.validity.notAfter = new Date(now + 397 * 24 * 60 * 60 * 1000);
  cert.setSubject([{ name: 'commonName', value: host }]);
  cert.setIssuer(ca.cert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames: [{ type: 2, value: host }] },
  ]);
  cert.sign(ca.key, f.md.sha256.create());
  const out = { key: f.pki.privateKeyToPem(leafKeys.privateKey), cert: f.pki.certificateToPem(cert) };
  leafCache.set(cacheKey, out);
  return out;
}

/* --------- response-body scanning (Layer 2): find an injected payload in an LLM reply --------- */

export interface ResponseFinding {
  kind: string;
  detail: string;
}

const RESPONSE_PATTERNS: ReadonlyArray<{ kind: string; re: RegExp }> = [
  { kind: 'pipe-to-shell', re: /(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b|\b(invoke-expression|iex)\b/i },
  { kind: 'base64-to-shell', re: /base64\s+-d[^\n|]{0,120}\|\s*(ba|z)?sh\b|\bpowershell(\.exe)?\b[^\n]{0,80}-e(nc(odedcommand)?)?\b/i },
  { kind: 'install-from-url', re: /\b(pip[0-9.]*|npm|pnpm|yarn|bun|gem|cargo|go)\b[^\n]{0,60}\b(install|add|get)\b[^\n]{0,120}(https?:\/\/|git\+)/i },
  { kind: 'known-malicious-package', re: /\bgrokwrapper\b|\blitellm\b[^\n]{0,20}1\.82\.[78]\b/i },
  { kind: 'ioc-endpoint', re: /\b(awstore\.cloud|api\.kiro\.cheap|eth-fastscan\.org|jsonkeeper\.com|recargapopular\.com|welovechinatown\.info)\b/i },
  { kind: 'raw-ip-url', re: /https?:\/\/(\d{1,3}\.){3}\d{1,3}([:/]|\b)/ },
  { kind: 'secret-read-directive', re: /\b(cat|read|type|get-content|gc)\b[^\n]{0,40}(\.env\b|\.ssh[/\\]id_rsa|\.aws[/\\]credentials|[/\\]etc[/\\]passwd)/i },
  { kind: 'lolbin-download', re: /\b(certutil(\.exe)?\b[^\n]{0,80}(-urlcache|http)|bitsadmin[^\n]{0,80}\/transfer|mshta[^\n]{0,60}https?:\/\/)/i },
  { kind: 'base-url-override', re: /\b(ANTHROPIC|OPENAI|OPENROUTER)_?(BASE_URL|API_BASE)\b\s*[=:]/i },
];

/** Scan a (decrypted) response body for indicators that a router injected an executable payload. */
export function scanResponse(body: string): ResponseFinding[] {
  const text = typeof body === 'string' ? body.slice(0, 1_000_000) : '';
  const out: ResponseFinding[] = [];
  for (const p of RESPONSE_PATTERNS) if (p.re.test(text)) out.push({ kind: p.kind, detail: `injected-payload pattern "${p.kind}"` });
  // a very long base64 blob in a chat response is anomalous (staged binary / encoded payload)
  const b64 = /[A-Za-z0-9+/]{800,}={0,2}/.exec(text);
  if (b64) out.push({ kind: 'oversized-base64', detail: `base64 blob of ${b64[0].length} chars in response` });
  return out;
}
