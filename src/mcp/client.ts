/**
 * Minimal MCP client — connect to a configured server and pull its live `tools/list`.
 *
 * stdio transport: spawn the server command and exchange newline-delimited JSON-RPC (initialize ->
 * notifications/initialized -> tools/list). HTTP/"streamable" transport: POST JSON-RPC, tolerating either
 * a JSON body or an SSE (`data:`) stream and an optional `Mcp-Session-Id`. Best-effort + hard timeout;
 * a server that fails to speak the protocol yields an error string, never a hang.
 *
 * SECURITY NOTE: with --connect this SPAWNS the configured MCP server (or calls its URL). That is the only
 * way to obtain tool descriptions to scan (mcp-scan does the same). Scan only servers you intend to run.
 */
import { spawn } from 'node:child_process';
import type { ToolDef } from './scanner.js';
import type { McpServer } from './discover.js';

export interface ListResult {
  tools: ToolDef[];
  error?: string;
}

const CLIENT_INFO = { name: 'cerberus-scan', version: '0.1.0' };
const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: CLIENT_INFO } };
const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };
const INITIALIZED = { jsonrpc: '2.0', method: 'notifications/initialized' };

export function listTools(server: McpServer, timeoutMs = 8000): Promise<ListResult> {
  return server.transport === 'http' ? listToolsHttp(server, timeoutMs) : listToolsStdio(server, timeoutMs);
}

function listToolsStdio(server: McpServer, timeoutMs: number): Promise<ListResult> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(server.command as string, server.args ?? [], { env: { ...process.env, ...server.env }, stdio: ['pipe', 'pipe', 'ignore'] });
    } catch (e) {
      return resolve({ tools: [], error: `spawn failed: ${(e as Error).message}` });
    }
    let buf = '';
    let done = false;
    const finish = (r: ListResult): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      resolve(r);
    };
    const timer = setTimeout(() => finish({ tools: [], error: 'timeout' }), timeoutMs);
    const send = (o: unknown): void => { try { child.stdin.write(JSON.stringify(o) + '\n'); } catch { /* stdin closed */ } };
    child.on('error', (e) => finish({ tools: [], error: `spawn error: ${e.message}` }));
    child.on('close', (code) => finish({ tools: [], error: `server exited before tools/list (code ${code})` }));
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(line) as Record<string, unknown>;
        } catch {
          continue;
        }
        if (msg['id'] === 1) {
          send(INITIALIZED);
          send(LIST);
        } else if (msg['id'] === 2) {
          finish({ tools: toolsFrom(msg), error: msg['error'] ? JSON.stringify(msg['error']) : undefined });
        }
      }
    });
    send(INIT);
  });
}

async function listToolsHttp(server: McpServer, timeoutMs: number): Promise<ListResult> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const url = server.url as string;
  const base = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' } as Record<string, string>;
  try {
    const initRes = await fetch(url, { method: 'POST', headers: base, body: JSON.stringify(INIT), signal: ctrl.signal });
    const sid = initRes.headers.get('mcp-session-id');
    await readBody(initRes);
    const h2 = sid ? { ...base, 'mcp-session-id': sid } : base;
    await fetch(url, { method: 'POST', headers: h2, body: JSON.stringify(INITIALIZED), signal: ctrl.signal }).catch(() => undefined);
    const listRes = await fetch(url, { method: 'POST', headers: h2, body: JSON.stringify(LIST), signal: ctrl.signal });
    const msg = await readBody(listRes);
    if (!msg) return { tools: [], error: 'no MCP response body' };
    return { tools: toolsFrom(msg), error: msg['error'] ? JSON.stringify(msg['error']) : undefined };
  } catch (e) {
    return { tools: [], error: (e as Error).message };
  } finally {
    clearTimeout(timer);
  }
}

/** Read a JSON-RPC message from a JSON or SSE (text/event-stream) response body. */
async function readBody(res: Response): Promise<Record<string, unknown> | null> {
  const text = await res.text();
  const trimmed = text.trimStart();
  if (trimmed.startsWith('{')) {
    try {
      return JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
  // SSE: pick the last `data:` line that parses to an object carrying a result/error.
  let last: Record<string, unknown> | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith('data:')) continue;
    try {
      const obj = JSON.parse(line.slice(5).trim()) as Record<string, unknown>;
      if (obj && (obj['result'] || obj['error'])) last = obj;
    } catch {
      /* skip */
    }
  }
  return last;
}

function toolsFrom(msg: Record<string, unknown>): ToolDef[] {
  const result = msg['result'];
  if (result && typeof result === 'object' && Array.isArray((result as Record<string, unknown>)['tools'])) {
    return ((result as Record<string, unknown>)['tools'] as ToolDef[]).filter((t) => t && typeof t.name === 'string');
  }
  return [];
}
