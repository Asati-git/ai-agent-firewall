/**
 * MCP server discovery — find the MCP servers configured across the common agent config files, so
 * `cerberus scan` can connect and pull each server's live `tools/list` (instead of needing a hand-captured
 * JSON dump). Pure parsing (serversFromConfig) is separated from disk IO (discoverServers) for testing.
 */
import { existsSync, readFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';

export interface McpServer {
  name: string;
  source: string; // which config file it came from
  transport: 'stdio' | 'http';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

/** Parse one config object into server descriptors. Accepts `mcpServers`/`servers`, stdio or url, and
 *  Claude's per-project map (`projects[path].mcpServers`). */
export function serversFromConfig(source: string, parsed: unknown): McpServer[] {
  const out: McpServer[] = [];
  if (!parsed || typeof parsed !== 'object') return out;
  const root = parsed as Record<string, unknown>;

  const collect = (map: unknown): void => {
    if (!map || typeof map !== 'object') return;
    for (const [name, raw] of Object.entries(map as Record<string, unknown>)) {
      if (!raw || typeof raw !== 'object') continue;
      const s = raw as Record<string, unknown>;
      const url = typeof s['url'] === 'string' ? (s['url'] as string) : undefined;
      const command = typeof s['command'] === 'string' ? (s['command'] as string) : undefined;
      if (url) out.push({ name, source, transport: 'http', url });
      else if (command)
        out.push({
          name,
          source,
          transport: 'stdio',
          command,
          args: Array.isArray(s['args']) ? (s['args'] as unknown[]).filter((a): a is string => typeof a === 'string') : [],
          env: s['env'] && typeof s['env'] === 'object' ? (s['env'] as Record<string, string>) : undefined,
        });
    }
  };

  collect(root['mcpServers']);
  collect(root['servers']); // VS Code `.vscode/mcp.json` uses `servers`
  // Claude Code `~/.claude.json`: per-project server maps
  if (root['projects'] && typeof root['projects'] === 'object') {
    for (const proj of Object.values(root['projects'] as Record<string, unknown>)) {
      if (proj && typeof proj === 'object') collect((proj as Record<string, unknown>)['mcpServers']);
    }
  }
  return dedupe(out);
}

/** Candidate config file paths across agents (project-level under cwd, plus user-level under home). */
export function configLocations(home: string, cwd: string): string[] {
  const app = process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming');
  const claudeDesktop =
    platform() === 'darwin'
      ? join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json')
      : join(app, 'Claude', 'claude_desktop_config.json');
  return [
    join(cwd, '.mcp.json'),
    join(cwd, '.cursor', 'mcp.json'),
    join(cwd, '.vscode', 'mcp.json'),
    join(cwd, '.gemini', 'settings.json'),
    join(home, '.claude.json'),
    join(home, '.cursor', 'mcp.json'),
    join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    claudeDesktop,
  ];
}

/** Read + parse every existing config location and return the union of discovered servers. */
export function discoverServers(home = homedir(), cwd = process.cwd()): McpServer[] {
  const out: McpServer[] = [];
  for (const path of configLocations(home, cwd)) {
    if (!existsSync(path)) continue;
    try {
      out.push(...serversFromConfig(path, JSON.parse(readFileSync(path, 'utf8'))));
    } catch {
      /* skip unreadable / non-JSON config */
    }
  }
  return dedupe(out);
}

/** Dedupe by name+command/url (the same server is often declared in several configs). */
function dedupe(servers: McpServer[]): McpServer[] {
  const seen = new Set<string>();
  const out: McpServer[] = [];
  for (const s of servers) {
    const key = `${s.name}|${s.transport}|${s.url ?? ''}|${s.command ?? ''}|${(s.args ?? []).join(' ')}`;
    if (!seen.has(key)) (seen.add(key), out.push(s));
  }
  return out;
}
