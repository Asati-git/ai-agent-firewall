#!/usr/bin/env node
/**
 * `cerberus` launcher. Prefers the compiled CLI in `dist/` (published package); falls back to
 * running the TypeScript source via tsx when `dist/` is absent (local dev). Either way it exports
 * CB_HOME (and legacy AG_HOME) = the package root so the CLI can resolve bundled resources (rules/,
 * dashboard/dist/) consistently whether it runs from src/ or dist/.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const distCli = join(root, 'dist', 'cli', 'index.js');
const args = process.argv.slice(2);

// Prefer compiled dist/ (built package); else run TS source via tsx (dev). If NEITHER is present,
// the project hasn't been set up — fail with a clear instruction instead of a raw ERR_MODULE_NOT_FOUND.
let spawnArgs;
if (existsSync(distCli)) {
  spawnArgs = [distCli, ...args];
} else if (existsSync(join(root, 'node_modules', 'tsx'))) {
  spawnArgs = ['--import', 'tsx', join(root, 'src', 'cli', 'index.ts'), ...args];
} else {
  process.stderr.write(
    '\nCerberus is not set up yet — dependencies are missing.\n\n' +
      'From the project folder, run:\n' +
      '  npm install            # installs dependencies (this step is easy to skip!)\n' +
      '  npm run build:engine   # optional: compile to dist/ for faster startup\n\n' +
      'then re-run your command (e.g. `node bin/cerberus.mjs engine`).\n\n',
  );
  process.exit(1);
}

const child = spawn(process.execPath, spawnArgs, {
  stdio: 'inherit',
  env: { ...process.env, CB_HOME: root, AG_HOME: root },
});
child.on('exit', (code) => process.exit(code ?? 0));
