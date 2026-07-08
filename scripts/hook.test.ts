// Fail-closed contract test for the hook client (run: npx tsx scripts/hook.test.ts).
//
// The single most important safety property: when the engine is unreachable, a PreToolUse hook must
// DENY (fail closed), and only flip to allow under the explicit AG_FAIL_OPEN=1 escape hatch. This is a
// headline guarantee with no other coverage — a regression here would ship green and be catastrophic.
// We spawn the real `cerberus hook` against a CLOSED port and inspect the verdict it emits on stdout.
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}

const ROOT = resolve(import.meta.dirname, '..');
const CLOSED_PORT = '59413'; // nothing listens here ⇒ /intercept POST gets ECONNREFUSED
const PRE_EVENT = JSON.stringify({
  hook_event_name: 'PreToolUse',
  tool_name: 'Bash',
  tool_input: { command: 'rm -rf /' },
  session_id: 'hook-test',
});

/** Run `cerberus hook` (via tsx) with a PreToolUse event on stdin; return the parsed stdout verdict. */
function runHook(extraEnv: Record<string, string>): { permissionDecision?: string; reason?: string } {
  const r = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'hook'], {
    cwd: ROOT,
    input: PRE_EVENT,
    encoding: 'utf8',
    env: { ...process.env, AG_ENGINE_PORT: CLOSED_PORT, AG_NOTIFY: '0', ...extraEnv },
    timeout: 20_000,
  });
  try {
    const out = JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string; permissionDecisionReason?: string } };
    return { permissionDecision: out.hookSpecificOutput?.permissionDecision, reason: out.hookSpecificOutput?.permissionDecisionReason };
  } catch {
    return { reason: `unparseable stdout: ${JSON.stringify(r.stdout)} / stderr: ${JSON.stringify(r.stderr)}` };
  }
}

// ── engine down, default posture ⇒ DENY (fail closed) ──
{
  const v = runHook({});
  check('engine unreachable → deny (fail closed)', v.permissionDecision === 'deny', JSON.stringify(v));
  check('deny reason mentions the engine + how to recover', !!v.reason && /engine unreachable/i.test(v.reason), v.reason ?? '');
}

// ── engine down, explicit escape hatch ⇒ ALLOW ──
{
  const v = runHook({ AG_FAIL_OPEN: '1' });
  check('engine unreachable + AG_FAIL_OPEN=1 → allow', v.permissionDecision === 'allow', JSON.stringify(v));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
