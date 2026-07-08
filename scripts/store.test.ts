// Unit test for the InMemoryPendingStore — the synchronous HITL hold lifecycle (run: npx tsx scripts/store.test.ts).
//
// This is the fail-closed heart of a held call: the open socket stays parked until a human decides, the
// TTL fires (→ BLOCK), or the client disconnects (→ BLOCK). None of it had direct coverage (M11).
import { InMemoryPendingStore } from '../src/policy/store.js';
import type { FinalAction, SecurityViolation } from '../src/contract/types.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}

// Keep the loop alive so the store's unref'd TTL timer can fire during our awaits.
const keepAlive = setInterval(() => {}, 1000);

const viol = (id: string): SecurityViolation => ({
  id, toolCall: { tool: 'Bash', input: { command: 'x' } }, category: 'EXECUTE',
  ruleId: 'r', reason: 'test', createdAt: 0, ttlMs: 30, signal: 'policy',
});

// ── TTL timeout → fail-closed BLOCK, entry removed, 'resolved' event emitted ──
{
  const store = new InMemoryPendingStore();
  const events: [string, FinalAction][] = [];
  store.on('resolved', (id: string, action: FinalAction) => events.push([id, action]));
  const p = store.registerContext(viol('t1'), 30);
  check('pending() shows the held call', store.pending().length === 1 && store.pending()[0]?.id === 't1');
  const res = await p;
  check('TTL fires → BLOCK', res.action === 'BLOCK' && /timed out/i.test(res.reason), JSON.stringify(res));
  check('entry removed after TTL', store.pending().length === 0);
  check("'resolved' event emitted with BLOCK", events.some(([id, a]) => id === 't1' && a === 'BLOCK'));
}

// ── human ALLOW resolves the parked promise, clears the timer, removes the entry ──
{
  const store = new InMemoryPendingStore();
  const p = store.registerContext(viol('a1'), 5000);
  await store.resolveContext('a1', 'ALLOW');
  const res = await p;
  check('human ALLOW → promise resolves ALLOW', res.action === 'ALLOW' && /approved/i.test(res.reason), JSON.stringify(res));
  check('entry removed after approve', store.pending().length === 0);
}

// ── human deny → BLOCK ──
{
  const store = new InMemoryPendingStore();
  const p = store.registerContext(viol('d1'), 5000);
  await store.resolveContext('d1', 'BLOCK');
  const res = await p;
  check('human deny → promise resolves BLOCK', res.action === 'BLOCK' && /denied/i.test(res.reason), JSON.stringify(res));
}

// ── client disconnect (cleanup) → fail-closed BLOCK ──
{
  const store = new InMemoryPendingStore();
  const p = store.registerContext(viol('c1'), 5000);
  await store.cleanup('c1');
  const res = await p;
  check('cleanup → fail-closed BLOCK', res.action === 'BLOCK' && /disconnected/i.test(res.reason), JSON.stringify(res));
  check('entry removed after cleanup', store.pending().length === 0);
}

// ── robustness: unknown id is a no-op; first resolution wins over a later one ──
{
  const store = new InMemoryPendingStore();
  await store.resolveContext('nope', 'ALLOW'); // must not throw
  check('resolve of unknown id is a no-op', store.pending().length === 0);

  const p = store.registerContext(viol('x1'), 5000);
  await store.resolveContext('x1', 'ALLOW');
  await store.resolveContext('x1', 'BLOCK'); // entry already gone → no-op
  const res = await p;
  check('first resolution wins (ALLOW), later resolve ignored', res.action === 'ALLOW', JSON.stringify(res));
}

clearInterval(keepAlive);
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
