/**
 * Shared regex compilation for the policy `matches` op and the `rules validate` linter.
 *
 * A rule pattern may carry an inline-flags prefix — `(?i)`, `(?is)`, … — because JavaScript's RegExp has
 * no inline-flag syntax; we translate it to the constructor's `flags` argument. Keeping this in ONE place
 * means the linter accepts EXACTLY the patterns the engine will run at runtime (no validate/runtime drift,
 * which is how a `(?i)` rule could lint-fail while working fine live, or vice-versa).
 */

/** Compile a rule pattern, honoring an optional leading `(?flags)` prefix. Throws on a genuinely bad regex. */
export function compileMatchPattern(pattern: string): RegExp {
  let src = pattern;
  let flags = '';
  const inline = /^\(\?([a-z]+)\)/.exec(src);
  if (inline) {
    flags = inline[1] as string;
    src = src.slice(inline[0].length);
  }
  return new RegExp(src, flags);
}

/** The `matches` op body: true iff `value` matches `pattern`. A malformed rule never throws in the hot path. */
export function testMatch(pattern: unknown, value: unknown): boolean {
  if (typeof pattern !== 'string' || typeof value !== 'string') return false;
  try {
    return compileMatchPattern(pattern).test(value);
  } catch {
    return false;
  }
}
