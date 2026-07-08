/**
 * Environment configuration with the CB_* → AG_* migration path.
 *
 * Cerberus reads `CB_<NAME>` first and falls back to the legacy `AG_<NAME>` (the pre-rename AgentGuard
 * prefix), so existing setups keep working while new docs use CB_*. `numEnv` VALIDATES its input: a
 * typo like `CB_MAX_RATE=3o` parses to NaN and would silently disable the runaway guard (`rate > NaN`
 * is always false) — instead we warn loudly on stderr and fall back to the safe default (M8).
 */

/** Read `CB_<name>` (preferred) or the legacy `AG_<name>`. */
export function rawEnv(name: string): string | undefined {
  return process.env[`CB_${name}`] ?? process.env[`AG_${name}`];
}

export function strEnv(name: string, def: string): string {
  const v = rawEnv(name);
  return v === undefined ? def : v;
}

/** A finite number, or the default. Non-numeric input warns (never silently becomes NaN) — M8. */
export function numEnv(name: string, def: number): number {
  const raw = rawEnv(name);
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n)) {
    process.stderr.write(`Cerberus: ignoring invalid numeric env ${envLabel(name)}=${JSON.stringify(raw)} — using default ${def}.\n`);
    return def;
  }
  return n;
}

/** A boolean flag: "1"/"true" ⇒ true, "0"/"false" ⇒ false, absent ⇒ default. */
export function flagEnv(name: string, def: boolean): boolean {
  const raw = rawEnv(name);
  if (raw === undefined) return def;
  const v = raw.toLowerCase();
  if (v === '1' || v === 'true') return true;
  if (v === '0' || v === 'false') return false;
  return def;
}

/** Which concrete variable name is in effect (for diagnostics). */
function envLabel(name: string): string {
  return process.env[`CB_${name}`] !== undefined ? `CB_${name}` : `AG_${name}`;
}
