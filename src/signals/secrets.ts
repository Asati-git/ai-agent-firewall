/**
 * Curated structured-secret patterns (D8) — the single source of truth shared by the content signal
 * (session-taint / egress content-match) and the MITM proxy's outbound-prompt REDACTION. `valueGroup` is
 * the capture group holding the secret VALUE (default: the whole match); `confidence` is 0–1.
 */
export interface SecretPattern {
  type: string;
  re: RegExp;
  confidence: number;
  valueGroup?: number;
}

export const SECRET_PATTERNS: ReadonlyArray<SecretPattern> = [
  { type: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/, confidence: 0.98 },
  { type: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, confidence: 0.98 },
  { type: 'openai-key', re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/, confidence: 0.97 },
  { type: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, confidence: 0.95 },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/, confidence: 0.95 },
  { type: 'private-key', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/, confidence: 0.9 },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, confidence: 0.9 },
  {
    type: 'generic-secret-assignment',
    re: /\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['"]?([A-Za-z0-9_\-.]{12,})/i,
    confidence: 0.85,
    valueGroup: 1,
  },
];

/** A full PEM private-key block (used by redaction to strip the whole key, not just the BEGIN line). */
const PEM_BLOCK = /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g;

export interface FoundSecret {
  value: string;
  type: string;
  confidence: number;
}

/** Detect the STRUCTURED secrets (no entropy fallback) in `text` — high-confidence, low false positives. */
export function detectStructuredSecrets(text: string): FoundSecret[] {
  const out: FoundSecret[] = [];
  for (const { type, re, confidence, valueGroup } of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    let m: RegExpExecArray | null;
    while ((m = g.exec(text)) !== null) {
      const value = (valueGroup != null ? m[valueGroup] : m[0]) ?? m[0];
      if (value && value.length >= 8) out.push({ value, type, confidence });
      if (m.index === g.lastIndex) g.lastIndex++;
    }
  }
  return out;
}

export interface RedactionResult {
  text: string;
  count: number;
  types: string[];
}

/**
 * Replace structured secret VALUES in `text` with `[REDACTED:<type>]`. Only high-confidence structured
 * patterns (never the entropy heuristic) so it won't corrupt a benign prompt. Full PEM private-key blocks
 * are stripped whole. Returns the redacted text + how many/which secret types were removed (never the value).
 */
export function redactSecrets(text: string): RedactionResult {
  let out = text;
  const types = new Set<string>();
  let count = 0;

  // 1) full PEM private-key blocks
  out = out.replace(PEM_BLOCK, () => {
    count++;
    types.add('private-key');
    return '[REDACTED:private-key]';
  });

  // 2) structured token values — replace ALL raw occurrences, longest first (avoid partial overlaps)
  const found = detectStructuredSecrets(out)
    .filter((f) => f.type !== 'private-key')
    .sort((a, b) => b.value.length - a.value.length);
  for (const f of found) {
    if (f.value.length < 8 || !out.includes(f.value)) continue;
    out = out.split(f.value).join(`[REDACTED:${f.type}]`);
    count++;
    types.add(f.type);
  }
  return { text: out, count, types: [...types] };
}
