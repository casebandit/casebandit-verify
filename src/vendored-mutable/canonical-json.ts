/**
 * ============================================================================
 * VENDORED-MUTABLE-BOUNDARY DEPENDENCY — DO NOT EDIT BY HAND.
 *
 * Verbatim copy of casenotes-saas `apps/web/lib/canonical-json.ts`.
 * Pinned to source content-hash (sha256):
 *   a91824d9b62c5f7e7057c0b702e31f599a607d2c2a4576036754e2949387b0ea
 *
 * Lives under `vendored-mutable/` only because it is the dependency of
 * `ledger-hmac.ts` (the genuinely-mutable leaf). The JCS RFC 8785 serializer
 * itself is a fixed spec; it is co-located here so the whole keyed-path HMAC
 * message construction sits behind ONE pinned-hash boundary + the golden vectors.
 * ============================================================================
 *
 * JCS RFC 8785 canonicalizer. Dependency-free. Produces a stable byte sequence
 * for HMAC binding. Choices: UTF-8 NFC; integer-only numbers (floats throw); JCS
 * lexicographic key order; null/undefined values omitted; arrays preserve order.
 */

export function canonicalize(value: unknown): Uint8Array {
  return new TextEncoder().encode(serialize(value));
}

function serialize(value: unknown): string {
  if (value === null) {
    return 'null';
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return serializeNumber(value);
  if (typeof value === 'string') return serializeString(value);
  if (Array.isArray(value)) return serializeArray(value);
  if (typeof value === 'object') return serializeObject(value as Record<string, unknown>);
  throw new TypeError(`canonicalize: unsupported value of type ${typeof value}`);
}

function serializeNumber(n: number): string {
  if (Number.isNaN(n)) throw new TypeError('canonicalize: NaN is not permitted');
  if (!Number.isFinite(n)) throw new TypeError('canonicalize: Infinity is not permitted');
  if (!Number.isInteger(n)) {
    throw new TypeError(`canonicalize: non-integer number ${n} is not permitted (integer timestamps only)`);
  }
  return String(n);
}

function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code === 0x22) out += '\\"';
    else if (code === 0x5c) out += '\\\\';
    else if (code === 0x08) out += '\\b';
    else if (code === 0x09) out += '\\t';
    else if (code === 0x0a) out += '\\n';
    else if (code === 0x0c) out += '\\f';
    else if (code === 0x0d) out += '\\r';
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += s[i];
  }
  out += '"';
  return out;
}

function serializeArray(arr: unknown[]): string {
  const parts: string[] = [];
  for (const el of arr) {
    if (el === undefined) parts.push('null');
    else if (el === null) parts.push('null');
    else parts.push(serialize(el));
  }
  return '[' + parts.join(',') + ']';
}

function serializeObject(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === null || v === undefined) continue;
    parts.push(serializeString(k) + ':' + serialize(v));
  }
  return '{' + parts.join(',') + '}';
}
