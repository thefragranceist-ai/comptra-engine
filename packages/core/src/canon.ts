/**
 * RFC 8785 JSON Canonicalization Scheme (JCS) — the load-bearing correctness boundary.
 *
 * Any byte drift between the Node hasher, a Python SDK, and an auditor's verifier would
 * falsely "fracture" an honest chain. So this is deliberately small, pinned, and covered by
 * golden vectors. It supports exactly the value space Comptra records use:
 *   objects, arrays, strings, integers, booleans, null.
 *
 * Hard invariants that dodge every known drift source:
 *   - numbers MUST be safe integers (money is integer minor-units; floats throw).
 *   - object keys sorted by UTF-16 code unit (JS string compare).
 *   - strings escaped per RFC 8785 (only mandatory escapes; everything else literal UTF-8).
 */

export function canonicalize(value: unknown): string {
  return ser(value);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

function ser(v: unknown): string {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    const n = v as number;
    if (!Number.isFinite(n)) throw new CanonError('non-finite number');
    if (!Number.isInteger(n)) throw new CanonError('non-integer number (money must be integer minor units)');
    if (!Number.isSafeInteger(n)) throw new CanonError('integer out of IEEE-754 safe range');
    return String(n);
  }
  if (t === 'string') return quote(v as string);
  if (Array.isArray(v)) return '[' + v.map(ser).join(',') + ']';
  if (t === 'object') {
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort(cmpUtf16);
    return '{' + keys.map((k) => quote(k) + ':' + ser(o[k])).join(',') + '}';
  }
  throw new CanonError('unsupported type: ' + t);
}

// JCS sorts member names by UTF-16 code units. JavaScript's default string comparison
// is exactly UTF-16 code-unit order, so '<' is correct here.
function cmpUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function quote(s: string): string {
  let out = '"';
  // iterate by code point so surrogate pairs are emitted intact as literal UTF-8
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    switch (ch) {
      case '"': out += '\\"'; continue;
      case '\\': out += '\\\\'; continue;
    }
    if (c === 0x08) out += '\\b';
    else if (c === 0x09) out += '\\t';
    else if (c === 0x0a) out += '\\n';
    else if (c === 0x0c) out += '\\f';
    else if (c === 0x0d) out += '\\r';
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

export class CanonError extends Error {
  constructor(msg: string) {
    super('JCS canonicalization: ' + msg);
    this.name = 'CanonError';
  }
}
