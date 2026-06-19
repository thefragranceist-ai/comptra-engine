/**
 * Crypto primitives — WebCrypto only (identical on Node 22+ and Cloudflare Workers).
 * Deliberately NOT node:crypto, so the same bytes are produced everywhere the ledger runs.
 */

export const GENESIS_HASH = '0'.repeat(64);

export function toHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('odd-length hex');
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}

const utf8 = new TextEncoder();

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const d = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return new Uint8Array(d);
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(await sha256(bytes));
}

/** record_hash = SHA-256( utf8(prev_hash_hex) || JCS(record_without_record_hash) ) */
export async function chainHash(prevHashHex: string, canonicalRecordBytes: Uint8Array): Promise<string> {
  const prefix = utf8.encode(prevHashHex);
  const buf = new Uint8Array(prefix.length + canonicalRecordBytes.length);
  buf.set(prefix, 0);
  buf.set(canonicalRecordBytes, prefix.length);
  return sha256Hex(buf);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// ---- Ed25519 (signed checkpoints) ----
export type Ed25519KeyPair = { privateKey: CryptoKey; publicKey: CryptoKey };

export async function generateEd25519(): Promise<Ed25519KeyPair> {
  const kp = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

export async function signEd25519(privateKey: CryptoKey, bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, bytes as BufferSource));
}

export async function verifyEd25519(publicKeyRawHex: string, sigB64: string, bytes: Uint8Array): Promise<boolean> {
  const pub = await importPublicKey(publicKeyRawHex);
  return crypto.subtle.verify({ name: 'Ed25519' }, pub, b64decode(sigB64) as BufferSource, bytes as BufferSource);
}

export async function exportPublicKeyHex(publicKey: CryptoKey): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.exportKey('raw', publicKey)));
}

export async function exportPrivateKeyPkcs8Hex(privateKey: CryptoKey): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey)));
}

export async function importPublicKey(rawHex: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', fromHex(rawHex) as BufferSource, { name: 'Ed25519' }, true, ['verify']);
}

export async function importPrivateKey(pkcs8Hex: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', fromHex(pkcs8Hex) as BufferSource, { name: 'Ed25519' }, true, ['sign']);
}

export function b64encode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
