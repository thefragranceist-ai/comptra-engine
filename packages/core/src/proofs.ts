import { sha256, concat, toHex, fromHex } from './hash.ts';
import { merkleRoot } from './merkle.ts';

/**
 * RFC 9162 (Certificate Transparency v2) Merkle inclusion + consistency proofs.
 *
 * These are the two proofs that turn the audit ledger from "re-read the whole log to check it"
 * into "prove one record is in a signed tree in O(log n)" and "prove tree m is an append-only
 * PREFIX of tree n in O(log n)". The consistency proof is the load-bearing primitive behind the
 * witness layer (witness.ts): a witness will only co-sign a new checkpoint if it is consistent
 * with the last one it saw, which is what makes a split-view / fork attack detectable.
 *
 * Hashing matches merkle.ts exactly (domain-separated): leaf = SHA-256(0x00 || JCS(record)),
 * node = SHA-256(0x01 || left || right), split at the largest power of two strictly < n.
 */

const D1 = new Uint8Array([0x01]);
const node = (l: Uint8Array, r: Uint8Array) => sha256(concat(D1, l, r));

function k_of(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2; // largest power of two strictly < n
  return k;
}
function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
const isPow2 = (m: number) => m > 0 && (m & (m - 1)) === 0;

// ---- inclusion proof (RFC 9162 §2.1.3.1 PATH) ----
/** Audit path proving the leaf at index m is in the Merkle tree over leaves[0:n]. */
export async function inclusionProof(leaves: Uint8Array[], m: number): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (m < 0 || m >= n) throw new Error('inclusionProof: index out of range');
  return PATH(m, leaves);
}
async function PATH(m: number, leaves: Uint8Array[]): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (n === 1) return [];
  const k = k_of(n);
  if (m < k) return [...(await PATH(m, leaves.slice(0, k))), await merkleRoot(leaves.slice(k))];
  return [...(await PATH(m - k, leaves.slice(k))), await merkleRoot(leaves.slice(0, k))];
}

// ---- verify inclusion (RFC 9162 §2.1.3.2) ----
export async function verifyInclusion(
  leafHash: Uint8Array, m: number, n: number, proof: Uint8Array[], root: Uint8Array,
): Promise<boolean> {
  if (m >= n) return false;
  let fn = m, sn = n - 1;
  let r = leafHash;
  for (const p of proof) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = await node(p, r);
      if ((fn & 1) === 0) { do { fn >>= 1; sn >>= 1; } while ((fn & 1) === 0 && fn !== 0); }
    } else {
      r = await node(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(r, root);
}

// ---- consistency proof (RFC 9162 §2.1.4.1 PROOF / SUBPROOF) ----
/** Proof that the tree over leaves[0:m] is an append-only prefix of the tree over leaves[0:n]. */
export async function consistencyProof(leaves: Uint8Array[], m: number, n: number): Promise<Uint8Array[]> {
  if (m < 0 || m > n || n > leaves.length) throw new Error('consistencyProof: bad sizes');
  if (m === 0 || m === n) return [];
  return SUBPROOF(m, leaves.slice(0, n), true);
}
async function SUBPROOF(m: number, leaves: Uint8Array[], b: boolean): Promise<Uint8Array[]> {
  const n = leaves.length;
  if (m === n) return b ? [] : [await merkleRoot(leaves)];
  const k = k_of(n);
  if (m <= k) return [...(await SUBPROOF(m, leaves.slice(0, k), b)), await merkleRoot(leaves.slice(k))];
  return [...(await SUBPROOF(m - k, leaves.slice(k), false)), await merkleRoot(leaves.slice(0, k))];
}

// ---- verify consistency (RFC 9162 §2.1.4.2) ----
export async function verifyConsistency(
  m: number, n: number, proof: Uint8Array[], firstRoot: Uint8Array, secondRoot: Uint8Array,
): Promise<boolean> {
  if (m > n) return false;
  if (m === n) return proof.length === 0 && eq(firstRoot, secondRoot);
  if (m === 0) return proof.length === 0; // empty tree is a prefix of every tree
  // §2.1.4.2: if m is an exact power of two, prepend first_hash to the path
  const path = isPow2(m) ? [firstRoot, ...proof] : proof.slice();
  if (path.length === 0) return false;
  let fn = m - 1, sn = n - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
  let fr = path[0], sr = path[0];
  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = await node(c, fr);
      sr = await node(c, sr);
      if ((fn & 1) === 0) { do { fn >>= 1; sn >>= 1; } while ((fn & 1) === 0 && fn !== 0); }
    } else {
      sr = await node(sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(fr, firstRoot) && eq(sr, secondRoot);
}

// ---- hex convenience (proofs cross the wire as hex arrays) ----
export const proofToHex = (p: Uint8Array[]): string[] => p.map(toHex);
export const proofFromHex = (p: string[]): Uint8Array[] => p.map(fromHex);
