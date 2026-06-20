import type { LedgerRecord, Checkpoint } from '@comptra/schema';
import { canonicalBytes } from './canon.ts';
import { sha256, toHex, concat, signEd25519, verifyEd25519, b64encode } from './hash.ts';
import { GENESIS_HASH } from './hash.ts';

/**
 * RFC 9162 Merkle Tree Hash with mandatory domain separation
 *   leaf  = SHA-256(0x00 || JCS(record))
 *   node  = SHA-256(0x01 || left || right)
 *   empty = SHA-256("")
 *   split at the largest power of two strictly < n
 * (A naive SHA-256(left||right) is second-preimage weak and would be flagged in a review.)
 *
 * Checkpoints Ed25519-sign {tree_size, root_hash, prev_checkpoint_hash, ...}. An auditor who
 * retained an old signed checkpoint can prove a later whole-history rewrite — the chain alone
 * cannot (an operator with DB write access can recompute a self-consistent forged chain).
 */

const D0 = new Uint8Array([0x00]);
const D1 = new Uint8Array([0x01]);

export async function leafHash(record: LedgerRecord): Promise<Uint8Array> {
  return sha256(concat(D0, canonicalBytes(record)));
}

export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  const n = leaves.length;
  if (n === 0) return sha256(new Uint8Array(0));
  if (n === 1) return leaves[0];
  let k = 1;
  while (k * 2 < n) k *= 2; // largest power of two strictly < n
  const left = await merkleRoot(leaves.slice(0, k));
  const right = await merkleRoot(leaves.slice(k));
  return sha256(concat(D1, left, right));
}

export async function merkleRootHex(records: LedgerRecord[]): Promise<string> {
  const leaves = await Promise.all(records.map(leafHash));
  return toHex(await merkleRoot(leaves));
}

export type CheckpointBody = Omit<Checkpoint, 'signature' | 'cosignatures'>;

export async function buildCheckpoint(args: {
  tenant_id: string;
  chain_key: string;
  records: LedgerRecord[];
  prev_checkpoint_hash?: string;
  key_id: string;
  ts: string;
  signPrivateKey: CryptoKey;
}): Promise<Checkpoint> {
  const body: CheckpointBody = {
    v: 1,
    tenant_id: args.tenant_id,
    chain_key: args.chain_key,
    tree_size: args.records.length,
    root_hash: await merkleRootHex(args.records),
    prev_checkpoint_hash: args.prev_checkpoint_hash ?? GENESIS_HASH,
    ts: args.ts,
    key_id: args.key_id,
  };
  const signature = b64encode(await signEd25519(args.signPrivateKey, canonicalBytes(body)));
  return { ...body, signature, cosignatures: [] };
}

/** Verify only the operator's Ed25519 signature over a checkpoint body (no records needed).
 *  Witnesses use this: they attest to (tree_size, root_hash) via consistency proofs, not the full log. */
export async function verifyCheckpointSignature(cp: Checkpoint, pubKeyHex: string): Promise<boolean> {
  const { signature, cosignatures, ...body } = cp;
  return verifyEd25519(pubKeyHex, signature, canonicalBytes(body));
}

export async function verifyCheckpoint(cp: Checkpoint, records: LedgerRecord[], pubKeyHex: string): Promise<{ ok: boolean; reason?: string }> {
  if (records.length < cp.tree_size) return { ok: false, reason: 'fewer records than the checkpoint tree_size' };
  const root = await merkleRootHex(records.slice(0, cp.tree_size));
  if (root !== cp.root_hash) return { ok: false, reason: 'recomputed Merkle root does not match the signed root' };
  const { signature, cosignatures, ...body } = cp;
  const sigOk = await verifyEd25519(pubKeyHex, signature, canonicalBytes(body));
  if (!sigOk) return { ok: false, reason: 'Ed25519 checkpoint signature invalid' };
  return { ok: true };
}
