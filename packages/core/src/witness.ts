import type { Checkpoint, Cosignature, WitnessRef } from '@comptra/schema';
import { canonicalBytes } from './canon.ts';
import { signEd25519, verifyEd25519, b64encode, fromHex } from './hash.ts';
import { verifyCheckpointSignature } from './merkle.ts';
import { verifyConsistency, proofFromHex } from './proofs.ts';

/**
 * The witness layer — Comptra's split-view / fork defense (the C2SP tlog-witness / Sigsum model,
 * adapted). This is the part an operator with full DB write access CANNOT cheat, and the part that
 * is genuinely hard to replicate: it requires an independent quorum of witnesses, each holding the
 * last head it cosigned, each refusing to cosign anything that is not an append-only extension.
 *
 *   operator  ──(new checkpoint + RFC9162 consistency proof from the witness's last head)──▶  witness
 *   witness verifies: operator sig ✓, tree_size monotonic ✓, consistency proof ✓  ──▶  Ed25519 cosignature
 *   auditor requires: operator sig + a t-of-n quorum of valid cosignatures over (tree_size, root_hash)
 *
 * Why it closes split-view: to show two different histories at the same tree_size, an operator would
 * need t honest witnesses to each cosign a head inconsistent with the one they already cosigned —
 * which the consistency check makes impossible. A fork is therefore detectable, not merely auditable.
 */

const STMT_KIND = 'comptra.witness.cosig.v1';

/** The exact bytes a witness signs — binds the witness identity to a specific (tenant, chain, size, root). */
export function witnessStatementBytes(args: {
  tenant_id: string; chain_key: string; tree_size: number; root_hash: string; witness_id: string;
}): Uint8Array {
  return canonicalBytes({
    kind: STMT_KIND,
    tenant_id: args.tenant_id,
    chain_key: args.chain_key,
    tree_size: args.tree_size,
    root_hash: args.root_hash,
    witness_id: args.witness_id,
  });
}

export type WitnessState = { tree_size: number; root_hash: string };
export const freshWitnessState = (): WitnessState => ({ tree_size: 0, root_hash: '' });

export type WitnessReview =
  | { ok: true; cosignature: Cosignature; state: WitnessState }
  | { ok: false; reason: string };

/**
 * A witness reviews a new checkpoint against the last head it cosigned, and cosigns iff:
 *   (1) the operator's signature over the checkpoint is valid,
 *   (2) tree_size does not regress, and
 *   (3) the supplied RFC 9162 consistency proof from the witness's last head verifies (append-only).
 */
export async function witnessReview(args: {
  state: WitnessState;
  checkpoint: Checkpoint;
  operatorPubKeyHex: string;
  consistencyProofHex: string[];
  witnessId: string;
  witnessPrivateKey: CryptoKey;
  ts: string;
}): Promise<WitnessReview> {
  const { state, checkpoint: cp } = args;

  if (!(await verifyCheckpointSignature(cp, args.operatorPubKeyHex))) {
    return { ok: false, reason: 'operator checkpoint signature invalid' };
  }
  if (cp.tree_size < state.tree_size) {
    return { ok: false, reason: `tree_size regressed (${cp.tree_size} < last cosigned ${state.tree_size})` };
  }
  if (cp.tree_size === state.tree_size && state.tree_size > 0 && cp.root_hash !== state.root_hash) {
    return { ok: false, reason: 'same tree_size, different root — fork at the last cosigned head' };
  }
  const firstRoot = state.tree_size === 0 ? new Uint8Array(0) : fromHex(state.root_hash);
  const consistent = await verifyConsistency(
    state.tree_size, cp.tree_size, proofFromHex(args.consistencyProofHex), firstRoot, fromHex(cp.root_hash),
  );
  if (!consistent) {
    return { ok: false, reason: 'consistency proof from the last cosigned head failed (not append-only)' };
  }
  const sig = b64encode(await signEd25519(args.witnessPrivateKey, witnessStatementBytes({
    tenant_id: cp.tenant_id, chain_key: cp.chain_key, tree_size: cp.tree_size, root_hash: cp.root_hash, witness_id: args.witnessId,
  })));
  return {
    ok: true,
    cosignature: { witness_id: args.witnessId, ts: args.ts, signature: sig },
    state: { tree_size: cp.tree_size, root_hash: cp.root_hash },
  };
}

/** Verify a single cosignature over a checkpoint, given the witness's public key. */
export async function verifyCosignature(cp: Checkpoint, cosig: Cosignature, witnessPubKeyHex: string): Promise<boolean> {
  return verifyEd25519(witnessPubKeyHex, cosig.signature, witnessStatementBytes({
    tenant_id: cp.tenant_id, chain_key: cp.chain_key, tree_size: cp.tree_size, root_hash: cp.root_hash, witness_id: cosig.witness_id,
  }));
}

export type QuorumResult = { ok: boolean; valid: number; threshold: number; witnesses: string[]; reason?: string };

/** Verify a t-of-n witness quorum over a checkpoint. Counts DISTINCT valid witnesses from the registry. */
export async function verifyQuorum(cp: Checkpoint, registry: WitnessRef[], threshold: number): Promise<QuorumResult> {
  const byId = new Map(registry.map((w) => [w.witness_id, w.public_key]));
  const seen = new Set<string>();
  for (const cs of cp.cosignatures ?? []) {
    if (seen.has(cs.witness_id)) continue;            // one vote per witness
    const pub = byId.get(cs.witness_id);
    if (!pub) continue;                                // unknown witness — ignored, not trusted
    if (await verifyCosignature(cp, cs, pub)) seen.add(cs.witness_id);
  }
  const valid = seen.size;
  const ok = valid >= threshold;
  return { ok, valid, threshold, witnesses: [...seen], reason: ok ? undefined : `quorum not met: ${valid}/${threshold} valid cosignatures` };
}
