import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { LedgerRecord, WitnessRef } from '@comptra/schema';
import { sealRecord, GENESIS_HASH } from '../packages/core/src/chain.ts';
import { leafHash, buildCheckpoint } from '../packages/core/src/merkle.ts';
import { generateEd25519, exportPublicKeyHex } from '../packages/core/src/hash.ts';
import { consistencyProof, proofToHex } from '../packages/core/src/proofs.ts';
import { witnessReview, verifyQuorum, freshWitnessState, type WitnessState } from '../packages/core/src/witness.ts';

async function buildLog(n: number, tag = 'ok'): Promise<LedgerRecord[]> {
  const recs: LedgerRecord[] = [];
  let prev = GENESIS_HASH;
  for (let i = 0; i < n; i++) {
    const r = await sealRecord(prev, i, {
      tenant_id: 't', chain_key: 't/agent', agent_id: 'agent', end_customer_id: '-',
      decision: 'PASS', reason_code: 'PASS', vendor: { name: tag + '-' + i, mcc: '0000', country: 'US' },
      amount_minor: 100 + i, approved_amount_minor: 100 + i, currency: 'USD',
      mandate_ref: null, idempotency_key: 'k-' + tag + '-' + i, rail: 'sim',
      ts: '2026-01-01T00:00:00.000Z',
    });
    recs.push(r); prev = r.record_hash;
  }
  return recs;
}

async function setup() {
  const op = await generateEd25519();
  const opPub = await exportPublicKeyHex(op.publicKey);
  const ws = await Promise.all([0, 1, 2].map(() => generateEd25519()));
  const ids = ['witness-a', 'witness-b', 'witness-c'];
  const registry: WitnessRef[] = await Promise.all(ws.map(async (w, i) => ({
    witness_id: ids[i], public_key: await exportPublicKeyHex(w.publicKey), operator: 'independent',
  })));
  return { op, opPub, ws, ids, registry };
}
const cp = (records: LedgerRecord[], size: number, op: CryptoKey, prev = GENESIS_HASH) =>
  buildCheckpoint({ tenant_id: 't', chain_key: 't/agent', records: records.slice(0, size), prev_checkpoint_hash: prev, key_id: 'op-key', ts: '2026-01-01T00:00:00.000Z', signPrivateKey: op });

test('honest append-only growth: every witness cosigns, quorum is met', async () => {
  const { op, opPub, ws, ids, registry } = await setup();
  const log = await buildLog(20);
  const leaves = await Promise.all(log.map(leafHash));
  const states: WitnessState[] = ids.map(freshWitnessState);

  // checkpoint at size 8, then 15 (append-only)
  for (const size of [8, 15]) {
    const checkpoint = await cp(log, size, op.privateKey);
    for (let w = 0; w < 3; w++) {
      const proof = proofToHex(await consistencyProof(leaves, states[w].tree_size, size));
      const rev = await witnessReview({
        state: states[w], checkpoint, operatorPubKeyHex: opPub,
        consistencyProofHex: proof, witnessId: ids[w], witnessPrivateKey: ws[w].privateKey, ts: '2026-01-01T00:00:00.000Z',
      });
      assert.ok(rev.ok, `witness ${w} should cosign size ${size}: ${rev.ok ? '' : rev.reason}`);
      if (rev.ok) { checkpoint.cosignatures.push(rev.cosignature); states[w] = rev.state; }
    }
    const q = await verifyQuorum(checkpoint, registry, 2);
    assert.ok(q.ok, `quorum should be met at size ${size} (${q.valid}/${q.threshold})`);
    assert.equal(q.valid, 3);
  }
});

test('SPLIT-VIEW is impossible: once a witness cosigns a head it refuses any other root at that size, so a fork cannot reach quorum', async () => {
  const { op, opPub, ws, ids, registry } = await setup();
  const honest = await buildLog(12, 'real');
  const honestLeaves = await Promise.all(honest.map(leafHash));
  const states: WitnessState[] = ids.map(freshWitnessState);

  // all three witnesses cosign the honest head at size 12
  const good = await cp(honest, 12, op.privateKey);
  for (let w = 0; w < 3; w++) {
    const proof = proofToHex(await consistencyProof(honestLeaves, 0, 12));
    const rev = await witnessReview({ state: states[w], checkpoint: good, operatorPubKeyHex: opPub, consistencyProofHex: proof, witnessId: ids[w], witnessPrivateKey: ws[w].privateKey, ts: '2026-01-01T00:00:00.000Z' });
    assert.ok(rev.ok);
    if (rev.ok) { good.cosignatures.push(rev.cosignature); states[w] = rev.state; }
  }
  assert.ok((await verifyQuorum(good, registry, 2)).ok);

  // operator forks: a DIFFERENT size-12 log, presented to the auditor
  const forked = await buildLog(12, 'fork');
  const forkLeaves = await Promise.all(forked.map(leafHash));
  const evil = await cp(forked, 12, op.privateKey);
  assert.notEqual(evil.root_hash, good.root_hash, 'fork must have a different root');

  // every witness refuses to cosign a second, different root at the same tree_size
  for (let w = 0; w < 3; w++) {
    const proof = proofToHex(await consistencyProof(forkLeaves, states[w].tree_size, 12)); // self-consistent, but...
    const rev = await witnessReview({ state: states[w], checkpoint: evil, operatorPubKeyHex: opPub, consistencyProofHex: proof, witnessId: ids[w], witnessPrivateKey: ws[w].privateKey, ts: '2026-01-01T00:00:00.000Z' });
    assert.equal(rev.ok, false, `witness ${w} must refuse the fork at the same size`);
    if (!rev.ok) assert.match(rev.reason, /fork|different root/i);
  }
  // the fork therefore carries no valid cosignatures -> the auditor's quorum check rejects it
  const q = await verifyQuorum(evil, registry, 2);
  assert.equal(q.ok, false);
  assert.equal(q.valid, 0);
});

test('a witness refuses a rewrite of history it has already cosigned (consistency fails)', async () => {
  const { op, opPub, ws, ids, registry } = await setup();
  const real = await buildLog(10, 'real');
  const realLeaves = await Promise.all(real.map(leafHash));
  let state = freshWitnessState();

  const cp6 = await cp(real, 6, op.privateKey);
  const rev6 = await witnessReview({ state, checkpoint: cp6, operatorPubKeyHex: opPub, consistencyProofHex: proofToHex(await consistencyProof(realLeaves, 0, 6)), witnessId: ids[0], witnessPrivateKey: ws[0].privateKey, ts: '2026-01-01T00:00:00.000Z' });
  assert.ok(rev6.ok); if (rev6.ok) state = rev6.state;

  // operator rewrites the FIRST 6 records then extends to 10 — not an append-only superset of what the witness saw
  const rewritten = await buildLog(10, 'rewrite');
  const rwLeaves = await Promise.all(rewritten.map(leafHash));
  const cp10 = await cp(rewritten, 10, op.privateKey);
  const rev10 = await witnessReview({ state, checkpoint: cp10, operatorPubKeyHex: opPub, consistencyProofHex: proofToHex(await consistencyProof(rwLeaves, 6, 10)), witnessId: ids[0], witnessPrivateKey: ws[0].privateKey, ts: '2026-01-01T00:00:00.000Z' });
  assert.equal(rev10.ok, false);
  if (!rev10.ok) assert.match(rev10.reason, /consistency|append-only/i);
});

test('quorum ignores forged and unknown cosignatures', async () => {
  const { op, opPub, ws, ids, registry } = await setup();
  const log = await buildLog(5);
  const leaves = await Promise.all(log.map(leafHash));
  const checkpoint = await cp(log, 5, op.privateKey);

  // one genuine cosignature
  const rev = await witnessReview({ state: freshWitnessState(), checkpoint, operatorPubKeyHex: opPub, consistencyProofHex: proofToHex(await consistencyProof(leaves, 0, 5)), witnessId: ids[0], witnessPrivateKey: ws[0].privateKey, ts: '2026-01-01T00:00:00.000Z' });
  assert.ok(rev.ok); if (rev.ok) checkpoint.cosignatures.push(rev.cosignature);

  // a forged cosignature claiming witness-b but signed with a stranger key
  const stranger = await generateEd25519();
  const forged = await witnessReview({ state: freshWitnessState(), checkpoint, operatorPubKeyHex: opPub, consistencyProofHex: proofToHex(await consistencyProof(leaves, 0, 5)), witnessId: 'witness-b', witnessPrivateKey: stranger.privateKey, ts: '2026-01-01T00:00:00.000Z' });
  assert.ok(forged.ok); if (forged.ok) checkpoint.cosignatures.push(forged.cosignature);

  const q = await verifyQuorum(checkpoint, registry, 2);
  assert.equal(q.valid, 1, 'only the genuine cosignature counts; the forged witness-b is rejected');
  assert.equal(q.ok, false);
});
