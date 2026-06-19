import { test } from 'node:test';
import assert from 'node:assert/strict';
import { merkleRootHex, buildCheckpoint, verifyCheckpoint, generateEd25519, exportPublicKeyHex, sealRecord, GENESIS_HASH } from '@comptra/core';
import type { LedgerRecord, RecordDraft } from '@comptra/core';

function draft(seq: number, amount: number): RecordDraft {
  return {
    tenant_id: 't', chain_key: 't|a|-', agent_id: 'a', end_customer_id: '-',
    decision: 'PASS', reason_code: 'PASS', vendor: { name: 'openai', mcc: '0000', country: 'US' },
    amount_minor: amount, approved_amount_minor: amount, currency: 'USD', mandate_ref: null,
    idempotency_key: 'i' + seq, rail: 'simulated', ts: '2026-06-19T12:00:0' + (seq % 10) + '.000Z',
  };
}
async function chain(n: number): Promise<LedgerRecord[]> {
  const recs: LedgerRecord[] = [];
  let prev = GENESIS_HASH;
  for (let i = 0; i < n; i++) { const r = await sealRecord(prev, i, draft(i, (i + 1) * 1000)); recs.push(r); prev = r.record_hash; }
  return recs;
}

test('S4: Merkle root is stable, order-sensitive, and 64 hex', async () => {
  const c = await chain(5);
  const r1 = await merkleRootHex(c);
  assert.match(r1, /^[0-9a-f]{64}$/);
  assert.equal(await merkleRootHex(c), r1);
  assert.notEqual(await merkleRootHex([c[1], c[0], c[2], c[3], c[4]]), r1);
});

test('S4: Merkle root changes if any record changes', async () => {
  const c = await chain(5);
  const r1 = await merkleRootHex(c);
  const t = c.map((x, i) => (i === 2 ? { ...x, amount_minor: 999_999 } : x));
  assert.notEqual(await merkleRootHex(t), r1);
});

test('S4: a signed checkpoint verifies and catches a tampered record + a flipped signature', async () => {
  const c = await chain(6);
  const kp = await generateEd25519();
  const pub = await exportPublicKeyHex(kp.publicKey);
  const cp = await buildCheckpoint({ tenant_id: 't', chain_key: 't|a|-', records: c, key_id: 'k1', ts: '2026-06-19T12:00:00.000Z', signPrivateKey: kp.privateKey });

  assert.equal((await verifyCheckpoint(cp, c, pub)).ok, true);

  const tampered = c.map((x, i) => (i === 3 ? { ...x, amount_minor: 1 } : x));
  const r = await verifyCheckpoint(cp, tampered, pub);
  assert.equal(r.ok, false);
  assert.match(r.reason ?? '', /Merkle root/);

  const badSig = { ...cp, signature: cp.signature.slice(0, -3) + (cp.signature.endsWith('AAA') ? 'BBB' : 'AAA') };
  assert.equal((await verifyCheckpoint(badSig, c, pub)).ok, false);
});

test('S4: a checkpoint does not verify under a different public key (operator cannot forge anchors)', async () => {
  const c = await chain(4);
  const kp = await generateEd25519();
  const other = await generateEd25519();
  const cp = await buildCheckpoint({ tenant_id: 't', chain_key: 't|a|-', records: c, key_id: 'k1', ts: '2026-06-19T12:00:00.000Z', signPrivateKey: kp.privateKey });
  assert.equal((await verifyCheckpoint(cp, c, await exportPublicKeyHex(other.publicKey))).ok, false);
  assert.equal((await verifyCheckpoint(cp, c, await exportPublicKeyHex(kp.publicKey))).ok, true);
});
