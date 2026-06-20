import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '../packages/core/src/hash.ts';
import { merkleRoot } from '../packages/core/src/merkle.ts';
import {
  inclusionProof, verifyInclusion, consistencyProof, verifyConsistency,
} from '../packages/core/src/proofs.ts';

const enc = new TextEncoder();
async function leaves(n: number): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) out.push(await sha256(enc.encode('leaf-' + i)));
  return out;
}

test('inclusion proof verifies against the independent Merkle root for every (n, m)', async () => {
  for (let n = 1; n <= 33; n++) {
    const ls = await leaves(n);
    const root = await merkleRoot(ls);
    for (let m = 0; m < n; m++) {
      const proof = await inclusionProof(ls, m);
      assert.equal(await verifyInclusion(ls[m], m, n, proof, root), true, `n=${n} m=${m} should verify`);
    }
  }
});

test('inclusion proof rejects a wrong leaf, wrong root, and a tampered path', async () => {
  const n = 21;
  const m: number = 13;
  const ls = await leaves(n);
  const root = await merkleRoot(ls);
  const proof = await inclusionProof(ls, m);
  assert.equal(await verifyInclusion(ls[m], m, n, proof, root), true);
  // wrong leaf
  assert.equal(await verifyInclusion(ls[m === 0 ? 1 : m - 1], m, n, proof, root), false);
  // wrong root
  const badRoot = await sha256(enc.encode('not-the-root'));
  assert.equal(await verifyInclusion(ls[m], m, n, proof, badRoot), false);
  // tampered path node
  const bad = proof.slice();
  bad[0] = await sha256(enc.encode('flip'));
  assert.equal(await verifyInclusion(ls[m], m, n, bad, root), false);
});

test('consistency proof verifies append-only for every (m <= n)', async () => {
  for (let n = 1; n <= 33; n++) {
    const ls = await leaves(n);
    const rootN = await merkleRoot(ls);
    for (let m = 0; m <= n; m++) {
      const rootM = await merkleRoot(ls.slice(0, m));
      const proof = await consistencyProof(ls, m, n);
      assert.equal(await verifyConsistency(m, n, proof, rootM, rootN), true, `consistency n=${n} m=${m}`);
    }
  }
});

test('SPLIT-VIEW: a witness holding tree[m] rejects a forked second tree of the same size', async () => {
  const m = 9, n = 17;
  const base = await leaves(n);                 // the honest log
  const rootM = await merkleRoot(base.slice(0, m));
  const honestRootN = await merkleRoot(base);
  const honestProof = await consistencyProof(base, m, n);
  // honest extension verifies
  assert.equal(await verifyConsistency(m, n, honestProof, rootM, honestRootN), true);

  // operator forks AFTER m: same first m leaves, different suffix => different size-n root
  const forked = base.slice(0, m);
  for (let i = m; i < n; i++) forked.push(await sha256(enc.encode('FORK-' + i)));
  const forkedRootN = await merkleRoot(forked);
  assert.notEqual(
    Buffer.from(honestRootN).toString('hex'),
    Buffer.from(forkedRootN).toString('hex'),
    'forked root must differ',
  );
  // the witness's retained rootM cannot be made consistent with the forged root:
  const forkedProof = await consistencyProof(forked, m, n);
  assert.equal(await verifyConsistency(m, n, forkedProof, rootM, forkedRootN), true);  // self-consistent fork
  assert.equal(await verifyConsistency(m, n, forkedProof, rootM, honestRootN), false); // but NOT vs the honest head
  assert.equal(await verifyConsistency(m, n, honestProof, rootM, forkedRootN), false); // and honest proof rejects the fork
});

test('consistency rejects a non-prefix (history rewrite) where the first root does not match', async () => {
  const m = 5, n = 12;
  const ls = await leaves(n);
  const rootN = await merkleRoot(ls);
  const proof = await consistencyProof(ls, m, n);
  const wrongRootM = await sha256(enc.encode('rewritten-prefix'));
  assert.equal(await verifyConsistency(m, n, proof, wrongRootM, rootN), false);
});
