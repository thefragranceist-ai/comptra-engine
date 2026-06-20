import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import type { LedgerRecord, AuditReport } from '@comptra/schema';
import { merkleRootHex, leafHash, verifyChain, verifyCheckpoint, verifyQuorum } from '@comptra/core';
import { inclusionProof, verifyInclusion, consistencyProof, verifyConsistency, proofFromHex, proofToHex } from '../packages/core/src/proofs.ts';

const DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'conformance');
const vectors = JSON.parse(readFileSync(join(DIR, 'vectors.json'), 'utf8'));
const report: AuditReport = JSON.parse(readFileSync(join(DIR, 'report.json'), 'utf8'));

test('golden vectors: the implementation reproduces the published hashes + proofs (wire format is locked)', async () => {
  const records: LedgerRecord[] = vectors.records;
  // record hashes + chain
  assert.deepEqual(records.map((r) => r.record_hash), vectors.record_hashes);
  assert.ok((await verifyChain(records)).ok);
  // merkle root
  assert.equal(await merkleRootHex(records), vectors.merkle_root);
  // inclusion proof reproduces + verifies
  const leaves = await Promise.all(records.map(leafHash));
  assert.deepEqual(proofToHex(await inclusionProof(leaves, vectors.inclusion.index)), vectors.inclusion.proof);
  assert.equal(
    await verifyInclusion(leaves[vectors.inclusion.index], vectors.inclusion.index, vectors.inclusion.tree_size,
      proofFromHex(vectors.inclusion.proof), proofFromHex([vectors.inclusion.root])[0]),
    true,
  );
  // consistency proof reproduces + verifies
  const c = vectors.consistency;
  assert.deepEqual(proofToHex(await consistencyProof(leaves, c.first, c.second)), c.proof);
  assert.equal(
    await verifyConsistency(c.first, c.second, proofFromHex(c.proof), proofFromHex([c.first_root])[0], proofFromHex([c.second_root])[0]),
    true,
  );
});

test('the self-contained witnessed report verifies: chain + Ed25519 checkpoint + t-of-n witness quorum', async () => {
  assert.ok((await verifyChain(report.records)).ok, 'chain');
  const cp = report.checkpoints.at(-1)!;
  assert.ok((await verifyCheckpoint(cp, report.records, report.public_key)).ok, 'checkpoint');
  assert.ok(report.witnessing, 'report carries witnessing');
  const q = await verifyQuorum(cp, report.witnessing!.witnesses, report.witnessing!.threshold);
  assert.ok(q.ok && q.valid >= report.witnessing!.threshold, `quorum ${q.valid}/${q.threshold}`);
});

test('cross-language: the dependency-free Python reference verifier agrees byte-for-byte', async (t) => {
  let py = '';
  for (const cand of ['python', 'python3', 'py']) {
    try { execFileSync(cand, ['--version'], { stdio: 'ignore' }); py = cand; break; } catch { /* keep trying */ }
  }
  if (!py) return t.skip('python not available');
  const script = join(DIR, '..', 'verifiers', 'comptra_verify.py');
  // clean report verifies (exit 0)
  execFileSync(py, [script, join(DIR, 'report.json')], { stdio: 'ignore', env: { ...process.env, PYTHONIOENCODING: 'utf-8' } });
  // tampered report is rejected (non-zero exit)
  const tampered: AuditReport = JSON.parse(readFileSync(join(DIR, 'report.json'), 'utf8'));
  tampered.records[3].amount_minor = 7777777;
  const tmp = join(DIR, '_conformance_tampered.json');
  (await import('node:fs')).writeFileSync(tmp, JSON.stringify(tampered));
  let rejected = false;
  try { execFileSync(py, [script, tmp], { stdio: 'ignore', env: { ...process.env, PYTHONIOENCODING: 'utf-8' } }); }
  catch { rejected = true; }
  (await import('node:fs')).unlinkSync(tmp);
  assert.ok(rejected, 'Python verifier must reject the tampered report');
});
