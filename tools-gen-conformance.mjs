// generates golden conformance vectors + a self-contained witnessed audit report
import { writeFileSync, mkdirSync } from 'node:fs';
import { sealRecord, GENESIS_HASH } from './packages/core/src/chain.ts';
import { leafHash, merkleRootHex } from './packages/core/src/merkle.ts';
import { inclusionProof, verifyInclusion, consistencyProof, proofToHex } from './packages/core/src/proofs.ts';
import { generateEd25519, exportPublicKeyHex, exportPrivateKeyPkcs8Hex, importPrivateKey } from './packages/core/src/hash.ts';
import { buildReport } from './apps/api/src/report.ts';

mkdirSync('conformance', { recursive: true });
const TS = '2026-06-20T12:00:00.000Z';
const N = 9;
const records = [];
let prev = GENESIS_HASH;
for (let i = 0; i < N; i++) {
  const r = await sealRecord(prev, i, {
    tenant_id: 'acme', chain_key: 'acme|agent_42|-', agent_id: 'agent_42', end_customer_id: '-',
    decision: i % 4 === 3 ? 'BLOCK' : 'PASS', reason_code: i % 4 === 3 ? 'PER_CALL_CAP' : 'PASS',
    vendor: { name: ['openai','anthropic','aws'][i % 3], mcc: '7372', country: 'US' },
    amount_minor: 1000 * (i + 1), approved_amount_minor: i % 4 === 3 ? null : 1000 * (i + 1),
    currency: 'USD', mandate_ref: null, idempotency_key: 'idem-' + i, rail: 'stripe-issuing', ts: TS,
  });
  records.push(r); prev = r.record_hash;
}
const leaves = await Promise.all(records.map(leafHash));
const root = await merkleRootHex(records);
const incIdx = 5, incProof = await inclusionProof(leaves, incIdx);
const m = 4, consProof = await consistencyProof(leaves, m, N);
const vectors = {
  spec: 'comptra-conformance-v1',
  note: 'Golden vectors. Any implementation that reproduces these hashes/proofs is wire-compatible.',
  records,
  record_hashes: records.map((r) => r.record_hash),
  merkle_root: root,
  inclusion: { index: incIdx, tree_size: N, leaf_hash: Buffer.from(leaves[incIdx]).toString('hex'), proof: proofToHex(incProof), root },
  consistency: { first: m, second: N, first_root: await merkleRootHex(records.slice(0, m)), second_root: root, proof: proofToHex(consProof) },
};
writeFileSync('conformance/vectors.json', JSON.stringify(vectors, null, 2));

// a fully witnessed, self-contained report
const op = await generateEd25519();
const opPub = await exportPublicKeyHex(op.publicKey);
const ws = await Promise.all([0,1,2].map(() => generateEd25519()));
const witnesses = await Promise.all(ws.map(async (w, i) => ({
  witness_id: ['witness-eu-1','witness-us-1','witness-ch-1'][i],
  privateKey: w.privateKey, publicKeyHex: await exportPublicKeyHex(w.publicKey),
})));
const report = await buildReport({
  tenantId: 'acme', agentId: 'agent_42', customerId: null, records, pubKeyHex: opPub, generatedAt: TS,
  signer: { privateKey: op.privateKey, keyId: 'op-2026-06' },
  witnessing: { threshold: 2, witnesses },
});
writeFileSync('conformance/report.json', JSON.stringify(report, null, 2));
console.log('wrote conformance/vectors.json + conformance/report.json');
console.log('records:', N, '| merkle_root:', root.slice(0,16)+'…', '| cosignatures:', report.checkpoints.at(-1).cosignatures.length);
