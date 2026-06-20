#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import {
  verifyChain, verifyCheckpoint, verifyQuorum, witnessReview, freshWitnessState,
  generateEd25519, exportPublicKeyHex, exportPrivateKeyPkcs8Hex, importPrivateKey,
} from '@comptra/core';
import type { LedgerRecord, Checkpoint, WitnessRef } from '@comptra/schema';

/**
 * The standalone auditor. Re-derives the hash chain from a ledger export, verifies the Ed25519
 * signed checkpoints, AND checks the witness quorum — WITHOUT trusting (or contacting) Comptra.
 * It can also ACT as an independent witness. This is the wedge made runnable.
 *
 *   node bin/comptra.ts verify  <ledger.jsonl | audit-report.json> [--pubkey <hex>]
 *   node bin/comptra.ts witness <witness-request.json>     # cosign iff append-only-consistent
 *   node bin/comptra.ts keygen
 */

const C = { dim: '\x1b[2m', green: '\x1b[32m', red: '\x1b[31m', amber: '\x1b[33m', bold: '\x1b[1m', reset: '\x1b[0m' };
const [cmd, ...args] = process.argv.slice(2);

type Loaded = { records: LedgerRecord[]; checkpoints: Checkpoint[]; publicKey: string; witnessing?: { threshold: number; witnesses: WitnessRef[] } };
function loadFile(file: string): Loaded {
  const raw = readFileSync(file, 'utf8').trim();
  if (raw.startsWith('{') && raw.includes('"records"')) {
    const obj = JSON.parse(raw);
    return { records: obj.records ?? [], checkpoints: obj.checkpoints ?? [], publicKey: obj.public_key ?? '', witnessing: obj.witnessing };
  }
  return { records: raw.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l) as LedgerRecord), checkpoints: [], publicKey: '' };
}
const flag = (name: string) => { const i = args.indexOf('--' + name); return i >= 0 ? args[i + 1] : undefined; };

async function verify() {
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) { console.error('usage: comptra verify <ledger.jsonl | report.json> [--pubkey <hex>]'); process.exit(2); }
  const { records, checkpoints, publicKey, witnessing } = loadFile(file);
  const pub = flag('pubkey') ?? publicKey;
  let ok = true;

  const v = await verifyChain(records);
  if (v.ok) {
    console.log(`${C.green}✓ chain intact${C.reset}  ${v.size} records  ${C.dim}root ${v.head.slice(0, 12)}…${C.reset}`);
    console.log(`${C.dim}  re-derived independently: every record_hash = SHA-256(prev_hash || JCS(record)).${C.reset}`);
  } else {
    ok = false;
    console.log(`${C.red}✗ chain broken at record ${String(v.fractureSeq).padStart(4, '0')}${C.reset}  ${C.dim}${v.reason}${C.reset}`);
    console.log(`  ${C.dim}expected ${String(v.expectedHash).slice(0, 20)}…  found ${String(v.foundHash).slice(0, 20)}…${C.reset}`);
  }

  if (checkpoints.length && pub) {
    for (const cp of checkpoints) {
      const r = await verifyCheckpoint(cp, records, pub);
      if (r.ok) console.log(`${C.green}✓ checkpoint${C.reset}  tree_size ${cp.tree_size}  ${C.dim}Ed25519 root ${cp.root_hash.slice(0, 12)}… verified${C.reset}`);
      else { ok = false; console.log(`${C.red}✗ checkpoint invalid${C.reset}  ${C.dim}${r.reason}${C.reset}`); }

      // witness quorum — the split-view defense
      if (witnessing && (cp.cosignatures?.length ?? 0) > 0) {
        const q = await verifyQuorum(cp, witnessing.witnesses, witnessing.threshold);
        if (q.ok) console.log(`${C.green}  ✓ witness quorum${C.reset}  ${q.valid}/${q.threshold} independent cosignatures  ${C.dim}[${q.witnesses.join(', ')}]${C.reset}`);
        else { ok = false; console.log(`${C.amber}  ✗ witness quorum NOT met${C.reset}  ${C.dim}${q.reason} — a fork cannot reach quorum, so treat this head as unwitnessed${C.reset}`); }
      } else if (witnessing) {
        console.log(`${C.dim}  (no cosignatures on this checkpoint; quorum ${witnessing.threshold}-of-${witnessing.witnesses.length} required)${C.reset}`);
      }
    }
  } else if (checkpoints.length) {
    console.log(`${C.dim}(${checkpoints.length} signed checkpoint(s) — pass --pubkey <hex> to verify)${C.reset}`);
  }
  process.exit(ok ? 0 : 1);
}

// act as an independent witness: cosign iff the new head is an append-only extension of the prev head.
async function witness() {
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) { console.error('usage: comptra witness <request.json>'); process.exit(2); }
  const req = JSON.parse(readFileSync(file, 'utf8'));
  const state = req.prev_state ?? freshWitnessState();
  const rev = await witnessReview({
    state, checkpoint: req.checkpoint, operatorPubKeyHex: req.operator_public_key,
    consistencyProofHex: req.consistency_proof ?? [], witnessId: req.witness_id,
    witnessPrivateKey: await importPrivateKey(req.witness_private_key_pkcs8_hex),
    ts: req.ts ?? new Date().toISOString(),
  });
  if (rev.ok) {
    console.error(`${C.green}✓ cosigned${C.reset} tree_size ${req.checkpoint.tree_size} ${C.dim}as ${req.witness_id}${C.reset}`);
    console.log(JSON.stringify({ cosignature: rev.cosignature, next_state: rev.state }, null, 2));
  } else {
    console.error(`${C.red}✗ refused to cosign${C.reset}  ${C.dim}${rev.reason}${C.reset}`);
    process.exit(1);
  }
}

async function main() {
  if (cmd === 'verify') return verify();
  if (cmd === 'witness') return witness();
  if (cmd === 'keygen') {
    const kp = await generateEd25519();
    console.log(JSON.stringify({
      public_key_hex: await exportPublicKeyHex(kp.publicKey),
      private_key_pkcs8_hex: await exportPrivateKeyPkcs8Hex(kp.privateKey),
      note: 'Ed25519 key (checkpoint signer OR witness). Keep the private key OUTSIDE the ledger DB trust domain.',
    }, null, 2));
    return;
  }
  console.log(`${C.bold}comptra${C.reset} — standalone audit verifier & witness`);
  console.log(`  comptra verify  <ledger.jsonl | report.json>   re-derive the chain, verify checkpoints + witness quorum`);
  console.log(`  comptra witness <request.json>                 act as an independent witness (cosign iff append-only)`);
  console.log(`  comptra keygen                                 mint an Ed25519 key`);
}

main().catch((e) => { console.error(e); process.exit(2); });
