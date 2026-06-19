#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { verifyChain, verifyCheckpoint, generateEd25519, exportPublicKeyHex, exportPrivateKeyPkcs8Hex } from '@comptra/core';
import type { LedgerRecord, Checkpoint } from '@comptra/schema';

/**
 * The standalone auditor. Re-derives the hash chain from a ledger export and localizes
 * any tamper — WITHOUT trusting (or even contacting) Comptra's servers. This IS the wedge.
 *
 *   node bin/comptra.ts verify <comptra.ledger.jsonl | audit-report.json>
 *   node bin/comptra.ts keygen
 */

const C = { dim: '\x1b[2m', green: '\x1b[32m', red: '\x1b[31m', bold: '\x1b[1m', reset: '\x1b[0m' };
const [cmd, ...args] = process.argv.slice(2);

function loadFile(file: string): { records: LedgerRecord[]; checkpoints: Checkpoint[]; publicKey: string } {
  const raw = readFileSync(file, 'utf8').trim();
  if (raw.startsWith('{') && raw.includes('"records"')) {
    const obj = JSON.parse(raw);
    return { records: obj.records ?? [], checkpoints: obj.checkpoints ?? [], publicKey: obj.public_key ?? '' };
  }
  return { records: raw.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l) as LedgerRecord), checkpoints: [], publicKey: '' };
}
function flag(name: string): string | undefined {
  const i = args.indexOf('--' + name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main() {
  if (cmd === 'verify') {
    const file = args.find((a) => !a.startsWith('--'));
    if (!file) { console.error('usage: comptra verify <ledger.jsonl | report.json> [--pubkey <hex>]'); process.exit(2); }
    const { records, checkpoints, publicKey } = loadFile(file);
    const pub = flag('pubkey') ?? publicKey;
    const v = await verifyChain(records);
    let ok = v.ok;
    if (v.ok) {
      console.log(`${C.green}✓ chain intact${C.reset}  ${v.size} records  ${C.dim}root ${v.head.slice(0, 12)}…${C.reset}`);
      console.log(`${C.dim}re-derived independently: every record_hash = SHA-256(prev_hash || JCS(record)).${C.reset}`);
    } else {
      ok = false;
      console.log(`${C.red}✗ chain broken at record ${String(v.fractureSeq).padStart(4, '0')}${C.reset}`);
      console.log(`  ${C.dim}reason:${C.reset} ${v.reason}`);
      console.log(`  ${C.dim}expected:${C.reset} ${String(v.expectedHash).slice(0, 24)}…`);
      console.log(`  ${C.dim}found:   ${C.reset} ${String(v.foundHash).slice(0, 24)}…`);
    }
    if (checkpoints.length && pub) {
      for (const cp of checkpoints) {
        const r = await verifyCheckpoint(cp, records, pub);
        if (r.ok) console.log(`${C.green}✓ checkpoint${C.reset}  tree_size ${cp.tree_size}  ${C.dim}Ed25519-signed root ${cp.root_hash.slice(0, 12)}… verified${C.reset}`);
        else { ok = false; console.log(`${C.red}✗ checkpoint invalid${C.reset}  ${C.dim}${r.reason}${C.reset}`); }
      }
    } else if (checkpoints.length) {
      console.log(`${C.dim}(${checkpoints.length} signed checkpoint(s) present — pass --pubkey <hex> to verify the signature)${C.reset}`);
    }
    process.exit(ok ? 0 : 1);
  }

  if (cmd === 'keygen') {
    const kp = await generateEd25519();
    console.log(JSON.stringify({
      public_key_hex: await exportPublicKeyHex(kp.publicKey),
      private_key_pkcs8_hex: await exportPrivateKeyPkcs8Hex(kp.privateKey),
      note: 'Ed25519 checkpoint signing key. Keep the private key OUTSIDE the ledger DB trust domain.',
    }, null, 2));
    return;
  }

  console.log(`${C.bold}comptra${C.reset} — standalone audit verifier`);
  console.log(`  comptra verify <ledger.jsonl | report.json>   re-derive the chain, localize any tamper`);
  console.log(`  comptra keygen                                mint an Ed25519 checkpoint key`);
}

main().catch((e) => { console.error(e); process.exit(2); });
