#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { verifyChain, generateEd25519, exportPublicKeyHex, exportPrivateKeyPkcs8Hex } from '@comptra/core';
import type { LedgerRecord } from '@comptra/schema';

/**
 * The standalone auditor. Re-derives the hash chain from a ledger export and localizes
 * any tamper — WITHOUT trusting (or even contacting) Comptra's servers. This IS the wedge.
 *
 *   node bin/comptra.ts verify <comptra.ledger.jsonl | audit-report.json>
 *   node bin/comptra.ts keygen
 */

const C = { dim: '\x1b[2m', green: '\x1b[32m', red: '\x1b[31m', bold: '\x1b[1m', reset: '\x1b[0m' };
const [cmd, ...args] = process.argv.slice(2);

function loadRecords(file: string): LedgerRecord[] {
  const raw = readFileSync(file, 'utf8').trim();
  // an audit report (single JSON object with .records) or a JSONL ledger
  if (raw.startsWith('{') && raw.includes('"records"')) {
    const obj = JSON.parse(raw);
    if (Array.isArray(obj.records)) return obj.records as LedgerRecord[];
  }
  return raw.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l) as LedgerRecord);
}

async function main() {
  if (cmd === 'verify') {
    const file = args[0];
    if (!file) { console.error('usage: comptra verify <ledger.jsonl | report.json>'); process.exit(2); }
    const records = loadRecords(file);
    const v = await verifyChain(records);
    if (v.ok) {
      console.log(`${C.green}✓ chain intact${C.reset}  ${v.size} records  ${C.dim}root ${v.head.slice(0, 12)}…${C.reset}`);
      console.log(`${C.dim}re-derived independently: every record_hash = SHA-256(prev_hash || JCS(record)).${C.reset}`);
      process.exit(0);
    }
    console.log(`${C.red}✗ chain broken at record ${String(v.fractureSeq).padStart(4, '0')}${C.reset}`);
    console.log(`  ${C.dim}reason:${C.reset} ${v.reason}`);
    console.log(`  ${C.dim}expected:${C.reset} ${String(v.expectedHash).slice(0, 24)}…`);
    console.log(`  ${C.dim}found:   ${C.reset} ${String(v.foundHash).slice(0, 24)}…`);
    process.exit(1);
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
