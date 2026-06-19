import type { LedgerRecord } from '@comptra/schema';
import { canonicalBytes } from './canon.ts';
import { chainHash, GENESIS_HASH } from './hash.ts';

/**
 * The hash-chain spine.
 *   record_hash = SHA-256( utf8(prev_hash) || JCS(record_without_record_hash) )
 * prev_hash IS inside the hash input, so insert / delete / reorder / edit all fracture.
 * genesis prev_hash = 64 zero hex chars.
 */

export type RecordDraft = Omit<LedgerRecord, 'v' | 'seq' | 'prev_hash' | 'record_hash'>;

export async function sealRecord(prevHash: string, seq: number, draft: RecordDraft): Promise<LedgerRecord> {
  const base = { v: 1 as const, seq, ...draft, prev_hash: prevHash };
  const record_hash = await chainHash(prevHash, canonicalBytes(base));
  return { ...base, record_hash };
}

function bodyOf(rec: LedgerRecord): Omit<LedgerRecord, 'record_hash'> {
  const { record_hash, ...rest } = rec;
  return rest;
}

export type VerifyResult =
  | { ok: true; size: number; head: string }
  | { ok: false; fractureSeq: number; reason: string; expectedHash: string; foundHash: string };

/** Full O(n) honest re-walk; on any divergence returns the exact first fractured seq. */
export async function verifyChain(records: LedgerRecord[]): Promise<VerifyResult> {
  let prev = GENESIS_HASH;
  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    if (rec.seq !== i) {
      return { ok: false, fractureSeq: rec.seq, reason: `seq out of order (expected ${i}, found ${rec.seq})`, expectedHash: String(i), foundHash: String(rec.seq) };
    }
    if (rec.prev_hash !== prev) {
      return { ok: false, fractureSeq: rec.seq, reason: 'prev_hash does not link to the running head (record inserted or deleted)', expectedHash: prev, foundHash: rec.prev_hash };
    }
    const expected = await chainHash(prev, canonicalBytes(bodyOf(rec)));
    if (rec.record_hash !== expected) {
      return { ok: false, fractureSeq: rec.seq, reason: 'record_hash mismatch (a sealed record was altered)', expectedHash: expected, foundHash: rec.record_hash };
    }
    prev = rec.record_hash;
  }
  return { ok: true, size: records.length, head: prev };
}

export { GENESIS_HASH };
