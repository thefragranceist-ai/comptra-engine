import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, CanonError } from '@comptra/core';
import { chainHash, sha256Hex, generateEd25519, signEd25519, verifyEd25519, exportPublicKeyHex, b64encode, canonicalBytes, GENESIS_HASH } from '@comptra/core';

test('JCS sorts object keys by UTF-16 code unit', () => {
  assert.equal(canonicalize({ b: 1, a: 2, A: 3 }), '{"A":3,"a":2,"b":1}');
});

test('JCS is independent of insertion order (same bytes for re-ordered keys)', () => {
  const x = canonicalize({ seq: 0, amount_minor: 4200, vendor: { name: 'openai', mcc: '0000' } });
  const y = canonicalize({ vendor: { mcc: '0000', name: 'openai' }, amount_minor: 4200, seq: 0 });
  assert.equal(x, y);
});

test('JCS rejects floats (money must be integer minor units)', () => {
  assert.throws(() => canonicalize({ amount: 42.005 }), CanonError);
  assert.throws(() => canonicalize({ amount: NaN }), CanonError);
});

test('JCS escapes only mandatory characters, leaves unicode literal', () => {
  assert.equal(canonicalize('a"\\\n\t€'), '"a\\"\\\\\\n\\t€"');
});

test('JCS golden vector (a representative ledger record body)', () => {
  const rec = {
    v: 1, seq: 7, tenant_id: 't_demo', chain_key: 't_demo|agent_4a9f1c|-',
    agent_id: 'agent_4a9f1c', end_customer_id: '-', decision: 'PASS', reason_code: 'PASS',
    vendor: { name: 'openai', mcc: '0000', country: 'US' },
    amount_minor: 420000, approved_amount_minor: 420000, currency: 'USD',
    mandate_ref: null, idempotency_key: 'idem-1', rail: 'simulated',
    ts: '2026-06-19T12:00:00.000Z', prev_hash: GENESIS_HASH,
  };
  const out = canonicalize(rec);
  // keys must be sorted; spot-check the prefix and that no whitespace exists
  assert.ok(out.startsWith('{"agent_id":"agent_4a9f1c","amount_minor":420000,'));
  assert.ok(!/\s/.test(out));
});

test('chainHash is deterministic and 64 hex chars', async () => {
  const body = canonicalBytes({ seq: 0, x: 1 });
  const h1 = await chainHash(GENESIS_HASH, body);
  const h2 = await chainHash(GENESIS_HASH, body);
  assert.equal(h1, h2);
  assert.match(h1, /^[0-9a-f]{64}$/);
});

test('sha256Hex matches a known vector ("abc")', async () => {
  const h = await sha256Hex(new TextEncoder().encode('abc'));
  assert.equal(h, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('Ed25519 sign + verify round-trips, rejects a tampered message', async () => {
  const kp = await generateEd25519();
  const pubHex = await exportPublicKeyHex(kp.publicKey);
  const msg = new TextEncoder().encode('checkpoint:42');
  const sig = b64encode(await signEd25519(kp.privateKey, msg));
  assert.equal(await verifyEd25519(pubHex, sig, msg), true);
  assert.equal(await verifyEd25519(pubHex, sig, new TextEncoder().encode('checkpoint:43')), false);
});
