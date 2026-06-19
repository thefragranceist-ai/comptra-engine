import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runGate, verifyChain, KeyedMutex,
  MemLedgerStore, MemCounterStore, MemPolicyStore, MemIdempotencyStore,
} from '@comptra/core';
import type { GateDeps } from '@comptra/core';
import { Policy, GateRequest } from '@comptra/schema';

function freshDeps(nowMs = Date.parse('2026-06-19T12:00:00.000Z')): GateDeps & { _policies: MemPolicyStore; _ledger: MemLedgerStore } {
  const ledger = new MemLedgerStore();
  const policies = new MemPolicyStore();
  return {
    ledger, counters: new MemCounterStore(), policies, idem: new MemIdempotencyStore(),
    mutex: new KeyedMutex(), now: () => nowMs, rail: 'simulated', _policies: policies, _ledger: ledger,
  };
}
const req = (amount: number, vendor = 'openai', idem?: string) =>
  GateRequest.parse({ agent_id: 'agent_4a9f1c', vendor: { name: vendor }, amount_minor: amount, idempotency_key: idem });

test('S8: a PASS and a BLOCK both seal into the chain; verify is intact', async () => {
  const d = freshDeps();
  await d._policies.set('t', 'agent_4a9f1c', '-', Policy.parse({ per_call_cap_minor: 5000, daily_cap_minor: 25000 }));

  const pass = await runGate(d, 't', req(4200));
  assert.equal(pass.decision.decision, 'PASS');
  assert.equal(pass.record.seq, 0);

  const block = await runGate(d, 't', req(6000));
  assert.equal(block.decision.decision, 'BLOCK');
  assert.equal(block.decision.reason_code, 'PER_CALL_CAP');
  assert.equal(block.record.seq, 1);

  const chain = await d.ledger.readChain('t|agent_4a9f1c|-');
  assert.equal(chain.length, 2);
  const v = await verifyChain(chain);
  assert.equal(v.ok, true);
});

test('S8: idempotency replay returns the same decision and writes NO second row', async () => {
  const d = freshDeps();
  await d._policies.set('t', 'agent_4a9f1c', '-', Policy.parse({ daily_cap_minor: 1_000_000 }));
  const first = await runGate(d, 't', req(1000, 'openai', 'idem-key-1'));
  const second = await runGate(d, 't', req(1000, 'openai', 'idem-key-1'));
  assert.equal(second.replayed, true);
  assert.equal(second.record.record_hash, first.record.record_hash);
  const chain = await d.ledger.readChain('t|agent_4a9f1c|-');
  assert.equal(chain.length, 1, 'replay must not double-write');
});

test('S8: budget accumulates across calls until the daily cap blocks', async () => {
  const d = freshDeps();
  await d._policies.set('t', 'agent_4a9f1c', '-', Policy.parse({ daily_cap_minor: 2500 }));
  assert.equal((await runGate(d, 't', req(1000))).decision.decision, 'PASS');
  assert.equal((await runGate(d, 't', req(1000))).decision.decision, 'PASS');
  const third = await runGate(d, 't', req(1000)); // 3000 > 2500
  assert.equal(third.decision.reason_code, 'DAILY_CAP');
});

test('S8: freeze is an instant kill-switch', async () => {
  const d = freshDeps();
  await d._policies.set('t', 'agent_4a9f1c', '-', Policy.parse({}));
  assert.equal((await runGate(d, 't', req(1))).decision.decision, 'PASS');
  await d._policies.freeze('t', 'agent_4a9f1c', '-', true);
  assert.equal((await runGate(d, 't', req(1))).decision.reason_code, 'FROZEN');
});

test('S8: 30 concurrent fires seal with monotonic seq and a verifiable chain', async () => {
  const d = freshDeps();
  await d._policies.set('t', 'agent_4a9f1c', '-', Policy.parse({ daily_cap_minor: 1_000_000_000 }));
  const outs = await Promise.all(Array.from({ length: 30 }, (_, i) => runGate(d, 't', req(100 + i))));
  const seqs = outs.map((o) => o.record.seq).sort((a, b) => a - b);
  assert.deepEqual(seqs, Array.from({ length: 30 }, (_, i) => i)); // 0..29, no gaps/dupes
  const chain = await d.ledger.readChain('t|agent_4a9f1c|-');
  const v = await verifyChain(chain);
  assert.equal(v.ok, true, 'concurrent appends must produce an intact chain');
});
