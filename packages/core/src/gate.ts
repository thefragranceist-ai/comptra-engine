import { Policy } from '@comptra/schema';
import type { GateRequest, GateDecision, LedgerRecord } from '@comptra/schema';
import { decide, emptyCounters } from './policy.ts';
import { sealRecord } from './chain.ts';
import type { LedgerStore, CounterStore, PolicyStore, IdempotencyStore, KeyedMutex } from './store.ts';

/**
 * The Gate orchestrator — the one place where a decision becomes a sealed, chained record.
 * Per-chain serialized (prev_hash never raced). Idempotent (a replay returns the cached
 * decision with NO second ledger row). EVERY attempt is recorded (PASS and BLOCK) — an audit
 * ledger that omits denials is not an audit ledger; budget is only consumed on PASS.
 */

export type GateDeps = {
  ledger: LedgerStore;
  counters: CounterStore;
  policies: PolicyStore;
  idem: IdempotencyStore;
  mutex: KeyedMutex;
  now: () => number;
  rail?: string;
};

export type GateOutcome = { decision: GateDecision; record: LedgerRecord; replayed: boolean };

export async function runGate(deps: GateDeps, tenantId: string, req: GateRequest): Promise<GateOutcome> {
  const chainKey = `${tenantId}|${req.agent_id}|${req.end_customer_id}`;
  return deps.mutex.run(chainKey, async () => {
    const idemKey = req.idempotency_key ? `${tenantId}:${req.idempotency_key}` : null;
    if (idemKey) {
      const cached = await deps.idem.get(idemKey);
      if (cached) return { decision: cached.decision, record: cached.record, replayed: true };
    }

    const now = deps.now();
    const policy: Policy = (await deps.policies.get(tenantId, req.agent_id, req.end_customer_id)) ?? Policy.parse({});
    const counters = (await deps.counters.get(chainKey)) ?? emptyCounters(now, policy.rate_limit?.capacity ?? 0);

    const { decision, counters: next } = decide(req, policy, counters, now);

    const head = await deps.ledger.head(chainKey);
    const record = await sealRecord(head.hash, head.seq + 1, {
      tenant_id: tenantId,
      chain_key: chainKey,
      agent_id: req.agent_id,
      end_customer_id: req.end_customer_id,
      decision: decision.decision,
      reason_code: decision.reason_code,
      vendor: req.vendor,
      amount_minor: req.amount_minor,
      approved_amount_minor: decision.approved_amount_minor,
      currency: req.currency,
      mandate_ref: req.mandate_ref,
      idempotency_key: req.idempotency_key ?? '-',
      rail: deps.rail ?? 'simulated',
      ts: new Date(now).toISOString(),
    });

    await deps.ledger.append(record);
    await deps.counters.set(chainKey, next);

    const out: GateOutcome = { decision, record, replayed: false };
    if (idemKey) await deps.idem.set(idemKey, { decision, record });
    return out;
  });
}
