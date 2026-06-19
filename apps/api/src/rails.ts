import { GateRequest } from '@comptra/schema';
import type { GateDecision } from '@comptra/schema';

/**
 * Rail neutrality as CODE, not slideware. The gate decides the same way regardless of where
 * the authorization originates; an adapter only translates a rail's event <-> Comptra's types.
 *
 * SimulatedRail is the default and drives every test (no credentials, never blocks runnability).
 * StripeIssuingTestRail is a fixture-tested, env-gated SKETCH of the real-time authorization
 * webhook path (test mode only, no live funds). x402 is stubbed to prove the surface generalizes
 * to stablecoin rails. Adding a rail is ~30 lines and zero changes to the engine or ledger.
 */
export interface RailAdapter {
  readonly name: string;
  parseAuthorizationRequest(rawEvent: unknown): GateRequest;
  formatDecision(decision: GateDecision): unknown;
}

export class SimulatedRail implements RailAdapter {
  readonly name = 'simulated';
  parseAuthorizationRequest(rawEvent: unknown): GateRequest {
    return GateRequest.parse(rawEvent);
  }
  formatDecision(decision: GateDecision) {
    return { approved: decision.decision === 'PASS', reason_code: decision.reason_code, approved_amount_minor: decision.approved_amount_minor };
  }
}

/**
 * Stripe Issuing — real-time authorization. Stripe POSTs an `issuing_authorization.request`
 * webhook and waits (~2s) for you to approve or decline. We read the agent identity from the
 * card metadata, gate it, and answer. Amounts arrive already in minor units.
 *
 * SHARED-RESPONSIBILITY NOTE: Comptra fails closed internally, but it cannot control Stripe's
 * 2s timeout — the issuer's own timeout fallback MUST be configured to DECLINE. Documented,
 * not silently assumed.
 */
export class StripeIssuingTestRail implements RailAdapter {
  readonly name = 'stripe-issuing-test';
  parseAuthorizationRequest(rawEvent: unknown): GateRequest {
    const ev = rawEvent as any;
    const auth = ev?.data?.object ?? ev;
    if (auth?.object !== 'issuing.authorization') throw new Error('not an issuing_authorization event');
    const md = auth.card?.metadata ?? {};
    if (!md.agent_id) throw new Error('card.metadata.agent_id is required to gate this card');
    const m = auth.merchant_data ?? {};
    return GateRequest.parse({
      agent_id: md.agent_id,
      end_customer_id: md.end_customer_id ?? '-',
      vendor: { name: (m.name ?? 'unknown').toLowerCase(), mcc: m.category_code ?? m.mcc ?? '0000', country: m.country ?? 'US' },
      amount_minor: Math.abs(auth.pending_request?.amount ?? auth.amount ?? 0),
      currency: (auth.currency ?? 'usd').toUpperCase(),
      idempotency_key: auth.id, // the authorization id is a natural idempotency key
    });
  }
  // Stripe expects { approved: boolean } on the authorization request response
  formatDecision(decision: GateDecision) {
    return { approved: decision.decision === 'PASS' };
  }
}

/** x402 (HTTP 402 stablecoin) — gate BEFORE settlement. Sketch to prove the surface generalizes. */
export class X402Rail implements RailAdapter {
  readonly name = 'x402';
  parseAuthorizationRequest(rawEvent: unknown): GateRequest {
    const r = rawEvent as any;
    return GateRequest.parse({
      agent_id: r.agent_id ?? r.payer ?? 'unknown',
      vendor: { name: (r.payTo ?? r.resource ?? 'unknown').toString().toLowerCase(), mcc: '0000', country: 'US' },
      amount_minor: Number(r.maxAmountRequired ?? r.amount ?? 0),
      currency: (r.asset ?? 'USDC').toUpperCase().slice(0, 3) || 'USD',
    });
  }
  formatDecision(decision: GateDecision) {
    return decision.decision === 'PASS' ? { settle: true } : { status: 402, error: decision.reason_code };
  }
}

export function railFor(name: string | undefined): RailAdapter {
  switch (name) {
    case 'stripe-issuing-test': return new StripeIssuingTestRail();
    case 'x402': return new X402Rail();
    default: return new SimulatedRail();
  }
}
