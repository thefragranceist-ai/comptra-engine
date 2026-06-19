import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SimulatedRail, StripeIssuingTestRail, X402Rail, railFor } from '../apps/api/src/rails.ts';

// a recorded Stripe issuing_authorization.request webhook (test mode shape)
const STRIPE_EVENT = {
  type: 'issuing_authorization.request',
  data: {
    object: {
      id: 'iauth_test_123',
      object: 'issuing.authorization',
      amount: 420000,
      currency: 'usd',
      pending_request: { amount: 420000, currency: 'usd' },
      merchant_data: { name: 'OPENAI', category_code: '5734', country: 'US' },
      card: { metadata: { agent_id: 'agent_4a9f1c', end_customer_id: 'cust_42' } },
    },
  },
};

test('S12: Stripe adapter maps the webhook to a GateRequest (identity from card metadata)', () => {
  const req = new StripeIssuingTestRail().parseAuthorizationRequest(STRIPE_EVENT);
  assert.equal(req.agent_id, 'agent_4a9f1c');
  assert.equal(req.end_customer_id, 'cust_42');
  assert.equal(req.vendor.name, 'openai');
  assert.equal(req.vendor.mcc, '5734');
  assert.equal(req.amount_minor, 420000);
  assert.equal(req.currency, 'USD');
  assert.equal(req.idempotency_key, 'iauth_test_123'); // authorization id => idempotent
});

test('S12: Stripe adapter formats a decision as { approved } and rejects non-issuing events', () => {
  const rail = new StripeIssuingTestRail();
  assert.deepEqual(rail.formatDecision({ decision: 'PASS', reason_code: 'PASS', approved_amount_minor: 1 }), { approved: true });
  assert.deepEqual(rail.formatDecision({ decision: 'BLOCK', reason_code: 'PER_CALL_CAP', approved_amount_minor: null }), { approved: false });
  assert.throws(() => rail.parseAuthorizationRequest({ type: 'charge.succeeded', data: { object: { object: 'charge' } } }));
});

test('S12: a card with no agent_id is rejected (cannot gate an unidentified card)', () => {
  const bad = { data: { object: { object: 'issuing.authorization', amount: 1, currency: 'usd', merchant_data: {}, card: { metadata: {} } } } };
  assert.throws(() => new StripeIssuingTestRail().parseAuthorizationRequest(bad), /agent_id/);
});

test('S12: x402 adapter maps a 402 payload and gates before settle', () => {
  const req = new X402Rail().parseAuthorizationRequest({ agent_id: 'agent_x', payTo: 'api.weather.example', maxAmountRequired: 250, asset: 'USDC' });
  assert.equal(req.agent_id, 'agent_x');
  assert.equal(req.amount_minor, 250);
  assert.equal(req.vendor.name, 'api.weather.example');
});

test('S12: SimulatedRail is the default and round-trips a GateRequest', () => {
  assert.equal(railFor(undefined).name, 'simulated');
  assert.equal(railFor('stripe-issuing-test').name, 'stripe-issuing-test');
  const req = new SimulatedRail().parseAuthorizationRequest({ agent_id: 'a', vendor: { name: 'openai' }, amount_minor: 10 });
  assert.equal(req.amount_minor, 10);
});
