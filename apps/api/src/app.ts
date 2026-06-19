import { Hono } from 'hono';
import type { Context } from 'hono';
import { runGate, verifyChain, KeyedMutex, sha256Hex } from '@comptra/core';
import type { LedgerStore, CounterStore, PolicyStore, IdempotencyStore } from '@comptra/core';
import { GateRequest, Policy } from '@comptra/schema';
import type { ApiKeyRecord } from './store-file.ts';
import { buildReport } from './report.ts';

export interface KeyLookup {
  byHash(h: string): ApiKeyRecord | null;
  put(h: string, r: ApiKeyRecord): void;
}
export type Stores = {
  ledger: LedgerStore;
  counters: CounterStore;
  policies: PolicyStore;
  idem: IdempotencyStore;
  keys: KeyLookup;
};
type Vars = { tenant: string; role: string; env: string };
const enc = new TextEncoder();

function randHex(n: number): string {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
export function mintKey(env: 'live' | 'test'): string {
  return `cmp_${env}_${randHex(18)}`;
}
export async function keyHash(raw: string): Promise<string> {
  return sha256Hex(enc.encode(raw));
}

export function createApp(stores: Stores, opts: { rail?: string; now?: () => number; pubKeyHex?: string; signer?: { privateKey: CryptoKey; keyId: string } } = {}) {
  const app = new Hono<{ Variables: Vars }>();
  const now = opts.now ?? (() => Date.now());
  const deps = {
    ledger: stores.ledger, counters: stores.counters, policies: stores.policies, idem: stores.idem,
    mutex: new KeyedMutex(), now, rail: opts.rail ?? 'simulated',
  };

  const problem = (_c: Context, status: number, type: string, title: string, detail?: string, extra?: object) =>
    new Response(
      JSON.stringify({ type: `https://errors.comptra.dev/${type}`, title, status, ...(detail ? { detail } : {}), ...(extra ?? {}) }),
      { status, headers: { 'content-type': 'application/problem+json' } },
    );
  const allow = (c: Context, ...roles: string[]) => c.get('role') === 'admin' || roles.includes(c.get('role'));

  // ---- auth: Bearer cmp_* -> tenant + role (tenant NEVER trusted from the body) ----
  app.use('/v1/*', async (c, next) => {
    const m = (c.req.header('authorization') || '').match(/^Bearer\s+(cmp_(?:live|test)_[0-9a-f]+)$/);
    if (!m) return problem(c, 401, 'unauthorized', 'Missing or malformed API key (Authorization: Bearer cmp_…)');
    const key = stores.keys.byHash(await keyHash(m[1]));
    if (!key) return problem(c, 401, 'unauthorized', 'Unknown API key');
    c.set('tenant', key.tenant_id); c.set('role', key.role); c.set('env', key.env);
    await next();
  });

  // ---- the gate (hot path). A BLOCK is HTTP 200, a normal business outcome ----
  app.post('/v1/gate', async (c) => {
    if (!allow(c, 'gate:decide')) return problem(c, 403, 'forbidden', 'Key lacks gate:decide scope');
    let body: unknown;
    try { body = await c.req.json(); } catch { return problem(c, 400, 'invalid-json', 'Request body is not valid JSON'); }
    const parsed = GateRequest.safeParse(body);
    if (!parsed.success) return problem(c, 422, 'validation', 'Invalid gate request', undefined, { errors: parsed.error.issues });
    const req = parsed.data;
    const idem = c.req.header('idempotency-key');
    if (idem) req.idempotency_key = idem;
    const out = await runGate(deps, c.get('tenant'), req);
    return c.json({
      decision: out.decision.decision,
      reason_code: out.decision.reason_code,
      decision_id: 'dec_' + out.record.record_hash.slice(0, 24),
      approved_amount_minor: out.decision.approved_amount_minor,
      limit: out.decision.limit ?? null,
      observed: out.decision.observed ?? null,
      ledger_seq: out.record.seq,
      record_hash: out.record.record_hash,
      replayed: out.replayed,
    });
  });

  // ---- control plane ----
  app.post('/v1/policies', async (c) => {
    if (!allow(c, 'admin')) return problem(c, 403, 'forbidden', 'admin scope required');
    const body: any = await c.req.json().catch(() => null);
    if (!body?.agent_id) return problem(c, 422, 'validation', 'agent_id is required');
    const policy = Policy.safeParse(body);
    if (!policy.success) return problem(c, 422, 'validation', 'Invalid policy', undefined, { errors: policy.error.issues });
    const customer = body.end_customer_id ?? '-';
    await stores.policies.set(c.get('tenant'), body.agent_id, customer, policy.data);
    return c.json({ ok: true, agent_id: body.agent_id, end_customer_id: customer, policy: policy.data });
  });

  app.post('/v1/policies/:agentId/freeze', async (c) => {
    if (!allow(c, 'admin')) return problem(c, 403, 'forbidden', 'admin scope required');
    await stores.policies.freeze(c.get('tenant'), c.req.param('agentId'), c.req.query('end_customer_id') ?? '-', true);
    return c.json({ ok: true, frozen: true });
  });
  app.delete('/v1/policies/:agentId/freeze', async (c) => {
    if (!allow(c, 'admin')) return problem(c, 403, 'forbidden', 'admin scope required');
    await stores.policies.freeze(c.get('tenant'), c.req.param('agentId'), c.req.query('end_customer_id') ?? '-', false);
    return c.json({ ok: true, frozen: false });
  });

  app.get('/v1/ledger', async (c) => {
    if (!allow(c, 'ledger:read')) return problem(c, 403, 'forbidden', 'ledger:read scope required');
    const tenant = c.get('tenant'); const agent = c.req.query('agent_id'); const customer = c.req.query('end_customer_id') ?? '-';
    const records = agent
      ? await stores.ledger.readChain(`${tenant}|${agent}|${customer}`)
      : (await stores.ledger.readAll()).filter((r) => r.tenant_id === tenant);
    return c.json({ records, count: records.length });
  });

  app.get('/v1/ledger/verify', async (c) => {
    if (!allow(c, 'ledger:read')) return problem(c, 403, 'forbidden', 'ledger:read scope required');
    const tenant = c.get('tenant'); const agent = c.req.query('agent_id'); const customer = c.req.query('end_customer_id') ?? '-';
    if (!agent) return problem(c, 422, 'validation', 'agent_id is required to verify a chain');
    const v = await verifyChain(await stores.ledger.readChain(`${tenant}|${agent}|${customer}`));
    return c.json(v);
  });

  app.post('/v1/report', async (c) => {
    if (!allow(c, 'ledger:read')) return problem(c, 403, 'forbidden', 'ledger:read scope required');
    const body: any = await c.req.json().catch(() => ({}));
    const tenant = c.get('tenant'); const agent = body.agent_id; const customer = body.end_customer_id ?? '-';
    const records = agent
      ? await stores.ledger.readChain(`${tenant}|${agent}|${customer}`)
      : (await stores.ledger.readAll()).filter((r) => r.tenant_id === tenant);
    const policy = agent ? (await stores.policies.get(tenant, agent, customer)) ?? undefined : undefined;
    const report = await buildReport({ tenantId: tenant, agentId: agent ?? null, customerId: agent ? customer : null, records, policy, pubKeyHex: opts.pubKeyHex ?? '', generatedAt: new Date(now()).toISOString(), signer: opts.signer });
    return c.json(report);
  });

  app.post('/v1/keys', async (c) => {
    if (!allow(c, 'admin')) return problem(c, 403, 'forbidden', 'admin scope required');
    const body: any = await c.req.json().catch(() => ({}));
    const role = body.role ?? 'gate:decide'; const env = body.env ?? 'test';
    const raw = mintKey(env);
    stores.keys.put(await keyHash(raw), { tenant_id: c.get('tenant'), role, env, prefix: raw.slice(0, 13), created_at: new Date(now()).toISOString() });
    return c.json({ api_key: raw, role, env, note: 'shown once — store it now' }, 201);
  });

  app.get('/health', (c) => c.json({ ok: true, service: 'comptra', ts: new Date(now()).toISOString() }));
  app.onError((err, c) => problem(c, 500, 'internal', 'Internal error', String((err as Error)?.message ?? err)));
  return app;
}
