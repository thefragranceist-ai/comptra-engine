/**
 * Cloudflare Workers entry — SKETCH.
 *
 * The SAME Hono app object that runs on Node runs here unchanged; only the entry and the store
 * bindings differ. This sketch uses the in-memory stores (state is per-isolate, i.e. ephemeral),
 * so it is a runnable demo, not durable. For production, swap Mem* for D1 / Durable Object stores
 * behind the existing LedgerStore / CounterStore / PolicyStore interfaces — the Durable Object's
 * single-writer-per-object model makes hash-chain serialization a free platform property.
 *
 * Secrets (wrangler): COMPTRA_ADMIN_KEY (raw), COMPTRA_SIGNING_KEY_PKCS8_HEX (Ed25519 private).
 */
import { createApp, keyHash, type Stores, type KeyLookup } from './app.ts';
import type { ApiKeyRecord } from './store-file.ts';
import { MemLedgerStore, MemCounterStore, MemPolicyStore, MemIdempotencyStore, importPrivateKey } from '@comptra/core';
import { Policy } from '@comptra/schema';

type Env = { COMPTRA_ADMIN_KEY?: string; COMPTRA_SIGNING_KEY_PKCS8_HEX?: string };

class MemKeys implements KeyLookup {
  private m = new Map<string, ApiKeyRecord>();
  byHash(h: string) { return this.m.get(h) ?? null; }
  put(h: string, r: ApiKeyRecord) { this.m.set(h, r); }
}

let appPromise: Promise<ReturnType<typeof createApp>> | null = null;

async function build(env: Env) {
  const keys = new MemKeys();
  if (env.COMPTRA_ADMIN_KEY) {
    keys.put(await keyHash(env.COMPTRA_ADMIN_KEY), { tenant_id: 't_demo', role: 'admin', env: 'test', prefix: env.COMPTRA_ADMIN_KEY.slice(0, 13), created_at: '1970-01-01T00:00:00.000Z' });
  }
  const stores: Stores = { ledger: new MemLedgerStore(), counters: new MemCounterStore(), policies: new MemPolicyStore(), idem: new MemIdempotencyStore(), keys };
  await stores.policies.set('t_demo', 'agent_4a9f1c', '-', Policy.parse({ vendor_allowlist: ['openai', 'anthropic', 'aws'], per_call_cap_minor: 500000, daily_cap_minor: 2500000 }));

  let signer: { privateKey: CryptoKey; keyId: string } | undefined;
  if (env.COMPTRA_SIGNING_KEY_PKCS8_HEX) {
    signer = { privateKey: await importPrivateKey(env.COMPTRA_SIGNING_KEY_PKCS8_HEX), keyId: 'comptra-ed25519-1' };
  }
  return createApp(stores, { rail: 'simulated', signer });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    appPromise ??= build(env);
    const app = await appPromise;
    return app.fetch(req);
  },
};
