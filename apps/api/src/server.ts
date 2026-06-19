import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createApp, mintKey, keyHash, type Stores } from './app.ts';
import { FileLedgerStore, FileKV, FileCounterStore, FilePolicyStore, KeyStore, MemIdempotencyStore } from './store-file.ts';
import type { ApiKeyRecord } from './store-file.ts';
import { generateEd25519, exportPublicKeyHex, exportPrivateKeyPkcs8Hex } from '@comptra/core';
import type { Counters } from '@comptra/core';
import { Policy } from '@comptra/schema';

const DATA = process.env.COMPTRA_DATA ?? './data';
const PORT = Number(process.env.PORT ?? 8787);
if (!existsSync(DATA)) mkdirSync(DATA, { recursive: true });

// signing key (persisted; in prod this lives outside the DB trust domain)
const keyFile = `${DATA}/signing-key.json`;
let pubKeyHex = '';
if (existsSync(keyFile)) {
  pubKeyHex = JSON.parse(readFileSync(keyFile, 'utf8')).public_key_hex;
} else {
  const kp = await generateEd25519();
  pubKeyHex = await exportPublicKeyHex(kp.publicKey);
  writeFileSync(keyFile, JSON.stringify({ public_key_hex: pubKeyHex, private_key_pkcs8_hex: await exportPrivateKeyPkcs8Hex(kp.privateKey) }, null, 2));
}

const keys = new KeyStore(new FileKV<ApiKeyRecord>(`${DATA}/keys.json`));
const stores: Stores = {
  ledger: new FileLedgerStore(`${DATA}/comptra.ledger.jsonl`),
  counters: new FileCounterStore(new FileKV<Counters>(`${DATA}/counters.json`)),
  policies: new FilePolicyStore(new FileKV<Policy>(`${DATA}/policies.json`)),
  idem: new MemIdempotencyStore(),
  keys,
};

// first-run seed: an admin key + a demo policy, so the gate works out of the box
let seededKey: string | null = null;
if (keys.isEmpty()) {
  const raw = mintKey('test');
  keys.put(await keyHash(raw), { tenant_id: 't_demo', role: 'admin', env: 'test', prefix: raw.slice(0, 13), created_at: new Date().toISOString() });
  seededKey = raw;
  await stores.policies.set(
    't_demo',
    'agent_4a9f1c',
    '-',
    Policy.parse({
      vendor_allowlist: ['openai', 'anthropic', 'aws'],
      per_call_cap_minor: 500000, // $5,000
      daily_cap_minor: 2500000, // $25,000
      rate_limit: { capacity: 60, refill_per_sec: 1 },
      currency: 'USD',
    }),
  );
}

const app = createApp(stores, { rail: 'simulated', pubKeyHex });

// serve the static dashboard at /
app.use('/*', serveStatic({ root: './apps/dashboard' }));

serve({ fetch: app.fetch, port: PORT }, (info) => {
  console.log(`\n  Comptra API + dashboard  ->  http://localhost:${info.port}`);
  console.log(`  data dir: ${DATA}   signing pubkey: ${pubKeyHex.slice(0, 16)}…`);
  if (seededKey) {
    console.log(`\n  seeded admin API key (test mode, shown once):\n    ${seededKey}`);
    console.log(`\n  try it:`);
    console.log(`    curl -s localhost:${info.port}/v1/gate -H "Authorization: Bearer ${seededKey}" \\`);
    console.log(`      -H "Content-Type: application/json" \\`);
    console.log(`      -d '{"agent_id":"agent_4a9f1c","vendor":{"name":"openai"},"amount_minor":420000}'`);
  }
  console.log('');
});
