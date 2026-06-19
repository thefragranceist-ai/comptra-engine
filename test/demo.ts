import { writeFileSync, mkdirSync } from 'node:fs';
import {
  runGate, verifyChain, KeyedMutex,
  MemLedgerStore, MemCounterStore, MemPolicyStore, MemIdempotencyStore,
} from '@comptra/core';
import type { GateDeps } from '@comptra/core';
import { Policy, GateRequest } from '@comptra/schema';
import { buildReport } from '../apps/api/src/report.ts';

const C = { dim: '\x1b[2m', green: '\x1b[32m', red: '\x1b[31m', amber: '\x1b[33m', bold: '\x1b[1m', reset: '\x1b[0m' };
const money = (m: number) => '$' + (m / 100).toLocaleString('en-US', { minimumFractionDigits: 2 });
const log = (s = '') => console.log(s);

async function main() {
  log(`\n${C.bold}Comptra — live demo${C.reset}  ${C.dim}(spend-control + tamper-evident audit ledger, no server, real crypto)${C.reset}\n`);

  const now = Date.parse('2026-06-19T12:00:00.000Z');
  const ledger = new MemLedgerStore();
  const policies = new MemPolicyStore();
  const deps: GateDeps = { ledger, counters: new MemCounterStore(), policies, idem: new MemIdempotencyStore(), mutex: new KeyedMutex(), now: () => now, rail: 'simulated' };

  await policies.set('t_demo', 'agent_4a9f1c', '-', Policy.parse({
    vendor_allowlist: ['openai', 'anthropic', 'aws'],
    per_call_cap_minor: 500000, daily_cap_minor: 800000, currency: 'USD',
  }));
  log(`${C.dim}policy:${C.reset} agent_4a9f1c  per-call ≤ ${money(500000)}  daily ≤ ${money(800000)}  allow [openai, anthropic, aws]\n`);

  const attempts = [
    { vendor: 'openai', amt: 80 },
    { vendor: 'anthropic', amt: 420000 },
    { vendor: 'openai', amt: 600000 }, // over per-call cap -> BLOCK
    { vendor: 'casino', amt: 100 }, // vendor not allowed -> BLOCK
    { vendor: 'aws', amt: 350000 }, // pushes daily over 800000 -> BLOCK
  ];

  log(`${C.dim} #     agent          vendor       amount        verdict       hash${C.reset}`);
  for (let i = 0; i < attempts.length; i++) {
    const a = attempts[i];
    const out = await runGate(deps, 't_demo', GateRequest.parse({ agent_id: 'agent_4a9f1c', vendor: { name: a.vendor }, amount_minor: a.amt }));
    const pass = out.decision.decision === 'PASS';
    const verdict = pass ? `${C.green}✓ SEALED${C.reset}` : `${C.red}✗ ${out.decision.reason_code}${C.reset}`;
    log(` ${String(out.record.seq).padStart(4, '0')}  agent_4a9f1c   ${a.vendor.padEnd(11)}  ${money(a.amt).padStart(11)}  ${verdict.padEnd(24)} ${C.dim}${out.record.record_hash.slice(0, 12)}…${C.reset}`);
  }

  const chain = await ledger.readChain('t_demo|agent_4a9f1c|-');
  let v = await verifyChain(chain);
  log(`\n  verify: ${v.ok ? `${C.green}✓ chain intact${C.reset} (${chain.length} records)` : `${C.red}✗ broken${C.reset}`}`);

  // ---- the proof: tamper with a sealed record, watch the chain fracture ----
  log(`\n${C.amber}  an operator quietly edits record 0001's amount from ${money(chain[1].amount_minor)} to ${money(1)}…${C.reset}`);
  const tampered = chain.map((r, i) => (i === 1 ? { ...r, amount_minor: 1 } : r));
  v = await verifyChain(tampered);
  if (!v.ok) log(`  verify: ${C.red}✗ chain broken at record ${String(v.fractureSeq).padStart(4, '0')}${C.reset}  ${C.dim}(${v.reason})${C.reset}`);
  log(`  verify(original): ${C.green}✓ still intact${C.reset}  ${C.dim}— forgery is mathematically detectable, not a matter of trust.${C.reset}`);

  // ---- the wedge artifact ----
  const report = await buildReport({ tenantId: 't_demo', agentId: 'agent_4a9f1c', customerId: '-', records: chain, pubKeyHex: 'demo', generatedAt: new Date(now).toISOString() });
  log(`\n${C.bold}  Agent Spend Audit Report${C.reset}  ${C.dim}(the export that unblocks a security review)${C.reset}`);
  log(`    records ${report.summary.records}   sealed ${C.green}${report.summary.sealed}${C.reset}   void ${C.red}${report.summary.blocked}${C.reset}   verified ${report.summary.verified ? C.green + 'true' : C.red + 'false'}${C.reset}`);
  log(`    root ${C.dim}${report.summary.root_hash?.slice(0, 24)}…${C.reset}`);

  const file = './data/demo.ledger.jsonl';
  mkdirSync('./data', { recursive: true });
  writeFileSync(file, chain.map((r) => JSON.stringify(r)).join('\n') + '\n');
  log(`\n  wrote ${file}`);
  log(`  ${C.dim}an auditor re-checks it independently with:${C.reset}  ${C.bold}npm run comptra -- verify ${file}${C.reset}\n`);
}
main().catch((e) => { console.error(e); process.exit(1); });
