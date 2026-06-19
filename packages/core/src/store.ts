import type { LedgerRecord, Policy, GateDecision } from '@comptra/schema';
import type { Counters } from './policy.ts';
import { GENESIS_HASH } from './hash.ts';

/**
 * Storage seams (dependency-injected). Core ships in-memory impls (used by all tests);
 * the API ships file-backed impls; a Turso/D1 impl is the deploy swap — same interface.
 */

export interface LedgerStore {
  append(rec: LedgerRecord): Promise<void>;
  head(chainKey: string): Promise<{ seq: number; hash: string }>;
  readChain(chainKey: string): Promise<LedgerRecord[]>;
  readAll(): Promise<LedgerRecord[]>;
}

export interface CounterStore {
  get(scopeKey: string): Promise<Counters | null>;
  set(scopeKey: string, c: Counters): Promise<void>;
}

export interface PolicyStore {
  get(tenantId: string, agentId: string, customerId: string): Promise<Policy | null>;
  set(tenantId: string, agentId: string, customerId: string, p: Policy): Promise<void>;
  freeze(tenantId: string, agentId: string, customerId: string, frozen: boolean): Promise<void>;
}

export type IdemRecord = { decision: GateDecision; record: LedgerRecord };
export interface IdempotencyStore {
  get(key: string): Promise<IdemRecord | null>;
  set(key: string, v: IdemRecord): Promise<void>;
}

/** Serializes async work per key so prev_hash always references the true chain head. */
export class KeyedMutex {
  private chains = new Map<string, Promise<unknown>>();
  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.chains.get(key) ?? Promise.resolve();
    const result = prev.then(fn, fn);
    this.chains.set(key, result.then(noop, noop));
    return result;
  }
}
function noop() {}

// ---------- in-memory implementations ----------
export class MemLedgerStore implements LedgerStore {
  private byChain = new Map<string, LedgerRecord[]>();
  private all: LedgerRecord[] = [];
  async append(rec: LedgerRecord) {
    const a = this.byChain.get(rec.chain_key) ?? [];
    a.push(rec);
    this.byChain.set(rec.chain_key, a);
    this.all.push(rec);
  }
  async head(chainKey: string) {
    const a = this.byChain.get(chainKey);
    if (!a || a.length === 0) return { seq: -1, hash: GENESIS_HASH };
    const last = a[a.length - 1];
    return { seq: last.seq, hash: last.record_hash };
  }
  async readChain(chainKey: string) {
    return [...(this.byChain.get(chainKey) ?? [])];
  }
  async readAll() {
    return [...this.all];
  }
}

export class MemCounterStore implements CounterStore {
  private m = new Map<string, Counters>();
  async get(k: string) { return this.m.get(k) ?? null; }
  async set(k: string, c: Counters) { this.m.set(k, c); }
}

export class MemPolicyStore implements PolicyStore {
  private m = new Map<string, Policy>();
  private key(t: string, a: string, c: string) { return `${t}|${a}|${c}`; }
  async get(t: string, a: string, c: string) {
    return this.m.get(this.key(t, a, c)) ?? this.m.get(this.key(t, a, '-')) ?? null;
  }
  async set(t: string, a: string, c: string, p: Policy) { this.m.set(this.key(t, a, c), p); }
  async freeze(t: string, a: string, c: string, frozen: boolean) {
    const cur = (await this.get(t, a, c)) as Policy | null;
    if (cur) this.m.set(this.key(t, a, c), { ...cur, frozen });
  }
}

export class MemIdempotencyStore implements IdempotencyStore {
  private m = new Map<string, IdemRecord>();
  async get(k: string) { return this.m.get(k) ?? null; }
  async set(k: string, v: IdemRecord) { this.m.set(k, v); }
}
