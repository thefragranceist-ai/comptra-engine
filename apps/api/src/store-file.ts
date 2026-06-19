import { appendFileSync, readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { GENESIS_HASH, MemIdempotencyStore } from '@comptra/core';
import type { LedgerStore, CounterStore, PolicyStore, Counters } from '@comptra/core';
import type { LedgerRecord, Policy } from '@comptra/schema';

function ensureDir(file: string) {
  const d = dirname(file);
  if (!existsSync(d)) mkdirSync(d, { recursive: true });
}

/** Append-only JSONL ledger — the canonical, auditor-readable artifact. Indexed in memory on boot. */
export class FileLedgerStore implements LedgerStore {
  private byChain = new Map<string, LedgerRecord[]>();
  private all: LedgerRecord[] = [];
  constructor(private file: string) {
    ensureDir(file);
    if (existsSync(file)) {
      for (const line of readFileSync(file, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        this.index(JSON.parse(line) as LedgerRecord);
      }
    }
  }
  private index(r: LedgerRecord) {
    const a = this.byChain.get(r.chain_key) ?? [];
    a.push(r);
    this.byChain.set(r.chain_key, a);
    this.all.push(r);
  }
  async append(rec: LedgerRecord) {
    appendFileSync(this.file, JSON.stringify(rec) + '\n');
    this.index(rec);
  }
  async head(chainKey: string) {
    const a = this.byChain.get(chainKey);
    if (!a || a.length === 0) return { seq: -1, hash: GENESIS_HASH };
    const l = a[a.length - 1];
    return { seq: l.seq, hash: l.record_hash };
  }
  async readChain(chainKey: string) { return [...(this.byChain.get(chainKey) ?? [])]; }
  async readAll() { return [...this.all]; }
}

/** Tiny JSON-file KV for the control plane (policies, counters, api keys). */
export class FileKV<T = unknown> {
  private m: Record<string, T> = {};
  constructor(private file: string) {
    ensureDir(file);
    if (existsSync(file)) { try { this.m = JSON.parse(readFileSync(file, 'utf8')); } catch { this.m = {}; } }
  }
  private save() { writeFileSync(this.file, JSON.stringify(this.m, null, 0)); }
  get(k: string): T | undefined { return this.m[k]; }
  set(k: string, v: T) { this.m[k] = v; this.save(); }
  del(k: string) { delete this.m[k]; this.save(); }
  entries(): [string, T][] { return Object.entries(this.m); }
}

export class FileCounterStore implements CounterStore {
  constructor(private kv: FileKV<Counters>) {}
  async get(k: string) { return this.kv.get(k) ?? null; }
  async set(k: string, c: Counters) { this.kv.set(k, c); }
}

export class FilePolicyStore implements PolicyStore {
  constructor(private kv: FileKV<Policy>) {}
  private key(t: string, a: string, c: string) { return `${t}|${a}|${c}`; }
  async get(t: string, a: string, c: string) {
    return this.kv.get(this.key(t, a, c)) ?? this.kv.get(this.key(t, a, '-')) ?? null;
  }
  async set(t: string, a: string, c: string, p: Policy) { this.kv.set(this.key(t, a, c), p); }
  async freeze(t: string, a: string, c: string, frozen: boolean) {
    const cur = this.kv.get(this.key(t, a, c)) ?? this.kv.get(this.key(t, a, '-'));
    if (cur) this.kv.set(this.key(t, a, c), { ...cur, frozen });
  }
}

export type ApiKeyRecord = { tenant_id: string; role: 'admin' | 'gate:decide' | 'ledger:read'; env: 'live' | 'test'; prefix: string; created_at: string };
export class KeyStore {
  constructor(private kv: FileKV<ApiKeyRecord>) {}
  byHash(hash: string) { return this.kv.get(hash) ?? null; }
  put(hash: string, rec: ApiKeyRecord) { this.kv.set(hash, rec); }
  isEmpty() { return this.kv.entries().length === 0; }
}

export { MemIdempotencyStore };
