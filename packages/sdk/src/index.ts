import { verifyChain } from '@comptra/core';
import type { GateResult, AuditReport, ReasonCode, Vendor } from '@comptra/schema';

/**
 * The Comptra SDK — the 4-line drop-in:
 *
 *   import { Comptra } from 'comptra';
 *   const comptra = new Comptra({ apiKey: process.env.COMPTRA_KEY });
 *   const d = await comptra.gate({ agentId, vendor: { name: 'openai' }, amountMinor: 4200 });
 *   if (!d.allowed) refuse(d.reason);   // a BLOCK is a normal outcome, never an exception
 *
 * gate() NEVER throws on a policy denial. It throws only on transport/auth/validation/rate-limit.
 * failMode 'closed' (default): if Comptra is unreachable the call throws, so you do NOT spend.
 */

export class ComptraError extends Error {}
export class ComptraAuthError extends ComptraError { name = 'ComptraAuthError'; }
export class ComptraValidationError extends ComptraError { name = 'ComptraValidationError'; }
export class ComptraRateLimitError extends ComptraError { name = 'ComptraRateLimitError'; }
export class ComptraUnavailableError extends ComptraError { name = 'ComptraUnavailableError'; }

export type ComptraOptions = {
  apiKey: string;
  baseUrl?: string;
  failMode?: 'closed' | 'open';
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
};

export type GateInput = {
  agentId: string;
  endCustomerId?: string;
  vendor: Vendor | { name: string; mcc?: string; country?: string };
  amountMinor: number;
  currency?: string;
  mandateRef?: string | null;
  idempotencyKey?: string;
};

export class Comptra {
  private base: string;
  private f: typeof fetch;
  constructor(private opts: ComptraOptions) {
    if (!opts.apiKey) throw new ComptraValidationError('apiKey is required');
    this.base = (opts.baseUrl ?? 'http://localhost:8787').replace(/\/$/, '');
    this.f = opts.fetchImpl ?? fetch;
  }

  private headers(extra: Record<string, string> = {}) {
    return { Authorization: `Bearer ${this.opts.apiKey}`, 'Content-Type': 'application/json', ...extra };
  }

  private async call(path: string, init: RequestInit): Promise<Response> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.opts.timeoutMs ?? 4000);
    try {
      return await this.f(this.base + path, { ...init, signal: ctrl.signal });
    } finally {
      clearTimeout(t);
    }
  }

  async gate(input: GateInput): Promise<GateResult> {
    const idem = input.idempotencyKey ?? cryptoRandomId();
    const body = JSON.stringify({
      agent_id: input.agentId,
      end_customer_id: input.endCustomerId ?? '-',
      vendor: { name: input.vendor.name, mcc: (input.vendor as any).mcc ?? '0000', country: (input.vendor as any).country ?? 'US' },
      amount_minor: input.amountMinor,
      currency: input.currency ?? 'USD',
      mandate_ref: input.mandateRef ?? null,
    });
    let res: Response;
    try {
      res = await this.call('/v1/gate', { method: 'POST', headers: this.headers({ 'Idempotency-Key': idem }), body });
    } catch (e) {
      // network / timeout — honor failMode
      if ((this.opts.failMode ?? 'closed') === 'open') {
        return { allowed: true, decisionId: 'fail-open', ledgerSeq: -1, recordHash: '' };
      }
      throw new ComptraUnavailableError('Comptra unreachable (failing closed): ' + String((e as Error)?.message ?? e));
    }
    if (res.status === 401) throw new ComptraAuthError('Invalid or missing API key');
    if (res.status === 422 || res.status === 400) throw new ComptraValidationError('Invalid gate request: ' + (await res.text()));
    if (res.status === 429) throw new ComptraRateLimitError('Comptra API rate limited');
    if (!res.ok) throw new ComptraUnavailableError('Comptra API error ' + res.status);
    const j: any = await res.json();
    if (j.decision === 'PASS') {
      return { allowed: true, decisionId: j.decision_id, ledgerSeq: j.ledger_seq, recordHash: j.record_hash };
    }
    return { allowed: false, reason: j.reason_code as ReasonCode, decisionId: j.decision_id, ledgerSeq: j.ledger_seq, limit: j.limit, observed: j.observed };
  }

  async freeze(input: { agentId: string; endCustomerId?: string }): Promise<{ ok: boolean }> {
    const q = input.endCustomerId ? `?end_customer_id=${encodeURIComponent(input.endCustomerId)}` : '';
    const res = await this.call(`/v1/policies/${encodeURIComponent(input.agentId)}/freeze${q}`, { method: 'POST', headers: this.headers() });
    if (res.status === 401) throw new ComptraAuthError('Invalid API key');
    if (!res.ok) throw new ComptraUnavailableError('freeze failed ' + res.status);
    return res.json();
  }

  async report(input: { agentId?: string; endCustomerId?: string } = {}): Promise<AuditReport> {
    const res = await this.call('/v1/report', { method: 'POST', headers: this.headers(), body: JSON.stringify({ agent_id: input.agentId, end_customer_id: input.endCustomerId }) });
    if (res.status === 401) throw new ComptraAuthError('Invalid API key');
    if (!res.ok) throw new ComptraUnavailableError('report failed ' + res.status);
    return res.json();
  }

  /** Verify a report's chain LOCALLY (do not trust Comptra's "verified" flag — recompute it). */
  ledger = {
    verify: async (report: AuditReport) => {
      const v = await verifyChain(report.records);
      return v.ok
        ? ({ ok: true as const, size: report.records.length })
        : ({ ok: false as const, fractureSeq: v.fractureSeq, expectedHash: v.expectedHash, foundHash: v.foundHash, reason: v.reason });
    },
  };
}

function cryptoRandomId(): string {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  return 'idem_' + Math.random().toString(16).slice(2) + Date.now().toString(16);
}
