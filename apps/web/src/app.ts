import {
  decide, emptyCounters, sealRecord, verifyChain, buildCheckpoint, verifyCheckpoint,
  generateEd25519, exportPublicKeyHex, exportPrivateKeyPkcs8Hex, importPrivateKey, GENESIS_HASH,
} from '@comptra/core';
import type { Counters } from '@comptra/core';
import { Policy } from '@comptra/schema';
import type { LedgerRecord, Checkpoint } from '@comptra/schema';
import { drawSeal, drawGate, seed, INK, GREEN, VERM } from './seal.ts';

/**
 * Comptra console — runs the REAL @comptra/core in the browser (the same code the test suite and
 * the API use). Every record is sealed with genuine SHA-256 hash-chaining; checkpoints are real
 * Ed25519 signatures; verification is the real O(n) verifier. No backend, no mock.
 */

const $ = (s: string) => document.querySelector(s) as HTMLElement;
const money = (m: number) => '$' + (m / 100).toLocaleString('en-US', { minimumFractionDigits: 2 });
const short = (h: string) => h.slice(0, 6) + '…' + h.slice(-4);
const now = () => Date.now();
const RM = matchMedia('(prefers-reduced-motion:reduce)').matches;

type State = {
  agentId: string;
  policy: ReturnType<typeof Policy.parse>;
  counters: Counters;
  records: LedgerRecord[];
  checkpoint: Checkpoint | null;
  privHex: string;
  pubHex: string;
};
let S: State;
let priv: CryptoKey;
let tamperedSeq = -1;
const KEY = 'comptra.console.v1';
const TENANT = 'live';

function chainKey() { return `${TENANT}|${S.agentId}|-`; }
function save() { localStorage.setItem(KEY, JSON.stringify(S)); }

async function boot() {
  const raw = localStorage.getItem(KEY);
  if (raw) {
    S = JSON.parse(raw);
    priv = await importPrivateKey(S.privHex);
  } else {
    const kp = await generateEd25519();
    S = {
      agentId: 'agent_4a9f1c',
      policy: Policy.parse({ vendor_allowlist: ['openai', 'anthropic', 'aws'], per_call_cap_minor: 500000, daily_cap_minor: 2500000, currency: 'USD' }),
      counters: emptyCounters(now()),
      records: [],
      checkpoint: null,
      privHex: await exportPrivateKeyPkcs8Hex(kp.privateKey),
      pubHex: await exportPublicKeyHex(kp.publicKey),
    };
    priv = kp.privateKey;
    save();
  }
  hydrateUI();
  renderAll();
  paintLogo();
  if (S.records.length) drawHero(S.records[S.records.length - 1], false);
  else drawHeroEmpty();
}

// ---------- the gate (real core) ----------
async function fire() {
  const vendor = ($('#vendor') as HTMLSelectElement).value;
  const amount_minor = Math.max(0, Math.round(parseFloat(($('#amount') as HTMLInputElement).value || '0') * 100));
  const req = { agent_id: S.agentId, end_customer_id: '-', vendor: { name: vendor, mcc: '0000', country: 'US' }, amount_minor, currency: 'USD', mandate_ref: null as string | null, idempotency_key: undefined as string | undefined };
  const t = now();
  const { decision, counters } = decide(req, S.policy, S.counters, t);
  const head = S.records.length ? { seq: S.records[S.records.length - 1].seq, hash: S.records[S.records.length - 1].record_hash } : { seq: -1, hash: GENESIS_HASH };
  const rec = await sealRecord(head.hash, head.seq + 1, {
    tenant_id: TENANT, chain_key: chainKey(), agent_id: S.agentId, end_customer_id: '-',
    decision: decision.decision, reason_code: decision.reason_code, vendor: req.vendor,
    amount_minor, approved_amount_minor: decision.approved_amount_minor, currency: 'USD',
    mandate_ref: null, idempotency_key: '-', rail: 'browser', ts: new Date(t).toISOString(),
  });
  S.counters = counters; S.records.push(rec); S.checkpoint = null; save();
  renderAll();
  setVerdict(decision.decision === 'PASS'
    ? `<b class="ok">✓ SEALED</b> &nbsp;record ${String(rec.seq).padStart(4, '0')} · ${short(rec.record_hash)} · money moved`
    : `<b class="no">✗ ${decision.reason_code}</b> &nbsp;record ${String(rec.seq).padStart(4, '0')} · sealed as VOID · money did <u>not</u> move`);
  drawHero(rec, true);
}

// ---------- verify / tamper / checkpoint (real core) ----------
async function doVerify() {
  const v = await verifyChain(S.records);
  const b = $('#vbanner');
  if (v.ok) {
    b.className = 'vbanner ok';
    b.innerHTML = `✓ chain intact · ${v.size} records · root <span class="mono">${short(v.head || GENESIS_HASH)}</span>` + (S.checkpoint ? ` · checkpoint signed` : '');
    tamperedSeq = -1;
  } else {
    b.className = 'vbanner bad';
    b.innerHTML = `✗ chain broken at record <b>${String(v.fractureSeq).padStart(4, '0')}</b> — ${v.reason}`;
    tamperedSeq = v.fractureSeq;
  }
  renderRows();
}

async function doTamper() {
  const sealedIdx = S.records.findIndex((r) => r.decision === 'PASS');
  if (sealedIdx < 0) { setBanner('fire a transaction first, then tamper with it', 'bad'); return; }
  const r = S.records[sealedIdx];
  S.records[sealedIdx] = { ...r, amount_minor: 1 }; // forge the amount, keep the old sealed hash
  save();
  setBanner(`an operator just rewrote record ${String(r.seq).padStart(4, '0')} from ${money(r.amount_minor)} to ${money(1)} — now press VERIFY`, 'warn');
  renderRows();
}

async function doCheckpoint() {
  if (!S.records.length) return;
  S.checkpoint = await buildCheckpoint({ tenant_id: TENANT, chain_key: chainKey(), records: S.records, key_id: 'comptra-ed25519-1', ts: new Date(now()).toISOString(), signPrivateKey: priv });
  save();
  setBanner(`checkpoint sealed · Ed25519-signed Merkle root <span class="mono">${short(S.checkpoint.root_hash)}</span> · tree_size ${S.checkpoint.tree_size}`, 'ok');
  renderRows();
}

function buildReport() {
  return {
    report: 'comptra-agent-spend-audit', version: 1, generated_at: new Date(now()).toISOString(), tenant_id: TENANT,
    scope: { agent_id: S.agentId, end_customer_id: '-', from_ts: null, to_ts: null },
    summary: { records: S.records.length, sealed: S.records.filter((r) => r.decision === 'PASS').length, blocked: S.records.filter((r) => r.decision === 'BLOCK').length, verified: tamperedSeq < 0, root_hash: S.checkpoint?.root_hash ?? (S.records.at(-1)?.record_hash ?? null) },
    policy: S.policy, records: S.records, checkpoints: S.checkpoint ? [S.checkpoint] : [],
    public_key: S.pubHex,
    canonicalization_spec: 'RFC 8785 JCS over the full record field set excluding record_hash; integer minor units; RFC3339 UTC.',
    hashing_spec: 'record_hash = SHA-256( utf8(prev_hash) || JCS(record_without_record_hash) ); genesis = 64 zero hex.',
    merkle_spec: 'RFC 9162 domain-separated Merkle (leaf 0x00, node 0x01); checkpoints Ed25519-signed.',
    threat_model: 'Tamper-evident against edit/insert/delete/reorder given retained signed checkpoints; verify() localizes the first fractured seq. Operator split-view (witnesses) is on the roadmap.',
    standalone_verifier: 'npm run comptra -- verify <this-file>.json  (or re-import it here).',
  };
}
function downloadReport() {
  const blob = new Blob([JSON.stringify(buildReport(), null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'comptra-agent-spend-audit.json'; a.click();
}

async function reVerify(file: File) {
  const txt = await file.text();
  let obj: any; try { obj = JSON.parse(txt); } catch { setBanner('that file is not valid JSON', 'bad'); return; }
  const records: LedgerRecord[] = obj.records ?? [];
  const v = await verifyChain(records);
  let msg = v.ok ? `✓ chain intact · ${v.size} records` : `✗ chain broken at record ${v.fractureSeq} — ${v.reason}`;
  if (v.ok && obj.checkpoints?.length && obj.public_key) {
    const cp = await verifyCheckpoint(obj.checkpoints[0], records, obj.public_key);
    msg += cp.ok ? ` · ✓ Ed25519 checkpoint verified` : ` · ✗ checkpoint ${cp.reason}`;
  }
  setBanner('independent re-verification (in your browser, no server): ' + msg, v.ok ? 'ok' : 'bad');
}

function reset() {
  localStorage.removeItem(KEY);
  location.reload();
}

// ---------- rendering ----------
function hydrateUI() {
  ($('#agent') as HTMLInputElement).value = S.agentId;
  const cap = $('#cap') as HTMLInputElement;
  cap.value = String((S.policy.per_call_cap_minor ?? 500000) / 100);
  $('#capval').textContent = money(S.policy.per_call_cap_minor ?? 500000);
  ($('#daily') as HTMLInputElement).value = String((S.policy.daily_cap_minor ?? 2500000) / 100);
  renderAllowChips();
}
function renderAllowChips() {
  const wrap = $('#allow'); wrap.innerHTML = '';
  for (const v of S.policy.vendor_allowlist) {
    const c = document.createElement('span'); c.className = 'chip'; c.textContent = v;
    wrap.appendChild(c);
  }
}
function setVerdict(html: string) { $('#verdict').innerHTML = html; }
function setBanner(html: string, kind: 'ok' | 'bad' | 'warn' = 'ok') { const b = $('#vbanner'); b.className = 'vbanner ' + kind; b.innerHTML = html; }

function sealCanvas(hash: string, broken: boolean, px = 30, r = 11): HTMLCanvasElement {
  const d = Math.min(2, devicePixelRatio || 1), c = document.createElement('canvas');
  c.width = px * d; c.height = px * d; c.className = 'chip-seal';
  const x = c.getContext('2d')!; x.setTransform(d, 0, 0, d, 0, 0); x.translate(px / 2, px / 2);
  drawSeal(x, 0, 0, r, hash, { t: 1, state: broken ? 'broken' : 'sealed' });
  return c;
}

function renderRows() {
  const tb = $('#rows'); tb.innerHTML = '';
  const list = [...S.records].reverse();
  for (const r of list) {
    const tr = document.createElement('tr');
    if (r.decision !== 'PASS') tr.className = 'void';
    const broken = tamperedSeq >= 0 && r.seq >= tamperedSeq && r.decision === 'PASS';
    const seal = document.createElement('td'); seal.className = 'cseal';
    seal.appendChild(sealCanvas(r.record_hash, broken));
    const seqTd = document.createElement('td'); seqTd.className = 'mono dim'; seqTd.textContent = String(r.seq).padStart(4, '0');
    const ven = document.createElement('td'); ven.textContent = r.vendor.name;
    const amt = document.createElement('td'); amt.className = 'mono amt'; amt.textContent = money(r.amount_minor);
    const ver = document.createElement('td'); ver.innerHTML = r.decision === 'PASS' ? '<span class="ok">SEALED</span>' : `<span class="no">${r.reason_code}</span>`;
    const hsh = document.createElement('td'); hsh.className = 'mono dim hide-s'; hsh.textContent = short(r.record_hash);
    tr.append(seal, seqTd, ven, amt, ver, hsh); tb.appendChild(tr);
  }
  $('#count').textContent = `${S.records.length} record${S.records.length === 1 ? '' : 's'}`;
  $('#root').innerHTML = S.records.length ? `head <span class="mono">${short(S.records[S.records.length - 1].record_hash)}</span>` : 'no records yet';
}
function renderAll() { hydrateUI(); renderRows(); }

// ---------- hero seal (the living current record) ----------
let heroRAF = 0;
function heroCtx() {
  const c = $('#hero') as HTMLCanvasElement, d = Math.min(2, devicePixelRatio || 1), sz = 260;
  c.width = sz * d; c.height = sz * d; const x = c.getContext('2d')!; x.setTransform(d, 0, 0, d, 0, 0); return { x, sz };
}
function drawHeroEmpty() {
  const { x, sz } = heroCtx(); x.clearRect(0, 0, sz, sz);
  drawGate(x, sz / 2, sz * 0.44, 104, INK, 0, true);
  x.font = '11px "IBM Plex Mono",monospace'; x.fillStyle = 'rgba(22,20,15,.4)'; x.textAlign = 'center';
  x.fillText('awaiting first record', sz / 2, sz - 18);
}
function drawHero(rec: LedgerRecord, animate: boolean) {
  cancelAnimationFrame(heroRAF);
  const { x, sz } = heroCtx(); const cx = sz / 2, cy = sz * 0.44, R = 96;
  const pass = rec.decision === 'PASS';
  const state = pass ? 'sealed' : 'void';
  const label = () => {
    x.font = '11px "IBM Plex Mono",monospace'; x.textAlign = 'center';
    x.fillStyle = pass ? GREEN : VERM; x.fillText(short(rec.record_hash), cx, sz - 26);
    x.fillStyle = 'rgba(22,20,15,.5)'; x.fillText(`record ${String(rec.seq).padStart(4, '0')} · ${rec.vendor.name} · ${money(rec.amount_minor)}`, cx, sz - 10);
  };
  if (!animate || RM) { x.clearRect(0, 0, sz, sz); drawSeal(x, cx, cy, R, rec.record_hash, { t: 1, state }); label(); return; }
  const t0 = performance.now();
  const frame = (n: number) => {
    const e = (n - t0) / 1000; // engrave 0..0.8s, strike 0.8..1.15s
    const t = Math.min(1, e / 0.8);
    const k = e <= 0.8 ? 1 : Math.min(1, (e - 0.8) / 0.35);
    x.clearRect(0, 0, sz, sz);
    drawSeal(x, cx, cy, R, rec.record_hash, { t, state: pass ? (t < 1 ? 'striking' : 'sealed') : 'void', k: pass ? k : 1 });
    if (t >= 1) label();
    if (e < 1.2) heroRAF = requestAnimationFrame(frame);
  };
  heroRAF = requestAnimationFrame(frame);
}

function paintLogo() {
  const c = $('#logo') as HTMLCanvasElement; if (!c) return;
  const d = Math.min(2, devicePixelRatio || 1); c.width = 30 * d; c.height = 30 * d;
  const x = c.getContext('2d')!; x.setTransform(d, 0, 0, d, 0, 0); drawGate(x, 15, 15, 26, GREEN, 0, false);
}

// ---------- wire ----------
function wire() {
  $('#fire').addEventListener('click', () => fire());
  $('#amount').addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Enter') fire(); });
  $('#verify').addEventListener('click', () => doVerify());
  $('#tamper').addEventListener('click', () => doTamper());
  $('#seal').addEventListener('click', () => doCheckpoint());
  $('#report').addEventListener('click', () => downloadReport());
  $('#reset').addEventListener('click', () => reset());
  const cap = $('#cap') as HTMLInputElement;
  cap.addEventListener('input', () => {
    S.policy.per_call_cap_minor = Math.round(parseFloat(cap.value) * 100);
    $('#capval').textContent = money(S.policy.per_call_cap_minor); save();
  });
  ($('#daily') as HTMLInputElement).addEventListener('change', (e) => {
    S.policy.daily_cap_minor = Math.round(parseFloat((e.target as HTMLInputElement).value || '0') * 100); save();
  });
  ($('#agent') as HTMLInputElement).addEventListener('change', (e) => { S.agentId = (e.target as HTMLInputElement).value || 'agent_4a9f1c'; save(); renderRows(); });
  const rv = $('#reverify') as HTMLInputElement;
  rv.addEventListener('change', () => { if (rv.files?.[0]) reVerify(rv.files[0]); });
}

wire();
boot();
