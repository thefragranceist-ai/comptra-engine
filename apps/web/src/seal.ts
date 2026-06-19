/**
 * The Comptra guilloché seal engine — a record's seal geometry is computed DETERMINISTICALLY
 * from its real SHA-256 record_hash (epitrochoid ribbon intaglio, two plates + relief). Same
 * hash -> same seal; a tampered record -> a visibly broken seal. Ported from the brand world.
 */
type Ctx = CanvasRenderingContext2D;
type SealState = 'sealed' | 'striking' | 'void' | 'broken';

export const INK = '#16140F', GREEN = '#1C7A4F', VERM = '#B23A1C', PAPER = '#EFE9DB';
const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const easeOutExpo = (x: number) => (x >= 1 ? 1 : 1 - Math.pow(2, -10 * x));
const hx = (h: string) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
function mix(a: string, b: string, t: number) {
  const pa = hx(a), pb = hx(b), h = (n: number) => Math.max(0, Math.min(255, Math.round(n))).toString(16).padStart(2, '0');
  return '#' + h(lerp(pa[0], pb[0], t)) + h(lerp(pa[1], pb[1], t)) + h(lerp(pa[2], pb[2], t));
}
export function seed(hex: string) {
  const I = (a: number, b: number) => parseInt(hex.slice(a, b), 16) || 0;
  return {
    k: 5 + (I(0, 2) % 14), rings: 7 + (I(2, 4) % 5), amp: 0.05 + (I(4, 6) / 255) * 0.11,
    phase: (I(6, 10) / 65535) * Math.PI * 2, rot: (I(10, 14) / 65535) * Math.PI * 2,
    k2: 1 + (I(14, 16) % 3), eps: 0.03 + (I(16, 18) / 255) * 0.06,
  };
}
const corrupt = (hex: string) => hex.split('').reverse().join('');

function ribbonRing(ctx: Ctx, rr: number, kk: number, ph: number, amp: number, t: number) {
  const steps = Math.max(110, Math.floor(190 * Math.min(1, t))), maxA = 2 * Math.PI * Math.min(1, t);
  const fwd: number[] = [], rev: number[] = [];
  for (let i = 0; i <= steps; i++) {
    const a = maxA * i / steps, c = Math.cos(kk * a + ph), rad = rr * (1 + amp * c), dr = -rr * amp * kk * Math.sin(kk * a + ph);
    const ca = Math.cos(a), sa = Math.sin(a), tx = dr * ca - rad * sa, ty = dr * sa + rad * ca, tl = Math.hypot(tx, ty) || 1;
    const nx = -ty / tl, ny = tx / tl, w = clamp(0.45 + 0.85 * (0.5 + 0.5 * c), 0.45, 1.3) * 0.5, px = rad * ca, py = rad * sa;
    fwd.push(px + nx * w, py + ny * w); rev.push(px - nx * w, py - ny * w);
  }
  ctx.beginPath();
  for (let i = 0; i < fwd.length; i += 2) i ? ctx.lineTo(fwd[i], fwd[i + 1]) : ctx.moveTo(fwd[0], fwd[1]);
  for (let i = rev.length - 2; i >= 0; i -= 2) ctx.lineTo(rev[i], rev[i + 1]);
  ctx.closePath();
}

function paintSeal(ctx: Ctx, R: number, hex: string, t: number, state: SealState, k: number) {
  const broken = state === 'void' || state === 'broken', s = seed(broken ? corrupt(hex) : hex), small = R < 16;
  const bloom = clamp(k / 0.17, 0, 1), setFront = clamp((k - 0.17) / 0.4, 0, 1), cool = clamp((k - 0.58) / 0.42, 0, 1);
  ctx.save(); ctx.rotate(s.rot);
  // luminous wax BODY behind the guilloche — semi-transparent so paper still breathes through the
  // open rosette while it reads as a glowing green medallion with a bright core (the WOW).
  if (state === 'sealed' && !small) {
    const wet = k < 1 ? clamp((0.17 - k) / 0.17, 0, 1) : 0;
    const bg = ctx.createRadialGradient(0, 0, 0, 0, 0, R * 1.02);
    bg.addColorStop(0, `rgba(123,255,200,${0.5 + 0.35 * wet})`);
    bg.addColorStop(0.46, 'rgba(28,122,79,0.46)');
    bg.addColorStop(0.9, 'rgba(12,51,34,0.52)');
    bg.addColorStop(1, 'rgba(22,20,15,0.58)');
    ctx.beginPath(); ctx.arc(0, 0, R * 1.02, 0, 7); ctx.fillStyle = bg; ctx.fill();
  }
  function applyFill(plateB: boolean) {
    if (plateB) { const c = mix(INK, PAPER, 0.14); ctx.fillStyle = c; ctx.strokeStyle = c; return; }
    if (state === 'sealed') {
      // static rich wax bloom; k stays a transient strike overlay (wetter core while striking)
      const core = k < 1 ? mix('#5BF2A9', '#D8FFEC', clamp((0.17 - k) / 0.17, 0, 1)) : '#5BF2A9';
      const g = ctx.createRadialGradient(0, 0, 0, 0, 0, R);
      g.addColorStop(0, core); g.addColorStop(0.55, GREEN); g.addColorStop(0.92, '#0c3322'); g.addColorStop(1, INK);
      ctx.fillStyle = g; ctx.strokeStyle = GREEN;
    } else if (broken) { ctx.fillStyle = VERM; ctx.strokeStyle = VERM; } else { ctx.fillStyle = INK; ctx.strokeStyle = INK; }
  }
  if (small) {
    applyFill(false); ctx.lineWidth = 1; ctx.globalAlpha = broken ? 0.9 : 0.95;
    for (let ring = 0; ring < s.rings; ring++) {
      const rr = R * (0.30 + 0.70 * ring / (s.rings - 1)), kk = s.k + (ring % 2 ? s.k2 : 0), ph = s.phase * (ring + 1), mA = 2 * Math.PI * Math.min(1, t);
      ctx.beginPath();
      for (let i = 0; i <= 150; i++) { const a = mA * i / 150, rad = rr * (1 + s.amp * Math.cos(kk * a + ph)); i ? ctx.lineTo(rad * Math.cos(a), rad * Math.sin(a)) : ctx.moveTo(rad * Math.cos(a), rad * Math.sin(a)); }
      ctx.stroke();
    }
    ctx.globalAlpha = 1; ctx.restore(); return;
  }
  for (const plateB of [true, false]) {
    applyFill(plateB); ctx.save(); if (plateB) ctx.translate(0.7, 0.7);
    for (let ring = 0; ring < s.rings; ring++) {
      const vg = ring / (s.rings - 1), amp = s.amp * (0.35 + 0.85 * vg), rr = R * (0.30 + 0.70 * vg), kk = s.k + (ring % 2 ? s.k2 : 0), ph = s.phase * (ring + 1);
      const a0 = clamp((t * 1.35 - ring * 0.05) * 3, 0, 1); if (a0 <= 0) continue;
      ctx.globalAlpha = (plateB ? 0.85 : (broken ? 0.92 : 1)) * a0; ribbonRing(ctx, rr, kk, ph, amp, t); ctx.fill();
    }
    ctx.restore();
  }
  if (!broken) {
    ctx.globalAlpha = 0.5;
    for (const e of [[0.5, 0.5, 'rgba(22,20,15,.12)'], [-0.5, -0.5, 'rgba(255,253,247,.5)']] as [number, number, string][]) {
      ctx.save(); ctx.translate(e[0], e[1]); ctx.fillStyle = e[2];
      for (let ring = 0; ring < s.rings; ring += 2) { const vg = ring / (s.rings - 1), amp = s.amp * (0.35 + 0.85 * vg), rr = R * (0.30 + 0.70 * vg), kk = s.k + (ring % 2 ? s.k2 : 0), ph = s.phase * (ring + 1); if ((t * 1.35 - ring * 0.05) <= 0) continue; ribbonRing(ctx, rr, kk, ph, amp, t); ctx.fill(); }
      ctx.restore();
    }
  }
  ctx.globalAlpha = 1; ctx.restore();
}

function ringBackstop(ctx: Ctx, R: number, state: SealState) {
  const broken = state === 'void' || state === 'broken', col = broken ? VERM : (state === 'sealed' ? GREEN : INK);
  ctx.save(); ctx.globalAlpha = 1; ctx.lineWidth = 1.4; ctx.strokeStyle = col; ctx.beginPath();
  if (broken) { ctx.arc(0, 0, R * 1.08, 0.5, Math.PI * 2 - 0.5); ctx.stroke(); ctx.beginPath(); ctx.lineWidth = 2; ctx.moveTo(-R * 0.82, -R * 0.82); ctx.lineTo(R * 0.82, R * 0.82); ctx.stroke(); }
  else { ctx.arc(0, 0, R * 1.08, 0, Math.PI * 2); ctx.stroke(); }
  ctx.restore();
}

export function drawSeal(ctx: Ctx, cx: number, cy: number, R: number, hex: string, opts: { t?: number; state?: SealState; k?: number; flash?: number | null } = {}) {
  let { t = 1, state = 'sealed', k = 1, flash = null } = opts;
  if (flash != null) k = clamp(1 - flash, 0, 1);
  const small = R < 16;
  ctx.save(); ctx.translate(cx, cy);
  if (state === 'sealed' && k < 1) { const press = lerp(1.06, 1.0, easeOutExpo(Math.min(k / 0.17, 1))) * (1 + 0.012 * Math.sin(clamp((k - 0.58) / 0.42, 0, 1) * Math.PI)); ctx.scale(press, press); }
  // cast shadow — the wax sits on the paper and lifts off it
  if (!small) {
    ctx.save(); ctx.translate(2, 5); ctx.scale(1, 0.84);
    const sh = ctx.createRadialGradient(0, 0, R * 0.4, 0, 0, R * 1.08);
    sh.addColorStop(0, 'rgba(22,20,15,.28)'); sh.addColorStop(0.7, 'rgba(22,20,15,.16)'); sh.addColorStop(1, 'rgba(22,20,15,0)');
    ctx.fillStyle = sh; ctx.beginPath(); ctx.arc(0, 0, R * 1.08, 0, 7); ctx.fill(); ctx.restore();
  }
  paintSeal(ctx, R, hex, t, state, k); ringBackstop(ctx, R, state);
  // specular sheen, light raking from top-left
  if (!small && state === 'sealed') {
    ctx.save(); ctx.globalCompositeOperation = 'soft-light';
    ctx.beginPath(); ctx.arc(0, 0, R * 1.06, 0, 7); ctx.clip();
    const sp = ctx.createRadialGradient(-R * 0.32, -R * 0.36, 0, -R * 0.32, -R * 0.36, R * 1.0);
    sp.addColorStop(0, 'rgba(255,253,247,.5)'); sp.addColorStop(1, 'rgba(255,253,247,0)');
    ctx.fillStyle = sp; ctx.fillRect(-R * 1.3, -R * 1.3, R * 2.6, R * 2.6); ctx.restore();
  }
  ctx.restore();
}

const RING_D = new Path2D('M8 8 H40 V19 H32 V16 H16 V32 H32 V29 H40 V40 H8 Z');
const TOOTH_D = new Path2D('M32 29 V23 L26 29 Z');
export function drawGate(ctx: Ctx, cx: number, cy: number, size: number, toothColor = GREEN, toothDY = 0, emboss = false) {
  ctx.save(); ctx.translate(cx, cy); const s = size / 48; ctx.scale(s, s); ctx.translate(-24, -24);
  if (emboss) {
    ctx.lineWidth = 1.4;
    ctx.save(); ctx.translate(-1, -1); ctx.strokeStyle = 'rgba(255,253,247,.6)'; ctx.stroke(RING_D); ctx.restore();
    ctx.save(); ctx.translate(1.4, 1.4); ctx.strokeStyle = 'rgba(22,20,15,.16)'; ctx.stroke(RING_D); ctx.restore();
  } else { ctx.fillStyle = INK; ctx.fill(RING_D); }
  ctx.save(); ctx.translate(0, toothDY || 0); ctx.fillStyle = toothColor; ctx.fill(TOOTH_D); ctx.restore();
  ctx.restore();
}
