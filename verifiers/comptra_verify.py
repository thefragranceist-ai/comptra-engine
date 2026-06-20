#!/usr/bin/env python3
"""
comptra_verify.py — a SECOND, independent reference verifier for the Comptra Agent Spend Audit
Report, written from the spec alone, with ZERO third-party dependencies (Python standard library
only; Ed25519 is implemented inline per RFC 8032).

This exists to prove the wire format is a real, language-independent SPEC: an auditor can verify a
report on their own machine, in a different language, without trusting Comptra's code or servers.
It re-derives byte-for-byte what packages/core does in TypeScript:

  1. RFC 8785 JCS canonicalization        4. Ed25519 checkpoint signature (RFC 8032)
  2. SHA-256 hash-chain (+ fracture loc)   5. t-of-n witness quorum (the split-view defense)
  3. RFC 9162 Merkle Tree Hash

Usage:  python comptra_verify.py <audit-report.json>
Exit:   0 = fully verified,  1 = a check failed,  2 = bad input.
"""
import sys, json, hashlib, base64

# ---------- RFC 8785 JCS (exactly matches packages/core/src/canon.ts) ----------
def _quote(s: str) -> str:
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == '\\': out.append('\\\\')
        elif c == 0x08: out.append('\\b')
        elif c == 0x09: out.append('\\t')
        elif c == 0x0a: out.append('\\n')
        elif c == 0x0c: out.append('\\f')
        elif c == 0x0d: out.append('\\r')
        elif c < 0x20: out.append('\\u%04x' % c)
        else: out.append(ch)
    out.append('"')
    return ''.join(out)

def canon(v) -> str:
    if v is None: return 'null'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v, bool): return 'true' if v else 'false'
    if isinstance(v, int): return str(v)
    if isinstance(v, float):
        if v.is_integer(): return str(int(v))
        raise ValueError('JCS: non-integer number (money must be integer minor units)')
    if isinstance(v, str): return _quote(v)
    if isinstance(v, list): return '[' + ','.join(canon(x) for x in v) + ']'
    if isinstance(v, dict):
        keys = sorted(v.keys())  # code-point order == UTF-16 code-unit order for ASCII keys
        return '{' + ','.join(_quote(k) + ':' + canon(v[k]) for k in keys) + '}'
    raise ValueError('JCS: unsupported type ' + type(v).__name__)

def cbytes(v) -> bytes: return canon(v).encode('utf-8')
def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def sha256h(b: bytes) -> str: return hashlib.sha256(b).hexdigest()

# ---------- hash chain (matches chain.ts / hash.ts) ----------
GENESIS = '0' * 64
def verify_chain(records):
    prev = GENESIS
    for i, rec in enumerate(records):
        if rec.get('seq') != i:
            return (False, i, 'seq out of order (expected %d, found %s)' % (i, rec.get('seq')))
        if rec.get('prev_hash') != prev:
            return (False, i, 'prev_hash does not link (record inserted or deleted)')
        body = {k: v for k, v in rec.items() if k != 'record_hash'}
        expected = sha256h(prev.encode('utf-8') + cbytes(body))
        if rec.get('record_hash') != expected:
            return (False, i, 'record_hash mismatch (a sealed record was altered)')
        prev = rec['record_hash']
    return (True, len(records), prev)

# ---------- RFC 9162 Merkle Tree Hash (matches merkle.ts) ----------
def leaf_hash(rec) -> bytes: return sha256(b'\x00' + cbytes(rec))
def merkle_root(leaves):
    n = len(leaves)
    if n == 0: return sha256(b'')
    if n == 1: return leaves[0]
    k = 1
    while k * 2 < n: k *= 2
    return sha256(b'\x01' + merkle_root(leaves[:k]) + merkle_root(leaves[k:]))

# ---------- Ed25519 verify, RFC 8032 reference (no dependencies) ----------
_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
def _inv(x): return pow(x, _p - 2, _p)
_d = -121665 * _inv(121666) % _p
def _add(P, Q):
    A = (P[1]-P[0]) * (Q[1]-Q[0]) % _p
    B = (P[1]+P[0]) * (Q[1]+Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B-A, D-C, D+C, B+A
    return (E*F % _p, G*H % _p, F*G % _p, E*H % _p)
def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1: Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q
def _eq(P, Q):
    return (P[0]*Q[2] - Q[0]*P[2]) % _p == 0 and (P[1]*Q[2] - Q[1]*P[2]) % _p == 0
def _recover_x(y, sign):
    if y >= _p: return None
    x2 = (y*y - 1) * _inv(_d*y*y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x*x - x2) % _p != 0: x = x * pow(2, (_p - 1) // 4, _p) % _p
    if (x*x - x2) % _p != 0: return None
    if (x & 1) != sign: x = _p - x
    return x
_gy = 4 * _inv(5) % _p
_G = (_recover_x(_gy, 0), _gy, 1, _recover_x(_gy, 0) * _gy % _p)
def _decompress(s):
    if len(s) != 32: return None
    y = int.from_bytes(s, 'little'); sign = (y >> 255) & 1; y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x*y % _p)
def ed25519_verify(public: bytes, msg: bytes, sig: bytes) -> bool:
    if len(public) != 32 or len(sig) != 64: return False
    A = _decompress(public)
    if A is None: return False
    R = _decompress(sig[:32])
    if R is None: return False
    S = int.from_bytes(sig[32:], 'little')
    if S >= _L: return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), 'little') % _L
    return _eq(_mul(S, _G), _add(R, _mul(h, A)))

# ---------- witness statement (matches witness.ts) ----------
def witness_statement(cp, witness_id) -> bytes:
    return cbytes({'kind': 'comptra.witness.cosig.v1', 'tenant_id': cp['tenant_id'],
                   'chain_key': cp['chain_key'], 'tree_size': cp['tree_size'],
                   'root_hash': cp['root_hash'], 'witness_id': witness_id})

# ---------- driver ----------
G, R, A, DIM, B = '\033[32m', '\033[31m', '\033[33m', '\033[2m', '\033[1m'; X = '\033[0m'
def main():
    try: sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception: pass
    if len(sys.argv) < 2:
        print('usage: python comptra_verify.py <audit-report.json>'); sys.exit(2)
    rep = json.load(open(sys.argv[1], encoding='utf-8'))
    records = rep.get('records', [])
    checkpoints = rep.get('checkpoints', [])
    pub_hex = rep.get('public_key', '')
    witnessing = rep.get('witnessing')
    ok = True

    res = verify_chain(records)
    if res[0]:
        print('%sOK chain intact%s  %d records  %sroot %s..%s' % (G, X, res[1], DIM, res[2][:12], X))
        print('%s  re-derived independently in Python: record_hash = SHA-256(prev_hash || JCS(record)).%s' % (DIM, X))
    else:
        ok = False
        print('%sX chain broken at record %04d%s  %s%s%s' % (R, res[1], X, DIM, res[2], X))

    if checkpoints and pub_hex:
        pub = bytes.fromhex(pub_hex)
        for cp in checkpoints:
            root = merkle_root([leaf_hash(r) for r in records[:cp['tree_size']]]).hex()
            body = {k: v for k, v in cp.items() if k not in ('signature', 'cosignatures')}
            sig_ok = (root == cp['root_hash']) and ed25519_verify(pub, cbytes(body), base64.b64decode(cp['signature']))
            if sig_ok:
                print('%sOK checkpoint%s  tree_size %d  %sEd25519 root %s.. verified%s' % (G, X, cp['tree_size'], DIM, cp['root_hash'][:12], X))
            else:
                ok = False; print('%sX checkpoint invalid%s (root or signature)' % (R, X))

            cosigs = cp.get('cosignatures', [])
            if witnessing and cosigs:
                reg = {w['witness_id']: w['public_key'] for w in witnessing['witnesses']}
                seen = set()
                for cs in cosigs:
                    if cs['witness_id'] in seen or cs['witness_id'] not in reg: continue
                    wp = bytes.fromhex(reg[cs['witness_id']])
                    if ed25519_verify(wp, witness_statement(cp, cs['witness_id']), base64.b64decode(cs['signature'])):
                        seen.add(cs['witness_id'])
                th = witnessing['threshold']
                if len(seen) >= th:
                    print('%s  OK witness quorum%s  %d/%d independent cosignatures  %s[%s]%s' % (G, X, len(seen), th, DIM, ', '.join(sorted(seen)), X))
                else:
                    ok = False; print('%s  X witness quorum NOT met%s  %s%d/%d — a fork cannot reach quorum%s' % (A, X, DIM, len(seen), th, X))

    print(('%s%s VERIFIED — no trust in Comptra required %s' % (B, G, X)) if ok else ('%s%s VERIFICATION FAILED %s' % (B, R, X)))
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
