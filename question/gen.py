#!/usr/bin/env python3
"""Generate every Coq file for one FCIDUMP: the hash proof and the whole-file parse.

Usage: gen.py FCIDUMP PREFIX [--ints-per-chunk N]

Writes, in the current folder (old files of this PREFIX are deleted first):
  PREFIX_data_pNN.v  raw bytes packed 7 per 63-bit integer, one chunk per file, with a
                     SHA-256 lemma per full chunk
  PREFIX_data.v      data_sha256 (the bytes hash to the file's SHA-256) and I0, defined as
                     FCIDUMP.parse (FCIDUMP_lib.v) of the bytes
  PREFIX_recs_pNN.v  the integral lines that end in each chunk, as records, with one kernel check
                     that they print back to exactly the chunk's bytes and that FCIDUMP.parse
                     accepts each one
  PREFIX_recs.v      parse_B0 : FCIDUMP.parse B0 = Some {| header values; ints := entries |}
                     and I0_value, from the general theorem RECS.parse_records (FCIDUMP_parse.v)
  PREFIX_manifest.txt  source, size, SHA-256, header values, entry count, chunks, tool checksums
Accepted integral lines (spaces only, LF):  [sp]number sp i sp j sp k sp l
  number = [-]digits[.digits][(e|E)[+|-]digits]   (1-3 exponent digits), no leading zeros on the
  integer part or the indices, indices 0..255, at most 63 spaces per gap.
INTS_PER_CHUNK (default 19968) must be a multiple of 64 so full chunks are whole SHA-256 blocks.
"""
import argparse
import hashlib
import re
import struct
import sys

K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
M = 0xffffffff


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M


def compress(h, block):
    w = list(struct.unpack('>16I', block))
    for t in range(16, 64):
        s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & M)
    a, b, c, d, e, f, g, hh = h
    for t in range(64):
        t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t]) & M
        t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M
        hh, g, f, e, d, c, b, a = g, f, e, (d + t1) & M, c, b, a, (t1 + t2) & M
    return [(x + y) & M for x, y in zip(h, [a, b, c, d, e, f, g, hh])]


def nlist(xs):
    return '[' + '; '.join(str(x) for x in xs) + ']%N'


def gen_data(path, prefix, ipc, cpf):
    assert ipc % 64 == 0, 'INTS_PER_CHUNK must be a multiple of 64'
    data = open(path, 'rb').read()
    digest = hashlib.sha256(data).hexdigest()
    bpc = 7 * ipc
    chunks = [data[i:i + bpc] for i in range(0, len(data), bpc)] or [b'']
    full, tail = chunks[:-1], chunks[-1]

    # SHA-256 state before and after every full chunk, for the per-chunk lemmas.
    states = [H0]
    for c in full:
        h = states[-1]
        for j in range(0, len(c), 64):
            h = compress(h, c[j:j + 64])
        states.append(h)

    head = ('From Coq Require Import ZArith NArith List.\n'
            'From Coq Require Uint63 PArray.\n'
            'Require Import FCIDUMP_lib.\n'
            'Import ListNotations.\n\n')
    files = []
    for f0 in range(0, len(chunks), cpf):
        name = '%s_data_p%02d' % (prefix, f0 // cpf)
        out = [head]
        for k in range(f0, min(f0 + cpf, len(chunks))):
            c = chunks[k]
            ints = [int.from_bytes(c[i:i + 7].ljust(7, b'\0'), 'little') for i in range(0, len(c), 7)] or [0]
            m = 'R%04d' % k
            out.append('Module %s.\nImport Uint63 PArray.\nLocal Open Scope uint63_scope.\n' % m)
            out.append('Fixpoint fill (a : array int) (i : int) (l : list int) : array int :=\n'
                       '  match l with nil => a | x :: t => fill (a.[i <- x]) (i + 1) t end.\n')
            out.append('Definition arr : array int := Eval vm_compute in fill (PArray.make %d 0) 0 ([%s])%%uint63.\n'
                       % (len(ints), ';'.join(map(str, ints))))
            out.append('Local Close Scope uint63_scope.\n')
            out.append('Definition len : nat := %d%%nat.\nDefinition nbytes : nat := %d%%nat.\n' % (len(ints), len(c)))
            out.append('Definition bytes : list N := FCIDUMP.unpack arr len nbytes.\n')
            out.append('Lemma bytes_length : List.length bytes = nbytes.\n'
                       'Proof. apply FCIDUMP_unpack.unpack_length. vm_compute. reflexivity. Qed.\n')
            if k < len(full):
                out.append('Definition st_in : list N := %s.\nDefinition st_out : list N := %s.\n'
                           % (nlist(states[k]), nlist(states[k + 1])))
                out.append('Lemma absorb_ok : FCIDUMP.absorb st_in bytes = st_out.\n'
                           'Proof. vm_cast_no_check (eq_refl st_out). Qed.\n')
            out.append('End %s.\n\n' % m)
        open(name + '.v', 'w').write(''.join(out))
        files.append(name)

    names = ['R%04d' % k for k in range(len(chunks))]
    fulln, tailn = names[:-1], names[-1]
    top = ['From Coq Require Import ZArith QArith NArith List.\n'
           'Require Import Coq.Strings.String.\n'
           'Require Export FCIDUMP_lib.\n']
    if fulln:
        # The multi-chunk proofs below use FCIDUMP_len.len_N, len_N_ok and pad_N_ok.
        top.append('Require FCIDUMP_len.\n')
    top += ['Require Export %s.\n' % f for f in files]
    top.append('Import ListNotations.\n\n')
    top.append('Definition full : list (list N) := [%s].\n' % '; '.join(n + '.bytes' for n in fulln))
    top.append('Definition tail : list N := %s.bytes.\n' % tailn)
    top.append('Definition RAWN : list N := List.concat (List.app full [tail]).\n')
    top.append('Definition B0 : list Ascii.ascii := FCIDUMP.to_ascii RAWN.\n')
    top.append('Definition sha256_expected : String.string := "%s"%%string.\n\n' % digest)
    if fulln:
        links = []
        for i in range(len(fulln)):
            nxt = names[i + 1]
            top.append('Lemma link_%d : %s.st_out = %s.\nProof. reflexivity. Qed.\n'
                       % (i, fulln[i], (nxt + '.st_in') if i + 1 < len(fulln) else nlist(states[-1])))
            links.append('link_%d' % i)
        top.append('Lemma start : FCIDUMP.H0 = %s.st_in.\nProof. vm_compute. reflexivity. Qed.\n\n' % fulln[0])
        # Byte counts as binary numbers, one small lemma per chunk, then the total from a
        # Forall2 proof term (rewriting the counts into one large goal is very slow).
        for k, n in enumerate(names):
            top.append('Lemma blen_%d : N.of_nat (List.length %s.bytes) = %d%%N.\n'
                       'Proof. rewrite %s.bytes_length. vm_compute. reflexivity. Qed.\n' % (k, n, len(chunks[k]), n))
        fa = ('(@Forall2_nil (list N) N (fun (c : list N) (n : N) => N.of_nat (List.length c) = n))')
        for k in reversed(range(len(fulln))):
            fa = '(@Forall2_cons _ _ _ _ _ _ _ blen_%d\n  %s)' % (k, fa)
        top.append('\nLemma total : FCIDUMP_len.len_N full tail = %d%%N.\nProof.\n'
                   '  rewrite (FCIDUMP_len.len_N_spec full tail %s %d%%N\n  %s\n  blen_%d).\n'
                   '  vm_compute. reflexivity.\nQed.\n\n'
                   % (len(data), nlist([len(c) for c in full]), len(tail), fa, len(names) - 1))
        # The state after all full chunks, as one chain of the per-chunk absorb lemmas.
        term = '(FCIDUMP_len.chain_nil %s.st_out)' % fulln[-1]
        for n in reversed(fulln):
            term = '(FCIDUMP_len.chain_cons _ _ _ _ _ %s.absorb_ok\n  %s)' % (n, term)
        top.append('Lemma all_chunks : fold_left FCIDUMP.absorb full FCIDUMP.H0 = %s.st_out.\nProof.\n'
                   '  rewrite start. apply FCIDUMP_len.chain_fold.\n  exact %s.\nQed.\n\n' % (fulln[-1], term))
        top.append('Theorem data_sha256 : FCIDUMP.sha256_stream full tail = sha256_expected.\nProof.\n'
                   '  unfold FCIDUMP.sha256_stream.\n'
                   '  rewrite FCIDUMP_len.pad_N_ok, FCIDUMP_len.len_N_ok, total, all_chunks.\n'
                   '  vm_cast_no_check (eq_refl sha256_expected).\nQed.\n\n')
    else:
        top.append('Theorem data_sha256 : FCIDUMP.sha256_stream full tail = sha256_expected.\n'
                   'Proof. vm_compute. reflexivity. Qed.\n\n')
        # Single chunk: the fingerprint in the form run reports, by direct computation.
        # (Multi-chunk files need the general lemma from FCIDUMP_stream.v.)
        top.append('Theorem data_digest : FCIDUMP.sha256_hex RAWN = sha256_expected.\n'
                   'Proof. vm_compute. reflexivity. Qed.\n\n')
    # Through a helper: an inline match on FCIDUMP.parse B0 makes Coq try to simplify the
    # parse of the whole file while checking the definition (minutes and >6 GB for FeMoco).
    top.append('Definition parse_or_empty (l : list Ascii.ascii) : FCIDUMP.FCI :=\n'
               '  match FCIDUMP.parse l with Some x => x | None => FCIDUMP.empty end.\n'
               'Definition I0 : FCIDUMP.FCI := parse_or_empty B0.\n')
    open(prefix + '_data.v', 'w').write(''.join(top))
    print('wrote %d data files and %s_data.v | bytes %d | chunks %d | sha256 %s'
          % (len(files), prefix, len(data), len(chunks), digest))



LINE = re.compile(rb"^( *)(-?)(0|[1-9]\d*)(?:(\.)(\d*))?(?:([eE])([+-]?)(\d{1,3}))?"
                  rb"( +)(0|[1-9]\d*)( +)(0|[1-9]\d*)( +)(0|[1-9]\d*)( +)(0|[1-9]\d*)$")


def render(r):
    (w0, neg, ip, dot, fp, flen, ex, w1, i, w2, j, w3, k, w4, l) = r
    s = " " * w0 + ("-" if neg else "") + str(ip)
    if dot:
        s += "." + str(fp).rjust(flen, "0")
    if ex is not None:
        cap, sg, nd, v = ex
        s += ("E" if cap else "e") + {0: "", 1: "-", 2: "+"}[sg] + str(v).rjust(nd, "0")
    s += " " * w1 + str(i) + " " * w2 + str(j) + " " * w3 + str(k) + " " * w4 + str(l) + "\n"
    return s.encode()


def records(text, unchecked=False):
    out = []
    for line in text.split(b"\n")[:-1]:
        m = LINE.match(line)
        if not m:
            sys.exit("line not in the accepted format: %r" % line[:80])
        (w0, neg, ip, dot, frac, e, esg, edig, w1, i, w2, j, w3, k, w4, l) = m.groups()
        ex = None if e is None else (e == b"E", {b"": 0, b"-": 1, b"+": 2}[esg], len(edig), int(edig))
        r = (len(w0), neg == b"-", int(ip), dot is not None, int(frac) if frac else 0,
             len(frac) if frac else 0, ex, len(w1), int(i), len(w2), int(j), len(w3), int(k), len(w4), int(l))
        if dot is not None and not frac:
            sys.exit("a number ending in '.' is not supported: %r" % line[:80])
        if not (r[2] < 2 ** 20 and r[5] < 32 and r[4] < 2 ** 66 and max(r[8], r[10], r[12], r[14]) < 256
                and max(r[0], r[7], r[9], r[11], r[13]) < 64):
            sys.exit("a field is too large for the record format: %r" % line[:80])
        out.append(r)
    if b"".join(map(render, out)) != text:
        sys.exit("records do not print back to the file's bytes")
    return out


def pack(r):
    (w0, neg, ip, dot, fp, flen, ex, w1, i, w2, j, w3, k, w4, l) = r
    b = (fp >> 62) | (ip << 4) | (flen << 24) | (int(neg) << 29) | (int(dot) << 30)
    if ex is not None:
        cap, sg, nd, v = ex
        b |= (1 << 31) | (int(cap) << 32) | (sg << 33) | (nd << 35) | (v << 37)
    c = i | (j << 8) | (k << 16) | (l << 24) | (w0 << 32) | (w1 << 38) | (w2 << 44) | (w3 << 50) | (w4 << 56)
    return [fp & ((1 << 62) - 1), b, c]


def nl(bs):
    return "[" + "; ".join(str(b) for b in bs) + "]%N"



def header_fields(data, hdr_end):
    h = data[:hdr_end]
    def one(key):
        m = re.findall(key + rb"=\s*(\d+)", h)
        return int(m[0]) if m else None
    orb = re.search(rb"ORBSYM=([0-9,]*)", h)
    orb = [int(x) for x in orb.group(1).split(b",") if x] if orb else []
    return one(rb"NORB"), one(rb"NELEC"), one(rb"MS2"), orb, one(rb"ISYM")


def header_canon(n, e, m, orb, isym):
    return (" &FCI NORB=%4d,NELEC=%2d,MS2=%d,\n  ORBSYM=%s\n  ISYM=%d,\n &END\n"
            % (n, e, m, "".join("%d," % o for o in orb), isym)).encode()


def header_bounds(n, e, m, orb, isym):
    return (1 <= n <= 255 and e <= 2 * n and m <= e and (e + m) % 2 == 0 and (e + m) // 2 <= n
            and len(orb) == n and all(1 <= o <= 8 for o in orb) and 1 <= isym <= 8)


def pkey(a, b):
    return a * 256 + b if b <= a else b * 256 + a


def classify(n, r):
    i, j, k, l = r[8], r[10], r[12], r[14]
    inr = lambda a: 1 <= a <= n
    if i == j == k == l == 0:
        return 2, 0
    if inr(i) and inr(j) and k == 0 and l == 0:
        return 1, pkey(i, j)
    if inr(i) and inr(j) and inr(k) and inr(l):
        p, q = pkey(i, j), pkey(k, l)
        return 0, (p * 65536 + q if q <= p else q * 65536 + p)
    return None


def wstep(n, st, r):
    blk, last, core = st
    if core:
        return None
    c = classify(n, r)
    if c is None:
        return None
    b, key = c
    if b == 2:
        return (2, 0, True)
    if b < blk:
        return None
    if b == blk:
        return (b, key, False) if last < key else None
    return (b, key, False)


def wlit(st):
    return '(%d%%nat, %d%%N, %s)' % (st[0], st[1], 'true' if st[2] else 'false')


def gen_records(path, prefix, ipc, unchecked=False):
    data = open(path, "rb").read()
    bpc = 7 * ipc
    chunks = [data[i:i + bpc] for i in range(0, len(data), bpc)]
    hdr_end = data.index(b"\n", data.index(b"&END")) + 1
    assert hdr_end <= len(chunks[0]), "header must fit in chunk 0"
    hn, he, hm, horb, hisym = header_fields(data, hdr_end)
    if None in (hn, he, hm, hisym):
        sys.exit("header lacks NORB, NELEC, MS2 or ISYM")
    if not unchecked:
        if data[:hdr_end] != header_canon(hn, he, hm, horb, hisym):
            sys.exit("header is not in the canonical form:\n%r\nexpected\n%r" % (data[:hdr_end], header_canon(hn, he, hm, horb, hisym)))
        if not header_bounds(hn, he, hm, horb, hisym):
            sys.exit("header values violate the bounds (NORB 1..255, NELEC <= 2 NORB, MS2 <= NELEC, NELEC+MS2 even, "
                     "alpha electrons <= NORB, NORB ORBSYM entries in 1..8, ISYM in 1..8)")
    st = (0, 0, False)
    head = ('From Coq Require Import ZArith NArith List.\n'
            'From Coq Require Uint63 PArray.\n'
            'Require Import FCIDUMP_lib FCIDUMP_parse %s_data_p%%02d.\n'
            'Import ListNotations.\n\n') % prefix
    carry = b""
    names = []
    total = 0
    for k, c in enumerate(chunks):
        q, rn = "Q%04d" % k, "R%04d" % k
        if k == 0:
            hdr, text = c[:hdr_end], c[hdr_end:]
        else:
            hdr, text = None, carry + c
        last = text.rfind(b"\n") + 1
        recs = records(text[:last], unchecked)
        st_in = st
        for idx, r in enumerate(recs):
            nxt = wstep(hn, st, r) if st is not None else None
            if nxt is None and st is not None and not unchecked:
                sys.exit("entry breaks the content rules (index range, block order two-electron / one-electron / core, "
                         "strictly increasing keys, one core line last): %r" % render(r)[:80])
            st = nxt
        st_out = st if st is not None else st_in
        st = st_out if st is not None else st_in
        cin, cout = (b"" if k == 0 else carry), text[last:]
        if k == len(chunks) - 1:
            assert cout == b"", "file must end with a newline"
        ints = [x for r in recs for x in pack(r)] or [0]
        o = [head % k, 'Module %s.\nImport Uint63 PArray.\nLocal Open Scope uint63_scope.\n' % q,
             'Fixpoint fill (a : array int) (i : int) (l : list int) : array int :=\n'
             '  match l with nil => a | x :: t => fill (a.[i <- x]) (i + 1) t end.\n',
             'Definition arr : array int := Eval vm_compute in fill (PArray.make %d 0) 0 ([%s])%%uint63.\n'
             % (len(ints), ';'.join(map(str, ints))),
             'Local Close Scope uint63_scope.\n',
             'Definition n : nat := %d%%nat.\n' % len(recs),
             'Definition recs : list RECS.rec := RECS.decode arr n.\n',
             'Definition cout : list N := %s.\n' % nl(cout)]
        if k == 0:
            o.append('Definition H : list N := %s.\n' % nl(hdr))
            o.append('Lemma ok : RECS.chunk0_ok H %s.bytes cout recs = true.\n'
                     'Proof. vm_cast_no_check (eq_refl true). Qed.\n' % rn)
            o.append('Definition eq : %s.bytes = H ++ flat_map RECS.render recs ++ cout :=\n'
                     '  proj1 (RECS.chunk0_ok_spec _ _ _ _ ok).\n' % rn)
            o.append('Definition okR : forallb RECS.rec_ok recs = true := proj2 (RECS.chunk0_ok_spec _ _ _ _ ok).\n')
        else:
            o.append('Definition cin : list N := %s.\n' % nl(cin))
            o.append('Lemma ok : RECS.chunk_ok cin %s.bytes cout recs = true.\n'
                     'Proof. vm_cast_no_check (eq_refl true). Qed.\n' % rn)
            o.append('Definition eq : cin ++ %s.bytes = flat_map RECS.render recs ++ cout :=\n'
                     '  proj1 (RECS.chunk_ok_spec _ _ _ _ ok).\n' % rn)
            o.append('Definition okR : forallb RECS.rec_ok recs = true := proj2 (RECS.chunk_ok_spec _ _ _ _ ok).\n')
        o.append('Lemma wf : RECS.wrun %d (Some %s) (map RECS.ival recs) = Some %s.\n'
                 'Proof. vm_cast_no_check (eq_refl (Some %s)). Qed.\n' % (hn, wlit(st_in), wlit(st_out), wlit(st_out)))
        o.append('End %s.\n' % q)
        name = '%s_recs_p%02d' % (prefix, k)
        open(name + '.v', 'w').write(''.join(o))
        names.append(name)
        carry = cout
        total += len(recs)

    n = len(chunks)
    hv = {}
    for key in (b"NORB", b"NELEC", b"MS2"):
        m = re.search(key + rb"=\s*(\d+)", data[:hdr_end])
        hv[key] = int(m.group(1))
    qs = ['Q%04d' % k for k in range(n)]
    rs = ['R%04d' % k for k in range(n)]
    nest = lambda items, last: ''.join('(%s ++ ' % x for x in items) + last + ')' * len(items)
    t = ['From Coq Require Import ZArith NArith QArith List.\n',
         'Require Import FCIDUMP_lib FCIDUMP_parse %s_data.\n' % prefix]
    t += ['Require Import %s.\n' % x for x in names]
    t.append('Import ListNotations.\n\n')
    if n == 1:
        t.append('Definition ALL : list RECS.rec := Q0000.recs.\n\n')
        t.append('Lemma raw_records : RAWN = Q0000.H ++ flat_map RECS.render ALL.\nProof.\n'
                 '  unfold RAWN, full, tail, ALL. cbn [List.app List.concat]. rewrite app_nil_r, Q0000.eq.\n'
                 '  unfold Q0000.cout. rewrite !app_nil_r. reflexivity.\nQed.\n\n')
        t.append('Lemma all_ok : forallb RECS.rec_ok ALL = true.\nProof. exact Q0000.okR. Qed.\n\n')
    else:
        t.append('Definition RS : list RECS.rec :=\n  %s.\n' % nest([q + '.recs' for q in qs[1:]], '[]'))
        t.append('Definition ALL : list RECS.rec := Q0000.recs ++ RS.\n')
        t.append('Definition CREST : list N := List.concat [%s].\n\n' % '; '.join(r + '.bytes' for r in rs[1:]))
        t.append('Lemma raw_split : RAWN = R0000.bytes ++ CREST.\nProof. reflexivity. Qed.\n\n')
        term = 'RECS.cb_nil'
        for q in reversed(qs[1:]):
            term = '(RECS.cb_cons _ _ _ _ _ _ %s.eq\n  %s)' % (q, term)
        t.append('Lemma chain : RECS.chainB Q0001.cin [%s] RS.\nProof.\n  exact %s.\nQed.\n\n'
                 % ('; '.join(r + '.bytes' for r in rs[1:]), term))
        t.append('Lemma raw_records : RAWN = Q0000.H ++ flat_map RECS.render ALL.\nProof.\n'
                 '  exact (eq_trans raw_split (eq_trans (f_equal (fun x => x ++ CREST) Q0000.eq)\n'
                 '    (RECS.assemble Q0000.H Q0000.recs Q0000.cout CREST RS (RECS.chainB_concat _ _ _ chain)))).\n'
                 'Qed.\n\n')
        term = '(eq_refl : forallb RECS.rec_ok [] = true)'
        for q in reversed(qs):
            term = '(RECS.forallb_app_true _ _ _ %s.okR\n  %s)' % (q, term)
        t.append('Lemma all_ok : forallb RECS.rec_ok ALL = true.\nProof.\n  exact %s.\nQed.\n\n' % term)
    t.append('Lemma header : RECS.header_ok (FCIDUMP.to_ascii Q0000.H) %d %d %d = true.\n'
             'Proof. vm_compute. reflexivity. Qed.\n\n' % (hv[b"NORB"], hv[b"NELEC"], hv[b"MS2"]))
    rec = ('{| FCIDUMP.norb := %d; FCIDUMP.nelec := %d; FCIDUMP.ms2 := %d; FCIDUMP.ints := map RECS.ival ALL |}'
           % (hv[b"NORB"], hv[b"NELEC"], hv[b"MS2"]))
    t.append('Theorem parse_B0 : FCIDUMP.parse B0 = Some %s.\nProof.\n'
             '  unfold B0. rewrite raw_records. unfold FCIDUMP.to_ascii at 1. rewrite map_app.\n'
             '  change (map Ascii.ascii_of_N Q0000.H) with (FCIDUMP.to_ascii Q0000.H).\n'
             '  change (map Ascii.ascii_of_N (flat_map RECS.render ALL))\n'
             '    with (FCIDUMP.to_ascii (flat_map RECS.render ALL)).\n'
             '  rewrite RECS.map_flat_map_render.\n'
             '  apply RECS.parse_records; [exact header | exact all_ok].\nQed.\n\n' % rec)
    t.append('Theorem I0_value : I0 = %s.\nProof. unfold I0, parse_or_empty. rewrite parse_B0. reflexivity. Qed.\n' % rec)
    term = '(eq_refl : RECS.wrun %d (Some %s) (map RECS.ival []) = Some %s)' % (hn, wlit(st), wlit(st))
    if n == 1:
        term = 'Q0000.wf'
        wall = 'ALL'
    else:
        for q in reversed(qs):
            term = '(RECS.wrun_chain _ _ _ _ _ _ %s.wf\n  %s)' % (q, term)
        wall = 'ALL'
    t.append('\nLemma all_wf : RECS.wrun %d (Some (0%%nat, 0%%N, false)) (map RECS.ival %s) = Some %s.\n'
             'Proof.\n  exact %s.\nQed.\n\n' % (hn, wall, wlit(st), term))
    orb = '[%s]%%nat' % '; '.join(map(str, horb))
    t.append('(* Well-formedness, rules 4-6 of the format specification: canonical header within the bounds,\n'
             '   and the entries in three ordered blocks with exactly one core line, last. *)\n')
    t.append('Theorem I0_wellformed :\n  Q0000.H = RECS.header_canon %d %d %d %s %d /\\\n'
             '  RECS.header_bounds %d %d %d %s %d = true /\\\n'
             '  RECS.wf_ints (FCIDUMP.norb I0) (FCIDUMP.ints I0) = true.\nProof.\n'
             '  split; [vm_compute; reflexivity | split; [vm_compute; reflexivity |]].\n'
             '  rewrite I0_value. change (RECS.wf_ints %d (map RECS.ival ALL) = true).\n'
             '  unfold RECS.wf_ints. rewrite all_wf. reflexivity.\nQed.\n'
             % (hn, he, hm, orb, hisym, hn, he, hm, orb, hisym, hn))
    open('%s_recs.v' % prefix, 'w').write(''.join(t))
    print('wrote %d record files and %s_recs.v | records %d | header %r' % (n, prefix, total, hv))




def clean(prefix):
    import glob, os
    for f in glob.glob(prefix + "_data_p*.v") + glob.glob(prefix + "_recs_p*.v") + \
             [prefix + "_data.v", prefix + "_recs.v", prefix + "_manifest.txt"]:
        for ext in ("", "o", "ok", "os", ".aux", "glob"):
            g = f + ext if ext != "glob" else f[:-2] + ".glob"
            if ext == ".aux":
                g = os.path.join(os.path.dirname(f), "." + os.path.basename(f)[:-2] + ".aux")
            if os.path.exists(g):
                os.remove(g)


def sha_file(path):
    try:
        return hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError:
        return "missing"


def main():
    ap = argparse.ArgumentParser(description="Generate the Coq hash and parse proofs for an FCIDUMP.")
    ap.add_argument("fcidump")
    ap.add_argument("prefix")
    ap.add_argument("--ints-per-chunk", type=int, default=19968)
    ap.add_argument("--unchecked", action="store_true",
                    help="skip gen.py's own header and content checks (for testing that Coq rejects a bad file)")
    a = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", a.prefix):
        sys.exit("PREFIX must be letters and digits, starting with a letter (it becomes a Coq file name)")
    data = open(a.fcidump, "rb").read()
    clean(a.prefix)
    gen_data(a.fcidump, a.prefix, a.ints_per_chunk, 1)
    gen_records(a.fcidump, a.prefix, a.ints_per_chunk, a.unchecked)
    hdr_end = data.index(b"\n", data.index(b"&END")) + 1
    hv = {k: int(re.search(k.encode() + rb"\s*=\s*(\d+)", data[:hdr_end]).group(1)) for k in ("NORB", "NELEC", "MS2")}
    nints = data[hdr_end:].count(b"\n")
    here = __import__("os").path.dirname(__import__("os").path.abspath(__file__))
    tools = {f: sha_file(__import__("os").path.join(here, f)) for f in
             ("gen.py", "FCIDUMP_lib.v", "FCIDUMP_len.v", "FCIDUMP_parse.v", "run_all.sh")}
    with open("%s_manifest.txt" % a.prefix, "w") as f:
        f.write("source      %s\nbytes       %d\nsha256      %s\nNORB        %d\nNELEC       %d\n"
                "MS2         %d\nints        %d\nchunks      %d\n"
                % (a.fcidump, len(data), hashlib.sha256(data).hexdigest(), hv["NORB"], hv["NELEC"],
                   hv["MS2"], nints, max(1, -(-len(data) // (7 * a.ints_per_chunk)))))
        for name, h in tools.items():
            f.write("tool        %s  %s\n" % (h, name))
    print("wrote %s_manifest.txt" % a.prefix)


if __name__ == "__main__":
    main()
