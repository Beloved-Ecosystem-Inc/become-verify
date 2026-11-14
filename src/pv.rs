// Decoding and acceptance of the 200 public-value bytes of BECOME's main_xc program. Pure: no proof, no I/O.
//
// Layout: 25 words of 8 little-endian bytes each:
//   word  0  v      upper-bound verdict (1 on accept)
//   word  1  u      upper bound (signed, x 1e-12 hartree; 0 in a completion proof)
//   word  2  norb   word 3  nelec
//   words 4..11  D0..D7  SHA-256 of the FCIDUMP: D_i holds digest bytes 4i..4i+3 big-endian (D_i < 2^32)
//   word 12  lv     lower-bound verdict (1 on accept)
//   word 13  l      lower bound (signed, x 1e-12 hartree; 0 in a completion proof)
//   word 14  md     mode: 0 = final proof (bounds in clear), 1 = completion proof (bounds hidden)
//   word 15  t      accuracy level of the proof (signed, x 1e-12 hartree)
//   word 16  ac     accept bit, computed by the program: v == 1, lv == 1, l <= u, 0 <= t, u - l <= t
//   words 17..24  C0..C7  commitment to (l, u, r): Poseidon2 over the KoalaBear field, each word < p
// An accepted proof certifies, by BECOME's Coq proof, that the bounds hold for the file whose SHA-256 is D.

pub const PV_WORDS: usize = 25;
pub const PV_BYTES: usize = 8 * PV_WORDS; // 200
/// KoalaBear prime p = 2^31 - 2^24 + 1; every C_i is a field element.
pub const KOALABEAR_P: u64 = 2130706433;
/// mode word values
pub const MODE_FULL: u64 = 0;
pub const MODE_COMPLETION: u64 = 1;

/// The decoded public values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pv {
    pub v: u64,
    pub u: i64,
    pub norb: u64,
    pub nelec: u64,
    pub d: [u64; 8],
    pub lv: u64,
    pub l: i64,
    pub md: u64,
    pub t: i64,
    pub ac: u64,
    pub c: [u64; 8],
}

/// sdec: two's-complement i64 view of a u64 (z < 2^63 ? z : z - 2^64).
pub fn sdec(z: u64) -> i64 { z as i64 }

/// decode_pvc: exactly 200 bytes, 25 little-endian u64 words; u, l and t signed. Nothing is checked here
/// beyond the length; the field checks are in `accept`.
pub fn decode_pvc(bs: &[u8]) -> Result<Pv, String> {
    if bs.len() != PV_BYTES {
        return Err(format!("public values: {} bytes, expected {} (25 words; the 112-byte 14-word and the 96-byte hi-only layouts are retired)", bs.len(), PV_BYTES));
    }
    let w = |i: usize| u64::from_le_bytes(bs[8 * i..8 * i + 8].try_into().unwrap());
    let mut d = [0u64; 8];
    for i in 0..8 { d[i] = w(4 + i); }
    let mut c = [0u64; 8];
    for i in 0..8 { c[i] = w(17 + i); }
    Ok(Pv { v: w(0), u: sdec(w(1)), norb: w(2), nelec: w(3), d, lv: w(12), l: sdec(w(13)),
            md: w(14), t: sdec(w(15)), ac: w(16), c })
}

/// D0..D7 -> the 32 digest bytes: D_i must be < 2^32 (else Err; a larger word is rejected, never truncated), and bytes
/// 4i..4i+3 are D_i big-endian.
pub fn digest_of_d(d: &[u64; 8]) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    for (i, x) in d.iter().enumerate() {
        if *x >= 1u64 << 32 { return Err(format!("digest word D{} >= 2^32", i)); }
        out[4 * i..4 * i + 4].copy_from_slice(&(*x as u32).to_be_bytes());
    }
    Ok(out)
}

/// C0..C7 must each be a KoalaBear field element (< P).
pub fn check_c(c: &[u64; 8]) -> Result<(), String> {
    for (i, x) in c.iter().enumerate() {
        if *x >= KOALABEAR_P { return Err(format!("commitment word C{} >= KoalaBear P", i)); }
    }
    Ok(())
}

/// The commitment C printed as 8 x 8 hex digits (each C_i < 2^31 fits 32 bits), so completion proofs can be matched
/// with the full proofs published later.
pub fn c_hex(c: &[u64; 8]) -> String { c.iter().map(|x| format!("{:08x}", x)).collect() }

/// The question the proof is checked against: norb, nelec and sha256 of the data (FCIDUMP) file bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question { pub norb: u64, pub nelec: u64, pub digest: [u8; 32] }

/// acc_met: 1 iff l <= u /\ 0 <= t /\ u - l <= t (exact integer arithmetic; i128 so u - l cannot overflow).
pub fn acc_met(u: i64, l: i64, t: i64) -> bool {
    l <= u && 0 <= t && (u as i128 - l as i128) <= t as i128
}

/// What an accepted proof certifies: the run holds bounds (l, u) with ClaimX b target l u for
/// the data D and C = Poseidon2(l, u, r0).  In mode 0 `u`, `l` are those bounds; in mode 1 they are 0 (hidden) and only
/// `c` speaks for them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted { pub md: u64, pub target: i64, pub u: i64, pub l: i64, pub d: [u64; 8], pub c: [u64; 8] }

/// The acceptance decision on decoded public values for one proof. Every rejection names its
/// reason; the order is fixed so that the first failing check is reported. `mode` is the expected mode (0 or 1) and
/// `target` the requested level x_i (non-negative; parse_target).
pub fn accept(pv: &Pv, q: &Question, mode: u64, target: i64) -> Result<Accepted, String> {
    if pv.ac != 1 { return Err(format!("accept bit ac = {} (the program did not accept)", pv.ac)); }
    if pv.v == 0 { return Err("hi verdict v = 0 (hi checker rejected)".into()); }
    if pv.lv == 0 { return Err("lo verdict lv = 0 (lo checker rejected)".into()); }
    if pv.md != MODE_FULL && pv.md != MODE_COMPLETION { return Err(format!("mode word md = {} is neither 0 nor 1", pv.md)); }
    if mode != MODE_FULL && mode != MODE_COMPLETION { return Err(format!("expected mode {} is neither 0 nor 1", mode)); }
    if pv.md != mode { return Err(format!("mode md = {} != expected mode {}", pv.md, mode)); }
    if target < 0 { return Err("precision target < 0".into()); }
    if pv.t < 0 { return Err("committed precision target t < 0".into()); }
    if pv.t != target { return Err(format!("committed precision target t = {} != requested level {}", pv.t, target)); }
    if pv.norb != q.norb { return Err("norb does not match the question".into()); }
    if pv.nelec != q.nelec { return Err("nelec does not match the question".into()); }
    let dg = digest_of_d(&pv.d)?;
    if dg != q.digest { return Err("D0..D7 != sha256 of the data file".into()); }
    check_c(&pv.c)?;
    if pv.md == MODE_FULL {
        // mode 0: the public u, l are the run's bounds; the accept bit must agree with acc_met recomputed on them
        if pv.l > pv.u { return Err("l > u (inconsistent bounds)".into()); }
        if !acc_met(pv.u, pv.l, pv.t) { return Err("u - l > precision target (claimed precision not met)".into()); }
    } else {
        // mode 1: the bounds are hidden, the program wrote 0 in both words
        if pv.u != 0 || pv.l != 0 { return Err("completion proof (mode 1) with nonzero u or l".into()); }
    }
    Ok(Accepted { md: pv.md, target, u: pv.u, l: pv.l, d: pv.d, c: pv.c })
}

/// decode + accept on the raw public-value bytes.
#[cfg(test)] // used only by the tests below; the checks go through accept()
pub fn check_pub(bs: &[u8], q: &Question, mode: u64, target: i64) -> Result<(Pv, Accepted), String> {
    let pv = decode_pvc(bs)?;
    let a = accept(&pv, q, mode, target)?;
    Ok((pv, a))
}

/// The set rule: every accepted proof of the set shares one D and one C (the host's tie between the
/// hidden bounds of a completion proof and the bounds revealed by the full proof with the same C; collision resistance
/// of Poseidon2 on cm_input is the cryptographic assumption behind it).  Returns the levels that are "revealed": the
/// targets with an accepted mode-1 proof AND an accepted mode-0 proof; a mode-1 level without its mode-0 proof is
/// not an error (it is still pending), a mode-0 proof without a mode-1 proof is listed too (it reveals on its own).
pub fn check_set(set: &[Accepted]) -> Result<Vec<i64>, String> {
    let first = set.first().ok_or("empty proof set")?;
    for (i, a) in set.iter().enumerate() {
        if a.d != first.d { return Err(format!("proof {} has a different D (another data file) than proof 0", i)); }
        if a.c != first.c { return Err(format!("proof {} has a different commitment C than proof 0 (not the same (l, u, r0))", i)); }
    }
    let mut revealed: Vec<i64> = set.iter().filter(|a| a.md == MODE_FULL).map(|a| a.target).collect();
    revealed.sort_unstable();
    revealed.dedup();
    Ok(revealed)
}

/// Levels with an accepted completion proof whose full proof is missing from the set (pending, not revealed).
#[cfg(test)] // used only by the tests below; the checks go through accept()
pub fn pending_levels(set: &[Accepted]) -> Vec<i64> {
    let mut p: Vec<i64> = set.iter().filter(|a| a.md == MODE_COMPLETION)
        .filter(|a| !set.iter().any(|b| b.md == MODE_FULL && b.target == a.target)).map(|a| a.target).collect();
    p.sort_unstable();
    p.dedup();
    p
}

/// The precision target t (x 1e-12 hartree): a plain non-negative decimal that fits an i64 (it is compared as a signed
/// word).
pub fn parse_target(s: &str) -> Result<i64, String> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) { return Err(format!("target {:?} is not a non-negative decimal", s)); }
    s.parse::<i64>().map_err(|_| format!("target {:?} does not fit a signed 64-bit word", s))
}

/// The mode: "0" / "full" or "1" / "completion".
#[cfg(test)] // used only by the tests below; the checks go through accept()
pub fn parse_mode(s: &str) -> Result<u64, String> {
    match s {
        "0" | "full" => Ok(MODE_FULL),
        "1" | "completion" => Ok(MODE_COMPLETION),
        _ => Err(format!("mode {:?} must be 0|full or 1|completion", s)),
    }
}

/// Raw little-endian bytes of a word list, as the image reads hints 2 and 3 (8 bytes per word, no length prefix).

pub fn hex32(b: &[u8; 32]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

/// Human-readable decoded fields (one line per field), for the verifier's output.  C is printed in hex so a completion
/// proof can be matched to the full proof published later.
#[cfg(test)] // used only by the tests below; the checks go through accept()
pub fn describe(pv: &Pv) -> String {
    let d = match digest_of_d(&pv.d) { Ok(dg) => hex32(&dg), Err(e) => format!("INVALID ({})", e) };
    let c = match check_c(&pv.c) { Ok(()) => c_hex(&pv.c), Err(e) => format!("INVALID ({})", e) };
    let mode = match pv.md { 0 => "0 (full proof: u, l in clear)", 1 => "1 (completion proof: u, l hidden)", _ => "INVALID" };
    format!(
        "decoded public values (25 words, 200 bytes):\n  v (hi verdict)  = {}\n  u (hi bound)    = {} (x 1e-12 hartree)\n  norb            = {}\n  nelec           = {}\n  D0..D7 (sha256) = {}\n  lv (lo verdict) = {}\n  l (lo bound)    = {} (x 1e-12 hartree)\n  md (mode)       = {}\n  t (target)      = {} (x 1e-12 hartree)\n  ac (accept bit) = {}\n  C0..C7 (Poseidon2 commitment, hex) = {}",
        pv.v, pv.u, pv.norb, pv.nelec, d, pv.lv, pv.l, mode, pv.t, pv.ac, c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    pub const DATA: &[u8] = b"&FCI NORB=6,NELEC=4\n/\n";
    pub fn q() -> Question { Question { norb: 6, nelec: 4, digest: Sha256::digest(DATA).into() } }

    pub fn dwords(dg: &[u8; 32]) -> [u64; 8] { let mut d = [0u64; 8]; for i in 0..8 { d[i] = u32::from_be_bytes(dg[4 * i..4 * i + 4].try_into().unwrap()) as u64; } d }
    pub const C: [u64; 8] = [1, 2, 3, KOALABEAR_P - 1, 0, 77, 1 << 30, 12345];
    /// 25 words, each 8 little-endian bytes
    pub fn enc(v: u64, u: i64, nb: u64, ne: u64, d: [u64; 8], lv: u64, l: i64, md: u64, t: i64, ac: u64, c: [u64; 8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(200);
        for x in [v, u as u64, nb, ne].iter().chain(d.iter()).chain([lv, l as u64, md, t as u64, ac].iter()).chain(c.iter()) { out.extend_from_slice(&x.to_le_bytes()); }
        assert_eq!(out.len(), PV_BYTES);
        out
    }
    // mode 0 at target 4: u = -5, l = -9, u - l = 4
    fn full() -> Vec<u8> { enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 4, 1, C) }
    // mode 1 at target 4: bounds hidden
    fn compl() -> Vec<u8> { enc(1, 0, 6, 4, dwords(&q().digest), 1, 0, 1, 4, 1, C) }

    #[test] fn roundtrip_decode() {
        let pv = decode_pvc(&full()).unwrap();
        assert_eq!(pv, Pv { v: 1, u: -5, norb: 6, nelec: 4, d: dwords(&q().digest), lv: 1, l: -9, md: 0, t: 4, ac: 1, c: C });
        assert_eq!(digest_of_d(&pv.d).unwrap(), q().digest);
    }
    #[test] fn sdec_twos_complement() {
        assert_eq!(sdec(0), 0); assert_eq!(sdec((1u64 << 63) - 1), i64::MAX);
        assert_eq!(sdec(1u64 << 63), i64::MIN); assert_eq!(sdec(u64::MAX), -1);
    }
    #[test] fn accept_full() {
        assert_eq!(check_pub(&full(), &q(), 0, 4).map(|x| x.1), Ok(Accepted { md: 0, target: 4, u: -5, l: -9, d: dwords(&q().digest), c: C }));
    }
    #[test] fn accept_completion() {
        assert_eq!(check_pub(&compl(), &q(), 1, 4).map(|x| x.1), Ok(Accepted { md: 1, target: 4, u: 0, l: 0, d: dwords(&q().digest), c: C }));
    }
    #[test] fn reject_old_112_and_96() {
        assert!(check_pub(&full()[..112], &q(), 0, 4).is_err());
        assert!(check_pub(&full()[..96], &q(), 0, 4).is_err());
    }
    #[test] fn reject_short_long() {
        assert!(check_pub(&full()[..199], &q(), 0, 4).is_err());
        let mut p = full(); p.push(0); assert!(check_pub(&p, &q(), 0, 4).is_err());
        assert!(check_pub(&[], &q(), 0, 4).is_err());
    }
    #[test] fn reject_ac0_any_mode() {
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 4, 0, C), &q(), 0, 4).is_err());
        assert!(check_pub(&enc(1, 0, 6, 4, dwords(&q().digest), 1, 0, 1, 4, 0, C), &q(), 1, 4).is_err());
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 4, 2, C), &q(), 0, 4).is_err()); // ac must be exactly 1
    }
    #[test] fn reject_v0_lv0_with_ac1() {
        assert!(check_pub(&enc(0, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 4, 1, C), &q(), 0, 4).is_err());
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 0, -9, 0, 4, 1, C), &q(), 0, 4).is_err());
        assert!(check_pub(&enc(0, -5, 6, 4, dwords(&q().digest), 0, -9, 0, 4, 1, C), &q(), 0, 4).is_err());
    }
    #[test] fn reject_bad_mode_word() {
        for md in [2u64, 3, u64::MAX] {
            assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, md, 4, 1, C), &q(), 0, 4).is_err());
            assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, md, 4, 1, C), &q(), md, 4).is_err());
        }
    }
    #[test] fn reject_wrong_expected_mode() {
        assert!(check_pub(&full(), &q(), 1, 4).is_err());
        assert!(check_pub(&compl(), &q(), 0, 4).is_err());
    }
    #[test] fn reject_cross_level() {
        // a proof made at x2 = 4 presented as x1 = 3 (or any other level), in both modes
        assert!(check_pub(&full(), &q(), 0, 3).is_err());
        assert!(check_pub(&full(), &q(), 0, 5).is_err());
        assert!(check_pub(&compl(), &q(), 1, 3).is_err());
        assert!(check_pub(&compl(), &q(), 1, 1_000_000).is_err());
    }
    #[test] fn reject_negative_t() {
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, -1, 1, C), &q(), 0, -1).is_err());
        assert!(accept(&decode_pvc(&full()).unwrap(), &q(), 0, -1).is_err());
    }
    #[test] fn reject_full_precision_not_met() {
        // ac = 1 but u - l = 4 > t = 3 (impossible from the program, still checked)
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 3, 1, C), &q(), 0, 3).is_err());
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 0, 1, C), &q(), 0, 0).is_err());
    }
    #[test] fn reject_full_l_gt_u() { assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -4, 0, 100, 1, C), &q(), 0, 100).is_err()); }
    #[test] fn accept_full_l_eq_u_target0() { assert!(check_pub(&enc(1, 7, 6, 4, dwords(&q().digest), 1, 7, 0, 0, 1, C), &q(), 0, 0).is_ok()); }
    #[test] fn reject_completion_nonzero_bounds() {
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, 0, 1, 4, 1, C), &q(), 1, 4).is_err());
        assert!(check_pub(&enc(1, 0, 6, 4, dwords(&q().digest), 1, -9, 1, 4, 1, C), &q(), 1, 4).is_err());
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 1, 4, 1, C), &q(), 1, 4).is_err());
    }
    #[test] fn reject_wrong_d() {
        let mut d = dwords(&q().digest); d[7] ^= 1; assert!(check_pub(&enc(1, -5, 6, 4, d, 1, -9, 0, 4, 1, C), &q(), 0, 4).is_err());
        let mut d = dwords(&q().digest); d[0] ^= 1 << 31; assert!(check_pub(&enc(1, 0, 6, 4, d, 1, 0, 1, 4, 1, C), &q(), 1, 4).is_err());
    }
    #[test] fn reject_d_high_bits() { let mut d = dwords(&q().digest); d[3] |= 1 << 32; assert!(check_pub(&enc(1, -5, 6, 4, d, 1, -9, 0, 4, 1, C), &q(), 0, 4).is_err()); }
    #[test] fn reject_wrong_file() {
        let other = Question { digest: Sha256::digest(b"other bytes").into(), ..q() };
        assert!(check_pub(&full(), &other, 0, 4).is_err());
        assert!(check_pub(&compl(), &other, 1, 4).is_err());
    }
    #[test] fn reject_norb_nelec() {
        assert!(check_pub(&enc(1, -5, 7, 4, dwords(&q().digest), 1, -9, 0, 4, 1, C), &q(), 0, 4).is_err());
        assert!(check_pub(&enc(1, -5, 6, 2, dwords(&q().digest), 1, -9, 0, 4, 1, C), &q(), 0, 4).is_err());
    }
    #[test] fn reject_c_not_field_element() {
        for i in 0..8 {
            let mut c = C; c[i] = KOALABEAR_P;
            assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 4, 1, c), &q(), 0, 4).is_err(), "C{} = P accepted", i);
            let mut c = C; c[i] = 1u64 << 32;
            assert!(check_pub(&enc(1, 0, 6, 4, dwords(&q().digest), 1, 0, 1, 4, 1, c), &q(), 1, 4).is_err(), "C{} = 2^32 accepted", i);
        }
        let mut c = C; c[2] = KOALABEAR_P - 1;
        assert!(check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 4, 1, c), &q(), 0, 4).is_ok());
    }
    #[test] fn no_overflow_in_u_minus_l() {
        assert!(!acc_met(i64::MAX, i64::MIN, i64::MAX));
        assert!(check_pub(&enc(1, i64::MAX, 6, 4, dwords(&q().digest), 1, i64::MIN, 0, i64::MAX, 1, C), &q(), 0, i64::MAX).is_err());
        assert!(acc_met(i64::MAX, 0, i64::MAX));
    }
    #[test] fn set_rule_shared_d_and_c() {
        let f = check_pub(&full(), &q(), 0, 4).unwrap().1;
        let c1 = check_pub(&compl(), &q(), 1, 4).unwrap().1;
        assert_eq!(check_set(&[c1.clone(), f.clone()]), Ok(vec![4]));
        // different C between the completion proof and the full proof of the same level (C0-vs-C negative)
        let mut c2 = C; c2[0] ^= 1;
        let f2 = check_pub(&enc(1, -5, 6, 4, dwords(&q().digest), 1, -9, 0, 4, 1, c2), &q(), 0, 4).unwrap().1;
        assert!(check_set(&[c1.clone(), f2]).is_err());
        // two proofs with different D
        let other = Question { digest: Sha256::digest(b"other bytes").into(), ..q() };
        let f3 = check_pub(&enc(1, -5, 6, 4, dwords(&other.digest), 1, -9, 0, 4, 1, C), &other, 0, 4).unwrap().1;
        assert!(check_set(&[c1.clone(), f3]).is_err());
        assert!(check_set(&[]).is_err());
        // a completion proof alone: nothing revealed, level pending
        assert_eq!(check_set(&[c1.clone()]), Ok(vec![]));
        assert_eq!(pending_levels(&[c1.clone()]), vec![4]);
        assert_eq!(pending_levels(&[c1, f]), Vec::<i64>::new());
    }
    #[test] fn parse_target_rules() {
        assert_eq!(parse_target("0"), Ok(0)); assert_eq!(parse_target("1600000000"), Ok(1_600_000_000));
        assert!(parse_target("-1").is_err()); assert!(parse_target("").is_err()); assert!(parse_target("1e9").is_err());
        assert!(parse_target("9223372036854775808").is_err()); assert_eq!(parse_target("9223372036854775807"), Ok(i64::MAX));
    }
    #[test] fn parse_mode_rules() {
        assert_eq!(parse_mode("0"), Ok(0)); assert_eq!(parse_mode("full"), Ok(0));
        assert_eq!(parse_mode("1"), Ok(1)); assert_eq!(parse_mode("completion"), Ok(1));
        assert!(parse_mode("2").is_err()); assert!(parse_mode("").is_err());
    }
    #[test] fn describe_mentions_fields() {
        let s = describe(&decode_pvc(&full()).unwrap());
        assert!(s.contains("v (hi verdict)  = 1") && s.contains("u (hi bound)    = -5") && s.contains("l (lo bound)    = -9"));
        assert!(s.contains(&hex32(&q().digest)) && s.contains(&c_hex(&C)) && s.contains("md (mode)       = 0") && s.contains("ac (accept bit) = 1"));
        assert_eq!(c_hex(&C).len(), 64);
    }
}
