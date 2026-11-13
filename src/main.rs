// become-verify: verify-only checker for BECOME certified ground-state energy proofs (main_xc, SP1 6.8.1 Groth16).
// Pure Rust: the official sp1-verifier Groth16 verifier with its compiled-in verifying key; no prover, no network.
// Input: the proof.bin you download (SP1ProofWithPublicValues as .save() writes it) and your FCIDUMP file.
// The public-value decoding and acceptance rules are src/pv.rs (the same rules BECOME uses).

mod pv;
mod proofbin;

use sha2::{Digest, Sha256};
use std::process::exit;

/// SP1 program verifying key of main_xc (manifest `vkey`; release image.elf 66d71b5b...).
const VKEY: &str = "0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b";

const USAGE: &str = "usage:
  become-verify <proof.bin> <fcidump> --level <ordered-level>
  become-verify pair <completion.bin> <final.bin> <fcidump> --level <ordered-level>
  become-verify fingerprint <fcidump>
Levels are integers in units of 1e-12 hartree (Standard 1593601437, Precise 1593601, Ultra-precise 159).
A proof made at a tighter level than the one ordered passes.";

fn fail(msg: &str) -> ! { println!("FAIL: {}", msg); exit(1) }

/// NORB and NELEC from the FCIDUMP header (&FCI NORB=..,NELEC=..,...).
fn header_int(text: &str, key: &str) -> Option<u64> {
    let up = text.to_ascii_uppercase();
    let i = up.find(&format!("{}=", key))? + key.len() + 1;
    let digits: String = up[i..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

fn question(fcidump: &str) -> pv::Question {
    let bytes = std::fs::read(fcidump).unwrap_or_else(|e| fail(&format!("cannot read {}: {}", fcidump, e)));
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).to_string();
    let norb = header_int(&head, "NORB").unwrap_or_else(|| fail("FCIDUMP header has no NORB="));
    let nelec = header_int(&head, "NELEC").unwrap_or_else(|| fail("FCIDUMP header has no NELEC="));
    pv::Question { norb, nelec, digest: Sha256::digest(&bytes).into() }
}

/// Verify one proof.bin: Groth16 under VKEY with the built-in key, then the public values against the file; the
/// proof's own level must be the ordered level or tighter. `mode`: None accepts either kind.
fn check_one(path: &str, q: &pv::Question, mode: Option<u64>, ordered: i64) -> pv::Accepted {
    let raw = std::fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {}: {}", path, e)));
    let p = proofbin::parse(&raw).unwrap_or_else(|e| fail(&format!("{}: {}", path, e)));
    if proofbin::dec_to_hex32(&p.vkey_input).as_deref() != Some(VKEY) { fail(&format!("{}: not a proof of the BECOME main_xc program (key {})", path, VKEY)) }
    if let Err(e) = sp1_verifier::Groth16Verifier::verify(&p.onchain_bytes, &p.public_values, VKEY, *sp1_verifier::GROTH16_VK_BYTES) {
        fail(&format!("{}: the Groth16 proof does not verify: {}", path, e))
    }
    let d = pv::decode_pvc(&p.public_values).unwrap_or_else(|e| fail(&format!("{}: {}", path, e)));
    let md = mode.unwrap_or(d.md);
    // Accept at the proof's own level t (pv.rs requires an exact match), then require t <= the ordered level:
    // ClaimX at t implies ClaimX at every looser level (Coq: ClaimXMono.claimX_weaken).
    let a = pv::accept(&d, q, md, d.t).unwrap_or_else(|e| fail(&format!("{}: {}", path, e)));
    if a.target > ordered { fail(&format!("{}: proof level {} is looser than the ordered level {}", path, a.target, ordered)) }
    a
}

fn level(args: &[String]) -> i64 {
    match args { [flag, v] if flag == "--level" => pv::parse_target(v).unwrap_or_else(|e| fail(&e)), _ => { eprintln!("{}", USAGE); exit(2) } }
}
fn digest_hex(d: &[u64; 8]) -> String { pv::hex32(&pv::digest_of_d(d).unwrap()) }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("fingerprint") if a.len() == 3 => {
            let b = std::fs::read(&a[2]).unwrap_or_else(|e| fail(&format!("cannot read {}: {}", a[2], e)));
            println!("{}", pv::hex32(&Sha256::digest(&b).into()));
        }
        Some("pair") if a.len() == 7 => {
            let ord = level(&a[5..]);
            let q = question(&a[4]);
            let c = check_one(&a[2], &q, Some(pv::MODE_COMPLETION), ord);
            let f = check_one(&a[3], &q, Some(pv::MODE_FULL), ord);
            if pv::check_set(&[c.clone(), f.clone()]).is_err() { fail("the two proofs do not share one fingerprint D and one commitment C") }
            if c.target != f.target { fail("the two proofs were made at different levels") }
            println!("PASS");
            println!("  both proofs verify under the BECOME main_xc key {}", VKEY);
            println!("  both are about your file: SHA-256 {}", digest_hex(&f.d));
            println!("  same commitment C = {}: the revealed bounds are the ones sealed before payment", pv::c_hex(&f.c));
            println!("  lower bound l = {}, upper bound u = {} (x 1e-12 hartree); level {} meets your order {}", f.l, f.u, f.target, ord);
        }
        Some(p) if a.len() == 5 && p != "pair" && p != "fingerprint" => {
            let ord = level(&a[3..]);
            let q = question(&a[2]);
            let r = check_one(p, &q, None, ord);
            println!("PASS");
            println!("  the proof verifies under the BECOME main_xc key {}", VKEY);
            println!("  it is about your file: SHA-256 {}", digest_hex(&r.d));
            println!("  level {} meets your order {}; commitment C = {}", r.target, ord, pv::c_hex(&r.c));
            if r.md == pv::MODE_FULL {
                println!("  final proof: lower bound l = {}, upper bound u = {} (x 1e-12 hartree)", r.l, r.u);
            } else {
                println!("  completion proof: bounds sealed; the final proof will carry the same C");
            }
        }
        _ => { eprintln!("{}", USAGE); exit(2) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // a synthetic accepted record: v=1, lv=1, ac=1, D = sha256(b"x"), C words < P
    fn record(md: u64, t: i64, l: i64, u: i64) -> (Vec<u8>, pv::Question) {
        let dg: [u8; 32] = Sha256::digest(b"x").into();
        let mut w = [0u64; 25];
        w[0] = 1; w[1] = u as u64; w[2] = 8; w[3] = 8;
        for i in 0..8 { w[4 + i] = u32::from_be_bytes(dg[4 * i..4 * i + 4].try_into().unwrap()) as u64; }
        w[12] = 1; w[13] = l as u64; w[14] = md; w[15] = t as u64; w[16] = 1;
        for i in 0..8 { w[17 + i] = 1000 + i as u64; }
        (w.iter().flat_map(|x| x.to_le_bytes()).collect(), pv::Question { norb: 8, nelec: 8, digest: dg })
    }
    fn level_ok(b: &[u8], q: &pv::Question, md: u64, ordered: i64) -> Result<pv::Accepted, String> {
        let d = pv::decode_pvc(b)?; let a = pv::accept(&d, q, md, d.t)?;
        if a.target > ordered { return Err("looser".into()) } Ok(a)
    }
    #[test] fn tighter_proof_accepted_for_looser_order() {
        let (b, q) = record(0, 159, -1000, -900);
        assert!(level_ok(&b, &q, 0, 159).is_ok());
        assert!(level_ok(&b, &q, 0, 1593601437).is_ok());
    }
    #[test] fn looser_proof_rejected_for_tighter_order() {
        let (b, q) = record(0, 1593601, -1000, -900);
        assert!(level_ok(&b, &q, 0, 159).is_err());
    }
    #[test] fn completion_must_hide_bounds() {
        let (b, q) = record(1, 159, 0, 0); assert!(level_ok(&b, &q, 1, 159).is_ok());
        let (b, q) = record(1, 159, -1000, -900); assert!(level_ok(&b, &q, 1, 159).is_err());
    }
    #[test] fn wrong_file_rejected() {
        let (b, mut q) = record(0, 159, -1000, -900); q.digest[0] ^= 1;
        assert!(level_ok(&b, &q, 0, 159).is_err());
    }
    #[test] fn garbage_groth16_rejected() {
        let (b, _) = record(0, 159, -1000, -900);
        assert!(sp1_verifier::Groth16Verifier::verify(&[0u8; 400], &b, VKEY, *sp1_verifier::GROTH16_VK_BYTES).is_err());
    }
}
