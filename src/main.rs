// become-verify: verify-only checker for BECOME certified ground-state energy proofs (main_xc, SP1 6.8.1 Groth16).
// Pure Rust: the official sp1-verifier Groth16 verifier with its compiled-in verifying key; no prover, no network.
// Input: the proof.bin you download (SP1ProofWithPublicValues as .save() writes it) and your FCIDUMP file.
// The checks are in src/lib.rs (shared with the browser build in wasm/); the public-value decoding and acceptance
// rules are src/pv.rs (the same rules BECOME uses).

use become_verify::{check_pair, check_proof, pv, report_pair, report_single, PairFile};
use std::process::exit;

const USAGE: &str = "usage:
  become-verify <proof.bin> <fcidump> --level <ordered-level>
  become-verify pair <completion.bin> <final.bin> <fcidump> --level <ordered-level>
  become-verify fingerprint <fcidump>
Levels are integers in units of 1e-12 hartree (Standard 1593601437, Precise 1593601, Ultra-precise 159).
A proof made at a tighter level than the one ordered passes.";

fn fail(msg: &str) -> ! { println!("FAIL: {}", msg); exit(1) }

fn read(path: &str) -> Vec<u8> { std::fs::read(path).unwrap_or_else(|e| fail(&format!("cannot read {}: {}", path, e))) }

fn question(fcidump: &str) -> pv::Question { become_verify::question(&read(fcidump)).unwrap_or_else(|e| fail(&e)) }

fn level(args: &[String]) -> i64 {
    match args { [flag, v] if flag == "--level" => pv::parse_target(v).unwrap_or_else(|e| fail(&e)), _ => { eprintln!("{}", USAGE); exit(2) } }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("fingerprint") if a.len() == 3 => println!("{}", become_verify::fingerprint(&read(&a[2]))),
        Some("pair") if a.len() == 7 => {
            let ord = level(&a[5..]);
            let q = question(&a[4]);
            let (c, f) = (read(&a[2]), read(&a[3]));
            match check_pair(&c, &f, &q, ord) {
                Ok((_, f)) => { println!("PASS"); for l in report_pair(&f, ord) { println!("{}", l); } }
                Err((PairFile::Completion, e)) => fail(&format!("{}: {}", a[2], e)),
                Err((PairFile::Final, e)) => fail(&format!("{}: {}", a[3], e)),
                Err((PairFile::Both, e)) => fail(&e),
            }
        }
        Some(p) if a.len() == 5 && p != "pair" && p != "fingerprint" => {
            let ord = level(&a[3..]);
            let q = question(&a[2]);
            let r = check_proof(&read(p), &q, None, ord).unwrap_or_else(|e| fail(&format!("{}: {}", p, e)));
            println!("PASS");
            for l in report_single(&r, ord) { println!("{}", l); }
        }
        _ => { eprintln!("{}", USAGE); exit(2) }
    }
}

#[cfg(test)]
mod tests {
    use become_verify::{pv, VKEY};
    use sha2::{Digest, Sha256};
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
    #[test] fn header_fields() {
        let q = become_verify::question(b"&FCI NORB=  6,NELEC=4,MS2=0,\n/\n").unwrap();
        assert_eq!((q.norb, q.nelec), (6, 4));
        assert!(become_verify::question(b"&FCI NELEC=4\n/\n").is_err());
        assert_eq!(become_verify::fingerprint(b"x"), pv::hex32(&Sha256::digest(b"x").into()));
    }
}
