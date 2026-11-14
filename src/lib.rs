// become-verify as a library: the checks the command-line tool runs (src/main.rs) and the browser build runs
// (wasm/, compiled to WebAssembly). One copy of the logic: the same program key, the same proof-file reader, the same
// public-value rules (src/pv.rs) and the same PASS/FAIL text. Pure: no file system, no network, no clock.

pub mod pv;
pub mod proofbin;

use sha2::{Digest, Sha256};

/// SP1 program verifying key of main_xc (manifest `vkey`; release image.elf 66d71b5b...).
pub const VKEY: &str = "0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b";

/// The become-verify version (Cargo.toml), so a browser page can show which release it runs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// How many bytes at the start of an FCIDUMP are searched for the NORB= and NELEC= header fields.
pub const HEADER_BYTES: usize = 4096;

/// NORB and NELEC from the FCIDUMP header (&FCI NORB=..,NELEC=..,...).
pub fn header_int(text: &str, key: &str) -> Option<u64> {
    let up = text.to_ascii_uppercase();
    let i = up.find(&format!("{}=", key))? + key.len() + 1;
    let digits: String = up[i..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// The question from the first bytes of the FCIDUMP (at least its header; HEADER_BYTES are read) and the SHA-256 of
/// the whole file. Lets a caller hash a large file in pieces (the browser build) and still ask the same question.
pub fn question_from_parts(head: &[u8], digest: [u8; 32]) -> Result<pv::Question, String> {
    let head = String::from_utf8_lossy(&head[..head.len().min(HEADER_BYTES)]).to_string();
    let norb = header_int(&head, "NORB").ok_or("FCIDUMP header has no NORB=")?;
    let nelec = header_int(&head, "NELEC").ok_or("FCIDUMP header has no NELEC=")?;
    Ok(pv::Question { norb, nelec, digest })
}

/// The question a proof is checked against, from the whole FCIDUMP file.
pub fn question(fcidump: &[u8]) -> Result<pv::Question, String> {
    question_from_parts(fcidump, Sha256::digest(fcidump).into())
}

/// The SHA-256 of a file, as 64 lowercase hex digits (`become-verify fingerprint`).
pub fn fingerprint(bytes: &[u8]) -> String { pv::hex32(&Sha256::digest(bytes).into()) }

/// Verify one proof file: Groth16 under VKEY with the built-in key, then the public values against the file; the
/// proof's own level must be the ordered level or tighter. `mode`: None accepts either kind. The error is the reason
/// only (the command-line tool puts the file name in front).
pub fn check_proof(raw: &[u8], q: &pv::Question, mode: Option<u64>, ordered: i64) -> Result<pv::Accepted, String> {
    let p = proofbin::parse(raw)?;
    if proofbin::dec_to_hex32(&p.vkey_input).as_deref() != Some(VKEY) {
        return Err(format!("not a proof of the BECOME main_xc program (key {})", VKEY));
    }
    if let Err(e) = sp1_verifier::Groth16Verifier::verify(&p.onchain_bytes, &p.public_values, VKEY, *sp1_verifier::GROTH16_VK_BYTES) {
        return Err(format!("the Groth16 proof does not verify: {}", e));
    }
    let d = pv::decode_pvc(&p.public_values)?;
    let md = mode.unwrap_or(d.md);
    // Accept at the proof's own level t (pv.rs requires an exact match), then require t <= the ordered level:
    // ClaimX at t implies ClaimX at every looser level (Coq: ClaimXMono.claimX_weaken).
    let a = pv::accept(&d, q, md, d.t)?;
    if a.target > ordered { return Err(format!("proof level {} is looser than the ordered level {}", a.target, ordered)); }
    Ok(a)
}

/// Which file of a pair a failure is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairFile { Completion, Final, Both }

/// The pair check: the completion proof (mode 1) and the final proof (mode 0) each pass check_proof, share one
/// fingerprint D and one commitment C, and were made at the same level.
pub fn check_pair(completion: &[u8], fin: &[u8], q: &pv::Question, ordered: i64)
    -> Result<(pv::Accepted, pv::Accepted), (PairFile, String)> {
    let c = check_proof(completion, q, Some(pv::MODE_COMPLETION), ordered).map_err(|e| (PairFile::Completion, e))?;
    let f = check_proof(fin, q, Some(pv::MODE_FULL), ordered).map_err(|e| (PairFile::Final, e))?;
    if pv::check_set(&[c.clone(), f.clone()]).is_err() {
        return Err((PairFile::Both, "the two proofs do not share one fingerprint D and one commitment C".into()));
    }
    if c.target != f.target { return Err((PairFile::Both, "the two proofs were made at different levels".into())); }
    Ok((c, f))
}

fn digest_hex(d: &[u64; 8]) -> String { pv::hex32(&pv::digest_of_d(d).unwrap_or([0u8; 32])) }

/// The lines a single-proof PASS prints (after the first line, PASS).
pub fn report_single(r: &pv::Accepted, ordered: i64) -> Vec<String> {
    let mut v = vec![
        format!("  the proof verifies under the BECOME main_xc key {}", VKEY),
        format!("  it is about your file: SHA-256 {}", digest_hex(&r.d)),
        format!("  level {} meets your order {}; commitment C = {}", r.target, ordered, pv::c_hex(&r.c)),
    ];
    if r.md == pv::MODE_FULL {
        v.push(format!("  final proof: lower bound l = {}, upper bound u = {} (x 1e-12 hartree)", r.l, r.u));
    } else {
        v.push("  completion proof: bounds sealed; the final proof will carry the same C".into());
    }
    v
}

/// The lines a pair PASS prints (after the first line, PASS).
pub fn report_pair(f: &pv::Accepted, ordered: i64) -> Vec<String> {
    vec![
        format!("  both proofs verify under the BECOME main_xc key {}", VKEY),
        format!("  both are about your file: SHA-256 {}", digest_hex(&f.d)),
        format!("  same commitment C = {}: the revealed bounds are the ones sealed before payment", pv::c_hex(&f.c)),
        format!("  lower bound l = {}, upper bound u = {} (x 1e-12 hartree); level {} meets your order {}", f.l, f.u, f.target, ordered),
    ]
}

/// The digest bytes of an accepted proof's D words, as 64 hex digits.
pub fn accepted_sha256(a: &pv::Accepted) -> String { digest_hex(&a.d) }
