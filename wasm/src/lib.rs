// become-verify in the browser. Thin bindings over the library the command-line tool uses (../src/lib.rs): the same
// program key, proof-file reader, Groth16 verifier, public-value rules and PASS/FAIL lines. Every call works on bytes
// the page already holds; nothing here touches the network. Results are JSON strings (no extra dependencies).

use become_verify as bv;
use bv::pv;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// The program key built in (the same constant as the command-line tool).
#[wasm_bindgen]
pub fn vkey() -> String { bv::VKEY.to_string() }

/// The become-verify crate version this was built from.
#[wasm_bindgen]
pub fn version() -> String { bv::VERSION.to_string() }

/// SHA-256 of a whole file held in memory, as 64 hex digits (`become-verify fingerprint`).
#[wasm_bindgen]
pub fn fingerprint(bytes: &[u8]) -> String { bv::fingerprint(bytes) }

/// An FCIDUMP read in pieces (large files): feed every byte in order with update(), then finish() gives the JSON
/// {"ok":true,"norb":..,"nelec":..,"sha256":".."} (or {"ok":false,"error":".."} when the header lacks NORB/NELEC).
#[wasm_bindgen]
pub struct Fcidump { h: Sha256, head: Vec<u8>, n: u64 }

#[wasm_bindgen]
impl Fcidump {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Fcidump { Fcidump { h: Sha256::new(), head: Vec::new(), n: 0 } }
    pub fn update(&mut self, chunk: &[u8]) {
        if self.head.len() < bv::HEADER_BYTES {
            let k = (bv::HEADER_BYTES - self.head.len()).min(chunk.len());
            self.head.extend_from_slice(&chunk[..k]);
        }
        self.h.update(chunk);
        self.n += chunk.len() as u64;
    }
    pub fn finish(self) -> String {
        let digest: [u8; 32] = self.h.finalize().into();
        match bv::question_from_parts(&self.head, digest) {
            Ok(q) => format!("{{\"ok\":true,\"norb\":{},\"nelec\":{},\"sha256\":\"{}\",\"bytes\":{}}}", q.norb, q.nelec, pv::hex32(&digest), self.n),
            Err(e) => format!("{{\"ok\":false,\"error\":{},\"sha256\":\"{}\",\"bytes\":{}}}", js(&e), pv::hex32(&digest), self.n),
        }
    }
}

impl Default for Fcidump { fn default() -> Self { Self::new() } }

fn js(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn question(norb: u32, nelec: u32, sha256_hex: &str) -> Result<pv::Question, String> {
    let h = sha256_hex.trim().to_ascii_lowercase();
    if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("the FCIDUMP SHA-256 must be 64 hex digits".into()); }
    let mut digest = [0u8; 32];
    for i in 0..32 { digest[i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).map_err(|_| "bad hex")?; }
    Ok(pv::Question { norb: norb as u64, nelec: nelec as u64, digest })
}

fn lines_json(first: &str, rest: &[String]) -> String {
    let mut v = vec![js(first)];
    v.extend(rest.iter().map(|l| js(l)));
    format!("[{}]", v.join(","))
}

fn fail_json(what: &str, msg: String) -> String {
    let line = format!("FAIL: {}", msg);
    format!("{{\"ok\":false,\"verdict\":\"FAIL\",\"check\":{},\"vkey\":{},\"error\":{},\"lines\":{}}}",
            js(what), js(bv::VKEY), js(&msg), lines_json(&line, &[]))
}

fn accepted_json(a: &pv::Accepted) -> String {
    let kind = if a.md == pv::MODE_FULL { "final" } else { "completion" };
    let bounds = if a.md == pv::MODE_FULL { format!(",\"lower_pHa\":\"{}\",\"upper_pHa\":\"{}\"", a.l, a.u) } else { String::new() };
    format!("{{\"kind\":\"{}\",\"level\":{},\"sha256\":\"{}\",\"commitment\":\"{}\"{}}}", kind, a.target, bv::accepted_sha256(a), pv::c_hex(&a.c), bounds)
}

/// `become-verify <proof> <fcidump> --level <level>`: one proof file (either kind) against the question (norb, nelec
/// and the FCIDUMP's SHA-256, from the file's header and hash). `level` is the ordered level as a decimal integer.
#[wasm_bindgen]
pub fn check_single(proof: &[u8], norb: u32, nelec: u32, sha256_hex: &str, level: &str) -> String {
    let q = match question(norb, nelec, sha256_hex) { Ok(q) => q, Err(e) => return fail_json("single", e) };
    let ord = match pv::parse_target(level) { Ok(x) => x, Err(e) => return fail_json("single", e) };
    match bv::check_proof(proof, &q, None, ord) {
        Ok(a) => format!("{{\"ok\":true,\"verdict\":\"PASS\",\"check\":\"single\",\"vkey\":{},\"ordered\":{},\"proof\":{},\"lines\":{}}}",
                         js(bv::VKEY), ord, accepted_json(&a), lines_json("PASS", &bv::report_single(&a, ord))),
        Err(e) => fail_json("single", e),
    }
}

/// `become-verify pair <completion> <final> <fcidump> --level <level>`.
#[wasm_bindgen]
pub fn check_pair(completion: &[u8], fin: &[u8], norb: u32, nelec: u32, sha256_hex: &str, level: &str) -> String {
    let q = match question(norb, nelec, sha256_hex) { Ok(q) => q, Err(e) => return fail_json("pair", e) };
    let ord = match pv::parse_target(level) { Ok(x) => x, Err(e) => return fail_json("pair", e) };
    match bv::check_pair(completion, fin, &q, ord) {
        Ok((c, f)) => format!("{{\"ok\":true,\"verdict\":\"PASS\",\"check\":\"pair\",\"vkey\":{},\"ordered\":{},\"completion\":{},\"final\":{},\"lines\":{}}}",
                              js(bv::VKEY), ord, accepted_json(&c), accepted_json(&f), lines_json("PASS", &bv::report_pair(&f, ord))),
        Err((which, e)) => fail_json("pair", match which {
            bv::PairFile::Completion => format!("completion.bin: {}", e),
            bv::PairFile::Final => format!("final.bin: {}", e),
            bv::PairFile::Both => e,
        }),
    }
}
