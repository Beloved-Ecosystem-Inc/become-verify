// The real ethanol sample proofs (tests/fixtures/ethanol-sample) through the library the command-line tool and the
// browser build share: completion and pair PASS, and FAIL for a changed byte, a swapped pair, the wrong file and a
// looser proof level.
use become_verify::{check_pair, check_proof, pv, question, PairFile};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ethanol-sample/");
fn f(name: &str) -> Vec<u8> { std::fs::read(format!("{}{}", DIR, name)).unwrap() }
fn q() -> pv::Question { question(&f("pcq702_6-31g_cas8e8o.fcidump")).unwrap() }

#[test] fn fingerprint_is_the_catalog_file() {
    assert_eq!(become_verify::fingerprint(&f("pcq702_6-31g_cas8e8o.fcidump")), "14199aece64925c7b73f7e65e42448d7a288ef6f837939a0ed4d159b58000cfe");
    assert_eq!((q().norb, q().nelec), (8, 8));
}
#[test] fn completion_passes() {
    let a = check_proof(&f("completion.bin"), &q(), None, 159).unwrap();
    assert_eq!((a.md, a.target, a.l, a.u), (pv::MODE_COMPLETION, 159, 0, 0));
    assert!(check_proof(&f("completion.bin"), &q(), None, 1593601437).is_ok()); // a looser order passes too
}
#[test] fn pair_passes_with_one_commitment() {
    let (c, fin) = check_pair(&f("completion.bin"), &f("final.bin"), &q(), 159).unwrap();
    assert_eq!(c.c, fin.c);
    assert!(fin.l <= fin.u && fin.u - fin.l <= 159);
}
#[test] fn changed_byte_fails() {
    // a length field, the program key (public input 0), the Groth16 proof, the public values (a bound word, C)
    for i in [4usize, 50, 300, 900, 1678 + 8, 1678 + 8 * 13, 1850] {
        let mut b = f("final.bin"); b[i] ^= 1;
        assert!(check_pair(&f("completion.bin"), &b, &q(), 159).is_err(), "byte {} changed but passed", i);
    }
}
#[test] fn swapped_wrong_file_and_tighter_order_fail() {
    assert_eq!(check_pair(&f("final.bin"), &f("completion.bin"), &q(), 159).unwrap_err().0, PairFile::Completion);
    let other = pv::Question { digest: [7u8; 32], ..q() };
    assert!(check_proof(&f("completion.bin"), &other, None, 159).is_err());
    assert!(check_proof(&f("completion.bin"), &q(), None, 158).is_err());
}

/// Byte ranges of the fields of a proof file (bincode layout as proofbin.rs reads it): (name, start, end).
fn fields(b: &[u8]) -> Vec<(String, usize, usize)> {
    fn s(b: &[u8], out: &mut Vec<(String, usize, usize)>, name: String, i: &mut usize) {
        let n = u64::from_le_bytes(b[*i..*i + 8].try_into().unwrap()) as usize; out.push((name, *i + 8, *i + 8 + n)); *i += 8 + n;
    }
    let mut out = Vec::new(); let mut i = 4;
    for k in 0..5 { s(b, &mut out, format!("public input {}", k), &mut i); }
    s(b, &mut out, "encoded proof".into(), &mut i); s(b, &mut out, "raw proof".into(), &mut i);
    out.push(("Groth16 key hash".into(), i, i + 32)); i += 32;
    s(b, &mut out, "public values".into(), &mut i); s(b, &mut out, "circuit version".into(), &mut i);
    out
}
/// Change one character of a stored decimal or hex string to another valid digit of the same kind (same length).
fn bump(c: u8) -> u8 { match c { b'0'..=b'8' | b'a'..=b'e' => c + 1, b'9' => b'0', b'f' => b'0', _ => c ^ 1 } }

#[test] fn every_stored_copy_must_match() {
    // An outside review (Nov 14, 2026) changed one digit of a public-input copy stored in the file and still got PASS
    // (the verifier rebuilds those inputs and never read the copy). Each stored copy is now compared: change one valid
    // digit (first, middle and last) of every field, in both files, and the check must FAIL.
    for name in ["completion.bin", "final.bin"] {
        let orig = f(name);
        for (field, a, z) in fields(&orig) {
            for i in [a, (a + z) / 2, z - 1] {
                let mut b = orig.clone();
                b[i] = if field.starts_with("public input") || field.ends_with("proof") || field == "circuit version" { bump(b[i]) } else { b[i] ^ 1 };
                assert!(check_proof(&b, &q(), None, 159).is_err(), "{}: {} byte {} changed but passed", name, field, i);
            }
        }
    }
}
#[test] fn every_single_bit_flip_fails() {
    for name in ["completion.bin", "final.bin"] {
        let orig = f(name);
        for i in 0..orig.len() { for bit in [0u8, 3, 7] {
            let mut b = orig.clone(); b[i] ^= 1 << bit;
            assert!(check_proof(&b, &q(), None, 159).is_err(), "{}: byte {} bit {} flipped but passed", name, i, bit);
        } }
    }
}
