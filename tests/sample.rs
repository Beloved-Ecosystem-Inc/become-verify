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
    // a length field, the program key (public input 0), the Groth16 proof, the public values (a bound word, C). The
    // copy of the raw proof and public inputs 1-4 are not read: the verifier recomputes them from the key and values.
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
