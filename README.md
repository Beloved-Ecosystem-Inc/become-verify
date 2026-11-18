# become-verify

Checks BECOME certified ground-state energy proofs on your own computer, against your FCIDUMP file: the completion
proof (before payment, bounds sealed), the final proof (after payment, bounds revealed), and that the two belong
together. Verify-only: no prover, no network calls.

## In your browser

[Verify in your browser](https://become.belovedecosystem.com/energy/verify/) runs the same checks, built from this
repository's [wasm/](wasm/) (reproducible; see [wasm/SHA256SUMS](wasm/SHA256SUMS)). Your files are read in the page and
not sent anywhere.

## Download

Get your computer's file and `SHA256SUMS` from the
[v0.2.0 release](https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/tag/v0.2.0): `linux-x86_64`,
`linux-arm64`, `macos-arm64`, `macos-x86_64` or `windows-x86_64.exe`.

```sh
F=become-verify-v0.2.0-macos-arm64
curl -fLO https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/download/v0.2.0/$F
curl -fLO https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/download/v0.2.0/SHA256SUMS
grep " $F\$" SHA256SUMS | sha256sum -c -     # Mac: shasum -a 256 -c -
gh attestation verify $F --repo Beloved-Ecosystem-Inc/become-verify   # optional: built by this repo's release workflow
chmod +x $F && mv $F become-verify
```

On Windows, compare `Get-FileHash` of the `.exe` with its line in `SHA256SUMS`. A Mac may block a file downloaded in a
browser (`xattr -d com.apple.quarantine become-verify`); Windows SmartScreen may ask you to confirm.

## Build from source

```sh
git clone https://github.com/Beloved-Ecosystem-Inc/become-verify && cd become-verify
git checkout v0.2.0
cargo build --release --locked        # Rust from https://rustup.rs; the program is target/release/become-verify
```

## Run

```sh
./become-verify fingerprint your.fcidump                                         # must match the SHA-256 on your order
./become-verify completion.bin your.fcidump --level <level>                      # before you pay
./become-verify pair completion.bin final.bin your.fcidump --level <level>       # after you pay
```

`<level>` is the accuracy you ordered, in units of 10^-12 hartree: Standard `1593601437`, Precise `1593601`,
Ultra-precise `159`.

The first line is `PASS` or `FAIL: <reason>` (exit code 0 for PASS, 1 for FAIL, 2 for a usage error such as a missing
argument). A `--level` value that isn't a whole number of 0 or more, or a file that can't be read, is reported as
`FAIL: <reason>` with exit code 1. `PASS` means the
Groth16 proof verifies under BECOME's program key
`0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b` (built into the checker), it is about your file
(its SHA-256), and its level meets your order. A pair `PASS` also means both proofs carry the same commitment, so the
revealed bounds are the ones sealed before payment, and it prints them.

How far the proof goes today: that a pair `PASS` ties the revealed bounds to the sealed ones is proven in Coq at the
level of the program's specification. Restating that proof for the program as the machine runs it is still in
progress.

The proved statement is about the closed-shell sector: states with NELEC/2 electrons of each spin (MS2 = 0). The
checker reads NORB and NELEC from your file's header but not MS2, so for a file whose header gives MS2 other than 0,
a `PASS` is about that file's closed-shell ground state, not the spin state the header names.

BECOME's connector can also run this check on its server (v0.2.0, commit `325f346`); that is a convenience, not an
independent check.

## What you're trusting

- SP1 6.8.1: its Groth16 setup, and that SP1 runs a program the way the hand-written Coq model of the SP1 machine,
  which the proof is carried out against, describes.
- BECOME's checking program, whose soundness is proven in Coq (closed-shell sector, MS2 = 0; see above for what is
  proven at which level).
- BECOME's release gate, which checks that the program key built into this checker belongs to exactly the program
  image the Coq proof is about.
- The Coq proof checker (its kernel) that checked the proof.
- The official `sp1-verifier` crate (6.8.1) that checks the Groth16 proof here, and the Rust toolchain
  (`rust-toolchain.toml`) and crates (`Cargo.lock`) this checker is built with; for the ready-made downloads, also
  GitHub Actions, which builds them (see the attestation above).
- SHA-256 and Poseidon2 (KoalaBear) as hash functions.

## Reporting a problem

See [SECURITY.md](SECURITY.md).

## License

Apache-2.0 (see [LICENSE](LICENSE)).
