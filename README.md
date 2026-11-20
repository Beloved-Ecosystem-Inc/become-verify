# become-verify

Checks BECOME proofs of lower and upper bounds on the lowest energy of your FCIDUMP file's Hamiltonian, offline.

[Verify in your browser](https://become.belovedecosystem.com/energy/verify/) runs the same checks; your files stay on
your computer.

## Download

From the [v0.2.0 release](https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/tag/v0.2.0) (Linux, macOS,
Windows), for example:

```sh
F=become-verify-v0.2.0-macos-arm64
curl -fLO https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/download/v0.2.0/$F
curl -fLO https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/download/v0.2.0/SHA256SUMS
grep " $F\$" SHA256SUMS | shasum -a 256 -c - && chmod +x $F && mv $F become-verify
```

## Build from source

```sh
git clone https://github.com/Beloved-Ecosystem-Inc/become-verify && cd become-verify
git checkout v0.2.0
cargo build --release --locked    # target/release/become-verify
```

## Run

```sh
./become-verify fingerprint your.fcidump                                     # must match your order's SHA-256
./become-verify completion.bin your.fcidump --level <level>                  # before you pay
./become-verify pair completion.bin final.bin your.fcidump --level <level>   # after you pay
```

`--level N` means the bounds are at most N × 10^-12 hartree apart (u − l ≤ N × 10^-12 Ha): Standard `1593601437`,
Precise `1593601`, Ultra-precise `159` (1.59 × 10^-10 Ha).

`PASS` means the proof verifies under BECOME's built-in program key, is about your file, and meets your level; a pair
`PASS` also means the revealed bounds are the ones sealed before payment. Otherwise it prints `FAIL: <reason>` (exit 1).

## What you're trusting

- SP1 6.8.1 and its Groth16 setup. (Proofs carry SP1's circuit label `v6.1.0`, which 6.8.1 writes; become-verify
  requires it.)
- BECOME's checking program, whose soundness is proven in Coq (closed-shell sector, MS2 = 0).
- SHA-256 and Poseidon2 (KoalaBear).

The question itself, in Coq, and a check that your FCIDUMP is the file it's about: [question/](question/).

Report problems via [SECURITY.md](SECURITY.md). License: Apache-2.0 ([LICENSE](LICENSE)).
