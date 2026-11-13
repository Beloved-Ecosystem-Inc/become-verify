# become-verify

Verify-only checker for BECOME certified ground-state energy proofs (SP1 6.8.1 Groth16, program `main_xc`).
It runs on your own computer, makes no network calls and contains no prover. Licensed under Apache-2.0.

Full explanation (what PASS means, the 200 public bytes, the commitment, what you are trusting): [GUIDE.md](GUIDE.md).

## Quick start

```sh
# 1. Build (Rust from https://rustup.rs; rust-toolchain.toml pins the version)
git clone https://github.com/Beloved-Ecosystem-Inc/become-verify
cd become-verify
cargo build --release --locked

# 2. Save your files in this folder (your job page, or your AI via the BECOME connector, gives the links)
#    completion.bin   the completion proof (bounds sealed), sent with the "target met" notice
#    final.bin        the final proof (bounds revealed), after payment
#    your.fcidump     the FCIDUMP you ordered (for a catalog job the BECOME connector's kit gives the public
#                     catalog link and the file's own name; use that name in place of your.fcidump below)

# 3. Check it is your file: must print the FCIDUMP SHA-256 shown for your order
./target/release/become-verify fingerprint your.fcidump

# 4. Before you pay: the completion proof
./target/release/become-verify completion.bin your.fcidump --level <level>

# 5. After you pay: both proofs together
./target/release/become-verify pair completion.bin final.bin your.fcidump --level <level>
```

`<level>` is the accuracy you ordered, as an integer in units of 10^-12 hartree: Standard `1593601437`,
Precise `1593601`, Ultra-precise `159`.

## What you see

The first line is `PASS` or `FAIL: <reason>`; the exit code is 0 for PASS, 1 for FAIL, 2 for a usage error.
A completion-proof PASS looks like:

```
PASS
  the proof verifies under the BECOME main_xc key 0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b
  it is about your file: SHA-256 <your file's SHA-256>
  level <proof level> meets your order <ordered level>; commitment C = <64 hex digits>
  completion proof: bounds sealed; the final proof will carry the same C
```

A pair PASS adds that both proofs carry the same commitment C, then prints your lower and upper bounds (in units of
10^-12 hartree).

## Program key

Proofs are checked against one fixed SP1 program key, built into the checker
([src/main.rs](src/main.rs)):

    0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b

## Checking with your AI instead

If your AI app has the BECOME connector, ask it "Verify my BECOME job <id>." BECOME's server then runs this same
checker, at a pinned commit (see Versions), on your job's files and reports the result. That is a convenience run by BECOME, not an
independent check; running the commands above on your own computer is.

## Versions

BECOME's server (the connector's check) runs the checker built from commit
[`f3961a9`](https://github.com/Beloved-Ecosystem-Inc/become-verify/commit/f3961a902492c611cdd464824ee83664eed5ddbb),
the first public release. Later commits on `main` so far only add documentation, the toolchain pin and build-warning
fixes (code used only by the tests is compiled only for the tests); the checking logic, the program key and the output
are the same, so either gives the same PASS/FAIL on the same files. To build exactly what the server runs:

```sh
git checkout f3961a902492c611cdd464824ee83664eed5ddbb
cargo build --release --locked
```

## Tests

```sh
cargo test --release --locked
```
