# become-verify

Verify-only checker for BECOME certified ground-state energy proofs (SP1 6.8.1 Groth16, program `main_xc`).
It runs on your own computer, makes no network calls and contains no prover. Licensed under Apache-2.0.

Full explanation (what PASS means, the 200 public bytes, the commitment, what you are trusting): [GUIDE.md](GUIDE.md).

## Download (no Rust needed)

Each release on the [Releases page](https://github.com/Beloved-Ecosystem-Inc/become-verify/releases) has a
ready-to-run program for your computer, built by GitHub Actions from the tagged source
([.github/workflows/release.yml](.github/workflows/release.yml)), with a `SHA256SUMS` file and a GitHub build
provenance attestation for every file.

| Computer | File |
|---|---|
| Linux, Intel/AMD (x86_64) | `become-verify-v<version>-linux-x86_64` |
| Linux, ARM (arm64) | `become-verify-v<version>-linux-arm64` |
| Mac, Apple silicon (M1 and later) | `become-verify-v<version>-macos-arm64` |
| Mac, Intel | `become-verify-v<version>-macos-x86_64` |
| Windows (x86_64) | `become-verify-v<version>-windows-x86_64.exe` |

```sh
# Linux or Mac (pick your file from the table; <version> is the release, e.g. 0.2.0)
V=0.2.0; F=become-verify-v$V-macos-arm64
curl -fLO https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/download/v$V/$F
curl -fLO https://github.com/Beloved-Ecosystem-Inc/become-verify/releases/download/v$V/SHA256SUMS
grep " $F\$" SHA256SUMS | sha256sum -c -        # on a Mac: grep " $F\$" SHA256SUMS | shasum -a 256 -c -
chmod +x $F && mv $F become-verify
./become-verify pair completion.bin final.bin your.fcidump --level <level>
```

On Windows (PowerShell), download the `.exe` and `SHA256SUMS` from the release, compare
`Get-FileHash .\become-verify-v<version>-windows-x86_64.exe` with its line in `SHA256SUMS`, then run
`.\become-verify-v<version>-windows-x86_64.exe pair completion.bin final.bin your.fcidump --level <level>`.

Files downloaded with `curl` run as they are. A Mac may block a file downloaded with a browser because it is not
signed by Apple: run `xattr -d com.apple.quarantine become-verify` once. Windows SmartScreen may ask you to confirm.

To check where a file came from: `gh attestation verify <file> --repo Beloved-Ecosystem-Inc/become-verify` confirms it
was built by this repository's release workflow from the tagged commit.

## In your browser

[wasm/](wasm/) builds the same checks for the browser (WebAssembly): the same code in [src/lib.rs](src/lib.rs), the same
program key, the same PASS/FAIL lines. It runs on your own computer inside the web page; proof files and your FCIDUMP
are read there and are not sent anywhere. The build is reproducible: `wasm/build.sh` gives the same bytes as
[wasm/SHA256SUMS](wasm/SHA256SUMS), and CI checks that on every change. BECOME's "Verify in your browser" page shows
the SHA-256 of the WebAssembly file it ran and the commit it was built from, so you can rebuild it and compare.

## Build from source

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
([src/lib.rs](src/lib.rs)):

    0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b

## Checking with your AI instead

If your AI app has the BECOME connector, ask it "Verify my BECOME job <id>." BECOME's server then runs this same
checker, at a pinned commit (see Versions), on your job's files and reports the result. That is a convenience run by
BECOME, not an independent check; running it on your own computer (a download, a build from source, or the browser
page) is. An AI that can run code can also download a release and run the commands above itself.

## Versions

BECOME's server (the connector's check) runs the checker built from commit
[`f3961a9`](https://github.com/Beloved-Ecosystem-Inc/become-verify/commit/f3961a902492c611cdd464824ee83664eed5ddbb),
the first public release. Later commits keep the checking logic, the program key and the output the same, so every
version gives the same PASS/FAIL and the same lines on the same files. Version 0.2.0 moves the checks into a library
(`src/lib.rs`) shared with the browser build and builds the SP1 verifier without its unused compressed-proof part
(`default-features = false`; the Groth16 verifier is the same code); its output is byte-for-byte the same as `f3961a9`'s
on the sample proofs and on failing inputs. To build exactly what the server runs:

```sh
git checkout f3961a902492c611cdd464824ee83664eed5ddbb
cargo build --release --locked
```

## Code layout

- `src/lib.rs`: the checks (Groth16 under the built-in key, then the public values against your file), used by both
  the command-line tool and the browser build
- `src/proofbin.rs`: reads the SP1 proof file
- `src/pv.rs`: the 200 public bytes and the acceptance rules
- `src/main.rs`: the command-line tool
- `wasm/`: the browser build

## Tests

```sh
cargo test --release --locked            # includes the real ethanol sample proofs (tests/fixtures/ethanol-sample)
wasm/build.sh && node --test wasm/test/node-test.mjs
```
