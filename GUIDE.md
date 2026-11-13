# Checking your BECOME certified ground-state energy

You receive two proofs for your Hamiltonian (your FCIDUMP file), and a small program, `become-verify`, that checks them
on your own computer. Nothing is sent anywhere and nothing about BECOME has to be trusted beyond what is listed under
"What you are trusting" below.

## What you receive

| When | File |
|---|---|
| With the completion ("target met") notice | `completion.bin` (the completion proof: bounds sealed) |
| After payment | `final.bin` (the final proof: bounds revealed) |

Each is a standard SP1 6.8.1 proof file (`SP1ProofWithPublicValues`; your job page may call both `proof.bin`): a Groth16 proof plus its 200 bytes of public values. Both are
checked against one fixed program key, built into the checker:

    0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b

## Build the checker

Install Rust (https://rustup.rs), then in this repository's folder (the one with `Cargo.toml`):

    git clone https://github.com/Beloved-Ecosystem-Inc/become-verify
    cd become-verify
    cargo build --release --locked

`rust-toolchain.toml` pins the Rust version we build and test with.

It uses only the official pure-Rust SP1 6.8.1 Groth16 verifier. It contains no prover and makes no network calls.

## Check 1: the completion proof (before you pay)

    ./target/release/become-verify completion.bin your.fcidump --level <ordered-level>

The first line is `PASS` or `FAIL` (with the reason); the exit code is 0 for PASS, 1 for FAIL and 2 for a usage error.
`PASS` means:
- the Groth16 proof is genuine and was made by BECOME's checking program (the key above);
- it is about your file (it carries the SHA-256 of your file, which the checker computes itself);
- certified lower and upper bounds on the ground-state energy exist for your file, within your ordered accuracy;
- the bounds are sealed: the proof shows zeros in their place and a commitment C.

## Check 2: the final proof, and that it matches (after you pay)

    ./target/release/become-verify pair completion.bin final.bin your.fcidump --level <ordered-level>

`PASS` means both proofs are genuine, both are about your file, and they carry the same commitment C, so the bounds the
final proof reveals are exactly the ones sealed before you paid. It then prints your lower and upper bounds.

`become-verify fingerprint your.fcidump` prints the SHA-256 of your file (the same as `sha256sum`).

## Reading the numbers

- Energies and levels are whole numbers in units of 10^-12 hartree: a printed bound of `-154073387319800` means
  -154.0733873198 Ha.
- The accuracy levels as integers: Standard `1593601437`, Precise `1593601`, Ultra-precise `159`.
- A proof made at a tighter level is accepted for any looser order (if u - l is within the Ultra-precise width, it is
  within the Standard width too). The checker prints the proof's own level and your ordered level.

## What the 200 public bytes contain

25 words of 8 bytes, little-endian: hi verdict; upper bound u (0 in a completion proof); norb; nelec; the SHA-256 of
your file as 8 words D0..D7; lo verdict; lower bound l (0 in a completion proof); mode (1 = completion, 0 = final);
level t; accept bit; commitment C as 8 words.

## The commitment

C is a hash of the two bounds and a secret 256-bit random value. Which hash is used is fixed by the program key:

| Program key | Commitment hash |
|---|---|
| `0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b` | Poseidon2 (KoalaBear field) |

The checker confirms that your completion and final proofs carry the same C; that equality is what ties the revealed
bounds to the sealed ones. Recomputing C yourself from the bounds and the random value is not part of this version.

## What you are trusting

- The mathematics of the question: what "lower and upper bounds on the ground-state energy of this FCIDUMP" means, as
  written in BECOME's public Coq definition `ClaimX` (closed-shell sector, MS2 = 0).
- The Coq proof checker, which checked that BECOME's program only accepts correct bounds.
- SP1 (version 6.8.1) and its Groth16 setup, which prove that this exact program ran.
- SHA-256, and the commitment hash named for your program key above, as hash functions.

You do not need to trust BECOME's numerical methods, its computers or its word.

## Licence

This checker is licensed under the Apache License, Version 2.0 (see `LICENSE`).
