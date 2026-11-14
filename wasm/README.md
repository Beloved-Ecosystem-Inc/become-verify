# become-verify in the browser

The same checks as the command-line tool, compiled to WebAssembly: this crate is a thin layer over `../src/lib.rs`
(the program key, the proof-file reader, the SP1 Groth16 verifier, the public-value rules and the PASS/FAIL lines are
shared, not copied). It touches no network: a page hands it bytes it already holds.

## Build (reproducible)

Needs the Rust toolchain pinned in `../rust-toolchain.toml` and `wasm-bindgen-cli` 0.2.100
(`cargo install wasm-bindgen-cli --version 0.2.100 --locked`):

    wasm/build.sh
    (cd wasm && sha256sum -c SHA256SUMS)

`build.sh` maps local folder names away and builds with one codegen unit and no debug info, so the same commit gives
the same `pkg/become_verify_wasm_bg.wasm` on any machine. CI rebuilds it on every change and fails if the bytes differ
from `SHA256SUMS`.

## Use

    import init, { check_single, check_pair, Fcidump, vkey, version } from "./pkg/become_verify_wasm.js";
    await init({ module_or_path: wasmBytes });
    const fc = new Fcidump(); fc.update(fcidumpBytes); const q = JSON.parse(fc.finish());  // norb, nelec, sha256
    JSON.parse(check_single(completionBytes, q.norb, q.nelec, q.sha256, "159"));           // become-verify completion.bin
    JSON.parse(check_pair(completionBytes, finalBytes, q.norb, q.nelec, q.sha256, "159")); // become-verify pair

Each result has `verdict` (`PASS` or `FAIL`), `lines` (exactly what the command-line tool prints), and on PASS the
decoded fingerprint, level and commitment (and, for a final proof, the bounds).

## Test

    node --test wasm/test/node-test.mjs     # after build.sh; BV_CLI=<become-verify> also compares every line
