# Ethanol sample

BECOME's public sample proofs (an internal ethanol test job, Ultra-precise, `--level 159`), as published at
https://become.belovedecosystem.com/energy/verify-sample/ with the public catalog FCIDUMP
(PubChem CID 702, 6-31G*, CAS(8e,8o); SHA-256 `14199aece64925c7b73f7e65e42448d7a288ef6f837939a0ed4d159b58000cfe`).

| File | SHA-256 |
|---|---|
| `completion.bin` | `8951e819816781df4c85e7db659f9a192ca1fd4f611ef2a1438546bd78995d7d` |
| `final.bin` | `4c2cdb301af221b36f8f0962e66418c34d7d39a5eee35c57faa84e4c27cd0394` |

Used by `tests/sample.rs` (the command-line tool) and `wasm/test/node-test.mjs` (the browser build).
