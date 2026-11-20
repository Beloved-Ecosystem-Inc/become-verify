# The question in Coq

A BECOME energy result is about two things both sides hold:

- **Data**: your FCIDUMP file (for catalog molecules, see the [FCIDUMP catalog](https://zenodo.org/records/23601240)).
- **Question**: `EnergyQuestion.v` with `FCIDUMP_lib.v`. `ClaimX b x l u` says the bytes `b` parse to an FCIDUMP
  whose Hamiltonian's lowest energy lies in [l, u] × 10^-12 hartree, with u − l ≤ x. Both files use only Coq's
  standard library.

`gen.py` turns an FCIDUMP into Coq files holding its bytes, with proofs (checked by Coq, not by the script) that
the bytes have the file's SHA-256 and that `FCIDUMP.parse` reads them. `FCIDUMP_parse.v` and `FCIDUMP_len.v` are
the general lemmas those proofs use.

## Check

Needs Coq 8.18 and Python 3.

```sh
question/check.sh your.fcidump MOL       # COQCHK=1 also runs coqchk
become-verify fingerprint your.fcidump    # the same SHA-256 your proof is about
```

`OK <sha256>` means everything compiled, the proofs assume nothing beyond Coq's primitive integers and arrays, and
the SHA-256 proven in Coq is your file's. The ethanol sample:

```sh
question/check.sh tests/fixtures/ethanol-sample/pcq702_6-31g_cas8e8o.fcidump ETH
# OK 14199aece64925c7b73f7e65e42448d7a288ef6f837939a0ed4d159b58000cfe
```

| File | SHA-256 |
|---|---|
| `EnergyQuestion.v` | `92f83b19b4eec91b9b5827b5c7d27b666d8294a149918ba1408e3919d8c6a7ff` |
| `FCIDUMP_lib.v` | `8a5555985f8f6ee9f9bab9270d111d84d26874e5bd0d0b57ce9bbf8066dd5af3` |
| `FCIDUMP_parse.v` | `e2f3519c6cb6ecb46cf1da82c3e1e45de43bda831c7446ab23c7b08923973707` |
| `FCIDUMP_len.v` | `ab9f09af6a06d627abfc88b7cd155d46d1b800513fcd5eece1d5c98bd4980a3e` |
| `gen.py` | `7e44677cf0defbf958406218b9012dba77d71de3e6335605992579853529d91d` |
