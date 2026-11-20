#!/usr/bin/env bash
# Usage: check.sh FCIDUMP [PREFIX]
# Builds the Question and the Coq data layer for FCIDUMP in a fresh folder (work-PREFIX), checks that the
# proofs use no axioms beyond Coq's primitive integers and arrays, and that the SHA-256 proven in Coq is
# the file's SHA-256. COQCHK=1 also re-checks every compiled file with coqchk (slower).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
p=${2:-DATA}
w=$PWD/work-$p
coqc --version | grep -q 'version 8\.18\.' || { echo "FAIL: needs Coq 8.18"; exit 1; }
rm -rf "$w"; mkdir -p "$w"
cp "$here"/FCIDUMP_lib.v "$here"/FCIDUMP_len.v "$here"/FCIDUMP_parse.v "$here"/EnergyQuestion.v \
   "$here"/gen.py "$here"/run_all.sh "$w"/
cd "$w"
python3 gen.py "$src" "$p"
bash run_all.sh "$p" "${JOBS:-2}" || true
grep -q '^ALL DONE' progress.log || { cat progress.log; echo "FAIL: build"; exit 1; }
coqc -Q . '' EnergyQuestion.v
cat > Assumptions.v <<V
Require Import ${p}_data ${p}_recs.
Print Assumptions data_sha256.
Print Assumptions parse_B0.
Print Assumptions I0_wellformed.
V
coqc -Q . '' Assumptions.v > assumptions.log
if grep -E '^[A-Za-z_][A-Za-z0-9_.]* :' assumptions.log | grep -vE '^(PrimInt63|PArray)\.' ; then
  echo "FAIL: unexpected assumption"; exit 1
fi
proven=$(sed -n 's/^Definition sha256_expected : String.string := "\([0-9a-f]*\)".*/\1/p' "${p}_data.v")
actual=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$src")
[ -n "$proven" ] && [ "$proven" = "$actual" ] || { echo "FAIL: proven $proven, file $actual"; exit 1; }
if [ "${COQCHK:-0}" = 1 ]; then
  coqchk -silent -Q . '' -norec FCIDUMP_lib FCIDUMP_len FCIDUMP_parse EnergyQuestion \
    $(ls ${p}_data*.vo ${p}_recs*.vo | sed 's/\.vo$//')
fi
echo "OK $actual"
