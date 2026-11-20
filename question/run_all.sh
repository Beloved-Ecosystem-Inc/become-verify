#!/usr/bin/env bash
# Build the data layer: library and length lemmas, every chunk file, the top file (hash),
# then the parse library, every record file and the joining file (parse).
# Usage: run_all.sh [PREFIX] [JOBS]   (defaults: FEMOCO, 2)
# Run gen.py first; keep this script
# in the same folder as the .v files.
# Compiled files that are newer than their source and the library are reused,
# so an interrupted build can be restarted. Progress goes to progress.log.
set -u
cd "$(dirname "$0")" || exit 1
prefix=${1:-FEMOCO}
jobs=${2:-2}
start=$(date +%s)
mkdir -p logs
echo "start $(date)" > progress.log

coq() { bash -c "ulimit -s unlimited; coqc -Q . '' $1.v" > "logs/$1.log" 2>&1; }

for f in FCIDUMP_lib FCIDUMP_len; do
  if [ "$f.vo" -nt "$f.v" ] && [ "$f.vo" -nt FCIDUMP_lib.v ]; then
    echo "reuse $f" >> progress.log
  elif coq "$f"; then
    echo "ok $f" >> progress.log
  else
    echo "FAIL $f (see logs/$f.log)" >> progress.log; exit 1
  fi
done

ls "${prefix}"_data_p*.v 2>/dev/null | sed 's/\.v$//' | sort > chunks.txt
n=$(wc -l < chunks.txt)
if [ "$n" -eq 0 ]; then
  echo "FAIL no ${prefix}_data_p*.v files; run gen.py first" >> progress.log; exit 1
fi
echo "chunks: $n" >> progress.log

compile_one() {
  f=$1
  if [ "$f.vo" -nt "$f.v" ] && [ "$f.vo" -nt FCIDUMP_lib.vo ]; then
    echo "reuse $f" >> progress.log; exit 0
  fi
  s=$(date +%s)
  if bash -c "ulimit -s unlimited; coqc -Q . '' $f.v" > "logs/$f.log" 2>&1; then
    echo "ok $f $(( $(date +%s)-s ))s" >> progress.log
  else
    echo "FAIL $f $(( $(date +%s)-s ))s" >> progress.log
  fi
}
export -f compile_one
xargs -P "$jobs" -I{} bash -c 'compile_one {}' < chunks.txt

fail=$(grep -c '^FAIL' progress.log)
echo "chunks done after $(( $(date +%s)-start ))s, failed=$fail" >> progress.log
if [ "$fail" -ne 0 ]; then
  echo "stopping before the top file: fix the failed chunks (see logs/) and rerun" >> progress.log; exit 1
fi

s=$(date +%s)
if coq "${prefix}_data"; then
  echo "TOP ok $(( $(date +%s)-s ))s" >> progress.log
else
  echo "TOP FAIL $(( $(date +%s)-s ))s (see logs/${prefix}_data.log)" >> progress.log; exit 1
fi

# Whole-file parse: parse library, record files, joining file.
if [ -f "${prefix}_recs.v" ]; then
  if [ "FCIDUMP_parse.vo" -nt FCIDUMP_parse.v ] && [ FCIDUMP_parse.vo -nt FCIDUMP_lib.vo ]; then
    echo "reuse FCIDUMP_parse" >> progress.log
  elif coq FCIDUMP_parse; then echo "ok FCIDUMP_parse" >> progress.log
  else echo "FAIL FCIDUMP_parse (see logs/FCIDUMP_parse.log)" >> progress.log; exit 1; fi
  ls "${prefix}"_recs_p*.v | sed 's/\.v$//' | sort > recs.txt
  compile_rec() {
    f=$1; d=${f/_recs_/_data_}
    if [ "$f.vo" -nt "$f.v" ] && [ "$f.vo" -nt FCIDUMP_parse.vo ] && [ "$f.vo" -nt "$d.vo" ]; then
      echo "reuse $f" >> progress.log; exit 0
    fi
    s=$(date +%s)
    if bash -c "ulimit -s unlimited; coqc -Q . '' $f.v" > "logs/$f.log" 2>&1; then
      echo "ok $f $(( $(date +%s)-s ))s" >> progress.log
    else
      echo "FAIL $f $(( $(date +%s)-s ))s" >> progress.log
    fi
  }
  export -f compile_rec
  xargs -P "$jobs" -I{} bash -c 'compile_rec {}' < recs.txt
  fail=$(grep -c '^FAIL' progress.log)
  if [ "$fail" -ne 0 ]; then echo "stopping before ${prefix}_recs.v: $fail failure(s)" >> progress.log; exit 1; fi
  s=$(date +%s)
  if coq "${prefix}_recs"; then echo "RECS ok $(( $(date +%s)-s ))s" >> progress.log
  else echo "RECS FAIL $(( $(date +%s)-s ))s (see logs/${prefix}_recs.log)" >> progress.log; exit 1; fi
fi
echo "ALL DONE after $(( $(date +%s)-start ))s $(date)" >> progress.log
