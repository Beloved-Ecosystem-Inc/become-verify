// The browser build (wasm/pkg) on the ethanol sample proofs, in Node: completion and pair PASS with the same lines
// the command-line tool prints, and FAIL for a changed byte, a swapped pair and the wrong file.
// Extra pairs: BV_EXTRA_PAIR="<completion>:<final>:<fcidump>:<level>" (checked for PASS; nothing is printed from it).
// Optional: BV_CLI=<path to become-verify> compares every line with the command-line tool's output.
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import { initSync, vkey, version, fingerprint, Fcidump, check_single, check_pair } from "../pkg/become_verify_wasm.js";

const here = new URL(".", import.meta.url);
const pkg = new URL("../pkg/", here), fx = new URL("../../tests/fixtures/ethanol-sample/", here);
initSync({ module: readFileSync(new URL("become_verify_wasm_bg.wasm", pkg)) });
const rd = (n) => readFileSync(new URL(n, fx));
const C = rd("completion.bin"), F = rd("final.bin"), FC = rd("pcq702_6-31g_cas8e8o.fcidump");
const SHA = "14199aece64925c7b73f7e65e42448d7a288ef6f837939a0ed4d159b58000cfe";

function fcInfo(bytes, chunk = 4097) {
  const h = new Fcidump();
  for (let i = 0; i < bytes.length; i += chunk) h.update(bytes.subarray(i, i + chunk));
  return JSON.parse(h.finish());
}
function cli(args) {
  try { return execFileSync(process.env.BV_CLI, args, { encoding: "utf8" }); } catch (e) { return e.stdout; }
}

test("key, version, fingerprint and streamed FCIDUMP header", () => {
  assert.equal(vkey(), "0x002904457a39ce1123f797598dfbac0fd12d7844be883c7154f37de353c81a2b");
  assert.match(version(), /^\d+\.\d+\.\d+$/);
  assert.equal(fingerprint(FC), SHA);
  const q = fcInfo(FC);
  assert.deepEqual([q.ok, q.norb, q.nelec, q.sha256, q.bytes], [true, 8, 8, SHA, FC.length]);
  assert.deepEqual(fcInfo(FC, 7), q);
  assert.equal(JSON.parse(new Fcidump().finish()).ok, false);
});

test("completion PASS, pair PASS", () => {
  const s = JSON.parse(check_single(C, 8, 8, SHA, "159"));
  assert.equal(s.verdict, "PASS"); assert.equal(s.proof.kind, "completion"); assert.equal(s.proof.sha256, SHA);
  assert.equal(s.lines[0], "PASS"); assert.ok(!("lower_pHa" in s.proof));
  const p = JSON.parse(check_pair(C, F, 8, 8, SHA, "159"));
  assert.equal(p.verdict, "PASS"); assert.equal(p.completion.commitment, p.final.commitment);
  assert.equal(p.final.level, 159);
  assert.ok(BigInt(p.final.lower_pHa) <= BigInt(p.final.upper_pHa));
  assert.ok(BigInt(p.final.upper_pHa) - BigInt(p.final.lower_pHa) <= 159n);
  if (process.env.BV_CLI) {
    const tmp = (n) => new URL(n, fx).pathname;
    assert.equal(cli([tmp("completion.bin"), tmp("pcq702_6-31g_cas8e8o.fcidump"), "--level", "159"]), s.lines.join("\n") + "\n");
    assert.equal(cli(["pair", tmp("completion.bin"), tmp("final.bin"), tmp("pcq702_6-31g_cas8e8o.fcidump"), "--level", "159"]), p.lines.join("\n") + "\n");
  }
});

test("FAIL: changed bytes, swapped pair, wrong file, tighter order, bad input", () => {
  for (const i of [4, 50, 300, 900, 1686, 1782, 1850]) {
    const b = Buffer.from(F); b[i] ^= 1;
    const r = JSON.parse(check_pair(C, b, 8, 8, SHA, "159"));
    assert.equal(r.verdict, "FAIL", "byte " + i); assert.match(r.lines[0], /^FAIL: /);
  }
  assert.match(JSON.parse(check_pair(F, C, 8, 8, SHA, "159")).error, /^completion\.bin: mode md = 0 != expected mode 1/);
  assert.match(JSON.parse(check_single(C, 8, 8, "00".repeat(32), "159")).error, /D0\.\.D7 != sha256/);
  assert.match(JSON.parse(check_single(C, 8, 6, SHA, "159")).error, /nelec/);
  assert.match(JSON.parse(check_single(C, 8, 8, SHA, "158")).error, /looser than the ordered level 158/);
  assert.equal(JSON.parse(check_single(C, 8, 8, "xyz", "159")).verdict, "FAIL");
  assert.equal(JSON.parse(check_single(C, 8, 8, SHA, "-1")).verdict, "FAIL");
  assert.equal(JSON.parse(check_single(new Uint8Array(0), 8, 8, SHA, "159")).verdict, "FAIL");
});

test("extra pairs (BV_EXTRA_PAIR)", { skip: !process.env.BV_EXTRA_PAIR }, () => {
  for (const spec of process.env.BV_EXTRA_PAIR.split(",")) {
    const [c, f, fc, lv] = spec.split(":");
    const q = fcInfo(readFileSync(fc));
    const r = JSON.parse(check_pair(readFileSync(c), readFileSync(f), q.norb, q.nelec, q.sha256, lv));
    assert.equal(r.verdict, "PASS", r.error);
    const t = Buffer.from(readFileSync(f)); t[900] ^= 1;
    assert.equal(JSON.parse(check_pair(readFileSync(c), t, q.norb, q.nelec, q.sha256, lv)).verdict, "FAIL");
  }
});

test("pkg matches wasm/SHA256SUMS", () => {
  const sums = readFileSync(new URL("../SHA256SUMS", here), "utf8").trim().split("\n").map((l) => l.split(/\s+/));
  for (const [h, n] of sums) assert.equal(createHash("sha256").update(readFileSync(new URL(n.replace(/^pkg\//, ""), pkg))).digest("hex"), h, n);
});
