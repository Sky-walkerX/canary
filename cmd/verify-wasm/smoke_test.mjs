// Smoke test for the browser checker. It runs by hand, never in CI: CI stays
// free of Node, and check_test.go covers the same Go code natively.
//
// Run it from the repository root, after building the module:
//
//   make wasm
//   node cmd/verify-wasm/smoke_test.mjs              # reads bin/wasm
//   node cmd/verify-wasm/smoke_test.mjs path/to/dir  # or another directory
//
// It loads canary.wasm with the wasm_exec.js that make wasm copied beside it,
// the same pair a browser loads. Then it checks the formats doc's example
// evidence file, a copy with one hex digit flipped, and a file that is not
// JSON. Every network API is replaced with one that records the attempt, and
// the test fails if the checker tried any of them.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const dir = path.resolve(root, process.argv[2] ?? "bin/wasm");
const doc = readFileSync(path.join(root, "docs/design/2026-09-30-v1-formats.md"), "utf8");

// docExample returns the first JSON block under "### Example" in the doc
// section whose heading starts with heading, as check_test.go reads it.
function docExample(heading) {
  let s = doc.slice(doc.indexOf("\n" + heading) + 1);
  assert.ok(s.startsWith(heading), `no section ${heading} in the formats doc`);
  const next = s.indexOf("\n## ", heading.length);
  if (next >= 0) s = s.slice(0, next);
  s = s.slice(s.indexOf("\n### Example"));
  s = s.slice(s.indexOf("```json\n") + "```json\n".length);
  return s.slice(0, s.indexOf("\n```") + 1);
}

// Record any attempt to reach the network. The checker must make none.
const attempts = [];
const refuse = (api) => (...args) => {
  attempts.push(`${api} ${String(args[0])}`);
  throw new Error(`smoke: the checker used ${api}`);
};
globalThis.fetch = refuse("fetch");
globalThis.WebSocket = function (url) { refuse("WebSocket")(url); };
globalThis.XMLHttpRequest = function () { refuse("XMLHttpRequest")(""); };
globalThis.EventSource = function (url) { refuse("EventSource")(url); };

// wasm_exec.js is a classic script that defines globalThis.Go.
vm.runInThisContext(readFileSync(path.join(dir, "wasm_exec.js"), "utf8"), { filename: "wasm_exec.js" });
const wasm = readFileSync(path.join(dir, "canary.wasm"));

const t0 = performance.now();
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
go.run(instance); // main sets the functions, then blocks in select {}
const loadMs = performance.now() - t0;
assert.equal(typeof globalThis.canaryVerify, "function", "canaryVerify is not set");
assert.equal(typeof globalThis.canaryCheckerInfo, "function", "canaryCheckerInfo is not set");

function verify(input) {
  const out = globalThis.canaryVerify(input);
  assert.equal(typeof out, "string", "canaryVerify did not return a string");
  return JSON.parse(out);
}

// The report fields only, without the two the checker adds.
function reportOf(out) {
  const { headline, html, ...report } = out;
  return report;
}

const good = docExample("## 6. The evidence file");
const wantReport = JSON.parse(docExample("## 7. VerifyReport and error codes"));

// The tampered copy flips one hex digit of the first proof sibling, as the
// public site's labelled copy does.
const sibling = JSON.parse(good).proof.siblings[0];
const flipped = (parseInt(sibling[1], 16) ^ 1).toString(16);
const tampered = good.replace(sibling, sibling[0] + flipped + sibling.slice(2));
assert.notEqual(tampered, good);
assert.equal(tampered.length, good.length);

const results = [];
function run(name, fn) {
  try {
    fn();
    results.push(`ok   ${name}`);
  } catch (err) {
    results.push(`FAIL ${name}: ${err.message}`);
  }
}

let goodMs = 0;
run("the doc example checks out, with the doc's report", () => {
  const t = performance.now();
  const out = verify(good);
  goodMs = performance.now() - t;
  assert.deepEqual(reportOf(out), wantReport);
  assert.equal(out.headline, "Checks out.");
  assert.ok(out.html.startsWith('<div class="report">'), "html is not the report partial");
  assert.equal(out.html.match(/class="step step-pass"/g)?.length, 8, "html does not show eight passed steps");
  assert.equal(out.error, undefined, "a report with markup names an error");
});

run("bytes and a string give the same output", () => {
  assert.equal(globalThis.canaryVerify(new TextEncoder().encode(good)), globalThis.canaryVerify(good));
});

run("the tampered copy does not check out, naming the inclusion step", () => {
  const out = verify(tampered);
  assert.equal(out.result, "does_not_check_out");
  assert.equal(out.code, "proof_invalid");
  assert.equal(out.headline, "Does not check out: inclusion failed.");
  const inclusion = out.checks.find((c) => c.step === "inclusion");
  assert.equal(inclusion.ok, false);
  assert.ok(out.html.includes('class="step step-fail"'), "html marks no step failed");
});

run("a file that is not JSON can't be read", () => {
  const out = verify("this is not an evidence file");
  assert.equal(out.result, "unreadable");
  assert.equal(out.code, "malformed");
  assert.equal(out.headline, "Can't read this file: it is not valid canary-evidence/1.");
  assert.ok(out.html.startsWith('<div class="report">'));
});

run("a call with no argument is a file it can't read", () => {
  assert.equal(verify().result, "unreadable");
});

run("canaryCheckerInfo names the build and the size limit", () => {
  const info = JSON.parse(globalThis.canaryCheckerInfo());
  assert.match(info.go_version, /^go1\./);
  assert.equal(info.go_release, "Go " + info.go_version.slice(2));
  assert.equal(info.max_file_bytes, 16 << 20);
  assert.ok(info.too_large.startsWith("Can't read this file: "));
  assert.ok(info.not_opened.startsWith("Can't read this file: "));
});

run("the checker made no network request", () => {
  assert.deepEqual(attempts, []);
});

console.log(results.join("\n"));
console.log(`canary.wasm: ${wasm.length} bytes; load and start ${loadMs.toFixed(0)} ms; first check ${goodMs.toFixed(1)} ms`);
const failed = results.filter((r) => r.startsWith("FAIL")).length;
process.exit(failed ? 1 : 0);
