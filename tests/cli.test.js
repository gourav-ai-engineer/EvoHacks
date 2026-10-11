const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const CLI = path.join(__dirname, "..", "cli.js");
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env: Object.assign({}, process.env, { NO_COLOR: "1" }) });

test("redteam command exits 0 when every case passes", () => {
  const result = run("redteam");
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /cases handled as expected/);
});

test("plan --json output verifies, and a tampered copy fails with exit code 3", () => {
  const out = run("plan", "--json", "Invoice INV-9 from Acme is for $1,200 but the PO shows $1,000.");
  assert.equal(out.status, 0);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "relayproof-"));
  const good = path.join(dir, "good.json");
  const bad = path.join(dir, "bad.json");
  fs.writeFileSync(good, out.stdout);
  const report = JSON.parse(out.stdout);
  report.plan.riskLevel = "LOW";
  fs.writeFileSync(bad, JSON.stringify(report));
  assert.equal(run("verify", good).status, 0);
  const tampered = run("verify", bad);
  assert.equal(tampered.status, 3);
  assert.match(tampered.stdout, /Tampered/);
});

test("batch --sample triages the sample inbox", () => {
  const result = run("batch", "--sample");
  assert.equal(result.status, 0);
  assert.match(result.stdout, /1 blocked/);
});
