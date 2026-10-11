#!/usr/bin/env node
/*
 * RelayProof command line — the same policy engine, scriptable.
 *
 *   node cli.js plan "Refund order ORD-7812 for $289"   plan + verify one request
 *   node cli.js plan --json "..."                         machine-readable output
 *   node cli.js batch inbox.txt                           triage a whole inbox file
 *   node cli.js batch --sample                            triage the built-in sample inbox
 *   node cli.js verify report.json                        check a report for tampering
 *   node cli.js redteam                                   run the adversarial suite (CI gate)
 */
const fs = require("fs");
const core = require("./lib/core.js");

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (text) => (tty ? "\x1b[" + code + "m" + text + "\x1b[0m" : String(text));
const c = { bold: paint(1), dim: paint(2), red: paint(31), green: paint(32), yellow: paint(33), magenta: paint(35), cyan: paint(36) };
const riskColor = { LOW: c.green, MEDIUM: c.yellow, HIGH: c.magenta, BLOCKED: c.red };

function usage() {
  console.log([
    c.bold("RelayProof CLI") + " — AI automation with proof before action",
    "",
    "  node cli.js plan [--json] \"request text\"",
    "  node cli.js batch [--json] <file | --sample>",
    "  node cli.js verify <report.json>",
    "  node cli.js redteam [--json]",
    ""
  ].join("\n"));
}

function printRun(run) {
  const p = run.plan;
  const color = riskColor[p.riskLevel] || ((x) => x);
  console.log(c.bold(p.title) + "  " + color(p.riskLevel + " " + p.riskScore + "/100") + "  " + c.dim(run.id));
  console.log(c.dim(p.riskReason));
  console.log("");
  p.fields.forEach((f) => console.log("  " + c.cyan(f.label.padEnd(18)) + f.value));
  console.log("");
  p.steps.forEach((s, i) => {
    const t = run.timeline[i];
    const mark = { done: c.green("✓"), waiting: c.yellow("⏸"), locked: c.red("✕"), skipped: c.dim("–"), pending: c.dim("…"), rejected: c.red("✕") }[t.state] || "?";
    console.log("  " + mark + " " + String(i + 1).padStart(2, "0") + " " + s.title.padEnd(36) + c.dim(t.output));
  });
  console.log("");
  run.checks.forEach((ch) => {
    const mark = ch.state === "pass" ? c.green("PASS") : ch.state === "warn" ? c.yellow("WARN") : c.red("FAIL");
    console.log("  " + mark + "  " + ch.name.padEnd(26) + c.dim(ch.detail));
  });
  if (run.artifacts.questions.length) {
    console.log("\n" + c.bold("Clarification questions"));
    run.artifacts.questions.forEach((q) => console.log("  • " + q));
  }
  console.log("\n" + c.bold("Status: ") + run.status + c.dim("  · est. " + run.minutesSaved + " min of manual work prepared · audit head " + run.events[run.events.length - 1].hash.slice(0, 12)));
}

function cmdPlan(args) {
  const json = args.includes("--json");
  const text = args.filter((a) => a !== "--json").join(" ").trim();
  if (!text) return usage(), 1;
  const run = core.createRun(text, core.localPlan(text));
  if (json) console.log(JSON.stringify(core.buildReport(run), null, 2));
  else printRun(run);
  return 0;
}

function cmdBatch(args) {
  const json = args.includes("--json");
  const target = args.find((a) => a !== "--json");
  if (!target) return usage(), 1;
  const source = target === "--sample" ? core.SAMPLE_INBOX : fs.readFileSync(target, "utf8");
  const runs = core.splitBatch(source).map((text) => core.createRun(text, core.localPlan(text)));
  if (json) {
    console.log(JSON.stringify(runs.map(core.buildReport), null, 2));
    return 0;
  }
  console.log(c.bold("Inbox autopilot — " + runs.length + " requests\n"));
  runs.forEach((run, i) => {
    const color = riskColor[run.plan.riskLevel];
    console.log(
      "  " + String(i + 1).padStart(2) + ". " + run.plan.title.padEnd(34) +
      color(run.plan.riskLevel.padEnd(8)) + run.status.padEnd(19) +
      c.dim(run.plan.missing.length + " missing · " + run.inputRedacted.slice(0, 48) + (run.inputRedacted.length > 48 ? "…" : ""))
    );
  });
  const count = (s) => runs.filter((r) => r.status === s).length;
  const minutes = runs.reduce((sum, r) => sum + r.minutesSaved, 0);
  console.log("\n  " + c.green(count("COMPLETED") + " auto-completed") + " · " + c.yellow(count("AWAITING APPROVAL") + " awaiting approval") + " · " + c.red(count("BLOCKED") + " blocked") + c.dim(" · est. " + minutes + " min of manual work prepared"));
  return 0;
}

function cmdVerify(args) {
  if (!args[0]) return usage(), 1;
  let report;
  try {
    report = JSON.parse(fs.readFileSync(args[0], "utf8"));
  } catch (error) {
    console.error(c.red("Could not read JSON: " + error.message));
    return 2;
  }
  const result = core.verifyReport(report);
  console.log((result.ok ? c.green("✓ ") : c.red("✕ ")) + result.reason);
  return result.ok ? 0 : 3;
}

function cmdRedTeam(args) {
  const result = core.runRedTeam();
  if (args.includes("--json")) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(c.bold("RelayProof red-team suite\n"));
    result.results.forEach((r) => {
      console.log("  " + (r.pass ? c.green("PASS") : c.red("FAIL")) + "  " + r.name.padEnd(32) + c.dim(r.actual.level + " " + r.actual.score + "/100" + (r.problems.length ? " — " + r.problems.join("; ") : "")));
    });
    console.log("\n  " + (result.passed === result.total ? c.green : c.red)(result.passed + "/" + result.total + " cases handled as expected"));
  }
  return result.passed === result.total ? 0 : 1;
}

function main(argv) {
  const [command, ...args] = argv;
  switch (command) {
    case "plan": return cmdPlan(args);
    case "batch": return cmdBatch(args);
    case "verify": return cmdVerify(args);
    case "redteam": return cmdRedTeam(args);
    default: usage(); return command ? 1 : 0;
  }
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { main: main };
