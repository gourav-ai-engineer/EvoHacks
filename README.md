# RelayProof

**AI automation with proof before action.**

Paste a messy request, or a whole inbox. RelayProof extracts the details, drafts the follow-up message and task ticket, and asks for whatever is missing. Risky actions pause until a person approves them, prompt-injection attacks are blocked, and every run leaves a tamper-evident audit trail.

> Built for **EvoHacks 2026: AI for Automation**. Everything runs as a safe simulation: RelayProof never sends messages, grants access, moves money or deletes data.

```
Request ──► Injection shield ──► Privacy redaction ──► AI / rules plan ──► 6 verification gates
                                                                              │
          Tamper-evident report ◄── Hash-chained audit ◄── Simulate ◄── Human gate (approve / reject)
```

![Workflow studio: an invoice exception with an explainable risk score, extracted fields, a missing PO number and steps paused at the human gate](docs/screenshot-studio.png)

| Prompt-injection attack, blocked before the AI | Inbox autopilot: six requests triaged at once |
| --- | --- |
| ![Blocked attack](docs/screenshot-blocked.png) | ![Inbox autopilot](docs/screenshot-inbox.png) |

---

## Why it exists

AI can turn a sentence into an action plan in seconds. In real operations (school admin, finance, customer support), speed alone isn't enough: a vague request, an over-permissioned action or a prompt-injection attack can cause expensive mistakes. Most automation demos go straight from intent to execution. RelayProof adds the missing layer: **plan, prove it, then act**.

## What it automates

| Manual chore | What RelayProof does automatically |
| --- | --- |
| Reading a request and pulling out the details | Extracts references (INV-, ORD-, PO-…), amounts and currency, dates, owners, vendors, systems and reasons |
| Noticing what's missing | Runs a per-category completeness check and writes **clarification questions** |
| Writing the follow-up | Drafts the **email/message** to the right person (approver, customer, finance or security) |
| Creating a ticket | Generates a **task ticket** with queue, priority (P0–P3), due date, labels and checklist |
| Triage of a full inbox | **Inbox autopilot** processes up to 20 requests at once and sorts them into auto-completed, awaiting approval and blocked |
| Spotting invoice mismatches | Computes the discrepancy, e.g. `$4,850 vs $4,580 · Δ $270 (5.6%)` |

## How it keeps automation safe

1. **Injection shield.** Six families of attack patterns (instruction override, role/mode hijack, secret or system-prompt exfiltration, approval bypass, encoded payloads, hidden markup) are detected after Unicode normalization, so tricks like zero-width characters don't slip through. Attacks are blocked **before** they reach the AI.
2. **Privacy shield.** Emails, phone numbers, Luhn-valid card numbers, government IDs, API keys and pasted passwords are redacted before the AI call, browser storage and report export.
3. **Explainable risk score (0–100).** Weighted signals (money movement +50, destructive +55, access changes +30, social-engineering pressure +15, …) show exactly *why* a request is LOW, MEDIUM or HIGH.
4. **AI can only make plans safer.** Model output is re-validated by the deterministic core. Risk can be raised but never lowered, unknown actions are replaced, and a human approval step is enforced for anything sensitive.
5. **A real human gate.** Gated runs pause at the approval step. An approver records a decision (with name and note); only then do the post-approval steps run and the "Open in email app" hand-off unlock. Blocked runs can never be approved, and bulk approval is disabled by design.
6. **Tamper-evident evidence.** Every event is SHA-256 hash-chained. Exported reports carry an integrity hash; re-upload a report (or run `node cli.js verify`) to detect any edit.
7. **Red-team suite in CI.** 16 adversarial and control cases run on every push, in the CLI and in the UI.

## Features

- **Workflow studio:** single-request planning with a five-stage track (Shield → Plan → Verify → Human gate → Simulate) and live step states
- **Human gate & outputs:** approve or reject, then copy or download the draft message, task ticket JSON and clarification questions
- **Verification report:** six gates (plan contract & allowlist, injection shield, risk gate, privacy shield, completeness, side-effect lock) plus a hash-chained audit trail
- **Inbox autopilot:** batch triage with summary chips and CSV export
- **Guardrails & red team:** see every rule and its weight, run the attack suite, and load any case with one click
- **Run history:** persisted in the browser, storing only redacted text
- **Two engines:** a deterministic local rules engine (works offline, no key) or Google Gemini through a hardened serverless API
- **CLI:** the same engine, scriptable for pipelines (`plan`, `batch`, `verify`, `redteam`)

## Quick start

No install or API key is needed.

```bash
git clone https://github.com/gourav-ai-engineer/EvoHacks.git
cd EvoHacks
node server.js            # → http://localhost:3000
```

You can also open `index.html` directly, or serve the folder with any static server (`python -m http.server`). Without the API, the app uses the local engine automatically.

### Enable AI planning (optional)

```bash
GEMINI_API_KEY=your-key node server.js
# optional: GEMINI_MODEL=gemini-3.5-flash-lite (default)
```

The header pill switches to **AI READY**. Keep the key server-side; never put it in `app.js`, HTML or a commit.

### Command line

```bash
node cli.js plan "Refund order ORD-7812 for \$289 because it arrived damaged"
node cli.js batch --sample          # triage the sample inbox
node cli.js plan --json "..." > report.json
node cli.js verify report.json      # exit code 3 if tampered
node cli.js redteam                 # exit code 1 if any case fails
```

### Tests

```bash
npm test          # 38 unit, API (mocked Gemini) and CLI tests, using Node's built-in runner
npm run redteam   # adversarial prompt suite
```

## Deploy

**Vercel (static app plus AI API):** import the repository, add `GEMINI_API_KEY` under Project Settings → Environment Variables, and deploy. `api/plan.js` becomes the serverless function, and `vercel.json` sets security headers and a 20-second limit.

**GitHub Pages (static, local engine):** Settings → Pages → Deploy from branch → `main` / root. All asset paths are relative, so it works from a sub-path.

## Architecture

```
lib/core.js       Shared engine (browser + Node, zero dependencies): normalization, injection shield,
                  redaction, extraction, risk scoring, completeness, planner, normalizePlan,
                  verification gates, run lifecycle, SHA-256, hash chain, reports, red-team suite
app.js            Web UI controller (rendering, approval flow, inbox autopilot, persistence)
index.html        Accessible single-page layout
styles.css        Responsive dark console theme
api/plan.js       Serverless endpoint: health check, rate limit, injection short-circuit,
                  redaction, Gemini JSON-schema call with timeout/retry, policy re-validation
server.js         Zero-dependency local server (static files + /api/plan)
cli.js            Command-line interface
tests/            node:test suites for core, API and CLI
```

One module enforces policy everywhere: the browser, the API, the CLI and CI all import `lib/core.js`, so the UI can never drift from what is tested.

### API

`GET /api/plan` → `{ status, version, ai, model }`

`POST /api/plan` with `{ "input": "..." }` → `{ mode, plan, ... }`, where `mode` is one of:

| mode | meaning |
| --- | --- |
| `gemini` | AI plan, re-validated by the policy core |
| `local-guard` | Injection shield blocked the request; the AI was never called |
| `local-demo` | No API key configured |
| `local-fallback` | Provider error, timeout or invalid JSON (`fallbackReason` explains which) |

## Honest limitations

- It is a prototype: no real integrations are connected, and every action is simulated.
- Pattern-based injection detection reduces risk but is **not** a complete defense against prompt injection.
- The report hash is tamper-*evident*, not tamper-*proof*. Someone who rewrites the whole file can recompute the hashes; production would sign reports with a server key.
- "Manual work prepared" is an estimate based on fixed per-step minutes (see `MANUAL_MINUTES` in `lib/core.js`).
- The rate limiter is in-memory per serverless instance.
- Before connecting real systems, a production version would need authentication, authorization, durable audit storage, integration-scoped credentials and an independent security review.

Use synthetic data only.

## License

MIT. See [LICENSE](LICENSE).
