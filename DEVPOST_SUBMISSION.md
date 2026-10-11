# Devpost submission kit: RelayProof

Copy each section into the matching Devpost field.

---

## Project name

RelayProof: AI Automation With Proof Before Action

## Tagline (≤ 200 chars)

Paste a messy request or a whole inbox. RelayProof drafts the follow-ups, asks for what's missing, blocks prompt-injection attacks, and pauses risky actions for a human, with a tamper-evident audit trail.

## Inspiration

At school and in part-time jobs we saw the same pattern: a lot of time goes into reading requests, copying details into tickets, chasing missing information and writing the same emails. AI can automate that, but the AI demos we tried jumped straight from "here's a sentence" to "action taken." In real operations, one wrong refund, one over-permissioned account or one hidden "ignore previous instructions" line can cost far more than the minutes saved. We wanted automation people can trust: **plan first, prove it, then act.**

## What it does

RelayProof turns unstructured requests into finished, reviewable work:

- **Extracts the details**: references (INV-, ORD-, PO-…), amounts, dates, owners, vendors, systems and reasons. For invoices it even computes the mismatch (`$4,850 vs $4,580 · Δ $270`).
- **Finds what's missing** with a per-category completeness check, then writes the clarification questions.
- **Produces the outputs**: a ready-to-send draft message to the right person and a task ticket with queue, priority, due date and checklist.
- **Inbox autopilot** triages up to 20 requests in one click: low-risk ones auto-complete, sensitive ones wait for approval, and attacks are blocked. Results export to CSV.

And it does this safely:

- **Injection shield** blocks six families of attacks (instruction override, jailbreak "developer mode", secret or system-prompt exfiltration, approval bypass, encoded payloads, hidden HTML comments) *before* the AI sees them, including zero-width-character tricks.
- **Privacy shield** redacts emails, phones, card numbers (Luhn-checked), government IDs, API keys and pasted passwords before the AI call, storage and export.
- **Explainable risk score (0–100)** shows exactly which signals drove the decision.
- **AI can only make plans safer**: model output is re-validated, so risk is never lowered, unknown actions are replaced, and approval is enforced.
- **A real human gate**: the run pauses at the approval step. An approver approves or rejects with a name and note, and only then do the remaining steps run and the "open in email app" hand-off unlock. Blocked runs can never be approved.
- **Tamper-evident proof**: every event is SHA-256 hash-chained, and exported reports can be re-verified in the app or the CLI. Edit one character and verification fails.
- **Red-team suite**: 16 adversarial and control cases run in the UI, the CLI and CI on every push.

## How we built it

- **One shared policy engine** (`lib/core.js`, zero dependencies) runs in the browser, the serverless API, the CLI and the tests, so the UI can never drift from what is tested.
- **Frontend:** HTML, CSS and vanilla JavaScript, responsive and accessible (keyboard shortcuts, skip link, ARIA live regions, reduced-motion support).
- **AI:** Google Gemini (`gemini-3.5-flash-lite` by default) through a Vercel serverless function, with a JSON response schema, an action-enum allowlist, a 12-second timeout, a retry without schema, per-client rate limiting and a deterministic fallback.
- **Crypto:** a pure-JS SHA-256 (verified against Node's crypto in tests) plus canonical JSON for hash-chained audit events and report integrity.
- **Quality:** 38 tests on Node's built-in runner (core logic, API with a mocked Gemini, CLI), and GitHub Actions on Node 22 and 24 with a red-team gate.
- **Zero-dependency local server and CLI**, so judges can run everything with only Node installed.

## Challenges we ran into

- **The API was silently broken.** Our first Gemini integration called the wrong REST path (missing `models/`) and put the key in the URL. Because we had a fallback, the app *looked* fine while the AI was never used. We fixed the endpoint, moved the key to the `x-goog-api-key` header, and added mocked API tests so it can't regress.
- **Regex false positives.** Our first reference extractor read the word "request" as a ticket ID `REQUEST` and "order" as `ORDER`. Requiring a digit fixed it, and the tests lock it in.
- **Balancing safety against usefulness.** "Disregard the old policy memo" is fine, but "disregard previous instructions" isn't. We added benign control cases to the red-team suite so we measure false positives as well as catches.
- **Making AI output trustworthy.** We designed `normalizePlan` so the model can only make a plan safer, never riskier.

## Accomplishments we're proud of

- A complete human-in-the-loop flow: steps visibly pause at the gate and resume only after a recorded decision.
- Tamper detection that judges can try themselves: export a report, edit it, re-upload it, and see which event was changed.
- 16/16 red-team cases and 38/38 tests passing in CI.
- The app works fully offline with no API key, and gets smarter with one.

## What we learned

- Guardrails belong *outside* the model. Deterministic checks around an LLM are easier to test and explain than prompt instructions alone.
- Explainability builds trust. Showing "+50 moves money ('refund')" is far more convincing than a bare "HIGH".
- Fallbacks can hide bugs, so test the happy path too.

## What's next

- Real integrations behind the gate (Gmail drafts, Google Calendar, Jira/Trello, Slack), each with scoped credentials
- Server-signed reports (Ed25519/HMAC) and durable audit storage
- Role-based approvers and approval policies by amount
- An ML classifier alongside the rules for injection detection, measured against the red-team suite

## Built with

`javascript` · `html5` · `css3` · `node.js` · `google-gemini` · `vercel` · `github-actions` · `sha-256` · `serverless`

## Try it out

- **Source code:** https://github.com/gourav-ai-engineer/EvoHacks
- **Live demo:** add your Vercel or GitHub Pages URL here after deploying (see the checklist below)
- **Run locally:** `git clone … && cd EvoHacks && node server.js`, then open http://localhost:3000

---

## Submission checklist

- [ ] Make the GitHub repository **public**.
- [ ] Merge this branch into `main`.
- [ ] Deploy:
  - **Vercel (recommended):** import the repo, add `GEMINI_API_KEY` (from Google AI Studio) as an environment variable, then deploy. Check that the header pill shows **AI READY**.
  - **or GitHub Pages:** Settings → Pages → Deploy from branch → `main` / root. This runs the local engine without AI.
- [ ] Put the live URL in "Try it out" above and in the Devpost links.
- [ ] Record the 2–3 minute video ([docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)) and upload it to YouTube (public or unlisted).
- [ ] Add 3–5 screenshots to the Devpost gallery: workflow studio, human gate, blocked attack, inbox autopilot, red-team results.
- [ ] Submit before **Oct 12, 2026, 12:30 AM IST**.
