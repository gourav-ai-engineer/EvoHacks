# Demo video script (about 2:45)

Judging covers impact, technical execution, creativity and presentation. Each beat below targets one or more of them. Record at 1080p with browser zoom at 110–125% so the text is readable. Before recording, click **Clear** in Run history so the metrics start at zero.

| Time | On screen | Say (roughly) |
| --- | --- | --- |
| 0:00–0:15 | Hero section | "AI can automate busywork, but one wrong refund or one hidden 'ignore previous instructions' can cost more than it saves. RelayProof is AI automation with proof before action." |
| 0:15–0:45 | Click **Access request** → **Build & verify** | "It extracts the details, scores risk from 0 to 100, and explains why: access changes add 30. It also noticed there's no owner, so it wrote the clarification question for me." Point at the *Needs clarification* chip and the step outputs. |
| 0:45–1:05 | Scroll to **Human gate** → type a name → **Approve & simulate** | "Sensitive work pauses here. When I approve, the remaining steps run in the sandbox, and the email hand-off unlocks. Here's the draft and the task ticket it generated." Click the *Task ticket* tab. |
| 1:05–1:25 | **Attack attempt** chip → Build | "Now an attack: ignore instructions, developer mode, reveal the API key. The injection shield blocks it before it ever reaches the AI, and the gate is locked, so even a human can't approve it." |
| 1:25–1:50 | **Inbox autopilot** → Load sample inbox → Run | "Real impact is a whole inbox at once. Six requests: one auto-completed, four waiting for approval, and the fake CEO wire-transfer request blocked. About an hour of manual triage prepared in seconds, with a CSV export." |
| 1:50–2:10 | Evidence panel → **Export report** → edit the JSON in a text editor → **Verify a report…** | "Every step is SHA-256 hash-chained. If I export the report and change one word, verification fails and shows exactly which event was modified." |
| 2:10–2:30 | **Run red-team suite** | "16 adversarial and control cases, including zero-width tricks and hidden HTML comments. The same suite runs in CI on every push, alongside 38 tests." |
| 2:30–2:45 | Terminal: `node cli.js batch --sample` (optional), then the hero | "The same engine powers the web app, the Gemini API and this CLI. RelayProof: plan first, prove it, then act." |

## Tips

- If Gemini is configured, show the **AI READY** pill and the AI-written draft tag. Otherwise say "it works fully offline with deterministic rules, and Gemini is optional."
- Keep the cursor still while talking, and use zoom to highlight key areas.
- Show the GitHub repo and the green CI badge or Actions tab for 2–3 seconds at the end.
