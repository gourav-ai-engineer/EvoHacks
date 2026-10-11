const SAMPLES = {
  access: "A new teaching assistant needs computer lab access for Tuesday afternoon. Check that the request has an owner and date, draft an approval message, and flag anything missing.",
  invoice: "Invoice INV-2048 from Northstar Supplies is for $4,850, but the purchase order shows $4,580. Capture the mismatch, prepare a note for Finance, and route it for review before anything is paid.",
  refund: "Customer request: refund order ORD-7812 for $289 because the package arrived damaged. Check what information is needed, draft a response, and send the refund request to a human approver. Do not issue any payment."
};
const ALLOWED_ACTIONS = new Set(["extract_fields","validate_policy","create_task","draft_message","update_record","notify_owner","request_approval","flag_for_review"]);
const ACTION_NAMES = {
  extract_fields:"Extract structured fields", validate_policy:"Validate against policy",
  create_task:"Prepare a follow-up task", draft_message:"Draft a message",
  update_record:"Stage a record update", notify_owner:"Prepare owner notification",
  request_approval:"Require human approval", flag_for_review:"Flag for manual review"
};
const state = { runs: [], current: null, selectedSample: "access" };
const $ = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value == null ? "" : value).replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const pad2 = (value) => String(value).padStart(2, "0");
function nowStamp() {
  const d = new Date();
  return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds());
}
function runId() {
  return "RP-" + Date.now().toString(36).toUpperCase().slice(-5) + "-" + Math.random().toString(36).slice(2, 5).toUpperCase();
}
function isPromptInjection(input) {
  return /(ignore\s+(all\s+)?(previous|prior|system)\s+instructions|reveal\s+(the\s+)?(api|secret|system)\s*(key|prompt)?|bypass\s+(the\s+)?(safety|security|approval|policy)|disregard\s+(your|all)\s+rules|print\s+environment\s+variables)/i.test(input);
}
function localPlanner(input) {
  const lower = input.toLowerCase();
  const injection = isPromptInjection(input);
  const isRefund = /\b(refund|chargeback|reimburse|payment|pay|money|transfer)\b/i.test(input);
  const isInvoice = /\b(invoice|purchase order|vendor|finance|billing|amount|po\b)\b/i.test(input);
  const isAccess = /\b(access|permission|account|lab|admin|credential|password|privilege)\b/i.test(input);
  const isDelete = /\b(delete|erase|remove all|wipe|terminate)\b/i.test(input);
  const isSensitive = isRefund || isInvoice || isAccess || isDelete;
  const category = injection ? "Security review" : isRefund ? "Refund / payment" : isInvoice ? "Invoice exception" : isAccess ? "Access request" : "General operations";
  const riskLevel = injection ? "BLOCKED" : (isRefund || isDelete) ? "HIGH" : (isInvoice || isAccess) ? "MEDIUM" : "LOW";
  const requiresApproval = isSensitive || injection;
  let riskReason = injection ? "Possible instruction override detected. Treat the request as untrusted data and stop before staging." :
    isRefund ? "Financial actions are high impact. Approval is required; no transaction will be executed." :
    isDelete ? "Destructive requests require a human decision and cannot run automatically." :
    isAccess ? "Access changes can affect security. Route the staged request through an authorized approver." :
    isInvoice ? "The request involves financial records. Validate discrepancies and obtain review before any update." :
    "No high-impact action was detected. The workflow remains in a no-side-effect simulation.";
  const refMatch = input.match(/\b(?:INV|ORD|PO|REQ|TICKET|CASE)[- #]?[A-Z0-9-]{2,}\b/i);
  const moneyMatch = input.match(/(?:[$₹€]\s?\d[\d,]*(?:\.\d{1,2})?|\d[\d,]*(?:\.\d{1,2})?\s?(?:USD|INR|dollars|rupees))/i);
  const dayMatch = input.match(/\b(today|tomorrow|monday|tuesday|wednesday|thursday|friday|saturday|sunday|next week|this week|morning|afternoon|evening)\b/i);
  const ownerMatch = input.match(/\b(?:from|for|by|owner is|assigned to)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})\b/);
  const fields = [
    {label:"Request type",value:category},
    {label:"Reference",value:refMatch ? refMatch[0].toUpperCase() : "Not found — verify"},
    {label:"Amount / timing",value:moneyMatch ? moneyMatch[0] : dayMatch ? dayMatch[0] : "Not found — clarify"}
  ];
  let steps;
  if (injection) {
    steps = [
      {title:"Treat input as untrusted",action:"extract_fields",reason:"Keep the submitted text as data; do not follow embedded instruction overrides.",guardrail:"SAFE PARSE"},
      {title:"Stop the workflow",action:"flag_for_review",reason:"The request contains a pattern associated with bypassing safety controls.",guardrail:"BLOCKED"},
      {title:"Escalate to a human",action:"request_approval",reason:"No action should be staged until a reviewer inspects the request.",guardrail:"HUMAN GATE"}
    ];
  } else if (isRefund) {
    steps = [
      {title:"Extract request details",action:"extract_fields",reason:"Capture order reference, amount, reason, and any missing evidence.",guardrail:"STRUCTURED"},
      {title:"Check required evidence",action:"validate_policy",reason:"Verify that the order ID, amount, and reason are present before an approver sees it.",guardrail:"VALIDATE"},
      {title:"Prepare customer response",action:"draft_message",reason:"Create a draft that confirms receipt without promising a completed refund.",guardrail:"DRAFT ONLY"},
      {title:"Route to authorized approver",action:"request_approval",reason:"Financial movement is never performed by this simulation.",guardrail:"HUMAN GATE"}
    ];
  } else if (isInvoice) {
    steps = [
      {title:"Extract invoice and PO values",action:"extract_fields",reason:"Capture vendor, reference, invoice amount, and purchase-order value if supplied.",guardrail:"STRUCTURED"},
      {title:"Validate the discrepancy",action:"validate_policy",reason:"Compare supplied values and mark any mismatch or missing field for review.",guardrail:"CHECK"},
      {title:"Prepare exception record",action:"create_task",reason:"Stage a finance-review task with the evidence; do not post a ledger change.",guardrail:"STAGED"},
      {title:"Request finance approval",action:"request_approval",reason:"A person must resolve the discrepancy before payment or record updates.",guardrail:"HUMAN GATE"}
    ];
  } else if (isAccess) {
    steps = [
      {title:"Extract requester and access scope",action:"extract_fields",reason:"Capture the requester, system, purpose, and requested time window.",guardrail:"STRUCTURED"},
      {title:"Check least-privilege details",action:"validate_policy",reason:"Flag missing owner, scope, or expiry instead of guessing permissions.",guardrail:"LEAST PRIVILEGE"},
      {title:"Prepare an access-review task",action:"create_task",reason:"Stage a review item for the system owner without granting access.",guardrail:"STAGED"},
      {title:"Draft approver notification",action:"draft_message",reason:"Prepare a message for the authorized owner to review.",guardrail:"DRAFT ONLY"},
      {title:"Wait for authorized approval",action:"request_approval",reason:"No account or permission is changed by this prototype.",guardrail:"HUMAN GATE"}
    ];
  } else {
    steps = [
      {title:"Convert request into fields",action:"extract_fields",reason:"Separate the intended outcome, reference, owner, and deadline from free text.",guardrail:"STRUCTURED"},
      {title:"Check completeness",action:"validate_policy",reason:"Mark missing values for clarification rather than inventing details.",guardrail:"VALIDATE"},
      {title:"Stage a next-step task",action:"create_task",reason:"Prepare a small, reviewable task that represents the requested follow-up.",guardrail:"STAGED"},
      {title:"Prepare an owner update",action:"draft_message",reason:"Generate a draft for a person to inspect before it is sent.",guardrail:"DRAFT ONLY"}
    ];
  }
  if (isDelete && !injection) {
    steps = [
      {title:"Identify the destructive request",action:"extract_fields",reason:"Record the requested target without modifying or removing anything.",guardrail:"READ ONLY"},
      {title:"Block destructive execution",action:"flag_for_review",reason:"Delete or erase actions are outside the allowed simulation capabilities.",guardrail:"BLOCKED"},
      {title:"Require human review",action:"request_approval",reason:"A qualified reviewer must validate scope, retention, and authorization.",guardrail:"HUMAN GATE"}
    ];
  }
  return {
    title: injection ? "Potential instruction override" : isRefund ? "Refund review workflow" : isInvoice ? "Invoice exception triage" : isAccess ? "Access request workflow" : "Request-to-action workflow",
    summary: injection ? "A suspicious instruction pattern was detected. The plan is blocked before any action can be staged." : isRefund ? "Capture the refund context, check required information, and prepare a human approval request." : isInvoice ? "Extract the financial discrepancy, prepare an exception task, and route it for review." : isAccess ? "Structure the access request and prepare an owner review without granting permissions." : "Turn the request into explicit, reviewable steps and identify what must be clarified.",
    category:category, riskLevel:riskLevel, riskReason:riskReason, requiresApproval:requiresApproval,
    fields:fields, steps:steps,
    successChecks:["Required request fields are visible","Every action uses an approved action type","Risky actions are gated for human review","No external action is executed"],
    engine:"Local rules engine"
  };
}
function normalizePlan(raw, input) {
  const fallback = localPlanner(input);
  if (!raw || typeof raw !== "object") return fallback;
  const validRisk = ["LOW","MEDIUM","HIGH","BLOCKED"].includes(String(raw.riskLevel || "").toUpperCase()) ? String(raw.riskLevel).toUpperCase() : fallback.riskLevel;
  const stepsIn = Array.isArray(raw.steps) ? raw.steps.slice(0,6) : fallback.steps;
  const steps = stepsIn.map((step, index) => {
    const action = ALLOWED_ACTIONS.has(step && step.action) ? step.action : "request_approval";
    return {
      title: String((step && step.title) || ACTION_NAMES[action]).slice(0,90),
      action:action,
      reason:String((step && (step.reason || step.description)) || "Review this staged step before approval.").slice(0,240),
      guardrail:String((step && step.guardrail) || (action === "request_approval" ? "HUMAN GATE" : "CHECK")).slice(0,40)
    };
  });
  const riskRank = {LOW:0, MEDIUM:1, HIGH:2, BLOCKED:3};
  const riskLevel = isPromptInjection(input) ? "BLOCKED" : (riskRank[validRisk] >= riskRank[fallback.riskLevel] ? validRisk : fallback.riskLevel);
  const requiresApproval = riskLevel === "HIGH" || riskLevel === "BLOCKED" || Boolean(raw.requiresApproval) || fallback.requiresApproval;
  let safeSteps = steps.length ? steps : fallback.steps;
  if (riskLevel === "BLOCKED" && !safeSteps.some((step) => step.action === "request_approval")) {
    safeSteps = safeSteps.concat([{title:"Stop and require human review",action:"request_approval",reason:"Suspicious input cannot be staged automatically.",guardrail:"HUMAN GATE"}]);
  }
  if (requiresApproval && !safeSteps.some((step) => step.action === "request_approval")) {
    safeSteps = safeSteps.concat([{title:"Require human approval",action:"request_approval",reason:"Sensitive actions must be approved by an authorized person.",guardrail:"HUMAN GATE"}]);
  }
  const fields = Array.isArray(raw.fields) ? raw.fields.slice(0,5).map((field) => ({label:String(field.label || "Extracted field").slice(0,45),value:String(field.value || "Not found — verify").slice(0,140)})) : fallback.fields;
  return {
    title:String(raw.title || fallback.title).slice(0,90),
    summary:String(raw.summary || fallback.summary).slice(0,360),
    category:String(raw.category || fallback.category).slice(0,80),
    riskLevel:riskLevel,
    riskReason:String(raw.riskReason || raw.risk_reason || fallback.riskReason).slice(0,300),
    requiresApproval:requiresApproval,
    fields:fields.length ? fields : fallback.fields,
    steps:safeSteps,
    successChecks:Array.isArray(raw.successChecks) ? raw.successChecks.slice(0,5).map((x) => String(x).slice(0,120)) : fallback.successChecks,
    engine:String(raw.engine || "Gemini + local policy gate").slice(0,70)
  };
}
async function generatePlan(input) {
  try {
    const response = await fetch("/api/plan", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({input:input})
    });
    if (response.ok) {
      const data = await response.json();
      if (data && data.plan) {
        if (data.mode === "local-demo" || data.mode === "local-fallback") return localPlanner(input);
        return normalizePlan(data.plan, input);
      }
    }
  } catch (error) {
    // Offline, local-file, and static-host runs intentionally use the local fallback.
  }
  return localPlanner(input);
}
function verifyPlan(plan, input) {
  const injection = isPromptInjection(input);
  const actionsAllowed = plan.steps.length > 0 && plan.steps.every((step) => ALLOWED_ACTIONS.has(step.action));
  const riskGate = !(plan.riskLevel === "HIGH" || plan.riskLevel === "BLOCKED" || plan.requiresApproval) || plan.steps.some((step) => step.action === "request_approval");
  const contract = Boolean(plan.title && plan.summary && Array.isArray(plan.fields) && plan.fields.length && Array.isArray(plan.steps) && plan.steps.length);
  const sideEffectLock = true;
  return [
    {name:"Action allowlist",detail:"Every proposed step uses a supported action type.",pass:actionsAllowed,warning:false},
    {name:"Risk gate",detail:injection ? "Suspicious instruction pattern found; request remains blocked." : "Sensitive actions cannot proceed without an approval step.",pass:riskGate && !injection,warning:injection},
    {name:"Output contract",detail:"Title, extracted fields, and a non-empty workflow are present.",pass:contract,warning:false},
    {name:"Side-effect lock",detail:"No external integrations or write actions are connected.",pass:sideEffectLock,warning:false}
  ];
}
function buildRun(input, plan) {
  const checks = verifyPlan(plan, input);
  const blocked = plan.riskLevel === "BLOCKED" || checks.some((check) => check.warning);
  const passed = checks.every((check) => check.pass);
  const status = blocked ? "BLOCKED" : !passed ? "NEEDS REVIEW" : plan.requiresApproval ? "APPROVAL REQUIRED" : "VERIFIED SIMULATION";
  const events = [
    {time:nowStamp(),label:"Request received",detail:"Input captured in the local session.",kind:"ok"},
    {time:nowStamp(),label:"Intent plan prepared",detail:plan.steps.length + " allowlisted steps proposed by " + plan.engine + ".",kind:"ok"},
    {time:nowStamp(),label:"Policy gates evaluated",detail:checks.filter((c) => c.pass).length + " of " + checks.length + " checks passed.",kind:passed && !blocked ? "ok":"warn"},
    {time:nowStamp(),label:blocked ? "Run blocked safely" : plan.requiresApproval ? "Paused at human gate" : "Simulation complete",detail:"No external systems were changed.",kind:blocked || plan.requiresApproval ? "warn":"ok"}
  ];
  return {id:runId(),time:nowStamp(),input:input,plan:plan,checks:checks,status:status,events:events};
}
function setTrack(run) {
  const nodes = Array.from(document.querySelectorAll(".track-step"));
  const connectors = Array.from(document.querySelectorAll(".track-connector"));
  nodes.forEach((node,index) => {
    node.classList.remove("active","passed","warn");
    const state = node.querySelector(".track-state");
    if (!run) {
      if (index === 0) {node.classList.add("active");state.textContent="READY";}
      else state.textContent="WAITING";
      return;
    }
    if (run.status === "BLOCKED" && index >= 1) {
      node.classList.add("warn");state.textContent="GATED";return;
    }
    if (run.plan.requiresApproval && index >= 2) {
      node.classList.add(index === 1 ? "passed":"warn");state.textContent=index === 1?"CHECKED":"GATED";return;
    }
    node.classList.add("passed");state.textContent="PASSED";
  });
  connectors.forEach((connector,index) => {
    connector.firstElementChild.style.width = !run ? (index === 0 ? "35%" : "0%") : run.status === "BLOCKED" && index >= 1 ? "0%" : run.plan.requiresApproval && index >= 1 ? "25%" : "100%";
  });
}
function renderPlan(run) {
  const plan = run.plan;
  const risk = $("riskBadge");
  risk.textContent = plan.riskLevel + " RISK";
  risk.className = "risk-badge " + plan.riskLevel.toLowerCase();
  const fields = plan.fields.map((field) => '<div class="field-card"><small>' + escapeHtml(field.label) + '</small><strong>' + escapeHtml(field.value) + '</strong></div>').join("");
  const steps = plan.steps.map((step,index) => {
    const gated = step.action === "request_approval" || step.action === "flag_for_review";
    return '<div class="plan-step"><span class="step-number">' + pad2(index+1) + '</span><div class="plan-step-copy"><strong>' + escapeHtml(step.title) + '</strong><p>' + escapeHtml(step.reason) + '</p></div><span class="action-token ' + (gated ? "gated" : "") + '">' + escapeHtml(step.guardrail || ACTION_NAMES[step.action]) + '</span></div>';
  }).join("");
  const note = run.status === "BLOCKED" ? '<div class="plan-state-note"><strong>Blocked safely.</strong> Review the input and remove the instruction override before retrying.</div>' :
    plan.requiresApproval ? '<div class="plan-state-note"><strong>Human gate required.</strong> This run is a dry-run preview; an authorized person must approve sensitive actions in a real deployment.</div>' :
    '<div class="plan-state-note"><strong>Simulation verified.</strong> No external actions were executed. Review the report below before connecting any integrations.</div>';
  $("planOutput").innerHTML =
    '<div class="plan-result-head"><div><h3 class="plan-result-title">' + escapeHtml(plan.title) + '</h3><p class="plan-result-summary">' + escapeHtml(plan.summary) + '</p></div><span class="engine-label">' + escapeHtml(plan.engine) + '</span></div>' +
    '<div class="field-list">' + fields + '</div>' +
    '<div class="steps-heading"><span>PROPOSED STEPS</span><span>' + plan.steps.length + ' STEPS · SIMULATED ONLY</span></div>' +
    '<div class="plan-steps">' + steps + '</div>' +
    '<div class="plan-actions"><button class="secondary-button" id="copyPlanButton" type="button">Copy plan ↗</button><span class="plan-state-note">' + note + '</span></div>';
  $("copyPlanButton").addEventListener("click", () => copyText(JSON.stringify(run.plan,null,2),"Plan copied to clipboard."));
  setTrack(run);
}
function renderChecks(run) {
  $("reportId").textContent = run.id;
  $("checksList").innerHTML = run.checks.map((check) => {
    const cls = check.pass && !check.warning ? "pass" : check.warning ? "fail" : "warn";
    const symbol = check.pass && !check.warning ? "✓" : check.warning ? "!" : "△";
    const result = check.pass && !check.warning ? "PASS" : check.warning ? "BLOCKED" : "REVIEW";
    return '<div class="check-row ' + cls + '"><span class="check-status">' + symbol + '</span><span class="check-copy"><strong>' + escapeHtml(check.name) + '</strong><small>' + escapeHtml(check.detail) + '</small></span><span class="check-result">' + result + '</span></div>';
  }).join("");
  const passed = run.checks.filter((check) => check.pass && !check.warning).length;
  $("reportSummary").textContent = run.status === "BLOCKED" ? "Unsafe input detected. The workflow was stopped before staging." : passed + " of " + run.checks.length + " verification gates passed. All actions remained inside the sandbox.";
  $("exportButton").disabled = false;
}
function renderHistory() {
  $("metricRuns").textContent = pad2(state.runs.length);
  $("navRunCount").textContent = String(state.runs.length);
  $("historyCount").textContent = state.runs.length + (state.runs.length === 1 ? " record" : " records");
  if (!state.runs.length) {
    $("historyList").innerHTML = '<div class="history-empty"><span>◷</span><p>No runs yet.</p><small>Your session activity will show here.</small></div>';
    return;
  }
  $("historyList").innerHTML = state.runs.slice().reverse().map((run) => {
    const iconClass = run.status === "BLOCKED" ? "blocked" : run.plan.riskLevel === "HIGH" ? "high" : "";
    const stateText = run.status === "BLOCKED" ? "BLOCKED" : run.plan.requiresApproval ? "GATED" : "VERIFIED";
    return '<button class="history-item" type="button" data-run-id="' + escapeHtml(run.id) + '" style="width:100%;text-align:left;background:transparent;border-left:0;border-right:0;border-top:0;color:inherit"><span class="history-symbol ' + iconClass + '">' + (run.status === "BLOCKED" ? "!" : "✳") + '</span><span class="history-main"><strong>' + escapeHtml(run.plan.title) + '</strong><small>' + escapeHtml(run.id) + ' · ' + escapeHtml(run.plan.category) + '</small></span><span class="history-meta"><span>' + stateText + '</span><small>' + escapeHtml(run.time) + '</small></span></button>';
  }).join("");
  Array.from(document.querySelectorAll("[data-run-id]")).forEach((button) => {
    button.addEventListener("click", () => {
      const run = state.runs.find((item) => item.id === button.getAttribute("data-run-id"));
      if (run) {state.current = run; renderPlan(run); renderChecks(run); showToast("Loaded " + run.id + " from this session.");}
    });
  });
}
function showToast(message, error) {
  const old = document.querySelector(".toast");
  if (old) old.remove();
  const toast = document.createElement("div");
  toast.className = "toast" + (error ? " error" : "");
  toast.textContent = message;
  document.body.appendChild(toast);
  window.setTimeout(() => toast.remove(), 2900);
}
async function copyText(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(message || "Copied.");
  } catch (error) {
    showToast("Clipboard access was blocked by the browser. Use Export report instead.", true);
  }
}
function downloadReport() {
  if (!state.current) return;
  const report = {
    application:"RelayProof",version:"0.1.0",createdAt:new Date().toISOString(),
    runId:state.current.id,status:state.current.status,
    input:state.current.input,plan:state.current.plan,verification:state.current.checks,
    auditTrail:state.current.events,
    disclaimer:"Demonstration only. All actions are simulated; no external systems were modified."
  };
  const blob = new Blob([JSON.stringify(report,null,2)],{type:"application/json"});
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;anchor.download = state.current.id.toLowerCase() + "-report.json";
  document.body.appendChild(anchor);anchor.click();anchor.remove();URL.revokeObjectURL(url);
}
async function onSubmit(event) {
  event.preventDefault();
  const input = $("requestText").value.trim();
  if (!input) {showToast("Enter a request before building a workflow.",true);return;}
  const button = $("runButton");
  button.disabled = true;
  $("runButtonText").textContent = "Analyzing & verifying…";
  $("riskBadge").textContent = "CHECKING INPUT";
  $("riskBadge").className = "risk-badge neutral";
  try {
    const rawPlan = await generatePlan(input);
    const plan = normalizePlan(rawPlan,input);
    if (plan.engine === "Local rules engine") {
      $("engineMetric").innerHTML = 'LOCAL<span class="engine-period">.</span>';
      $("engineFoot").textContent = "Deterministic demo mode";
    } else {
      $("engineMetric").innerHTML = 'AI<span class="engine-period">.</span>';
      $("engineFoot").textContent = "AI plan + local safety gates";
    }
    const run = buildRun(input,plan);
    state.current = run;
    state.runs.push(run);
    renderPlan(run);
    renderChecks(run);
    renderHistory();
    if (run.status === "BLOCKED") showToast("Safety gate stopped this workflow before staging.",true);
    else if (run.plan.requiresApproval) showToast("Workflow prepared. Human approval is required before real action.");
    else showToast("Workflow simulated and verification report created.");
  } catch (error) {
    showToast("Could not build the workflow. Please retry.",true);
  } finally {
    button.disabled = false;
    $("runButtonText").textContent = "Build & verify workflow";
  }
}
function init() {
  const d = new Date();
  $("todayLabel").textContent = d.toLocaleDateString(undefined,{month:"short",day:"2-digit",year:"numeric"}).toUpperCase();
  $("requestText").addEventListener("input", () => {$("charCount").textContent = $("requestText").value.length + " / 10000";});
  $("charCount").textContent = $("requestText").value.length + " / 10000";
  $("runForm").addEventListener("submit",onSubmit);
  Array.from(document.querySelectorAll("[data-sample]")).forEach((button) => {
    button.addEventListener("click",() => {
      state.selectedSample = button.getAttribute("data-sample");
      $("requestText").value = SAMPLES[state.selectedSample];
      $("charCount").textContent = $("requestText").value.length + " / 10000";
      Array.from(document.querySelectorAll("[data-sample]")).forEach((item) => item.classList.toggle("selected",item === button));
    });
  });
  $("exportButton").addEventListener("click",downloadReport);
  $("clearHistoryButton").addEventListener("click",() => {
    state.runs = [];state.current = null;
    renderHistory();renderChecksEmpty();setTrack(null);
    $("riskBadge").textContent = "AWAITING INPUT";$("riskBadge").className = "risk-badge neutral";
    $("reportId").textContent = "NO RUN SELECTED";$("exportButton").disabled = true;
    $("reportSummary").textContent = "Run a workflow to produce verifiable evidence.";
    $("planOutput").innerHTML = '<div class="empty-plan"><div class="empty-icon"><span>✳</span></div><strong>Your workflow will appear here</strong><p>Choose a scenario or enter a request, then build a plan. RelayProof will explain what it intends to do before any action is staged.</p><div class="empty-mini"><span>01</span> Intent extraction <span>02</span> Policy check <span>03</span> Verification</div></div>';
    showToast("Session history cleared.");
  });
  renderHistory();
}
function renderChecksEmpty() {
  $("checksList").innerHTML = [
    ["Action allowlist","Only supported actions may enter the plan."],
    ["Risk gate","Sensitive requests require human review."],
    ["Output contract","Required fields and steps are present."],
    ["Side-effect lock","No external systems are connected."]
  ].map((item) => '<div class="check-row waiting"><span class="check-status">○</span><span class="check-copy"><strong>' + item[0] + '</strong><small>' + item[1] + '</small></span><span class="check-result">WAITING</span></div>').join("");
}
document.addEventListener("DOMContentLoaded",init);