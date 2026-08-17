/* Project-scoped assessment reasoning workspace.
 * Loaded before app.js; all shared helpers are resolved when the workspace opens.
 */

function assessmentReasoning(project) {
  return project.assessment_reasoning || {summary:{}, methodology_cards:[], nodes:[], edges:[], hypotheses:[], checkpoints:[], advisory_only:true};
}

function reasoningWorkspaceNav() {
  const tabs = [["methodology","Methodology"],["map","System map"],["hypotheses","Hypotheses"],["checkpoints","Evidence checkpoints"]];
  return `<nav class="tool-workbench-nav reasoning-workbench-nav" aria-label="Assessment reasoning sections">${tabs.map(([id,label], index) => `<button class="tool-tab ${state.reasoningTab === id ? "active" : ""}" data-reasoning-tab="${id}" type="button"><span>0${index + 1}</span>${label}</button>`).join("")}</nav>`;
}

function reasoningTargetOptions(project, selected = "") {
  return `<option value="">Project-wide</option>${(project.targets || []).map((target) => `<option value="${esc(target.id)}" ${target.id === selected ? "selected" : ""}>${esc(target.name)} · ${esc(target.id)}</option>`).join("")}`;
}

function methodologyCardMarkup(card, pinnedCards) {
  const pinnedCard = pinnedCards.get(card.id);
  const pinned = Boolean(pinnedCard);
  const verified = pinnedCard?.trusted_for_model === true;
  const provenance = card.provenance || {};
  return `<article class="reasoning-card methodology-card ${pinned ? "pinned" : ""}">
    <div class="reasoning-card-head"><div>${badge(card.domain, "purple")}${badge(`v${card.version}`, "pending")}${pinned ? badge(verified ? "verified pinned snapshot" : "untrusted pinned snapshot", verified ? "authorized" : "error") : ""}</div><button class="${pinned ? "danger" : "secondary"} small-button" data-${pinned ? "unpin" : "pin"}-methodology="${esc(card.id)}" type="button">${pinned ? "Unpin" : "Pin to project"}</button></div>
    <h3>${esc(card.title)}</h3><p>${esc(card.summary)}</p>
    <div class="mapping-tags">${(card.capabilities || []).map((item) => badge(item, "purple")).join("")}</div>
    <details class="evidence-block"><summary>Reviewed procedure and evidence expectations</summary><div class="evidence-body"><div class="reasoning-detail-grid"><div><span class="section-label">Procedure</span><ol>${(card.procedure || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ol></div><div><span class="section-label">Required evidence</span><ul>${(card.required_evidence || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div><div><span class="section-label">Negative evidence</span><ul>${(card.negative_evidence || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div><div><span class="section-label">Stop conditions</span><ul>${(card.stop_conditions || []).map((item) => `<li>${esc(item)}</li>`).join("")}</ul></div></div></div></details>
    ${pinned && !verified ? `<div class="validation-note warning">The stored snapshot does not match this framework build and is excluded from model context. Unpin it, review the current card, and pin it again.</div>` : ""}
    <small>${esc(provenance.review_status || "framework-reviewed")} · snapshot SHA-256 ${esc(card.sha256 || "not recorded")}</small>
  </article>`;
}

function reasoningMethodologyMarkup(reasoning) {
  const cards = state.methodologyLibrary?.cards || [];
  const pinnedCards = new Map((reasoning.methodology_cards || []).map((item) => [item.card_id || item.id, item]));
  return `<div class="reasoning-layout"><section class="panel panel-pad"><div class="panel-head"><div><span class="section-label">Reviewed framework library</span><h2>Pin reusable assessment methods</h2><p>These are AdverScope-authored abstractions inspired by operator study material. Source notes are not copied, embedded, or changed.</p></div>${badge(`${pinnedCards.size} pinned`, pinnedCards.size ? "authorized" : "pending")}</div><div class="methodology-grid">${cards.map((card) => methodologyCardMarkup(card, pinnedCards)).join("") || `<div class="empty">The reviewed methodology library is unavailable.</div>`}</div></section></div>`;
}

function reasoningMapMarkup(project, reasoning) {
  const nodes = reasoning.nodes || [];
  const edges = reasoning.edges || [];
  const byId = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const nodeOptions = nodes.map((node) => `<option value="${esc(node.id)}">${esc(node.label)} · ${esc(node.kind)}</option>`).join("");
  const nodeKinds = ["component","identity","credential-reference","data","artifact","consumer","sink","route"];
  const edgeKinds = ["data-flow","trust","authority","uses-credential","triggers","produces","reaches","consumes"];
  return `<div class="reasoning-layout">
    <section class="panel panel-pad"><div class="panel-head"><div><span class="section-label">Component inventory</span><h2>Add a typed system-map node</h2><p>Store identity references and architecture facts, never credential values. Project-wide nodes can connect multiple saved targets.</p></div>${badge(`${nodes.length} nodes`, "purple")}</div>
      <form id="reasoning-node-form" class="stack reasoning-form"><div class="form-grid three"><label>Node type<select name="kind" required>${nodeKinds.map((item) => `<option value="${item}">${item.replaceAll("-", " ")}</option>`).join("")}</select></label><label>Confidence<select name="confidence"><option>unknown</option><option>likely</option><option>confirmed</option></select></label><label>Applies to<select name="target_id">${reasoningTargetOptions(project)}</select></label></div><label>Label<input name="label" maxlength="180" required placeholder="Retriever service or workload identity reference"></label><div class="form-grid two"><label>Description<textarea name="description" placeholder="Role in the assessed system"></textarea></label><label>Source reference<textarea name="source_ref" placeholder="Configuration path, trace ID, or retained evidence reference"></textarea></label></div><button class="secondary" type="submit">Add system-map node</button></form>
      <div class="reasoning-node-grid">${nodes.length ? nodes.map((node) => `<article class="reasoning-node"><div class="reasoning-card-head"><div>${badge(node.kind, "purple")}${badge(node.confidence, node.confidence === "confirmed" ? "authorized" : "pending")}</div><button class="danger small-button" data-delete-reasoning-node="${esc(node.id)}" type="button">Delete</button></div><strong>${esc(node.label)}</strong><p>${esc(node.description || "No description recorded.")}</p><small>${esc(node.target_id || "project-wide")} · ${esc(node.source_ref || "no source reference")}</small></article>`).join("") : `<div class="empty compact">Add components, identities, data, artifacts, consumers, sinks, or routes.</div>`}</div>
    </section>
    <section class="panel panel-pad"><div class="panel-head"><div><span class="section-label">Typed relationships</span><h2>Connect trust and data flow</h2><p>Reachability is descriptive and never grants permission. Confirmed edges should point to retained evidence.</p></div>${badge(`${edges.length} relationships`, "purple")}</div>
      ${nodes.length >= 2 ? `<form id="reasoning-edge-form" class="stack reasoning-form"><div class="form-grid three"><label>Source<select name="source_node_id" required><option value="">Select node</option>${nodeOptions}</select></label><label>Relationship<select name="kind" required>${edgeKinds.map((item) => `<option value="${item}">${item.replaceAll("-", " ")}</option>`).join("")}</select></label><label>Destination<select name="target_node_id" required><option value="">Select node</option>${nodeOptions}</select></label></div><div class="form-grid three"><label>Status<select name="status"><option>unknown</option><option>likely</option><option>confirmed</option><option>blocked</option></select></label><label>Label<input name="label" maxlength="180" placeholder="Optional relationship label"></label><label>Evidence IDs<input name="evidence_refs" placeholder="ev_..., ev_..."></label></div><label>Description<textarea name="description" placeholder="Why this relationship is believed to exist"></textarea></label><button class="secondary" type="submit">Add typed relationship</button></form>` : `<div class="validation-note">Add at least two nodes before creating a relationship.</div>`}
      <div class="relationship-table reasoning-relationship-list">${edges.length ? edges.map((edge) => `<div class="reasoning-relationship"><div><strong>${esc(byId[edge.source_node_id]?.label || edge.source_node_id)}</strong><span>${esc(edge.kind)} &rarr;</span><strong>${esc(byId[edge.target_node_id]?.label || edge.target_node_id)}</strong></div><div>${badge(edge.status, edge.status === "confirmed" ? "authorized" : edge.status === "blocked" ? "error" : "pending")}<button class="danger small-button" data-delete-reasoning-edge="${esc(edge.id)}" type="button">Delete</button></div>${edge.description ? `<p>${esc(edge.description)}</p>` : ""}</div>`).join("") : `<div class="empty compact">No component relationships recorded.</div>`}</div>
    </section>
  </div>`;
}

function reasoningHypothesesMarkup(project, reasoning) {
  const hypotheses = reasoning.hypotheses || [];
  const pins = reasoning.methodology_cards || [];
  return `<div class="reasoning-layout"><section class="panel panel-pad"><div class="panel-head"><div><span class="section-label">Decision record</span><h2>Separate facts, inferences, hypotheses, and failed paths</h2><p>GO/HOLD/NO-GO records the next reasoning decision. It does not authorize a request or declare a finding.</p></div>${badge(`${hypotheses.length} records`, "purple")}</div>
    <form id="reasoning-hypothesis-form" class="stack reasoning-form"><div class="form-grid three"><label>Classification<select name="classification"><option value="fact">FACT</option><option value="inference">INFERENCE</option><option value="hypothesis" selected>HYPOTHESIS</option><option value="failure">FAILURE / NEGATIVE EVIDENCE</option></select></label><label>Decision<select name="decision"><option value="go">GO</option><option value="hold" selected>HOLD</option><option value="no-go">NO-GO</option></select></label><label>Applies to<select name="target_id">${reasoningTargetOptions(project)}</select></label></div><label>Claim<textarea name="claim" required placeholder="What is known, inferred, being tested, or ruled out?"></textarea></label><label>Rationale<textarea name="rationale" placeholder="Premise and supporting reasoning"></textarea></label><div class="form-grid two"><label>Missing prerequisite / negative evidence<textarea name="missing_prerequisite" placeholder="What is absent, denied, unresolved, or contradictory?"></textarea></label><label>Cheapest discriminating test<textarea name="cheapest_test" placeholder="One bounded observation that would distinguish the alternatives"></textarea></label></div><label>Retained evidence IDs<input name="evidence_refs" placeholder="ev_..., ev_..."></label>${pins.length ? `<fieldset class="reasoning-card-refs"><legend>Pinned methodology references</legend>${pins.map((card) => `<label class="check-row"><input type="checkbox" name="methodology_card_ids" value="${esc(card.card_id || card.id)}"><span>${esc(card.title)}</span></label>`).join("")}</fieldset>` : ""}<button class="secondary" type="submit">Record reasoning decision</button></form>
    <div class="reasoning-hypothesis-list">${hypotheses.length ? hypotheses.map((item) => `<article class="reasoning-hypothesis ${item.classification}"><div class="reasoning-card-head"><div>${badge(item.classification.toUpperCase(), item.classification === "fact" ? "authorized" : item.classification === "failure" ? "error" : "purple")}${badge(item.decision.toUpperCase(), item.decision === "go" ? "authorized" : item.decision === "no-go" ? "error" : "pending")}</div><button class="danger small-button" data-delete-hypothesis="${esc(item.id)}" type="button">Delete</button></div><h3>${esc(item.claim)}</h3>${item.rationale ? `<p>${esc(item.rationale)}</p>` : ""}<div class="reasoning-decision-grid"><div><span class="section-label">Missing prerequisite / negative evidence</span><strong>${esc(item.missing_prerequisite || "none recorded")}</strong></div><div><span class="section-label">Cheapest discriminating test</span><strong>${esc(item.cheapest_test || "none recorded")}</strong></div></div><small>${esc(item.target_id || "project-wide")} · evidence ${esc((item.evidence_refs || []).join(", ") || "not linked")}</small></article>`).join("") : `<div class="empty compact">No facts, inferences, hypotheses, or failed paths recorded.</div>`}</div>
  </section></div>`;
}

function checkpointStageStatus(checkpoint, key) {
  return checkpoint.stages?.[key]?.status || "not-observed";
}

function reasoningCheckpointsMarkup(project, reasoning) {
  const checkpoints = reasoning.checkpoints || [];
  const stageFields = [["model_proposed","Model proposed"],["application_returned","Application returned"],["tool_executed","Tool executed"],["backend_changed","Backend changed"],["impact_verified","Impact independently verified"]];
  const stageOptions = ["not-observed","claimed","observed","verified","failed","not-applicable"];
  return `<div class="reasoning-layout"><section class="panel panel-pad"><div class="panel-head"><div><span class="section-label">Append-only evidence ladder</span><h2>Record what was actually observed</h2><p>Keep proposal, application output, execution, backend change, and independently verified impact separate. A manual checkpoint is never finding-grade by itself.</p></div>${badge(`${checkpoints.length} checkpoints`, "purple")}</div>
    <form id="reasoning-checkpoint-form" class="stack reasoning-form"><div class="form-grid three"><label>Title<input name="title" maxlength="180" required placeholder="Tool-use verification checkpoint"></label><label>Applies to<select name="target_id">${reasoningTargetOptions(project)}</select></label><label>Cleanup<select name="cleanup_status"><option value="not-required">not required</option><option>pending</option><option>completed</option><option>failed</option></select></label></div><div class="form-grid three"><label>Starting identity<input name="starting_identity" placeholder="Identity reference, never a credential value"></label><label>Run ID<input name="run_id" placeholder="run_..."></label><label>Retained evidence ID<input name="evidence_id" placeholder="ev_..."></label></div><div class="form-grid two"><label>Test case ID<input name="test_case_id" placeholder="case_..."></label><label>Correction of checkpoint<input name="correction_of_id" placeholder="rcheck_... (optional)"></label></div><div class="checkpoint-stage-grid">${stageFields.map(([key,label]) => `<label>${label}<select name="stage_${key}">${stageOptions.map((status) => `<option value="${status}">${status.replaceAll("-", " ")}</option>`).join("")}</select></label>`).join("")}</div><label>Prerequisite<textarea name="prerequisite" placeholder="What had to be true before the action?"></textarea></label><label>Bounded action<textarea name="action" placeholder="What was attempted?"></textarea></label><div class="form-grid two"><label>Observed result<textarea name="result" placeholder="What the application or tool returned"></textarea></label><label>Impact / independent verification<textarea name="impact" placeholder="Backend or consumer observation, if any"></textarea></label></div><label>Notes<textarea name="notes" placeholder="Correlation, caveats, or cleanup details"></textarea></label><button class="secondary" type="submit">Append evidence checkpoint</button></form>
    <div class="checkpoint-list">${checkpoints.length ? checkpoints.map((item) => `<article class="reasoning-checkpoint"><div class="reasoning-card-head"><div>${badge("append-only", "purple")}${badge(item.cleanup_status, item.cleanup_status === "completed" || item.cleanup_status === "not-required" ? "authorized" : item.cleanup_status === "failed" ? "error" : "pending")}${badge("not finding-grade", "pending")}</div><small>${esc(item.id)}</small></div><h3>${esc(item.title)}</h3><div class="checkpoint-ladder">${stageFields.map(([key,label], index) => `<div class="checkpoint-step"><span>0${index + 1}</span><strong>${esc(label)}</strong>${badge(checkpointStageStatus(item, key), checkpointStageStatus(item, key) === "verified" ? "authorized" : checkpointStageStatus(item, key) === "failed" ? "error" : "pending")}</div>`).join("")}</div><div class="reasoning-decision-grid"><div><span class="section-label">Action and result</span><strong>${esc(item.action || "not recorded")}</strong><p>${esc(item.result || "No result recorded.")}</p></div><div><span class="section-label">Impact and evidence</span><strong>${esc(item.impact || "not independently verified")}</strong><p>${esc(item.evidence_id || "No retained evidence linked")}</p></div></div>${item.correction_of_id ? `<small>Corrects ${esc(item.correction_of_id)}; the earlier record remains preserved.</small>` : ""}</article>`).join("") : `<div class="empty compact">No evidence checkpoints recorded.</div>`}</div>
  </section></div>`;
}

function renderAssessmentReasoning(project) {
  const reasoning = assessmentReasoning(project);
  const content = state.reasoningTab === "map" ? reasoningMapMarkup(project, reasoning) : state.reasoningTab === "hypotheses" ? reasoningHypothesesMarkup(project, reasoning) : state.reasoningTab === "checkpoints" ? reasoningCheckpointsMarkup(project, reasoning) : reasoningMethodologyMarkup(reasoning);
  $("main-content").innerHTML = `<div class="page-shell reasoning-page">${projectHeader(project, `${project.name} · ASSESSMENT REASONING`, "Build a traceable model of the assessment", "Pin reviewed methods, map components and trust, record facts and failed paths, then separate proposed actions from verified impact.")}<div class="validation-note warning reasoning-authority-notice"><strong>Advisory only</strong><p>${esc(reasoning.authority_notice || "Assessment reasoning cannot add scope, routes, identities, permissions, evidence, findings, or verdicts.")}</p></div>${reasoningWorkspaceNav()}${content}</div>`;
  wireAssessmentReasoning(project);
}

function parseReasoningIds(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

async function refreshAssessmentReasoning(projectId, message) {
  const [project, projects] = await Promise.all([api(`/api/projects/${encodeURIComponent(projectId)}`), api(projectListEndpoint)]);
  state.projects = projects.projects;
  if (state.current?.id === projectId) {
    state.current = project;
    if (state.view === "reasoning") renderProject(project, "reasoning");
  }
  if (message) notify(message);
}

async function reasoningRequest(button, path, options, message) {
  if (button) button.disabled = true;
  const projectMatch = String(path || "").match(/^\/api\/projects\/([^/]+)/);
  const projectId = projectMatch ? decodeURIComponent(projectMatch[1]) : String(state.current?.id || "");
  try {
    await trackProjectMutation((async () => {
      await api(path, options);
      await refreshAssessmentReasoning(projectId, message);
    })());
  } catch (error) {
    if (button) button.disabled = false;
    notify(error.message, true);
  }
}

function wireAssessmentReasoning(project) {
  document.querySelectorAll("[data-reasoning-tab]").forEach((button) => button.addEventListener("click", () => { state.reasoningTab = button.dataset.reasoningTab; renderAssessmentReasoning(state.current); renderProjectContext(state.current); }));
  document.querySelectorAll("[data-pin-methodology]").forEach((button) => button.addEventListener("click", () => reasoningRequest(button, `/api/projects/${encodeURIComponent(project.id)}/methodology-cards`, {method:"POST",body:JSON.stringify({card_id:button.dataset.pinMethodology})}, "Reviewed methodology snapshot pinned to the project.")));
  document.querySelectorAll("[data-unpin-methodology]").forEach((button) => button.addEventListener("click", () => reasoningRequest(button, `/api/projects/${encodeURIComponent(project.id)}/methodology-cards/${encodeURIComponent(button.dataset.unpinMethodology)}`, {method:"DELETE"}, "Methodology card unpinned. Historical run snapshots remain unchanged.")));
  $("reasoning-node-form")?.addEventListener("submit", (event) => { event.preventDefault(); const values = formData(event.target); reasoningRequest(event.submitter, `/api/projects/${encodeURIComponent(project.id)}/reasoning-nodes`, {method:"POST",body:JSON.stringify(values)}, "System-map node recorded."); });
  $("reasoning-edge-form")?.addEventListener("submit", (event) => { event.preventDefault(); const values = formData(event.target); values.evidence_refs = parseReasoningIds(values.evidence_refs); reasoningRequest(event.submitter, `/api/projects/${encodeURIComponent(project.id)}/reasoning-edges`, {method:"POST",body:JSON.stringify(values)}, "Typed relationship recorded."); });
  $("reasoning-hypothesis-form")?.addEventListener("submit", (event) => { event.preventDefault(); const data = new FormData(event.target); const values = Object.fromEntries(data.entries()); values.evidence_refs = parseReasoningIds(values.evidence_refs); values.methodology_card_ids = data.getAll("methodology_card_ids"); reasoningRequest(event.submitter, `/api/projects/${encodeURIComponent(project.id)}/hypotheses`, {method:"POST",body:JSON.stringify(values)}, "Reasoning decision recorded."); });
  $("reasoning-checkpoint-form")?.addEventListener("submit", (event) => { event.preventDefault(); const values = formData(event.target); values.stages = {}; for (const key of ["model_proposed","application_returned","tool_executed","backend_changed","impact_verified"]) { values.stages[key] = {status:values[`stage_${key}`]}; delete values[`stage_${key}`]; } reasoningRequest(event.submitter, `/api/projects/${encodeURIComponent(project.id)}/evidence-checkpoints`, {method:"POST",body:JSON.stringify(values)}, "Append-only evidence checkpoint recorded."); });
  document.querySelectorAll("[data-delete-reasoning-node]").forEach((button) => button.addEventListener("click", () => { if (window.confirm("Delete this node and its connected relationships?")) reasoningRequest(button, `/api/projects/${encodeURIComponent(project.id)}/reasoning-nodes/${encodeURIComponent(button.dataset.deleteReasoningNode)}`, {method:"DELETE"}, "System-map node deleted with its connected relationships."); }));
  document.querySelectorAll("[data-delete-reasoning-edge]").forEach((button) => button.addEventListener("click", () => reasoningRequest(button, `/api/projects/${encodeURIComponent(project.id)}/reasoning-edges/${encodeURIComponent(button.dataset.deleteReasoningEdge)}`, {method:"DELETE"}, "Relationship deleted.")));
  document.querySelectorAll("[data-delete-hypothesis]").forEach((button) => button.addEventListener("click", () => reasoningRequest(button, `/api/projects/${encodeURIComponent(project.id)}/hypotheses/${encodeURIComponent(button.dataset.deleteHypothesis)}`, {method:"DELETE"}, "Reasoning record deleted.")));
}
