"use strict";

const DATA_FILES = {
  summary: "/data/classification_summary.json",
  records: "/data/baseband_memory_cves.json",
  excluded: "/data/excluded_non_memory_cves.json",
  rceAudit: "/data/rce_candidate_audit.json",
  manifest: "/data/dataset_manifest.json",
};

const evidenceDescriptions = {
  E1: "A vendor or CVE record states the weakness or potential outcome.",
  E2: "Public evidence reproduces the failure or identifies a detailed root cause.",
  E3: "Public evidence characterizes an attacker-relevant memory primitive.",
  E4: "Public evidence demonstrates control-flow redirection.",
  E5: "Public evidence demonstrates or explicitly confirms arbitrary code execution.",
};

const state = {
  data: null,
  view: "included",
  query: "",
  filters: { vendor: "", impact: "", evidence: "", scope: "" },
  sort: { field: "date_published", direction: -1 },
  page: 1,
  pageSize: 25,
};

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escapeHtml = (value = "") => String(value).replace(/[&<>'"]/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
})[char]);

function impactClass(impact) {
  if (impact === "RCE") return "badge-rce";
  if (impact === "Write Primitive") return "badge-write";
  if (impact === "Excluded") return "badge-excluded";
  return "badge-dos";
}

function optionList(select, values) {
  const first = select.firstElementChild.outerHTML;
  select.innerHTML = first + values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("show"), 2200);
}

async function loadData() {
  const entries = await Promise.all(Object.entries(DATA_FILES).map(async ([key, url]) => {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
    return [key, await response.json()];
  }));
  const data = Object.fromEntries(entries);
  const byId = new Map([...data.records, ...data.excluded].map((record) => [record.cve_id, record]));
  data.rceAudit = data.rceAudit.map((audit) => ({
    ...byId.get(audit.cve_id),
    ...audit,
    impact: audit.final_impact,
    evidence: { level: audit.evidence_level, summary: audit.reason },
    primary_scope: byId.get(audit.cve_id)?.primary_scope || "Unknown",
    bug_family: byId.get(audit.cve_id)?.bug_family || "—",
    record_type: "audit",
  }));
  data.records = data.records.map((record) => ({ ...record, record_type: "included" }));
  data.excluded = data.excluded.map((record) => ({
    ...record,
    impact: "Excluded",
    evidence: { level: "—", summary: record.excluded_reason },
    primary_scope: "—",
    bug_family: "—",
    record_type: "excluded",
  }));
  data.byId = new Map([...data.records, ...data.excluded].map((record) => [record.cve_id, record]));
  return data;
}

function renderMetrics() {
  const { summary, manifest } = state.data;
  const years = Object.keys(summary.year).map(Number);
  $("#metricIncluded").textContent = summary.included_memory_safety_cves.toLocaleString();
  $("#metricRce").textContent = summary.impact.RCE.toLocaleString();
  $("#metricExplicit").textContent = `${summary.coverage.explicit_public_memory_safety_evidence.percent}%`;
  $("#metricYears").textContent = `${Math.min(...years)}–${Math.max(...years)}`;
  $(".signal-core b").textContent = summary.included_memory_safety_cves;
  $("#releaseLabel").textContent = `${manifest.analysis_release} · verified`;
  $("#includedTabCount").textContent = state.data.records.length;
  $("#rceTabCount").textContent = state.data.rceAudit.length;
  $("#excludedTabCount").textContent = state.data.excluded.length;
}

function renderTrend() {
  const values = state.data.summary.year_by_impact;
  const years = Object.keys(values).sort();
  const max = Math.max(...years.map((year) => Object.values(values[year]).reduce((a, b) => a + b, 0)));
  $("#trendChart").innerHTML = years.map((year) => {
    const row = values[year];
    const segment = (impact, klass) => `<span class="segment ${klass}" style="height:${((row[impact] || 0) / max) * 100}%"></span>`;
    return `<div class="year-stack" tabindex="0">${segment("DoS", "dos")}${segment("Write Primitive", "write")}${segment("RCE", "rce")}<label>${year.slice(2)}</label><span class="chart-tip"><b>${year}</b><br>RCE ${row.RCE || 0} · Write ${row["Write Primitive"] || 0}<br>DoS ${row.DoS || 0}</span></div>`;
  }).join("");
}

function renderImpact() {
  const impact = state.data.summary.impact;
  const total = Object.values(impact).reduce((a, b) => a + b, 0);
  const rceEnd = impact.RCE / total * 360;
  const writeEnd = rceEnd + impact["Write Primitive"] / total * 360;
  $("#impactDonut").style.background = `conic-gradient(var(--violet) 0 ${rceEnd}deg, var(--orange) ${rceEnd}deg ${writeEnd}deg, #c8c3b7 ${writeEnd}deg 360deg)`;
  $("#impactDonut strong").textContent = total;
  const colors = { RCE: "var(--violet)", "Write Primitive": "var(--orange)", DoS: "#c8c3b7" };
  $("#impactLegend").innerHTML = Object.entries(impact).map(([label, count]) => `<div><i style="background:${colors[label]}"></i><span>${escapeHtml(label)}</span><b>${count} · ${(count / total * 100).toFixed(1)}%</b></div>`).join("");
}

function renderVendors() {
  const values = Object.entries(state.data.summary.vendor).sort((a, b) => b[1] - a[1]);
  const max = values[0][1];
  $("#vendorBars").innerHTML = values.map(([label, count]) => `<div class="bar-row"><span>${escapeHtml(label)}</span><div class="bar-track"><div class="bar-fill" style="width:${count / max * 100}%"></div></div><b>${count}</b></div>`).join("");
}

function renderEvidence() {
  const levels = Object.entries(state.data.summary.evidence_level);
  $("#evidenceLadder").innerHTML = levels.map(([level, count]) => `<div class="evidence-step" title="${escapeHtml(evidenceDescriptions[level])}"><b>${level}</b><span>${count} records</span></div>`).join("");
  const rows = levels.map(([level]) => `<div class="dialog-evidence-row"><b>${level}</b><p>${escapeHtml(evidenceDescriptions[level])}</p></div>`).join("");
  $("#dialogEvidence").innerHTML = rows;
  $("#methodCards").innerHTML = levels.map(([level, count]) => `<article class="method-card"><strong>${level}</strong><h3>${count.toLocaleString()} records</h3><p>${escapeHtml(evidenceDescriptions[level])}</p></article>`).join("");
}

function currentDataset() {
  if (state.view === "rce") return state.data.rceAudit;
  if (state.view === "excluded") return state.data.excluded;
  return state.data.records;
}

function searchableText(record) {
  return [record.cve_id, record.vendor, record.description, record.cwe, record.impact,
    record.bug_class, record.bug_family, record.primary_scope, record.reachability,
    record.evidence?.summary, record.manual_enrichment?.protocol,
    record.manual_enrichment?.root_cause, ...(record.protocols || []), ...(record.rats || [])]
    .filter(Boolean).join(" ").toLowerCase();
}

function filteredRecords() {
  const query = state.query.trim().toLowerCase();
  const rows = currentDataset().filter((record) => {
    if (query && !searchableText(record).includes(query)) return false;
    if (state.filters.vendor && record.vendor !== state.filters.vendor) return false;
    if (state.filters.impact && record.impact !== state.filters.impact) return false;
    if (state.filters.evidence && record.evidence?.level !== state.filters.evidence) return false;
    if (state.filters.scope && record.primary_scope !== state.filters.scope) return false;
    return true;
  });
  const { field, direction } = state.sort;
  return rows.sort((a, b) => {
    const av = field === "evidence_level" ? a.evidence?.level : a[field];
    const bv = field === "evidence_level" ? b.evidence?.level : b[field];
    return String(av ?? "").localeCompare(String(bv ?? ""), undefined, { numeric: true }) * direction;
  });
}

function renderTable() {
  const rows = filteredRecords();
  const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
  state.page = Math.min(state.page, pages);
  const start = (state.page - 1) * state.pageSize;
  const visible = rows.slice(start, start + state.pageSize);
  $("#resultSummary").textContent = `${rows.length.toLocaleString()} of ${currentDataset().length.toLocaleString()} records`;
  $("#recordRows").innerHTML = visible.map((record) => `<tr data-cve="${escapeHtml(record.cve_id)}" data-type="${record.record_type}" tabindex="0">
    <td class="cve-cell">${escapeHtml(record.cve_id)}</td>
    <td>${escapeHtml(record.vendor || "—")}</td>
    <td class="muted-cell">${escapeHtml(record.year || record.date_published?.slice(0, 4) || "—")}</td>
    <td><span class="badge ${impactClass(record.impact)}">${escapeHtml(record.impact)}</span></td>
    <td>${escapeHtml(record.bug_family || "—")}</td>
    <td>${escapeHtml(record.primary_scope || "—")}</td>
    <td><span class="badge evidence-badge">${escapeHtml(record.evidence?.level || "—")}</span></td>
    <td class="row-arrow">↗</td>
  </tr>`).join("");
  $("#emptyState").hidden = visible.length !== 0;
  $("#pageStatus").textContent = `Page ${state.page} / ${pages}`;
  $("#previousPage").disabled = state.page <= 1;
  $("#nextPage").disabled = state.page >= pages;
}

function detailRecord(cve, type) {
  if (type === "audit") return state.data.rceAudit.find((item) => item.cve_id === cve);
  return state.data.byId.get(cve);
}

function safeSources(sources = []) {
  return sources.filter((source) => /^https?:\/\//.test(source.url || ""));
}

function openDrawer(record, updateHash = true) {
  if (!record) return;
  const evidence = record.evidence || {};
  const definitions = [
    ["Vendor", record.vendor], ["Published", record.date_published],
    ["Bug class", record.bug_class], ["Bug family", record.bug_family],
    ["Primary scope", record.primary_scope], ["RAT", (record.rats || []).join(", ")],
    ["Protocols", (record.protocols || []).join(", ")], ["Reachability", record.reachability],
    ["Primitive control", record.primitive_control], ["Patch ID", record.patch?.identifier],
  ].filter(([, value]) => value && value !== "—");
  const flags = evidence.arbitrary_code_execution !== undefined ? [
    ["Reproduced failure", evidence.reproduced_failure],
    ["Primitive characterized", evidence.primitive_characterized],
    ["Control-flow redirection", evidence.control_flow_redirection],
    ["Arbitrary code execution", evidence.arbitrary_code_execution],
  ] : [];
  const sources = safeSources(record.sources);
  $("#drawerContent").innerHTML = `
    <p class="drawer-kicker">${escapeHtml(record.record_type === "audit" ? "Legacy RCE decision" : "Artifact record")}</p>
    <h2 id="drawerTitle">${escapeHtml(record.cve_id)}</h2>
    <div class="drawer-badges"><span class="badge ${impactClass(record.impact)}">${escapeHtml(record.impact || "—")}</span><span class="badge evidence-badge">${escapeHtml(evidence.level || "—")}</span></div>
    <div class="drawer-summary"><b>${record.record_type === "excluded" ? "Exclusion rationale" : record.record_type === "audit" ? escapeHtml(record.decision) : "Evidence summary"}</b><p>${escapeHtml(evidence.summary || record.description || "No public summary encoded.")}</p></div>
    ${record.description ? `<section class="drawer-section"><h3>Canonical description</h3><p>${escapeHtml(record.description)}</p></section>` : ""}
    <section class="drawer-section"><h3>Classification</h3><dl class="definition-grid">${definitions.map(([term, value]) => `<div><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}</dl></section>
    ${record.manual_enrichment?.root_cause ? `<section class="drawer-section"><h3>Reviewed root cause</h3><p>${escapeHtml(record.manual_enrichment.root_cause)}</p></section>` : ""}
    ${flags.length ? `<section class="drawer-section"><h3>Evidence flags</h3><dl class="definition-grid">${flags.map(([term, value]) => `<div><dt>${escapeHtml(term)}</dt><dd>${value ? "Yes" : "No"}</dd></div>`).join("")}</dl></section>` : ""}
    <section class="drawer-section"><h3>Public sources · ${sources.length}</h3><div class="source-list">${sources.map((source) => `<a href="${escapeHtml(source.url)}" target="_blank" rel="noreferrer"><span>${escapeHtml(source.title)}</span><span>↗</span></a>`).join("") || "<p>No reviewed source attached.</p>"}</div></section>`;
  $("#drawerBackdrop").hidden = false;
  $("#detailDrawer").classList.add("open");
  $("#detailDrawer").setAttribute("aria-hidden", "false");
  document.body.classList.add("drawer-open");
  if (updateHash) history.replaceState(null, "", `#${record.cve_id}`);
  $("#closeDrawer").focus();
}

function closeDrawer(clearHash = true) {
  $("#detailDrawer").classList.remove("open");
  $("#detailDrawer").setAttribute("aria-hidden", "true");
  $("#drawerBackdrop").hidden = true;
  document.body.classList.remove("drawer-open");
  if (clearHash && location.hash.startsWith("#CVE-")) history.replaceState(null, "", location.pathname + location.search);
}

function resetFilters() {
  state.query = "";
  state.filters = { vendor: "", impact: "", evidence: "", scope: "" };
  $("#searchInput").value = "";
  for (const id of ["vendorFilter", "impactFilter", "evidenceFilter", "scopeFilter"]) $(`#${id}`).value = "";
  state.page = 1;
  renderTable();
}

function exportCsv() {
  const rows = filteredRecords();
  const fields = ["cve_id", "vendor", "date_published", "impact", "bug_class", "bug_family", "primary_scope", "evidence_level"];
  const quote = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const csv = [fields.join(","), ...rows.map((record) => fields.map((field) => quote(field === "evidence_level" ? record.evidence?.level : record[field])).join(","))].join("\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  link.download = `baseband-cves-${state.view}-filtered.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
  showToast(`Exported ${rows.length} records`);
}

function bindEvents() {
  $("#searchInput").addEventListener("input", (event) => { state.query = event.target.value; state.page = 1; renderTable(); });
  for (const [id, key] of [["vendorFilter", "vendor"], ["impactFilter", "impact"], ["evidenceFilter", "evidence"], ["scopeFilter", "scope"]]) {
    $(`#${id}`).addEventListener("change", (event) => { state.filters[key] = event.target.value; state.page = 1; renderTable(); });
  }
  $("#clearFilters").addEventListener("click", resetFilters);
  $("#previousPage").addEventListener("click", () => { state.page -= 1; renderTable(); });
  $("#nextPage").addEventListener("click", () => { state.page += 1; renderTable(); });
  $("#exportButton").addEventListener("click", exportCsv);
  $("#recordRows").addEventListener("click", (event) => { const row = event.target.closest("tr"); if (row) openDrawer(detailRecord(row.dataset.cve, row.dataset.type)); });
  $("#recordRows").addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key)) { event.preventDefault(); event.target.click(); } });
  $$("th button[data-sort]").forEach((button) => button.addEventListener("click", () => {
    const field = button.dataset.sort;
    state.sort.direction = state.sort.field === field ? -state.sort.direction : 1;
    state.sort.field = field;
    renderTable();
  }));
  $$(".dataset-tabs button").forEach((button) => button.addEventListener("click", () => {
    state.view = button.dataset.view;
    $$(".dataset-tabs button").forEach((item) => { item.classList.toggle("active", item === button); item.setAttribute("aria-selected", item === button); });
    resetFilters();
  }));
  $("#closeDrawer").addEventListener("click", () => closeDrawer());
  $("#drawerBackdrop").addEventListener("click", () => closeDrawer());
  $("#evidenceHelp").addEventListener("click", () => $("#evidenceDialog").showModal());
  $("#evidenceDialog .dialog-close").addEventListener("click", () => $("#evidenceDialog").close());
  document.addEventListener("keydown", (event) => {
    if (event.key === "/" && !/input|select|textarea/i.test(document.activeElement.tagName)) { event.preventDefault(); $("#searchInput").focus(); }
    if (event.key === "Escape") closeDrawer();
  });
}

async function init() {
  try {
    state.data = await loadData();
    renderMetrics();
    renderTrend();
    renderImpact();
    renderVendors();
    renderEvidence();
    optionList($("#vendorFilter"), Object.keys(state.data.summary.vendor).sort());
    optionList($("#impactFilter"), ["RCE", "Write Primitive", "DoS", "Excluded"]);
    optionList($("#evidenceFilter"), ["E1", "E2", "E3", "E4", "E5"]);
    optionList($("#scopeFilter"), Object.keys(state.data.summary.primary_scope));
    bindEvents();
    renderTable();
    const hashCve = location.hash.slice(1);
    if (/^CVE-\d{4}-\d+$/.test(hashCve)) openDrawer(state.data.byId.get(hashCve), false);
  } catch (error) {
    console.error(error);
    document.body.innerHTML = `<main class="empty-state"><span>!</span><h1>Artifact data unavailable</h1><p>${escapeHtml(error.message)}</p><p>Run the flake pipeline before starting the explorer.</p></main>`;
  }
}

init();
