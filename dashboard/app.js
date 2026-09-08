"use strict";

const POLL_INTERVAL_MS = 5000;
const ONLINE_FALLBACK_SECONDS = 300;
const MAX_RENDERED_RECORDS = 500;
const ACTIVE_SCAN_STATES = new Set(["QUEUED", "DISPATCHED", "RUNNING", "COLLECTING", "UPLOADING", "ANALYZING", "PENDING"]);
const FAILED_SCAN_STATES = new Set(["FAILED", "REJECTED", "EXPIRED", "CANCELLED", "PARTIAL"]);

const state = {
  token: sessionStorage.getItem("scanner-admin-token") || "",
  connected: false,
  endpoints: [],
  scans: [],
  installers: [],
  selectedScanId: null,
  report: null,
  findings: [],
  enrollmentGrant: null,
  enrollmentExpiryTimer: null,
  inventoryRendered: false,
  rawJsonRendered: false,
  pollTimer: null,
  inventoryFilterTimer: null
};

const byId = (id) => document.getElementById(id);
const all = (selector, root = document) => Array.from(root.querySelectorAll(selector));
const tokenInput = byId("admin-token");
tokenInput.value = state.token;

class ApiError extends Error {
  constructor(message, status, code = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

function textNode(value) {
  return document.createTextNode(value == null ? "" : String(value));
}

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value != null) node.textContent = String(value);
  return node;
}

function setStatus(message, kind = "info") {
  const banner = byId("status-banner");
  banner.hidden = false;
  banner.classList.remove("success", "warning", "error");
  if (kind !== "info") banner.classList.add(kind);
  byId("status").textContent = message;
}

function setConnected(connected) {
  state.connected = connected;
  byId("api-status-dot").classList.toggle("online", connected);
  byId("api-status-dot").classList.toggle("error", !connected && Boolean(state.token));
  byId("api-status-label").textContent = connected ? "API connected" : "Not connected";
  byId("connection-label").textContent = connected ? "Connected for this tab" : "Connect to API";
  byId("refresh-all").disabled = !connected;
  byId("refresh-scans").disabled = !connected;
  byId("generate-enrollment").disabled = !connected;
  updateScanButtons();
}

function itemsOf(value) {
  if (Array.isArray(value)) return value;
  for (const key of ["items", "endpoints", "scans", "installers", "results"]) {
    if (Array.isArray(value && value[key])) return value[key];
  }
  return [];
}

function safeDetail(value, fallback) {
  if (typeof value === "string" && value.trim()) return value.trim().slice(0, 500);
  if (value && typeof value === "object") {
    for (const key of ["message", "detail", "error", "code"]) {
      if (typeof value[key] === "string" && value[key].trim()) return value[key].trim().slice(0, 500);
    }
  }
  return fallback;
}

async function api(path, options = {}) {
  if (!state.token) throw new ApiError("Enter the local administrator token first.", 401);
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${state.token}`);
  headers.set("Accept", options.accept || "application/json");
  if (options.body !== undefined) headers.set("Content-Type", "application/json");

  const response = await fetch(path, {
    method: options.method || "GET",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });

  if (!response.ok) {
    let problem = null;
    try {
      problem = await response.json();
    } catch {
      problem = null;
    }
    const fallback = `The server returned HTTP ${response.status}.`;
    const detail = safeDetail(problem && problem.detail, safeDetail(problem, fallback));
    const code = problem && typeof problem.code === "string" ? problem.code : null;
    throw new ApiError(detail, response.status, code);
  }

  if (options.responseType === "blob") {
    return { blob: await response.blob(), headers: response.headers };
  }
  if (response.status === 204) return null;
  return response.json();
}

function normalizedState(value) {
  return String(value || "UNKNOWN").trim().toUpperCase();
}

function statusChip(value) {
  const normalized = normalizedState(value);
  const chip = element("span", "status-chip", humanize(normalized));
  chip.classList.add(normalized.toLowerCase().replace(/[^a-z0-9_-]/g, ""));
  if (ACTIVE_SCAN_STATES.has(normalized)) chip.classList.add("active");
  return chip;
}

function humanize(value) {
  return String(value == null ? "" : value)
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function safeDate(value) {
  if (!value) return "Not reported";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date);
}

function relativeTime(value) {
  if (!value) return "Never";
  const date = new Date(value);
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  if (!Number.isFinite(seconds)) return "Unknown";
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const ranges = [[60, "second"], [60, "minute"], [24, "hour"], [7, "day"], [4.345, "week"], [12, "month"], [Infinity, "year"]];
  let amount = seconds;
  for (const [limit, unit] of ranges) {
    if (Math.abs(amount) < limit) return formatter.format(Math.round(amount), unit);
    amount /= limit;
  }
  return safeDate(value);
}

function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let amount = bytes / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${units[index]}`;
}

function endpointOnline(endpoint) {
  if (typeof endpoint.online === "boolean") return endpoint.online;
  const reported = String(endpoint.connectivity_status || "").toUpperCase();
  if (reported === "ONLINE") return true;
  if (reported === "OFFLINE") return false;
  if (Number.isFinite(Number(endpoint.seconds_since_seen))) {
    return Number(endpoint.seconds_since_seen) <= ONLINE_FALLBACK_SECONDS;
  }
  const seen = new Date(endpoint.last_seen_at || endpoint.updated_at || 0).getTime();
  return Number.isFinite(seen) && Date.now() - seen <= ONLINE_FALLBACK_SECONDS * 1000;
}

function endpointLabel(endpoint) {
  return endpoint.hostname || endpoint.display_name || endpoint.endpoint_id || endpoint.id || "Unknown endpoint";
}

function endpointId(endpoint) {
  return endpoint.endpoint_id || endpoint.id || "";
}

function endpointScannable(endpoint) {
  return endpointOnline(endpoint) && endpoint.can_start_scan !== false;
}

function appendCell(row, content, className = "") {
  const cell = element("td", className);
  if (content instanceof Node) cell.append(content);
  else cell.textContent = content == null || content === "" ? "—" : String(content);
  row.append(cell);
  return cell;
}

function updateScanButtons() {
  const hasOnlineEndpoint = state.connected && state.endpoints.some(endpointScannable);
  all("[data-open-scan]").forEach((button) => {
    button.disabled = !hasOnlineEndpoint;
  });
}

function buildEndpointOptions(preferredId = null) {
  const select = byId("scan-endpoint");
  const previous = preferredId || select.value;
  select.replaceChildren();
  const online = state.endpoints.filter(endpointScannable);
  if (!online.length) {
    const option = element("option", "", "No online endpoint available");
    option.value = "";
    select.append(option);
    select.disabled = true;
    byId("submit-scan").disabled = true;
    return;
  }
  for (const endpoint of online) {
    const option = element("option");
    option.value = endpointId(endpoint);
    option.textContent = `${endpointLabel(endpoint)} · ${endpoint.os_family || endpoint.platform || "Unknown OS"}`;
    if (option.value === previous) option.selected = true;
    select.append(option);
  }
  select.disabled = false;
  byId("submit-scan").disabled = false;
}

function renderEndpoints() {
  const target = byId("endpoints");
  target.replaceChildren();
  const query = byId("endpoint-filter").value.trim().toLowerCase();
  const visible = state.endpoints.filter((endpoint) => {
    if (!query) return true;
    return [endpointLabel(endpoint), endpointId(endpoint), endpoint.os_family, endpoint.os_version, endpoint.architecture]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });

  for (const endpoint of visible) {
    const row = document.createElement("tr");
    const identity = element("div");
    identity.append(element("strong", "endpoint-name", endpointLabel(endpoint)));
    identity.append(element("small", "secondary-line", endpointId(endpoint)));
    appendCell(row, identity);

    const os = element("div", "os-cell");
    const family = String(endpoint.os_family || endpoint.platform || "OS").toUpperCase();
    os.append(element("span", "os-badge", family === "WINDOWS" ? "Win" : family === "MACOS" || family === "DARWIN" ? "Mac" : family === "LINUX" ? "Lx" : "OS"));
    const osText = element("span");
    osText.append(element("strong", "endpoint-name", humanize(family)));
    osText.append(element("small", "secondary-line", [endpoint.os_version, endpoint.architecture].filter(Boolean).join(" · ") || "Version not reported"));
    os.append(osText);
    appendCell(row, os);

    const agent = element("span");
    agent.append(element("strong", "endpoint-name", endpoint.scanner_version || "Not reported"));
    agent.append(element("small", "secondary-line", "Scanner version"));
    appendCell(row, agent);

    const seen = element("span");
    seen.append(element("strong", "endpoint-name", relativeTime(endpoint.last_seen_at || endpoint.updated_at)));
    seen.append(element("small", "secondary-line", safeDate(endpoint.last_seen_at || endpoint.updated_at)));
    appendCell(row, seen);

    appendCell(row, statusChip(endpointOnline(endpoint) ? "ONLINE" : "OFFLINE"));
    const action = element("button", "row-action", "Scan");
    action.type = "button";
    action.disabled = !endpointScannable(endpoint);
    action.addEventListener("click", () => openScanDialog(endpointId(endpoint)));
    appendCell(row, action);
    target.append(row);
  }

  byId("endpoints-empty").hidden = visible.length > 0;
  const onlineCount = state.endpoints.filter(endpointOnline).length;
  byId("metric-endpoints").textContent = String(state.endpoints.length);
  byId("metric-online").textContent = `${onlineCount} online · ${Math.max(0, state.endpoints.length - onlineCount)} offline`;
  buildEndpointOptions();
  updateScanButtons();
}

function scanState(scan) {
  if (scanReportReady(scan) && scan.report_summary && scan.report_summary.status) {
    return normalizedState(scan.report_summary.status);
  }
  return normalizedState(scan.report_status || scan.status || scan.state || scan.endpoint_status);
}

function scanReportReady(scan) {
  return scan.report_ready === true || scan.final_report_available === true;
}

function scanMatchesFilter(scan, filter) {
  const value = scanState(scan);
  if (filter === "ALL") return true;
  if (filter === "ACTIVE") return ACTIVE_SCAN_STATES.has(value);
  if (filter === "COMPLETE") return scanReportReady(scan) && !FAILED_SCAN_STATES.has(value);
  if (filter === "FAILED") return FAILED_SCAN_STATES.has(value);
  return true;
}

function renderScans() {
  const target = byId("scans");
  target.replaceChildren();
  const filter = byId("scan-filter").value;
  const visible = state.scans.filter((scan) => scanMatchesFilter(scan, filter));

  for (const scan of visible) {
    const row = document.createElement("tr");
    const id = scan.scan_id || scan.id || "";
    const scanCell = element("span");
    scanCell.append(element("strong", "scan-name", id));
    scanCell.append(element("small", "secondary-line", scan.job_id || "Job identifier not reported"));
    appendCell(row, scanCell);

    const endpoint = state.endpoints.find((item) => endpointId(item) === scan.endpoint_id);
    const endpointCell = element("span");
    endpointCell.append(element("strong", "endpoint-name", endpoint ? endpointLabel(endpoint) : scan.endpoint_id));
    endpointCell.append(element("small", "secondary-line", scan.endpoint_id));
    appendCell(row, endpointCell);

    appendCell(row, humanize(scan.scan_type || (scan.job && scan.job.scan_type) || "Not reported"));
    const stateCell = element("div", "scan-state-cell");
    stateCell.append(statusChip(scanState(scan)));
    const progress = Number(scan.progress_percent);
    if (Number.isFinite(progress)) {
      const progressBar = element("progress", "scan-progress");
      progressBar.max = 100;
      progressBar.value = Math.min(100, Math.max(0, progress));
      progressBar.setAttribute("aria-label", `${humanize(scan.phase || "Processing")} progress`);
      stateCell.append(progressBar);
      stateCell.append(element("small", "secondary-line", `${humanize(scan.phase || "Processing")} · ${Math.round(progress)}%`));
    }
    appendCell(row, stateCell);
    const created = element("span");
    created.append(element("strong", "endpoint-name", relativeTime(scan.created_at || scan.requested_at)));
    created.append(element("small", "secondary-line", safeDate(scan.created_at || scan.requested_at)));
    appendCell(row, created);

    const action = element("button", "row-action", scanReportReady(scan) ? "View report" : "Pending");
    action.type = "button";
    action.disabled = !scanReportReady(scan);
    action.addEventListener("click", () => loadReport(id));
    appendCell(row, action);
    target.append(row);
  }

  byId("scans-empty").hidden = visible.length > 0;
  const running = state.scans.filter((scan) => ACTIVE_SCAN_STATES.has(scanState(scan))).length;
  const complete = state.scans.filter(scanReportReady).length;
  byId("metric-running").textContent = String(running);
  byId("metric-complete").textContent = String(complete);
  const latest = state.scans[0];
  byId("metric-latest").textContent = latest ? `Latest requested ${relativeTime(latest.created_at || latest.requested_at)}` : "No scans requested";
}

function installerPlatform(value) {
  const platform = String(value || "").toUpperCase();
  return platform === "DARWIN" ? "MACOS" : platform;
}

function installerFormat(item, fallback) {
  const formats = {
    PORTABLE_EXECUTABLE: "EXE (portable)",
    WINDOWS_INSTALLER: "EXE installer",
    DEBIAN_PACKAGE: "DEB",
    MACOS_PACKAGE: "PKG"
  };
  return formats[String(item.package_type || "").toUpperCase()] || item.package_type || fallback;
}

function preferredInstaller(platform) {
  const candidates = state.installers.filter((item) => installerPlatform(item.platform) === platform);
  return candidates.find((item) => item.available && item.architecture === "x86_64") || candidates.find((item) => item.available) || candidates[0] || null;
}

function renderInstallers() {
  for (const card of all(".installer-card")) {
    const platform = card.dataset.platform;
    const item = preferredInstaller(platform);
    const button = card.querySelector("[data-download-platform]");
    const format = card.querySelector("[data-installer-format]");
    const version = card.querySelector("[data-installer-version]");
    const size = card.querySelector("[data-installer-size]");
    const note = card.querySelector("[data-installer-note]");
    const fallbackFormat = platform === "WINDOWS" ? "EXE" : platform === "LINUX" ? "DEB" : "PKG";

    card.classList.toggle("available", Boolean(item && item.available));
    format.textContent = item ? installerFormat(item, fallbackFormat) : fallbackFormat;
    version.textContent = item && item.version ? String(item.version) : "Not published";
    size.textContent = item ? formatBytes(item.size_bytes) : "—";
    button.disabled = !(item && item.available && item.download_url);
    button.textContent = button.disabled ? "Package not available" : `Download ${fallbackFormat}`;

    if (!item) {
      note.textContent = "No qualified artifact is published for this platform.";
    } else if (!item.available) {
      note.textContent = "Artifact metadata exists, but the package is not available for download.";
    } else if (String(item.package_type || "").toUpperCase() === "PORTABLE_EXECUTABLE") {
      note.textContent = `Portable test build · SHA-256 ${String(item.sha256 || "not reported").slice(0, 16)}…`;
    } else {
      note.textContent = `Managed package · SHA-256 ${String(item.sha256 || "not reported").slice(0, 16)}…`;
    }
  }
}

async function loadEndpoints() {
  const body = await api("/api/v1/platform/endpoints?limit=500&offset=0");
  state.endpoints = itemsOf(body);
  renderEndpoints();
}

async function loadScans() {
  const body = await api("/api/v1/platform/scans?limit=500&offset=0");
  state.scans = itemsOf(body);
  renderScans();
}

async function loadInstallers() {
  try {
    const body = await api("/api/v1/platform/installers");
    state.installers = itemsOf(body);
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404) throw error;
    state.installers = [];
  }
  renderInstallers();
}

function stopPolling() {
  if (state.pollTimer) window.clearTimeout(state.pollTimer);
  state.pollTimer = null;
}

function schedulePolling() {
  stopPolling();
  if (!state.connected || !state.scans.some((scan) => ACTIVE_SCAN_STATES.has(scanState(scan)))) return;
  state.pollTimer = window.setTimeout(async () => {
    if (!document.hidden) {
      try {
        await Promise.all([loadEndpoints(), loadScans()]);
      } catch (error) {
        setStatus(error.message, "error");
      }
    }
    schedulePolling();
  }, POLL_INTERVAL_MS);
}

async function loadDashboard(showMessage = true) {
  if (!state.token) {
    byId("connection-panel").hidden = false;
    byId("connection-toggle").setAttribute("aria-expanded", "true");
    setConnected(false);
    return;
  }
  stopPolling();
  byId("refresh-all").disabled = true;
  if (showMessage) setStatus("Connecting to the scanner control plane…");
  try {
    await Promise.all([loadEndpoints(), loadScans()]);
    setConnected(true);
    try {
      await loadInstallers();
    } catch (installerError) {
      state.installers = [];
      renderInstallers();
      setStatus(`Connected, but installer metadata could not be loaded: ${installerError.message}`, "warning");
      schedulePolling();
      return;
    }
    if (showMessage) setStatus(`Connected. Loaded ${state.endpoints.length} endpoint(s) and ${state.scans.length} scan(s).`, "success");
    schedulePolling();
  } catch (error) {
    setConnected(false);
    byId("connection-panel").hidden = false;
    byId("connection-toggle").setAttribute("aria-expanded", "true");
    setStatus(error.message, "error");
  } finally {
    byId("refresh-all").disabled = !state.connected;
  }
}

function randomIdempotencyKey() {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === "function") {
    return `dashboard-${globalThis.crypto.randomUUID()}`;
  }
  const values = new Uint32Array(4);
  globalThis.crypto.getRandomValues(values);
  return `dashboard-${Array.from(values, (value) => value.toString(16).padStart(8, "0")).join("")}`;
}

function openScanDialog(preferredEndpointId = null) {
  if (!state.connected) {
    setStatus("Connect to the API before starting a scan.", "warning");
    return;
  }
  buildEndpointOptions(preferredEndpointId);
  if (byId("scan-endpoint").disabled) {
    setStatus("No endpoint is online. Keep the installed agent running until it checks in.", "warning");
    return;
  }
  byId("authorization-reference").value = "";
  byId("scan-purpose").value = "Scheduled endpoint security assessment";
  byId("authorization-confirmed").checked = false;
  const dialog = byId("scan-dialog");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
  byId("authorization-reference").focus();
}

function closeScanDialog() {
  const dialog = byId("scan-dialog");
  if (typeof dialog.close === "function") dialog.close();
  else dialog.removeAttribute("open");
}

async function submitScan(event) {
  event.preventDefault();
  const form = byId("scan-form");
  if (!form.reportValidity()) return;
  const scanTypeInput = document.querySelector('input[name="scan-type"]:checked');
  const scanType = scanTypeInput ? scanTypeInput.value : "QUICK";
  const button = byId("submit-scan");
  button.disabled = true;
  button.textContent = "Queueing scan…";
  try {
    const body = {
      endpoint_id: byId("scan-endpoint").value,
      scan_type: scanType,
      authorization_reference: byId("authorization-reference").value.trim(),
      authorized_by: "local-dashboard-administrator",
      purpose: byId("scan-purpose").value.trim() || null,
      validity_seconds: scanType === "FULL" ? 7200 : 3600,
      timeout_seconds: scanType === "FULL" ? 3600 : 1800,
      policy_id: "enterprise-default",
      priority: 50
    };
    const created = await api("/api/v1/platform/scans", {
      method: "POST",
      headers: { "Idempotency-Key": randomIdempotencyKey() },
      body
    });
    closeScanDialog();
    await loadScans();
    setStatus(`Scan ${created.scan_id || "job"} is queued. Keep the endpoint agent running while it collects and uploads evidence.`, "success");
    byId("scans-section").scrollIntoView({ behavior: "smooth", block: "start" });
    schedulePolling();
  } catch (error) {
    setStatus(`The scan could not be started: ${error.message}`, "error");
  } finally {
    button.disabled = byId("scan-endpoint").disabled;
    button.textContent = "Start authorized scan";
  }
}

function reportEndpoint(report) {
  if (report && report.endpoint_scan && typeof report.endpoint_scan === "object") return report.endpoint_scan;
  if (report && report.endpoint_evidence && report.endpoint_evidence.result && typeof report.endpoint_evidence.result === "object") return report.endpoint_evidence.result;
  if (report && report.endpoint_result && typeof report.endpoint_result === "object") return report.endpoint_result;
  if (report && report.result && typeof report.result === "object") return report.result;
  return report && typeof report === "object" ? report : {};
}

function inventorySnapshot(report) {
  const sync = report && report.endpoint_evidence && report.endpoint_evidence.inventory_sync
    ? report.endpoint_evidence.inventory_sync
    : report && report.inventory_sync ? report.inventory_sync : {};
  const snapshot = sync.reconstructed_snapshot || sync.snapshot || {};
  return snapshot && snapshot.inventory && typeof snapshot.inventory === "object" ? snapshot.inventory : snapshot;
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function sectionRecords(report, ...keys) {
  const endpoint = reportEndpoint(report);
  const snapshot = inventorySnapshot(report);
  for (const key of keys) {
    if (Array.isArray(endpoint[key])) return endpoint[key];
    if (endpoint.security && Array.isArray(endpoint.security[key])) return endpoint.security[key];
    if (Array.isArray(snapshot[key])) return snapshot[key];
    if (snapshot.security && Array.isArray(snapshot.security[key])) return snapshot.security[key];
  }
  return [];
}

function normalizedSeverity(value) {
  const severity = String(value || "UNKNOWN").toUpperCase();
  if (severity === "INFORMATIONAL") return "INFO";
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].includes(severity) ? severity : "UNKNOWN";
}

function firstCve(item) {
  const candidates = [item.cve_id, item.vulnerability_id, ...(Array.isArray(item.aliases) ? item.aliases : [])];
  return candidates.find((value) => /^CVE-\d{4}-\d+$/i.test(String(value || ""))) || null;
}

function fixedVersionRemediation(item) {
  const fixed = arrayValue(item.fixed_versions).filter(Boolean);
  if (!fixed.length) return "Review the advisory and vendor guidance; a fixed version was not reported.";
  return `Upgrade ${item.package_name || "the affected component"} to ${fixed.join(", ")} or a later approved release.`;
}

function standardFinding(item, source, vulnerability = false) {
  const evidence = item.evidence && typeof item.evidence === "object" ? item.evidence : {};
  const title = vulnerability
    ? `${item.vulnerability_id || "Vulnerability"} · ${item.package_name || "Affected component"}`
    : item.title || item.summary || item.rule_id || "Security finding";
  const description = item.description || item.summary || "No description was reported.";
  const installed = item.installed_version ? ` ${item.installed_version}` : "";
  const asset = vulnerability
    ? `${item.package_name || "Component"}${installed}`
    : item.asset || (evidence.package_name ? `${evidence.package_name}${evidence.installed_version ? ` ${evidence.installed_version}` : ""}` : null) || item.endpoint_id || "Endpoint";
  const cve = firstCve({
    ...item,
    vulnerability_id: item.vulnerability_id || evidence.vulnerability_id || item.rule_id,
    aliases: item.aliases || evidence.aliases
  });
  const sourceNames = Array.isArray(evidence.source_names) ? evidence.source_names.join(", ") : null;
  const id = vulnerability
    ? `vuln:${item.vulnerability_id || title}:${item.package_name || ""}:${item.installed_version || ""}`
    : `finding:${item.finding_id || item.rule_id || title}`;
  return {
    id,
    severity: normalizedSeverity(item.severity),
    title,
    description,
    source: item.source || sourceNames || evidence.source || source,
    cvss: item.cvss_score ?? evidence.cvss_score,
    cve,
    asset,
    remediation: item.remediation || fixedVersionRemediation(item),
    raw: item
  };
}

function extractFindings(report) {
  const endpoint = reportEndpoint(report);
  const combined = [];
  if (Array.isArray(report && report.findings)) {
    for (const finding of report.findings) combined.push(standardFinding(finding, humanize(finding.category || "Canonical assessment"), false));
    return combined;
  }
  for (const finding of arrayValue(endpoint.findings)) combined.push(standardFinding(finding, "Endpoint policy", false));
  for (const vulnerability of arrayValue(endpoint.vulnerabilities)) combined.push(standardFinding(vulnerability, "Endpoint analysis", true));
  const cloudVulnerabilities = report && report.cloud_analysis ? arrayValue(report.cloud_analysis.vulnerabilities) : [];
  for (const vulnerability of cloudVulnerabilities) combined.push(standardFinding(vulnerability, "OSV / dep-scan", true));
  const unique = new Map();
  for (const finding of combined) if (!unique.has(finding.id)) unique.set(finding.id, finding);
  return Array.from(unique.values());
}

function severityCounts(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
  for (const finding of findings) counts[normalizedSeverity(finding.severity)] += 1;
  return counts;
}

function reportCompleteness(report) {
  const endpoint = reportEndpoint(report);
  return report.coverage || report.completeness || endpoint.completeness || {};
}

function reportGaps(report) {
  const completeness = reportCompleteness(report);
  const gaps = new Set(arrayValue(completeness.gaps).map(String));
  for (const limitation of arrayValue(report && report.limitations)) gaps.add(String(limitation));
  for (const section of arrayValue(completeness.sections)) {
    if (!section || normalizedState(section.state) === "OBSERVED" || normalizedState(section.state) === "NOT_APPLICABLE") continue;
    gaps.add(`${humanize(section.name)}: ${section.detail || humanize(section.state)}`);
  }
  for (const source of arrayValue(completeness.degraded_sources)) gaps.add(`${humanize(source)} did not complete successfully`);
  for (const tool of arrayValue(completeness.degraded_tools || completeness.degraded_collectors)) gaps.add(`${humanize(tool)} did not complete successfully`);
  for (const section of arrayValue(completeness.unobserved_endpoint_sections)) gaps.add(`${humanize(section)} was not observed`);
  for (const domain of arrayValue(completeness.unobserved_attack_surface_domains)) gaps.add(`Attack-surface domain ${domain} was not observed`);
  if (completeness.full_inventory_available === false) gaps.add("A complete inventory snapshot was not available");
  return Array.from(gaps);
}

function missingPatches(report) {
  const explicit = sectionRecords(report, "missing_patches", "missing_updates");
  if (explicit.length) return explicit;
  return sectionRecords(report, "updates").filter((update) => update && (update.installed === false || ["MISSING", "PENDING", "AVAILABLE"].includes(String(update.status || "").toUpperCase())));
}

function reportCount(report, collection, ...summaryKeys) {
  if (collection.length) return collection.length;
  const summaries = [report.summary, reportEndpoint(report).summary].filter((value) => value && typeof value === "object");
  for (const summary of summaries) {
    for (const key of summaryKeys) {
      const number = Number(summary[key]);
      if (Number.isFinite(number) && number >= 0) return number;
    }
  }
  return 0;
}

function replaceDefinitions(target, pairs) {
  target.replaceChildren();
  for (const [label, value] of pairs) {
    const group = element("div");
    group.append(element("dt", "", label));
    group.append(element("dd", "", displayValue(value)));
    target.append(group);
  }
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "Not observed";
  if (typeof value === "boolean") return value ? "Enabled / present" : "Disabled / absent";
  if (Array.isArray(value)) return value.length ? value.map((item) => displayValue(item)).join(", ") : "None observed";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "Structured value";
    }
  }
  return String(value).replace(/\u0000/g, "").trim() || "Not observed";
}

function renderToolList(report) {
  const target = byId("tool-list");
  target.replaceChildren();
  const tools = new Map();
  for (const tool of arrayValue(report.analysis_tools)) {
    if (tool && tool.name) tools.set(String(tool.name).toUpperCase(), tool);
  }
  const cloudTools = report.cloud_analysis && report.cloud_analysis.tools && typeof report.cloud_analysis.tools === "object" ? report.cloud_analysis.tools : {};
  for (const [name, tool] of Object.entries(cloudTools)) tools.set(name, tool || {});
  const readiness = report.tool_readiness && typeof report.tool_readiness === "object" ? report.tool_readiness : {};
  for (const [name, tool] of Object.entries(readiness)) if (!tools.has(name.toUpperCase())) tools.set(name, tool || {});

  const collectors = reportEndpoint(report).collectors;
  if (collectors && typeof collectors === "object") {
    const entries = Object.entries(collectors);
    const native = entries.filter(([name]) => name.startsWith("native."));
    if (native.length) {
      const degraded = native.some(([, item]) => normalizedState(item && item.status) !== "SUCCESS");
      tools.set("NATIVE COLLECTORS", {
        status: degraded ? "PARTIAL" : "SUCCESS",
        records_accepted: native.reduce((total, [, item]) => total + Number(item && item.records_collected || 0), 0)
      });
    }
    for (const name of ["osquery", "openscap", "osv-scanner", "depscan"]) {
      if (collectors[name] && !tools.has(name.toUpperCase())) tools.set(name, collectors[name]);
    }
  }

  if (!tools.size) {
    target.append(element("p", "secondary-line", "Tool status was not included in this report."));
    return;
  }
  for (const [name, tool] of tools) {
    const row = element("div", "tool-row");
    row.append(element("strong", "", humanize(name)));
    const records = tool.records_accepted ?? tool.records_collected ?? tool.summary?.vulnerability_count;
    row.append(element("small", "", records == null ? "Records not reported" : `${records} record(s)`));
    row.append(statusChip(tool.status));
    target.append(row);
  }
}

function renderReportOverview(report) {
  const endpoint = reportEndpoint(report);
  const os = endpoint.os || {};
  const identity = endpoint.endpoint || {};
  const selectedScan = state.scans.find((scan) => (scan.scan_id || scan.id) === state.selectedScanId) || {};
  replaceDefinitions(byId("scan-details"), [
    ["Scan ID", report.scan_id || endpoint.scan_id || state.selectedScanId],
    ["Report ID", report.report_id],
    ["Profile", endpoint.scan_type || selectedScan.scan_type || selectedScan.job?.scan_type],
    ["Status", report.status || report.summary?.status || endpoint.status],
    ["Started", safeDate(endpoint.started_at || selectedScan.created_at)],
    ["Completed", safeDate(report.analysis_completed_at || endpoint.finished_at || report.generated_at)],
    ["Policy", [endpoint.policy_id, endpoint.policy_version].filter(Boolean).join(" · ")],
    ["Scanner", endpoint.scanner_version || report.provenance?.endpoint_scanner_version]
  ]);
  replaceDefinitions(byId("endpoint-details"), [
    ["Hostname", os.hostname || identity.hostname],
    ["Endpoint ID", report.endpoint_id || endpoint.endpoint_id || identity.endpoint_id],
    ["Operating system", [os.name || identity.os_family, os.version].filter(Boolean).join(" ")],
    ["Build / kernel", os.build || os.kernel],
    ["Architecture", os.architecture],
    ["Manufacturer", identity.manufacturer || endpoint.hardware?.manufacturer],
    ["Model", identity.model || endpoint.hardware?.device_model],
    ["Last seen", safeDate(identity.last_seen_at || endpoint.timestamp)]
  ]);
  const security = endpoint.security || {};
  replaceDefinitions(byId("security-details"), [
    ["Firewall", security.firewall_enabled],
    ["Antivirus", security.antivirus_enabled],
    ["Antivirus current", security.antivirus_up_to_date],
    ["Disk encryption", security.disk_encryption_enabled],
    ["Secure Boot", security.secure_boot_enabled],
    ["TPM", security.tpm_present],
    ["User Account Control", security.uac_enabled],
    ["Pending reboot", security.pending_reboot]
  ]);
  const provenance = report.provenance || {};
  replaceDefinitions(byId("integrity-details"), [
    ["Canonical scan SHA-256", provenance.canonical_scan_sha256],
    ["Analysis status SHA-256", provenance.analysis_status_sha256],
    ["Assessment evidence SHA-256", provenance.assessment_evidence_sha256 || provenance.sbom_sha256],
    ["Policy checksum", provenance.policy_checksum],
    ["Cloud analyzers", provenance.cloud_analyzers || (provenance.tool_versions ? Object.keys(provenance.tool_versions) : null)],
    ["Vulnerability sources", provenance.vulnerability_sources]
  ]);
  renderToolList(report);
}

function renderCoverage(report) {
  const software = sectionRecords(report, "software", "packages");
  const services = sectionRecords(report, "services");
  const processes = sectionRecords(report, "processes");
  const listeners = sectionRecords(report, "listening_ports", "ports");
  const patches = missingPatches(report);
  const vulnerabilities = state.findings.filter((finding) => finding.id.startsWith("vuln:"));
  byId("coverage-software").textContent = String(reportCount(report, software, "software_count"));
  byId("coverage-services").textContent = String(reportCount(report, services, "service_count"));
  byId("coverage-processes").textContent = String(reportCount(report, processes, "process_count"));
  byId("coverage-listeners").textContent = String(reportCount(report, listeners, "listening_port_count"));
  byId("coverage-patches").textContent = String(reportCount(report, patches, "missing_patch_count", "missing_update_count"));
  byId("coverage-vulns").textContent = String(reportCount(report, vulnerabilities, "vulnerability_count"));

  const completeness = reportCompleteness(report);
  const complete = completeness.complete === true;
  const fixture = completeness.fixture_mode === true || normalizedState(report.status) === "FIXTURE";
  const grade = fixture ? "Fixture" : complete ? "Complete" : "Partial";
  const gradeNode = byId("coverage-grade");
  gradeNode.textContent = grade;
  gradeNode.className = `coverage-grade ${grade.toLowerCase()}`;
  byId("coverage-summary").textContent = fixture
    ? "This report contains non-production deterministic fixture evidence."
    : complete
      ? "All collectors required by this scan contract completed successfully."
      : "One or more required collectors, evidence sections, or analysis workers were incomplete.";

  const gapTarget = byId("coverage-gaps");
  gapTarget.replaceChildren();
  for (const gap of reportGaps(report)) gapTarget.append(element("li", "", gap));
}

function shorten(value, limit = 360) {
  const text = displayValue(value);
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

function renderFindings() {
  const target = byId("findings");
  target.replaceChildren();
  const query = byId("finding-filter").value.trim().toLowerCase();
  const severity = byId("severity-filter").value;
  const filtered = state.findings.filter((finding) => {
    if (severity !== "ALL" && finding.severity !== severity) return false;
    if (!query) return true;
    return [finding.title, finding.description, finding.source, finding.cve, finding.asset, finding.remediation]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(query));
  });

  for (const finding of filtered.slice(0, MAX_RENDERED_RECORDS)) {
    const row = document.createElement("tr");
    const severityNode = element("span", `severity-chip ${finding.severity.toLowerCase()}`, finding.severity);
    appendCell(row, severityNode);
    const findingCell = element("span");
    findingCell.append(element("strong", "finding-title", finding.title));
    const identifiers = [finding.cve, shorten(finding.description, 260)].filter(Boolean).join(" · ");
    findingCell.append(element("small", "finding-description", identifiers));
    appendCell(row, findingCell);
    appendCell(row, humanize(finding.source));
    appendCell(row, finding.cvss == null ? "—" : Number(finding.cvss).toFixed(1));
    appendCell(row, shorten(finding.asset, 180));
    appendCell(row, shorten(finding.remediation, 300), "remediation-cell");
    target.append(row);
  }
  byId("findings-empty").hidden = filtered.length > 0;
}

function inventoryDefinitions(report) {
  const endpoint = reportEndpoint(report);
  const updates = sectionRecords(report, "updates");
  const installedUpdates = updates.filter((item) => !item || item.installed !== false);
  const users = sectionRecords(report, "users");
  return [
    { label: "Operating system", records: endpoint.os ? [endpoint.os] : [], columns: ["name", "version", "build", "kernel", "architecture", "hostname", "boot_time", "timezone"] },
    { label: "Hardware", records: endpoint.hardware ? [endpoint.hardware] : [], columns: ["manufacturer", "device_model", "cpu", "memory_bytes", "disks", "gpus", "firmware_version", "tpm_present"] },
    { label: "Antivirus products", records: sectionRecords(report, "antivirus_products"), columns: ["name", "enabled", "real_time_protection_enabled", "signatures_up_to_date", "signature_version", "product_state", "source"] },
    { label: "Firewall profiles", records: sectionRecords(report, "firewall_profiles"), columns: ["name", "enabled", "default_inbound_action", "default_outbound_action", "logging_enabled", "log_path", "source"] },
    { label: "Encrypted volumes", records: sectionRecords(report, "encryption_volumes"), columns: ["mount_point", "volume_id", "protection_status", "encryption_percentage", "encryption_method", "locked", "source"] },
    { label: "Installed software", records: sectionRecords(report, "software", "packages"), columns: ["name", "version", "vendor", "package_manager", "architecture", "installation_date", "installation_path"] },
    { label: "Missing updates", records: missingPatches(report), columns: ["update_id", "title", "severity", "category", "status", "reboot_required", "released_at"] },
    { label: "Installed updates", records: installedUpdates, columns: ["update_id", "title", "installed_at", "category", "severity"] },
    { label: "Services", records: sectionRecords(report, "services"), columns: ["name", "display_name", "state", "startup_type", "executable_path", "user", "pid"] },
    { label: "Processes", records: sectionRecords(report, "processes"), columns: ["pid", "name", "executable_path", "parent_pid", "username", "memory_bytes", "started_at"] },
    { label: "Local listening ports (potential exposure)", records: sectionRecords(report, "listening_ports", "ports"), columns: ["protocol", "address", "port", "bind_scope", "remote_reachability", "pid", "process", "suspicious"] },
    { label: "Network interfaces", records: sectionRecords(report, "network_interfaces"), columns: ["name", "mac_address", "addresses", "gateway", "dns_servers", "state", "mtu"] },
    { label: "Local users", records: users, columns: ["username", "full_name", "uid", "sid", "enabled", "is_admin", "last_login_at", "groups"] },
    { label: "Local administrators", records: users.filter((user) => user && (user.is_admin === true || user.administrator === true)), columns: ["username", "full_name", "sid", "enabled", "last_login_at", "groups"] },
    { label: "Startup and persistence", records: sectionRecords(report, "persistence", "startup_items"), columns: ["name", "persistence_type", "source", "executable_path", "user", "enabled", "suspicious"] },
    { label: "Browser extensions", records: sectionRecords(report, "browser_extensions"), columns: ["browser", "name", "extension_id", "version", "enabled", "permissions", "source"] },
    { label: "Certificates", records: sectionRecords(report, "certificates"), columns: ["subject", "issuer", "thumbprint", "not_before", "not_after", "store", "has_private_key"] },
    { label: "Compliance results", records: sectionRecords(report, "compliance"), columns: ["rule_id", "profile_id", "title", "status", "severity", "remediation"] }
  ];
}

function objectRecord(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) return value;
  return { value };
}

function recordSearchText(record) {
  try {
    return JSON.stringify(record).toLowerCase();
  } catch {
    return String(record).toLowerCase();
  }
}

function recordColumns(records, preferred) {
  const keys = new Set();
  for (const record of records.slice(0, 30)) {
    for (const key of Object.keys(objectRecord(record))) keys.add(key);
  }
  const ordered = preferred.filter((key) => keys.has(key));
  for (const key of keys) if (!ordered.includes(key)) ordered.push(key);
  return ordered.slice(0, 8);
}

function renderInventory() {
  if (!state.report) return;
  const target = byId("inventory-accordions");
  target.replaceChildren();
  const query = byId("inventory-filter").value.trim().toLowerCase();

  for (const definition of inventoryDefinitions(state.report)) {
    const allRecords = definition.records;
    const filtered = query ? allRecords.filter((record) => recordSearchText(record).includes(query)) : allRecords;
    const details = document.createElement("details");
    if (query && filtered.length) details.open = true;
    const summary = document.createElement("summary");
    summary.append(textNode(definition.label));
    summary.append(element("span", "inventory-count", String(allRecords.length)));
    details.append(summary);

    if (!filtered.length) {
      details.append(element("div", "inventory-empty", query && allRecords.length ? "No records match this filter." : "No records were observed for this section."));
      target.append(details);
      continue;
    }

    const wrap = element("div", "inventory-table-wrap");
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");
    const columns = recordColumns(filtered, definition.columns);
    for (const column of columns) {
      const th = element("th", "", humanize(column));
      th.scope = "col";
      headRow.append(th);
    }
    head.append(headRow);
    table.append(head);
    const body = document.createElement("tbody");
    for (const raw of filtered.slice(0, MAX_RENDERED_RECORDS)) {
      const record = objectRecord(raw);
      const row = document.createElement("tr");
      for (const column of columns) appendCell(row, shorten(record[column], 280));
      body.append(row);
    }
    table.append(body);
    wrap.append(table);
    if (filtered.length > MAX_RENDERED_RECORDS) {
      wrap.append(element("p", "inventory-empty", `Showing the first ${MAX_RENDERED_RECORDS} of ${filtered.length} matching records. The JSON export contains the full dataset.`));
    }
    details.append(wrap);
    target.append(details);
  }
  state.inventoryRendered = true;
}

function renderRawJson() {
  if (!state.report) return;
  byId("report-json").textContent = JSON.stringify(state.report, null, 2);
  state.rawJsonRendered = true;
}

function renderReport(report) {
  state.report = report;
  state.findings = extractFindings(report);
  state.inventoryRendered = false;
  state.rawJsonRendered = false;
  byId("inventory-accordions").replaceChildren();
  byId("report-json").textContent = "Open the Raw JSON tab to render the canonical report.";

  const endpoint = reportEndpoint(report);
  const os = endpoint.os || {};
  const identity = endpoint.endpoint || {};
  const endpointRecordValue = state.endpoints.find((item) => endpointId(item) === (report.endpoint_id || endpoint.endpoint_id)) || {};
  const hostname = os.hostname || identity.hostname || endpointLabel(endpointRecordValue);
  const status = normalizedState(report.status || report.summary?.status || endpoint.status);
  byId("report-placeholder").hidden = true;
  byId("report-view").hidden = false;
  byId("report-title").textContent = `${hostname || "Endpoint"} security assessment`;
  byId("report-subtitle").textContent = `${report.scan_id || endpoint.scan_id || state.selectedScanId} · Completed ${safeDate(report.analysis_completed_at || endpoint.finished_at || report.generated_at)}`;
  const reportStatusNode = byId("report-status");
  reportStatusNode.replaceWith(statusChip(status));
  const replacement = document.querySelector(".report-title-line .status-chip");
  replacement.id = "report-status";

  const counts = severityCounts(state.findings);
  byId("severity-total").textContent = String(state.findings.length);
  byId("severity-critical").textContent = String(counts.CRITICAL);
  byId("severity-high").textContent = String(counts.HIGH);
  byId("severity-medium").textContent = String(counts.MEDIUM);
  byId("severity-low").textContent = String(counts.LOW);
  byId("findings-tab-count").textContent = String(state.findings.length);
  byId("metric-critical").textContent = String(counts.CRITICAL);

  renderCoverage(report);
  renderReportOverview(report);
  renderFindings();
  activateReportTab("overview", false);
}

async function loadReport(scanId) {
  state.selectedScanId = scanId;
  setStatus(`Loading final report ${scanId}…`);
  try {
    let report;
    try {
      report = await api(`/api/v1/platform/scans/${encodeURIComponent(scanId)}/report.json`);
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 404) throw error;
      report = await api(`/api/v1/platform/scans/${encodeURIComponent(scanId)}/report`);
    }
    renderReport(report);
    setStatus(`Loaded normalized report ${scanId}.`, "success");
    byId("report-section").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      setStatus("The endpoint evidence or cloud analysis is still in progress. This page will keep polling scan status.", "warning");
      schedulePolling();
    } else {
      setStatus(`The report could not be loaded: ${error.message}`, "error");
    }
  }
}

function activateReportTab(name, focus = true) {
  const panels = {
    overview: byId("report-overview-panel"),
    findings: byId("findings-panel"),
    inventory: byId("inventory-panel"),
    json: byId("raw-json-panel")
  };
  for (const button of all("[data-report-tab]")) {
    const selected = button.dataset.reportTab === name;
    button.setAttribute("aria-selected", selected ? "true" : "false");
    button.tabIndex = selected ? 0 : -1;
    if (selected && focus) button.focus();
  }
  for (const [key, panel] of Object.entries(panels)) panel.hidden = key !== name;
  if (name === "inventory" && !state.inventoryRendered) renderInventory();
  if (name === "json" && !state.rawJsonRendered) renderRawJson();
}

function safeFilename(value, fallback) {
  const basename = String(value || "").split(/[\\/]/).pop().replace(/[^a-zA-Z0-9._-]/g, "-");
  return basename && basename !== "." && basename !== ".." ? basename.slice(0, 180) : fallback;
}

function dispositionFilename(headers, fallback) {
  const disposition = headers.get("Content-Disposition") || "";
  const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (encoded) {
    try {
      return safeFilename(decodeURIComponent(encoded[1]), fallback);
    } catch {
      return fallback;
    }
  }
  const plain = disposition.match(/filename="?([^";]+)"?/i);
  return safeFilename(plain ? plain[1] : null, fallback);
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function downloadApiArtifact(path, fallbackFilename) {
  const parsed = new URL(path, window.location.origin);
  if (parsed.origin !== window.location.origin || !parsed.pathname.startsWith("/api/v1/platform/")) {
    throw new Error("The server returned an invalid artifact download URL.");
  }
  const result = await api(`${parsed.pathname}${parsed.search}`, { responseType: "blob", accept: "application/octet-stream,application/pdf,application/json" });
  const filename = dispositionFilename(result.headers, fallbackFilename);
  saveBlob(result.blob, filename);
  return { filename, headers: result.headers };
}

async function downloadInstaller(platform) {
  const item = preferredInstaller(platform);
  if (!item || !item.available || !item.download_url) {
    setStatus(`No qualified ${humanize(platform)} package is currently published.`, "warning");
    return;
  }
  setStatus(`Downloading ${item.filename || humanize(platform)}…`);
  try {
    await downloadApiArtifact(item.download_url, safeFilename(item.filename, `endpoint-scanner-${platform.toLowerCase()}`));
    byId("enrollment-platform").value = platform;
    setStatus(`Downloaded ${item.filename || humanize(platform) + " scanner"}. Verify its SHA-256 before installation.`, "success");
  } catch (error) {
    setStatus(`The scanner package could not be downloaded: ${error.message}`, "error");
  }
}

function enrollmentCommand(platform) {
  if (platform === "WINDOWS") {
    const installer = preferredInstaller("WINDOWS");
    const publishedSha256 = String((installer && installer.sha256) || "").trim().toLowerCase();
    const trustedSha256 = /^[0-9a-f]{64}$/.test(publishedSha256) ? publishedSha256 : null;
    const integrityCheck = trustedSha256
      ? [
          `$expectedScannerSha256 = '${trustedSha256}'`,
          "$actualScannerSha256 = (Get-FileHash -LiteralPath $scannerExe -Algorithm SHA256).Hash.ToLowerInvariant()",
          "if ($actualScannerSha256 -ne $expectedScannerSha256) { throw 'Downloaded scanner SHA-256 does not match the server manifest. Do not run it.' }"
        ]
      : ["throw 'A trusted scanner SHA-256 is unavailable. Reconnect the dashboard and download the published package again.'"];
    return [
      "$ErrorActionPreference = 'Stop'",
      "$currentPrincipal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())",
      "$isAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
      "if (-not $isAdministrator) { throw 'Run this setup from PowerShell opened as Administrator.' }",
      "$scannerExe = Join-Path $env:USERPROFILE 'Downloads\\endpoint-scanner.exe'",
      "if (-not (Test-Path -LiteralPath $scannerExe -PathType Leaf)) { throw \"Downloaded scanner not found at $scannerExe. Save it with the published filename or update `$scannerExe.\" }",
      ...integrityCheck,
      "$scannerRoot = Join-Path $env:LOCALAPPDATA 'EnterpriseEndpointScanner'",
      "$scannerState = Join-Path $scannerRoot 'state'",
      "$scannerConfig = Join-Path $scannerRoot 'scanner.local.json'",
      "New-Item -ItemType Directory -Path $scannerRoot -Force | Out-Null",
      "$endpointConfiguration = [ordered]@{",
      "  environment = 'development'",
      "  data_directory = $scannerState",
      "  log_level = 'INFO'",
      "  cloud = [ordered]@{",
      "    base_url = 'http://127.0.0.1:8080'",
      "    allow_insecure_loopback_http = $true",
      "    offload_vulnerability_analysis = $true",
      "    connect_timeout_seconds = 5",
      "    read_timeout_seconds = 30",
      "    max_retries = 5",
      "  }",
      "  scheduling = [ordered]@{ enabled = $false; startup_scan = $false; periodic_interval_seconds = $null }",
      "}",
      "[IO.File]::WriteAllText($scannerConfig, ($endpointConfiguration | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))",
      "& $scannerExe health --config $scannerConfig",
      "if ($LASTEXITCODE -ne 0) { throw 'Endpoint configuration or local scanner health check failed.' }",
      "$secureEnrollmentToken = Read-Host 'Copy the one-time token from the dashboard, then paste it here' -AsSecureString",
      "$tokenPointer = [IntPtr]::Zero",
      "try {",
      "  $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureEnrollmentToken)",
      "  $env:SCANNER_ENROLLMENT_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer)",
      "  if ([string]::IsNullOrWhiteSpace($env:SCANNER_ENROLLMENT_TOKEN)) { throw 'The one-time enrollment token is empty.' }",
      "  $enrollmentOutput = @(& $scannerExe enroll --config $scannerConfig)",
      "  if ($LASTEXITCODE -ne 0) { throw 'Endpoint enrollment failed.' }",
      "}",
      "finally {",
      "  Remove-Item Env:\\SCANNER_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue",
      "  if ($tokenPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer) }",
      "  if ($null -ne $secureEnrollmentToken) { $secureEnrollmentToken.Dispose() }",
      "  Set-Clipboard -Value ([string]::Empty) -ErrorAction SilentlyContinue",
      "}",
      "$enrollment = $enrollmentOutput[-1] | ConvertFrom-Json",
      "$endpointId = [string]$enrollment.endpoint_id",
      "if (-not $endpointId) { throw 'Enrollment did not return an endpoint ID.' }",
      "& $scannerExe agent --config $scannerConfig --endpoint-id $endpointId --poll-interval 5 --jitter 0.10"
    ].join("\n");
  }
  const executable = platform === "MACOS" ? "/usr/local/bin/endpoint-scanner" : "./endpoint-scanner";
  const config = platform === "MACOS" ? "./configured-macos.yaml" : "./configured-linux.yaml";
  return [
    "export SCANNER_ENROLLMENT_TOKEN='<paste the one-time token copied above>'",
    `sudo -E ${executable} enroll --config ${config}`,
    "unset SCANNER_ENROLLMENT_TOKEN"
  ].join("\n");
}

function stopEnrollmentTimer() {
  if (state.enrollmentExpiryTimer) window.clearInterval(state.enrollmentExpiryTimer);
  state.enrollmentExpiryTimer = null;
}

function clearEnrollmentGrant(hide = true) {
  stopEnrollmentTimer();
  state.enrollmentGrant = null;
  byId("enrollment-token").value = "";
  byId("enrollment-token").type = "password";
  byId("toggle-enrollment-token").textContent = "Show";
  byId("copy-enrollment-token").disabled = true;
  byId("copy-enrollment-command").disabled = true;
  byId("enrollment-command").textContent = "";
  byId("enrollment-expiry").textContent = "";
  if (hide) byId("enrollment-result").hidden = true;
}

function updateEnrollmentExpiry() {
  if (!state.enrollmentGrant) return;
  const expiresAt = new Date(state.enrollmentGrant.expires_at).getTime();
  const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  const minutes = Math.floor(seconds / 60);
  const remainder = String(seconds % 60).padStart(2, "0");
  byId("enrollment-expiry").textContent = seconds > 0 ? `Expires in ${minutes}:${remainder}` : "Expired";
  if (seconds === 0) {
    stopEnrollmentTimer();
    state.enrollmentGrant = null;
    byId("enrollment-token").value = "";
    byId("copy-enrollment-token").disabled = true;
    byId("copy-enrollment-command").disabled = true;
    setStatus("The one-time enrollment grant expired. Generate a new grant before enrolling the endpoint.", "warning");
  }
}

async function generateEnrollmentGrant(event) {
  event.preventDefault();
  if (!state.connected) {
    setStatus("Connect to the API before creating an enrollment grant.", "warning");
    return;
  }
  clearEnrollmentGrant();
  const button = byId("generate-enrollment");
  const platform = byId("enrollment-platform").value;
  const label = byId("enrollment-label").value.trim();
  button.disabled = true;
  button.textContent = "Generating…";
  try {
    const grant = await api("/api/v1/platform/enrollment-tokens", {
      method: "POST",
      headers: { "Idempotency-Key": randomIdempotencyKey() },
      body: { expires_in_seconds: 900, os_family: platform, label: label || null }
    });
    state.enrollmentGrant = grant;
    byId("enrollment-token").value = grant.enrollment_token || "";
    byId("enrollment-command").textContent = enrollmentCommand(platform);
    byId("enrollment-command-title").textContent = `${humanize(platform)} developer portable enrollment`;
    byId("copy-enrollment-token").disabled = !grant.enrollment_token;
    byId("copy-enrollment-command").disabled = false;
    byId("enrollment-result").hidden = false;
    updateEnrollmentExpiry();
    state.enrollmentExpiryTimer = window.setInterval(updateEnrollmentExpiry, 1000);
    setStatus("Created a one-time enrollment grant. It is not stored by this dashboard; copy it before it expires.", "success");
  } catch (error) {
    setStatus(`The enrollment grant could not be created: ${error.message}`, "error");
  } finally {
    button.disabled = !state.connected;
    button.textContent = "Generate one-time token";
  }
}

async function downloadJson() {
  if (!state.selectedScanId || !state.report) return;
  const fallback = `endpoint-security-${safeFilename(state.selectedScanId, "scan")}.json`;
  try {
    const artifact = await downloadApiArtifact(`/api/v1/platform/scans/${encodeURIComponent(state.selectedScanId)}/report.json`, fallback);
    const digest = artifact.headers.get("X-Report-SHA256");
    setStatus(digest ? `Downloaded the canonical JSON report · SHA-256 ${digest}` : "Downloaded the canonical JSON report.", "success");
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      const content = JSON.stringify(state.report, null, 2);
      saveBlob(new Blob([content], { type: "application/json;charset=utf-8" }), fallback);
      setStatus("Downloaded the canonical JSON currently loaded in this dashboard.", "success");
    } else {
      setStatus(`The JSON report could not be downloaded: ${error.message}`, "error");
    }
  }
}

async function downloadPdf() {
  if (!state.selectedScanId || !state.report) return;
  const fallback = `endpoint-security-${safeFilename(state.selectedScanId, "scan")}.pdf`;
  setStatus("Requesting the server-generated PDF report…");
  try {
    const artifact = await downloadApiArtifact(`/api/v1/platform/scans/${encodeURIComponent(state.selectedScanId)}/report.pdf`, fallback);
    const pdfDigest = artifact.headers.get("X-PDF-SHA256");
    const sourceDigest = artifact.headers.get("X-Source-JSON-SHA256");
    const integrity = [sourceDigest ? `source JSON ${sourceDigest}` : null, pdfDigest ? `PDF ${pdfDigest}` : null].filter(Boolean).join(" · ");
    setStatus(integrity ? `Downloaded the PDF · ${integrity}` : "Downloaded the PDF generated from the same canonical report revision.", "success");
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      setStatus(`The PDF is not ready yet: ${error.message}`, "warning");
    } else if (error instanceof ApiError && error.status === 404) {
      setStatus("PDF generation is not enabled on this local server. JSON remains available.", "warning");
    } else {
      setStatus(`The PDF report could not be downloaded: ${error.message}`, "error");
    }
  }
}

function resetDashboard() {
  stopPolling();
  clearEnrollmentGrant();
  state.endpoints = [];
  state.scans = [];
  state.installers = [];
  state.selectedScanId = null;
  state.report = null;
  state.findings = [];
  renderEndpoints();
  renderScans();
  renderInstallers();
  byId("metric-critical").textContent = "—";
  byId("report-view").hidden = true;
  byId("report-placeholder").hidden = false;
  setConnected(false);
}

byId("connection-toggle").addEventListener("click", () => {
  const panel = byId("connection-panel");
  panel.hidden = !panel.hidden;
  byId("connection-toggle").setAttribute("aria-expanded", panel.hidden ? "false" : "true");
  if (!panel.hidden) tokenInput.focus();
});

byId("connection-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = tokenInput.value.trim();
  if (!token || token.length > 4096 || /[\u0000-\u0020\u007f]/.test(token)) {
    setStatus("Enter a valid administrator token without spaces or control characters.", "error");
    return;
  }
  state.token = token;
  sessionStorage.setItem("scanner-admin-token", token);
  await loadDashboard();
  if (state.connected) {
    byId("connection-panel").hidden = true;
    byId("connection-toggle").setAttribute("aria-expanded", "false");
  }
});

byId("disconnect").addEventListener("click", () => {
  state.token = "";
  tokenInput.value = "";
  sessionStorage.removeItem("scanner-admin-token");
  resetDashboard();
  setStatus("The administrator token was removed from this browser tab.", "success");
});

byId("refresh-all").addEventListener("click", () => loadDashboard());
byId("refresh-scans").addEventListener("click", async () => {
  try {
    await loadScans();
    setStatus(`Loaded ${state.scans.length} scan(s).`, "success");
    schedulePolling();
  } catch (error) {
    setStatus(error.message, "error");
  }
});
byId("endpoint-filter").addEventListener("input", renderEndpoints);
byId("scan-filter").addEventListener("change", renderScans);
byId("finding-filter").addEventListener("input", renderFindings);
byId("severity-filter").addEventListener("change", renderFindings);
byId("inventory-filter").addEventListener("input", () => {
  if (state.inventoryFilterTimer) window.clearTimeout(state.inventoryFilterTimer);
  state.inventoryFilterTimer = window.setTimeout(renderInventory, 150);
});
byId("enrollment-form").addEventListener("submit", generateEnrollmentGrant);
byId("toggle-enrollment-token").addEventListener("click", () => {
  const input = byId("enrollment-token");
  input.type = input.type === "password" ? "text" : "password";
  byId("toggle-enrollment-token").textContent = input.type === "password" ? "Show" : "Hide";
});
byId("copy-enrollment-token").addEventListener("click", async () => {
  const token = byId("enrollment-token").value;
  if (!token) return;
  try {
    await navigator.clipboard.writeText(token);
    setStatus("Copied the one-time enrollment token. Paste it into the setup command's hidden token prompt; the command clears the process environment and clipboard afterward.", "success");
  } catch {
    setStatus("Clipboard access is unavailable. Select and copy the token manually.", "warning");
  }
});
byId("copy-enrollment-command").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(byId("enrollment-command").textContent);
    setStatus("Copied the developer setup command. Run it in elevated PowerShell, then return here and copy the token when the hidden prompt appears.", "success");
  } catch {
    setStatus("Clipboard access is unavailable. Select and copy the command manually.", "warning");
  }
});
byId("clear-enrollment").addEventListener("click", () => {
  clearEnrollmentGrant();
  setStatus("Cleared the enrollment grant from this page. The server-side grant will expire automatically if unused.", "success");
});
all("[data-open-scan]").forEach((button) => button.addEventListener("click", () => openScanDialog()));
all("[data-download-platform]").forEach((button) => button.addEventListener("click", () => downloadInstaller(button.dataset.downloadPlatform)));
byId("scan-form").addEventListener("submit", submitScan);
byId("close-scan-dialog").addEventListener("click", closeScanDialog);
byId("cancel-scan").addEventListener("click", closeScanDialog);
byId("scan-dialog").addEventListener("click", (event) => {
  if (event.target === byId("scan-dialog")) closeScanDialog();
});
byId("download-json").addEventListener("click", downloadJson);
byId("download-pdf").addEventListener("click", downloadPdf);
byId("copy-report").addEventListener("click", async () => {
  if (!state.report) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(state.report, null, 2));
    setStatus("Copied the canonical JSON report.", "success");
  } catch {
    setStatus("Clipboard access is unavailable. Use Download JSON instead.", "warning");
  }
});

all("[data-report-tab]").forEach((button) => {
  button.addEventListener("click", () => activateReportTab(button.dataset.reportTab));
  button.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const tabs = all("[data-report-tab]");
    const index = tabs.indexOf(button);
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    activateReportTab(tabs[next].dataset.reportTab);
  });
});

byId("dismiss-status").addEventListener("click", () => {
  byId("status-banner").hidden = true;
});

byId("mobile-menu").addEventListener("click", () => {
  const open = document.body.classList.toggle("nav-open");
  byId("mobile-menu").setAttribute("aria-expanded", open ? "true" : "false");
});
all(".nav-link").forEach((link) => link.addEventListener("click", () => {
  all(".nav-link").forEach((item) => item.classList.toggle("active", item === link));
  document.body.classList.remove("nav-open");
  byId("mobile-menu").setAttribute("aria-expanded", "false");
}));

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) schedulePolling();
});

renderInstallers();
renderEndpoints();
renderScans();
clearEnrollmentGrant();
setConnected(false);
if (state.token) loadDashboard();
