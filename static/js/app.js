/**
 * TINY MONITOR — Core Frontend Application Logic
 * Full-stack DFIR Operations & TinyFish Search API Integration
 */

(function () {
  "use strict";

  // State Management
  const State = {
    currentView: "overview",
    cases: [],
    selectedCase: null,
    evidence: [],
    intelHistory: [],
    systemStatus: null
  };

  // DOM Cache
  const DOM = {
    // Navigation
    navItems: document.querySelectorAll(".nav-item"),
    views: document.querySelectorAll(".view-section"),
    pageHeading: document.getElementById("page-heading"),
    topbarDot: document.getElementById("topbar-status-dot"),
    topbarStatusText: document.getElementById("topbar-status-text"),

    // KPIs
    kpiTotalCases: document.getElementById("kpi-total-cases"),
    kpiOpenCases: document.getElementById("kpi-open-cases"),
    kpiTotalEvidence: document.getElementById("kpi-total-evidence"),
    kpiVerifiedEvidence: document.getElementById("kpi-verified-evidence"),
    kpiFailedIntegrity: document.getElementById("kpi-failed-integrity"),
    kpiTotalLookups: document.getElementById("kpi-total-lookups"),

    // Overview Feeds
    overviewRecentActivity: document.getElementById("overview-recent-activity"),
    overviewRecentLookups: document.getElementById("overview-recent-lookups"),

    // Cases
    casesTableBody: document.getElementById("cases-table-body"),
    caseStatusFilters: document.getElementById("case-status-filters"),
    btnQuickNewCase: document.getElementById("btn-quick-new-case"),
    btnCasesCreate: document.getElementById("btn-cases-create"),
    qaNewCase: document.getElementById("qa-new-case"),
    modalCreateCase: document.getElementById("modal-create-case"),
    formCreateCase: document.getElementById("form-create-case"),

    // Case Dossier Modal
    modalCaseDetail: document.getElementById("modal-case-detail"),
    dossierCaseNumber: document.getElementById("dossier-case-number"),
    dossierCaseTitle: document.getElementById("dossier-case-title"),
    dossierStatusSelect: document.getElementById("dossier-status-select"),
    dossierSeveritySelect: document.getElementById("dossier-severity-select"),
    dossierDescription: document.getElementById("dossier-description"),
    dossierEvidenceList: document.getElementById("dossier-evidence-list"),
    dossierNotesList: document.getElementById("dossier-notes-list"),
    dossierNewNote: document.getElementById("dossier-new-note"),
    btnDossierAddNote: document.getElementById("btn-dossier-add-note"),
    btnDossierAddEvidence: document.getElementById("btn-dossier-add-evidence"),
    btnSaveDossierStatus: document.getElementById("btn-save-dossier-status"),
    btnDossierGeneratePdf: document.getElementById("btn-dossier-generate-pdf"),

    // Evidence
    evidenceCaseSelect: document.getElementById("evidence-case-select"),
    evidenceInvestigator: document.getElementById("evidence-investigator"),
    evidenceDescription: document.getElementById("evidence-description"),
    evidenceDropzone: document.getElementById("evidence-dropzone"),
    evidenceFileInput: document.getElementById("evidence-file-input"),
    dropzoneLabel: document.getElementById("dropzone-label"),
    clientHashPreview: document.getElementById("client-hash-preview"),
    clientFileName: document.getElementById("client-file-name"),
    clientFileSize: document.getElementById("client-file-size"),
    clientFileHash: document.getElementById("client-file-hash"),
    formUploadEvidence: document.getElementById("form-upload-evidence"),
    evidenceTableBody: document.getElementById("evidence-table-body"),
    btnRefreshEvidence: document.getElementById("btn-refresh-evidence"),

    // Threat Intel
    consoleStatusPill: document.getElementById("console-status-pill"),
    consoleKeyBadge: document.getElementById("console-key-badge"),
    intelIndicatorInput: document.getElementById("intel-indicator-input"),
    btnDetectIndicator: document.getElementById("btn-detect-indicator"),
    indicatorTypeBadge: document.getElementById("indicator-type-badge"),
    intelCaseSelect: document.getElementById("intel-case-select"),
    intelDomainType: document.getElementById("intel-domain-type"),
    intelPurposeInput: document.getElementById("intel-purpose-input"),
    formThreatSearch: document.getElementById("form-threat-search"),
    btnExecuteThreatSearch: document.getElementById("btn-execute-threat-search"),
    intelResultsContainer: document.getElementById("intel-results-container"),
    intelResultsCounter: document.getElementById("intel-results-counter"),
    intelHistoryTableBody: document.getElementById("intel-history-table-body"),

    // Timeline
    globalTimelineContainer: document.getElementById("global-timeline-container"),
    btnRefreshTimeline: document.getElementById("btn-refresh-timeline"),

    // Reports
    reportCaseSelect: document.getElementById("report-case-select"),
    reportInvestigator: document.getElementById("report-investigator"),
    formGenerateReport: document.getElementById("form-generate-report"),
    btnCompilePdf: document.getElementById("btn-compile-pdf"),
    reportDownloadCard: document.getElementById("report-download-card"),
    reportResFilename: document.getElementById("report-res-filename"),
    reportResMeta: document.getElementById("report-res-meta"),
    reportDownloadBtn: document.getElementById("report-download-btn"),

    // Settings
    settingsStatusBadge: document.getElementById("settings-status-badge"),
    settingsEndpoint: document.getElementById("settings-endpoint"),
    settingsKeyStatus: document.getElementById("settings-key-status"),
    settingsLastTested: document.getElementById("settings-last-tested"),
    btnTestTinyfishSettings: document.getElementById("btn-test-tinyfish-settings"),
    settingsTestOutput: document.getElementById("settings-test-output")
  };

  // View Title Mapping
  const ViewTitles = {
    "overview": "Operations Overview",
    "cases": "Incident Response Cases",
    "evidence": "Digital Evidence Repository",
    "threat-intel": "TinyFish Threat Intelligence Research",
    "timeline": "Chronological Investigation Audit Log",
    "reports": "Forensic Investigation Reports",
    "settings": "Integration & System Settings"
  };

  // --- Router & Navigation ---
  function switchView(viewName) {
    if (!ViewTitles[viewName]) return;
    State.currentView = viewName;

    DOM.views.forEach(view => {
      view.style.display = view.id === `view-${viewName}` ? "block" : "none";
    });

    DOM.navItems.forEach(item => {
      item.classList.toggle("active", item.dataset.view === viewName);
    });

    DOM.pageHeading.textContent = ViewTitles[viewName];

    // Trigger data fetch for current view
    if (viewName === "overview") loadOverview();
    else if (viewName === "cases") loadCases();
    else if (viewName === "evidence") loadEvidence();
    else if (viewName === "threat-intel") loadThreatIntel();
    else if (viewName === "timeline") loadTimeline();
    else if (viewName === "reports") loadReportsView();
    else if (viewName === "settings") loadSettings();
  }

  // --- API Helpers ---
  async function apiGet(endpoint) {
    const res = await fetch(endpoint);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  async function apiPost(endpoint, body) {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  async function apiPatch(endpoint, body) {
    const res = await fetch(endpoint, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  }

  // --- System Status & Initialization ---
  async function checkSystemStatus() {
    try {
      const data = await apiGet("/api/status");
      State.systemStatus = data;
      const tf = data.tinyfish || {};

      // Update Topbar Badge
      DOM.topbarDot.className = "status-dot";
      if (tf.status === "CONFIGURED_AND_TESTED") {
        DOM.topbarDot.classList.add("active");
        DOM.topbarStatusText.textContent = "TinyFish: Connected & Verified";
      } else if (tf.status === "CONFIGURED_UNTESTED") {
        DOM.topbarDot.classList.add("warn");
        DOM.topbarStatusText.textContent = "TinyFish: Configured (Untested)";
      } else if (tf.status === "NOT_CONFIGURED") {
        DOM.topbarDot.classList.add("warn");
        DOM.topbarStatusText.textContent = "TinyFish: Not Configured (.env)";
      } else if (tf.status === "AUTH_FAILED") {
        DOM.topbarDot.classList.add("danger");
        DOM.topbarStatusText.textContent = "TinyFish: Auth Failed (401)";
      } else {
        DOM.topbarDot.classList.add("danger");
        DOM.topbarStatusText.textContent = "TinyFish: Request Failed";
      }

      // Update Settings View if open
      if (DOM.settingsStatusBadge) {
        DOM.settingsStatusBadge.textContent = tf.status || "UNKNOWN";
        DOM.settingsStatusBadge.className = "badge " + (
          tf.status === "CONFIGURED_AND_TESTED" ? "badge-verified" :
          tf.status === "NOT_CONFIGURED" ? "badge-closed" : "badge-failed"
        );
        DOM.settingsEndpoint.textContent = tf.endpoint || "https://api.search.tinyfish.ai";
        DOM.settingsKeyStatus.textContent = tf.key_status || "Not Set";
        DOM.settingsLastTested.textContent = tf.last_tested ? new Date(tf.last_tested).toLocaleString() : "Never tested in this session";
      }

      // Update Console Pill
      if (DOM.consoleStatusPill) {
        DOM.consoleStatusPill.textContent = tf.status === "CONFIGURED_AND_TESTED" ? "API Verified" : (tf.status || "Ready");
      }
      if (DOM.consoleKeyBadge) {
        DOM.consoleKeyBadge.textContent = tf.key_status || "Key in .env";
      }
    } catch (err) {
      console.error("Status check error:", err);
      DOM.topbarDot.className = "status-dot danger";
      DOM.topbarStatusText.textContent = "Server Offline";
    }
  }

  // --- Overview Loader ---
  async function loadOverview() {
    try {
      const data = await apiGet("/api/dashboard/metrics");
      DOM.kpiTotalCases.textContent = data.total_cases;
      DOM.kpiOpenCases.textContent = data.open_cases;
      DOM.kpiTotalEvidence.textContent = data.total_evidence;
      DOM.kpiVerifiedEvidence.textContent = data.verified_evidence;
      DOM.kpiTotalLookups.textContent = data.total_lookups;

      if (data.failed_integrity > 0) {
        DOM.kpiFailedIntegrity.textContent = `${data.failed_integrity} Alert(s)`;
        DOM.kpiFailedIntegrity.style.color = "#ef4444";
      } else {
        DOM.kpiFailedIntegrity.textContent = "0 Flags";
        DOM.kpiFailedIntegrity.style.color = "#10b981";
      }

      // Render Recent Timeline Activity
      if (data.recent_activity && data.recent_activity.length > 0) {
        DOM.overviewRecentActivity.innerHTML = data.recent_activity.map(ev => `
          <div style="display: flex; gap: 12px; margin-bottom: 12px; padding-bottom: 10px; border-bottom: 1px solid rgba(255,255,255,0.04);">
            <div style="font-size: 11px; color: var(--text-dim); min-width: 70px;">
              ${ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : ""}
            </div>
            <div style="flex: 1;">
              <div style="font-weight: 600; font-size: 12.5px; color: #ffffff;">${escapeHtml(ev.title)}</div>
              <div style="font-size: 11.5px; color: var(--text-muted);">${escapeHtml(ev.description || "")}</div>
            </div>
          </div>
        `).join("");
      } else {
        DOM.overviewRecentActivity.innerHTML = `<div class="empty-state"><div class="empty-state-text">No investigation activity recorded yet.</div></div>`;
      }

      // Render Recent Lookups
      if (data.recent_lookups && data.recent_lookups.length > 0) {
        DOM.overviewRecentLookups.innerHTML = data.recent_lookups.map(lk => `
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,0.04);">
            <div>
              <span class="font-mono" style="font-weight: 700; color: var(--cyan-primary);">${escapeHtml(lk.indicator)}</span>
              <span class="badge badge-open" style="font-size: 9.5px; margin-left: 6px;">${escapeHtml(lk.indicator_type)}</span>
              <div style="font-size: 11px; color: var(--text-dim); margin-top: 2px;">
                ${lk.case_number ? `Case ${lk.case_number} • ` : ""}${lk.results_count} results
              </div>
            </div>
            <div>
              <span class="badge ${lk.status === 'SUCCESS' ? 'badge-verified' : (lk.status === 'ZERO_RESULTS' ? 'badge-closed' : 'badge-failed')}">
                ${lk.status}
              </span>
            </div>
          </div>
        `).join("");
      } else {
        DOM.overviewRecentLookups.innerHTML = `<div class="empty-state"><div class="empty-state-text">No threat intelligence queries run yet.</div></div>`;
      }
    } catch (err) {
      console.error("Overview load error:", err);
    }
  }

  // --- Cases Loader ---
  async function loadCases(statusFilter = "") {
    try {
      const url = statusFilter ? `/api/cases?status=${encodeURIComponent(statusFilter)}` : "/api/cases";
      const data = await apiGet(url);
      State.cases = data.cases || [];

      // Update case selector dropdowns across the app
      populateCaseDropdowns(State.cases);

      if (State.cases.length === 0) {
        DOM.casesTableBody.innerHTML = `
          <tr>
            <td colspan="9" class="empty-state">
              <div class="empty-state-text">No cases found ${statusFilter ? `with status '${statusFilter}'` : ""}. Click '+ New Case' to initialize an investigation.</div>
            </td>
          </tr>
        `;
        return;
      }

      DOM.casesTableBody.innerHTML = State.cases.map(c => `
        <tr>
          <td><b class="font-mono" style="color: var(--cyan-primary);">${escapeHtml(c.case_number)}</b></td>
          <td><b>${escapeHtml(c.title)}</b></td>
          <td><span class="badge badge-${c.severity.toLowerCase()}">${c.severity}</span></td>
          <td><span class="badge badge-${c.status.toLowerCase()}">${c.status}</span></td>
          <td>${escapeHtml(c.investigator)}</td>
          <td><span class="badge badge-open">${c.evidence_count || 0}</span></td>
          <td><span class="badge badge-investigating">${c.lookups_count || 0}</span></td>
          <td style="font-size: 11.5px; color: var(--text-dim);">${formatDate(c.updated_at)}</td>
          <td>
            <button class="btn btn-secondary btn-sm btn-view-dossier" data-case-id="${c.id}">
              Open Dossier
            </button>
          </td>
        </tr>
      `).join("");

      // Bind dossier buttons
      document.querySelectorAll(".btn-view-dossier").forEach(btn => {
        btn.addEventListener("click", () => openCaseDossier(parseInt(btn.dataset.caseId)));
      });
    } catch (err) {
      console.error("Error loading cases:", err);
      DOM.casesTableBody.innerHTML = `<tr><td colspan="9" class="alert alert-danger">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  function populateCaseDropdowns(cases) {
    const optionsHtml = '<option value="">Select Target Case...</option>' +
      cases.map(c => `<option value="${c.id}">${c.case_number} — ${escapeHtml(c.title)} (${c.severity})</option>`).join("");

    if (DOM.evidenceCaseSelect) DOM.evidenceCaseSelect.innerHTML = optionsHtml;
    if (DOM.intelCaseSelect) {
      DOM.intelCaseSelect.innerHTML = '<option value="">No case (Standalone Intelligence Research)</option>' +
        cases.map(c => `<option value="${c.id}">${c.case_number} — ${escapeHtml(c.title)}</option>`).join("");
    }
    if (DOM.reportCaseSelect) DOM.reportCaseSelect.innerHTML = optionsHtml;
  }

  // --- Case Dossier Modal ---
  async function openCaseDossier(caseId) {
    try {
      const data = await apiGet(`/api/cases/${caseId}`);
      State.selectedCase = data.case;

      DOM.dossierCaseNumber.textContent = data.case.case_number;
      DOM.dossierCaseTitle.textContent = data.case.title;
      DOM.dossierStatusSelect.value = data.case.status;
      DOM.dossierSeveritySelect.value = data.case.severity;
      DOM.dossierDescription.textContent = data.case.description || "No description provided.";

      // Render attached evidence
      if (data.evidence && data.evidence.length > 0) {
        DOM.dossierEvidenceList.innerHTML = `
          <table class="cyber-table" style="font-size: 12px;">
            <thead>
              <tr>
                <th>File</th>
                <th>SHA-256</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${data.evidence.map(ev => `
                <tr>
                  <td><b>${escapeHtml(ev.filename)}</b><br/><span style="font-size: 10px; color: var(--text-dim);">${ev.file_size} bytes</span></td>
                  <td><span class="font-mono" style="font-size: 10px;">${ev.sha256_hash.substring(0, 16)}...</span></td>
                  <td>
                    <span class="badge ${ev.integrity_status === 'VERIFIED_MATCH' ? 'badge-verified' : 'badge-failed'}">
                      ${ev.integrity_status === 'VERIFIED_MATCH' ? 'MATCH' : ev.integrity_status}
                    </span>
                  </td>
                  <td>
                    <button class="btn btn-secondary btn-sm btn-verify-inline" data-evidence-id="${ev.id}">Verify</button>
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        `;
        document.querySelectorAll(".btn-verify-inline").forEach(btn => {
          btn.addEventListener("click", () => verifyEvidenceHash(parseInt(btn.dataset.evidenceId), btn));
        });
      } else {
        DOM.dossierEvidenceList.innerHTML = `<div class="empty-state" style="padding: 12px;">No evidence files attached yet.</div>`;
      }

      // Render notes
      renderDossierNotes(data.notes || []);

      // Open Modal
      DOM.modalCaseDetail.classList.add("open");
    } catch (err) {
      alert("Error loading case dossier: " + err.message);
    }
  }

  function renderDossierNotes(notes) {
    if (notes.length === 0) {
      DOM.dossierNotesList.innerHTML = `<div style="font-size: 12px; color: var(--text-dim); font-style: italic;">No investigator notes recorded yet.</div>`;
      return;
    }
    DOM.dossierNotesList.innerHTML = notes.map(n => `
      <div style="background: var(--bg-input); border: 1px solid var(--border-card); padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 6px;">
        <div style="display: flex; justify-content: space-between; font-size: 10.5px; color: var(--text-dim); margin-bottom: 2px;">
          <b>${escapeHtml(n.author)}</b>
          <span>${formatDate(n.created_at)}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-main);">${escapeHtml(n.note)}</div>
      </div>
    `).join("");
  }

  // --- Digital Evidence Loader & Hash Management ---
  async function loadEvidence() {
    try {
      const casesData = await apiGet("/api/cases");
      State.cases = casesData.cases || [];
      populateCaseDropdowns(State.cases);

      let allEvidence = [];
      for (const c of State.cases) {
        const evData = await apiGet(`/api/cases/${c.id}/evidence`);
        (evData.evidence || []).forEach(e => {
          e.case_number = c.case_number;
          allEvidence.push(e);
        });
      }
      State.evidence = allEvidence;

      if (allEvidence.length === 0) {
        DOM.evidenceTableBody.innerHTML = `
          <tr>
            <td colspan="8" class="empty-state">
              <div class="empty-state-text">No digital evidence files stored yet. Use the acquisition form above to ingest forensic artifacts.</div>
            </td>
          </tr>
        `;
        return;
      }

      DOM.evidenceTableBody.innerHTML = allEvidence.map(ev => `
        <tr>
          <td><b class="font-mono" style="color: var(--cyan-primary);">${escapeHtml(ev.case_number)}</b></td>
          <td><b>${escapeHtml(ev.filename)}</b><br/><span style="font-size: 11px; color: var(--text-dim);">${ev.mime_type}</span></td>
          <td>${formatBytes(ev.file_size)}</td>
          <td>
            <span class="font-mono" style="color: var(--cyan-primary); cursor: pointer;" title="Click to copy full SHA-256" onclick="navigator.clipboard.writeText('${ev.sha256_hash}')">
              ${ev.sha256_hash.substring(0, 14)}...${ev.sha256_hash.substring(54)}
            </span>
          </td>
          <td style="font-size: 11.5px; color: var(--text-dim);">${formatDate(ev.acquisition_date)}</td>
          <td id="ev-status-badge-${ev.id}">
            <span class="badge ${ev.integrity_status === 'VERIFIED_MATCH' ? 'badge-verified' : (ev.integrity_status === 'UNVERIFIED' ? 'badge-open' : 'badge-failed')}">
              ${ev.integrity_status === 'VERIFIED_MATCH' ? 'VERIFIED MATCH' : ev.integrity_status}
            </span>
          </td>
          <td style="font-size: 11px; color: var(--text-dim);" id="ev-last-verified-${ev.id}">
            ${ev.last_verified_at ? formatDate(ev.last_verified_at) : 'Never'}
          </td>
          <td>
            <button class="btn btn-secondary btn-sm btn-verify-hash" data-evidence-id="${ev.id}">
              Verify Hash
            </button>
          </td>
        </tr>
      `).join("");

      // Bind verify buttons
      document.querySelectorAll(".btn-verify-hash").forEach(btn => {
        btn.addEventListener("click", () => verifyEvidenceHash(parseInt(btn.dataset.evidenceId), btn));
      });
    } catch (err) {
      console.error("Evidence load error:", err);
      DOM.evidenceTableBody.innerHTML = `<tr><td colspan="8" class="alert alert-danger">${escapeHtml(err.message)}</td></tr>`;
    }
  }

  // Verify Single Evidence Hash
  async function verifyEvidenceHash(evidenceId, btnElement) {
    const originalText = btnElement.innerHTML;
    btnElement.innerHTML = `<span class="spinner"></span> Hashing...`;
    btnElement.disabled = true;

    try {
      const res = await apiPost(`/api/evidence/${evidenceId}/verify`, { verified_by: "Lead Investigator" });
      const statusBadge = document.getElementById(`ev-status-badge-${evidenceId}`);
      const lastVerified = document.getElementById(`ev-last-verified-${evidenceId}`);

      if (statusBadge) {
        statusBadge.innerHTML = `
          <span class="badge ${res.status === 'VERIFIED_MATCH' ? 'badge-verified' : 'badge-failed'}">
            ${res.status === 'VERIFIED_MATCH' ? 'VERIFIED MATCH' : res.status}
          </span>
        `;
      }
      if (lastVerified) {
        lastVerified.textContent = formatDate(res.verified_at);
      }

      // If currently inside dossier modal, refresh evidence view
      if (State.selectedCase) {
        openCaseDossier(State.selectedCase.id);
      }
      checkSystemStatus();
    } catch (err) {
      alert("Integrity verification failed: " + err.message);
    } finally {
      btnElement.innerHTML = originalText;
      btnElement.disabled = false;
    }
  }

  // Client-Side SHA-256 Pre-calculation
  async function computeClientSHA256(file) {
    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // --- Threat Intelligence (TinyFish) Loader & Search ---
  async function loadThreatIntel() {
    try {
      checkSystemStatus();
      const casesData = await apiGet("/api/cases");
      State.cases = casesData.cases || [];
      populateCaseDropdowns(State.cases);

      const histData = await apiGet("/api/threat-intel/history");
      State.intelHistory = histData.lookups || [];

      renderIntelHistory(State.intelHistory);
    } catch (err) {
      console.error("Threat intel load error:", err);
    }
  }

  function renderIntelHistory(lookups) {
    if (lookups.length === 0) {
      DOM.intelHistoryTableBody.innerHTML = `
        <tr>
          <td colspan="8" class="empty-state">
            <div class="empty-state-text">No threat intelligence queries run yet.</div>
          </td>
        </tr>
      `;
      return;
    }

    DOM.intelHistoryTableBody.innerHTML = lookups.map(lk => `
      <tr>
        <td style="font-size: 11px; color: var(--text-dim);">${formatDate(lk.created_at)}</td>
        <td><b class="font-mono" style="color: var(--cyan-primary);">${lk.case_number ? escapeHtml(lk.case_number) : '-'}</b></td>
        <td><span class="font-mono" style="font-weight: 700; color: #ffffff;">${escapeHtml(lk.indicator)}</span></td>
        <td><span class="badge badge-open">${escapeHtml(lk.indicator_type)}</span></td>
        <td>
          <span class="badge ${lk.status === 'SUCCESS' ? 'badge-verified' : (lk.status === 'ZERO_RESULTS' ? 'badge-closed' : 'badge-failed')}">
            ${lk.status}
          </span>
        </td>
        <td><b>${lk.results_count}</b> leads</td>
        <td>${escapeHtml(lk.investigator)}</td>
        <td>
          <button class="btn btn-secondary btn-sm btn-revisit-lookup" data-lookup-id="${lk.id}">
            View Leads
          </button>
        </td>
      </tr>
    `).join("");

    document.querySelectorAll(".btn-revisit-lookup").forEach(btn => {
      btn.addEventListener("click", () => {
        const item = State.intelHistory.find(x => x.id === parseInt(btn.dataset.lookupId));
        if (item) {
          DOM.intelIndicatorInput.value = item.indicator;
          DOM.indicatorTypeBadge.textContent = `Type: ${item.indicator_type.toUpperCase()}`;
          renderIntelResults(item.results || [], item.indicator, item.status);
          DOM.intelResultsContainer.scrollIntoView({ behavior: "smooth" });
        }
      });
    });
  }

  function renderIntelResults(results, indicator, status) {
    DOM.intelResultsCounter.textContent = `${results.length} intelligence lead(s) retrieved for '${indicator}'`;

    if (results.length === 0) {
      if (status === "ZERO_RESULTS") {
        DOM.intelResultsContainer.innerHTML = `
          <div class="alert alert-info">
            <b>Query Succeeded:</b> TinyFish Search returned 0 public cybersecurity advisories or incident reports matching <code>${escapeHtml(indicator)}</code>. This indicator may be newly observed or private.
          </div>
        `;
      } else {
        DOM.intelResultsContainer.innerHTML = `
          <div class="empty-state">
            <div class="empty-state-text">No results found for this query.</div>
          </div>
        `;
      }
      return;
    }

    DOM.intelResultsContainer.innerHTML = results.map(r => `
      <div class="intel-result-card">
        <div class="intel-source-row">
          <span class="intel-site-pill">${escapeHtml(r.site_name || 'Web Source')}</span>
          ${r.date ? `<span style="color: var(--text-dim);">Published: ${escapeHtml(r.date)}</span>` : ""}
          <span style="margin-left: auto; color: var(--text-dim); font-size: 10px;">Position #${r.position}</span>
        </div>
        <div class="intel-title">
          <a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(r.title)}</a>
        </div>
        <div class="intel-snippet">${escapeHtml(r.snippet || "No text snippet available.")}</div>
        <div class="intel-footer">
          <a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer" class="intel-url">${escapeHtml(r.url)}</a>
          <span>Retrieved: ${formatDate(r.retrieved_at)}</span>
        </div>
      </div>
    `).join("");
  }

  // --- Timeline Loader ---
  async function loadTimeline() {
    try {
      const data = await apiGet("/api/timeline?limit=60");
      const events = data.timeline || [];

      if (events.length === 0) {
        DOM.globalTimelineContainer.innerHTML = `<div class="empty-state"><div class="empty-state-text">No investigation events logged.</div></div>`;
        return;
      }

      DOM.globalTimelineContainer.innerHTML = events.map(ev => {
        let dotClass = "evidence";
        let icon = "📋";
        if (ev.event_type === "INTEGRITY_VERIFIED") { dotClass = "verified"; icon = "✓"; }
        else if (ev.event_type === "INTEGRITY_FAILED") { dotClass = "mismatch"; icon = "!"; }
        else if (ev.event_type === "THREAT_INTEL_SEARCH") { dotClass = "intel"; icon = "🔍"; }
        else if (ev.event_type === "REPORT_GENERATED") { dotClass = "evidence"; icon = "📄"; }

        return `
          <div class="timeline-item">
            <div class="timeline-dot ${dotClass}">${icon}</div>
            <div class="timeline-content">
              <div class="timeline-header">
                <span class="timeline-title">${escapeHtml(ev.title)}</span>
                <span class="timeline-time">${formatDate(ev.timestamp)}</span>
              </div>
              <div class="timeline-desc">${escapeHtml(ev.description || "")}</div>
              <div style="font-size: 10.5px; color: var(--text-dim); margin-top: 6px;">
                ${ev.case_number ? `<b>Case ${ev.case_number}</b> • ` : ""}Actor: <b>${escapeHtml(ev.actor)}</b>
              </div>
            </div>
          </div>
        `;
      }).join("");
    } catch (err) {
      console.error("Timeline load error:", err);
    }
  }

  // --- Reports View Loader ---
  async function loadReportsView() {
    try {
      const casesData = await apiGet("/api/cases");
      State.cases = casesData.cases || [];
      populateCaseDropdowns(State.cases);
    } catch (err) {
      console.error("Reports load error:", err);
    }
  }

  // --- Settings Loader ---
  function loadSettings() {
    checkSystemStatus();
  }

  // --- Event Listeners Setup ---
  function setupEventListeners() {
    // Navigation Clicks
    DOM.navItems.forEach(item => {
      item.addEventListener("click", e => {
        e.preventDefault();
        switchView(item.dataset.view);
      });
    });

    // Quick Action Buttons
    if (DOM.btnQuickNewCase) DOM.btnQuickNewCase.addEventListener("click", () => DOM.modalCreateCase.classList.add("open"));
    if (DOM.btnCasesCreate) DOM.btnCasesCreate.addEventListener("click", () => DOM.modalCreateCase.classList.add("open"));
    if (DOM.qaNewCase) DOM.qaNewCase.addEventListener("click", () => DOM.modalCreateCase.classList.add("open"));
    if (DOM.qaUploadEvidence) DOM.qaUploadEvidence.addEventListener("click", () => switchView("evidence"));
    if (DOM.qaThreatLookup) DOM.qaThreatLookup.addEventListener("click", () => switchView("threat-intel"));
    if (DOM.qaGenerateReport) DOM.qaGenerateReport.addEventListener("click", () => switchView("reports"));
    if (document.getElementById("btn-view-all-timeline")) {
      document.getElementById("btn-view-all-timeline").addEventListener("click", () => switchView("timeline"));
    }
    if (document.getElementById("btn-view-all-intel")) {
      document.getElementById("btn-view-all-intel").addEventListener("click", () => switchView("threat-intel"));
    }
    if (DOM.btnRefreshEvidence) DOM.btnRefreshEvidence.addEventListener("click", loadEvidence);
    if (DOM.btnRefreshTimeline) DOM.btnRefreshTimeline.addEventListener("click", loadTimeline);

    // Modal Close buttons
    document.querySelectorAll("[data-close-modal]").forEach(btn => {
      btn.addEventListener("click", () => {
        const modalId = btn.dataset.closeModal;
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove("open");
      });
    });

    // Case Status Filters
    if (DOM.caseStatusFilters) {
      DOM.caseStatusFilters.querySelectorAll("button").forEach(btn => {
        btn.addEventListener("click", () => {
          DOM.caseStatusFilters.querySelectorAll("button").forEach(b => b.classList.remove("btn-primary"));
          btn.classList.add("btn-primary");
          loadCases(btn.dataset.filter);
        });
      });
    }

    // Create Case Form Submit
    if (DOM.formCreateCase) {
      DOM.formCreateCase.addEventListener("submit", async e => {
        e.preventDefault();
        const submitBtn = document.getElementById("btn-submit-case");
        submitBtn.disabled = true;
        submitBtn.textContent = "Initializing...";

        try {
          const res = await apiPost("/api/cases", {
            title: document.getElementById("case-title-input").value,
            severity: document.getElementById("case-severity-input").value,
            investigator: document.getElementById("case-investigator-input").value,
            description: document.getElementById("case-desc-input").value
          });
          DOM.modalCreateCase.classList.remove("open");
          DOM.formCreateCase.reset();
          loadCases();
          loadOverview();
          checkSystemStatus();
        } catch (err) {
          alert("Error creating case: " + err.message);
        } finally {
          submitBtn.disabled = false;
          submitBtn.textContent = "Initialize Case";
        }
      });
    }

    // Case Dossier: Save Status/Severity
    if (DOM.btnSaveDossierStatus) {
      DOM.btnSaveDossierStatus.addEventListener("click", async () => {
        if (!State.selectedCase) return;
        DOM.btnSaveDossierStatus.disabled = true;
        try {
          await apiPatch(`/api/cases/${State.selectedCase.id}`, {
            status: DOM.dossierStatusSelect.value,
            severity: DOM.dossierSeveritySelect.value,
            actor: "Lead Investigator"
          });
          alert("Case updated successfully.");
          loadCases();
          loadOverview();
        } catch (err) {
          alert("Update failed: " + err.message);
        } finally {
          DOM.btnSaveDossierStatus.disabled = false;
        }
      });
    }

    // Case Dossier: Add Note
    if (DOM.btnDossierAddNote) {
      DOM.btnDossierAddNote.addEventListener("click", async () => {
        if (!State.selectedCase) return;
        const noteText = DOM.dossierNewNote.value.trim();
        if (!noteText) return;

        try {
          await apiPost(`/api/cases/${State.selectedCase.id}/notes`, {
            note: noteText,
            author: "Lead Investigator"
          });
          DOM.dossierNewNote.value = "";
          openCaseDossier(State.selectedCase.id);
        } catch (err) {
          alert("Failed to add note: " + err.message);
        }
      });
    }

    // Case Dossier: Generate PDF button
    if (DOM.btnDossierGeneratePdf) {
      DOM.btnDossierGeneratePdf.addEventListener("click", async () => {
        if (!State.selectedCase) return;
        DOM.modalCaseDetail.classList.remove("open");
        switchView("reports");
        DOM.reportCaseSelect.value = State.selectedCase.id;
      });
    }

    // Dossier "+ Add Evidence" quick jump
    if (DOM.btnDossierAddEvidence) {
      DOM.btnDossierAddEvidence.addEventListener("click", () => {
        if (!State.selectedCase) return;
        DOM.modalCaseDetail.classList.remove("open");
        switchView("evidence");
        DOM.evidenceCaseSelect.value = State.selectedCase.id;
      });
    }

    // Evidence File Dropzone
    if (DOM.evidenceDropzone && DOM.evidenceFileInput) {
      DOM.evidenceDropzone.addEventListener("click", () => DOM.evidenceFileInput.click());

      DOM.evidenceDropzone.addEventListener("dragover", e => {
        e.preventDefault();
        DOM.evidenceDropzone.classList.add("dragover");
      });

      DOM.evidenceDropzone.addEventListener("dragleave", () => {
        DOM.evidenceDropzone.classList.remove("dragover");
      });

      DOM.evidenceDropzone.addEventListener("drop", e => {
        e.preventDefault();
        DOM.evidenceDropzone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          DOM.evidenceFileInput.files = e.dataTransfer.files;
          handleEvidenceFilePicked(e.dataTransfer.files[0]);
        }
      });

      DOM.evidenceFileInput.addEventListener("change", e => {
        if (e.target.files && e.target.files.length > 0) {
          handleEvidenceFilePicked(e.target.files[0]);
        }
      });
    }

    // Evidence Upload Form Submit
    if (DOM.formUploadEvidence) {
      DOM.formUploadEvidence.addEventListener("submit", async e => {
        e.preventDefault();
        const caseId = DOM.evidenceCaseSelect.value;
        const file = DOM.evidenceFileInput.files[0];
        if (!caseId) { alert("Please select a target case."); return; }
        if (!file) { alert("Please choose a file."); return; }

        const submitBtn = document.getElementById("btn-submit-evidence");
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span class="spinner"></span> Ingesting &amp; Hashing...`;

        const formData = new FormData();
        formData.append("file", file);
        formData.append("acquired_by", DOM.evidenceInvestigator.value);
        formData.append("description", DOM.evidenceDescription.value);

        try {
          const res = await fetch(`/api/cases/${caseId}/evidence`, {
            method: "POST",
            body: formData
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.error || "Upload failed");

          alert(`Evidence acquired successfully!\nSHA-256: ${data.evidence.sha256_hash}`);
          DOM.formUploadEvidence.reset();
          DOM.clientHashPreview.style.display = "none";
          DOM.dropzoneLabel.textContent = "Click to select or drag & drop evidence file";
          loadEvidence();
          loadOverview();
          checkSystemStatus();
        } catch (err) {
          alert("Evidence acquisition failed: " + err.message);
        } finally {
          submitBtn.disabled = false;
          submitBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Acquire &amp; Hash Evidence`;
        }
      });
    }

    // Auto-detect indicator type
    if (DOM.btnDetectIndicator && DOM.intelIndicatorInput) {
      DOM.btnDetectIndicator.addEventListener("click", async () => {
        const val = DOM.intelIndicatorInput.value.trim();
        if (!val) return;
        try {
          const data = await apiPost("/api/threat-intel/classify", { indicator: val });
          DOM.indicatorTypeBadge.textContent = `Type: ${data.indicator_type.toUpperCase()}`;
          if (data.suggested_purpose && !DOM.intelPurposeInput.value) {
            DOM.intelPurposeInput.value = data.suggested_purpose;
          }
        } catch (err) {
          console.error("Classification error:", err);
        }
      });

      DOM.intelIndicatorInput.addEventListener("blur", () => {
        if (DOM.intelIndicatorInput.value.trim()) {
          DOM.btnDetectIndicator.click();
        }
      });
    }

    // Threat Intel Search Form Submit
    if (DOM.formThreatSearch) {
      DOM.formThreatSearch.addEventListener("submit", async e => {
        e.preventDefault();
        const indicator = DOM.intelIndicatorInput.value.trim();
        if (!indicator) return;

        const submitBtn = DOM.btnExecuteThreatSearch;
        submitBtn.disabled = true;
        submitBtn.innerHTML = `<span class="spinner"></span> Querying TinyFish API...`;
        DOM.intelResultsContainer.innerHTML = `
          <div class="empty-state">
            <span class="spinner" style="width: 24px; height: 24px; color: var(--cyan-primary);"></span>
            <div class="empty-state-text" style="margin-top: 12px;">Querying TinyFish Search API for live cybersecurity advisories and leads...</div>
          </div>
        `;

        try {
          const caseId = DOM.intelCaseSelect.value ? parseInt(DOM.intelCaseSelect.value) : null;
          const payload = {
            indicator: indicator,
            case_id: caseId,
            domain_type: DOM.intelDomainType.value,
            purpose: DOM.intelPurposeInput.value.trim() || undefined,
            investigator: "Lead Investigator"
          };

          const res = await fetch("/api/threat-intel/search", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });
          const data = await res.json();

          if (!res.ok) {
            DOM.intelResultsContainer.innerHTML = `
              <div class="alert alert-danger">
                <b>TinyFish API Error:</b> ${escapeHtml(data.error || "Request failed")}
                ${data.status === 'AUTH_FAILED' ? '<div style="margin-top: 6px; font-size: 11.5px;">Please check or supply a valid, rotated key in your local <code>.env</code> file (TINYFISH_API_KEY).</div>' : ''}
              </div>
            `;
            checkSystemStatus();
            return;
          }

          renderIntelResults(data.results || [], indicator, data.status);
          loadThreatIntel();
          loadOverview();
          checkSystemStatus();
        } catch (err) {
          DOM.intelResultsContainer.innerHTML = `
            <div class="alert alert-danger">
              <b>Error:</b> ${escapeHtml(err.message)}
            </div>
          `;
        } finally {
          submitBtn.disabled = false;
          submitBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Execute TinyFish Query`;
        }
      });
    }

    // Generate Forensic PDF Report Form
    if (DOM.formGenerateReport) {
      DOM.formGenerateReport.addEventListener("submit", async e => {
        e.preventDefault();
        const caseId = DOM.reportCaseSelect.value;
        if (!caseId) { alert("Please select a target case."); return; }

        DOM.btnCompilePdf.disabled = true;
        DOM.btnCompilePdf.innerHTML = `<span class="spinner"></span> Compiling PDF Dossier...`;

        try {
          const res = await apiPost(`/api/cases/${caseId}/report`, {
            generated_by: DOM.reportInvestigator.value
          });
          const rep = res.report;
          DOM.reportDownloadCard.style.display = "block";
          DOM.reportResFilename.textContent = rep.filename;
          DOM.reportResMeta.textContent = `Size: ${formatBytes(rep.file_size)} • Generated: ${formatDate(rep.generated_at)}`;
          DOM.reportDownloadBtn.href = rep.download_url;
          DOM.reportDownloadCard.scrollIntoView({ behavior: "smooth" });
          loadOverview();
        } catch (err) {
          alert("Report compilation failed: " + err.message);
        } finally {
          DOM.btnCompilePdf.disabled = false;
          DOM.btnCompilePdf.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="12" y1="18" x2="12" y2="12"></line><line x1="9" y1="15" x2="15" y2="15"></line></svg> Compile Forensic PDF Report`;
        }
      });
    }

    // Test TinyFish Connection Button in Settings
    if (DOM.btnTestTinyfishSettings) {
      DOM.btnTestTinyfishSettings.addEventListener("click", async () => {
        DOM.btnTestTinyfishSettings.disabled = true;
        DOM.btnTestTinyfishSettings.innerHTML = `<span class="spinner"></span> Testing...`;
        DOM.settingsTestOutput.style.display = "block";
        DOM.settingsTestOutput.className = "alert alert-info";
        DOM.settingsTestOutput.innerHTML = `Sending genuine test query to <code>https://api.search.tinyfish.ai</code>...`;

        try {
          const res = await fetch("/api/tinyfish/test", { method: "POST" });
          const data = await res.json();

          if (data.status === "CONFIGURED_AND_TESTED") {
            DOM.settingsTestOutput.className = "alert alert-success";
            DOM.settingsTestOutput.innerHTML = `<b>Connection Verified:</b> ${escapeHtml(data.message)}`;
          } else if (data.status === "NOT_CONFIGURED") {
            DOM.settingsTestOutput.className = "alert alert-warning";
            DOM.settingsTestOutput.innerHTML = `<b>Not Configured:</b> ${escapeHtml(data.message)}`;
          } else if (data.status === "AUTH_FAILED") {
            DOM.settingsTestOutput.className = "alert alert-danger";
            DOM.settingsTestOutput.innerHTML = `<b>Authentication Failed (401):</b> ${escapeHtml(data.message)}<br/>Please provide a newly rotated key in <code>.env</code>.`;
          } else {
            DOM.settingsTestOutput.className = "alert alert-danger";
            DOM.settingsTestOutput.innerHTML = `<b>Test Failed:</b> ${escapeHtml(data.message)}`;
          }
          checkSystemStatus();
        } catch (err) {
          DOM.settingsTestOutput.className = "alert alert-danger";
          DOM.settingsTestOutput.innerHTML = `<b>Network Error:</b> ${escapeHtml(err.message)}`;
        } finally {
          DOM.btnTestTinyfishSettings.disabled = false;
          DOM.btnTestTinyfishSettings.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Test Connectivity Now`;
        }
      });
    }
  }

  async function handleEvidenceFilePicked(file) {
    DOM.dropzoneLabel.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
    DOM.clientFileName.textContent = file.name;
    DOM.clientFileSize.textContent = formatBytes(file.size);
    DOM.clientFileHash.textContent = "Calculating client-side SHA-256...";
    DOM.clientHashPreview.style.display = "block";

    try {
      const hash = await computeClientSHA256(file);
      DOM.clientFileHash.textContent = hash;
    } catch (err) {
      DOM.clientFileHash.textContent = "Unable to precompute hash: " + err.message;
    }
  }

  // --- Utility Formatting Helpers ---
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  function formatDate(isoStr) {
    if (!isoStr) return "-";
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
      return isoStr;
    }
  }

  // Initial App Boot
  document.addEventListener("DOMContentLoaded", () => {
    setupEventListeners();
    checkSystemStatus();
    loadOverview();

    // Periodic status refresh every 30s
    setInterval(checkSystemStatus, 30000);
  });
})();
