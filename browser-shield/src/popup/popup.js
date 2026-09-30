/**
 * ORION Browser Shield — Popup Controller
 * Manages 6 distinct security states, site identity, and dashboard deep-linking.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // Elements
  const hostnameEl = document.getElementById("hostname-text");
  const pageTitleEl = document.getElementById("page-title-text");
  const pillEl = document.getElementById("protection-pill");
  const pillTextEl = document.getElementById("protection-pill-text");

  // State Views
  const stateAnalyzing = document.getElementById("state-analyzing");
  const stateSafe = document.getElementById("state-safe");
  const stateSuspicious = document.getElementById("state-suspicious");
  const stateDanger = document.getElementById("state-danger");
  const stateUnavailable = document.getElementById("state-unavailable");

  // Danger View Content
  const dangerHeadline = document.getElementById("danger-headline");
  const dangerSubline = document.getElementById("danger-subline");
  const dangerWarningMsg = document.getElementById("danger-warning-message");
  const dangerFlagsList = document.getElementById("danger-flags-list");

  // Details
  const detailsSection = document.getElementById("details-section");
  const toggleDetailsBtn = document.getElementById("toggle-details-btn");
  const riskScoreDisplay = document.getElementById("risk-score-display");
  const detailThreatType = document.getElementById("detail-threat-type");
  const detailEvidenceList = document.getElementById("detail-evidence-list");

  // Actions
  const investigateBtn = document.getElementById("investigate-btn");
  const goBackBtn = document.getElementById("go-back-btn");
  const openDashboardBtn = document.getElementById("open-dashboard-btn");
  const retryBtn = document.getElementById("retry-btn");

  // Recent Section
  const recentSection = document.getElementById("recent-section");
  const recentList = document.getElementById("recent-list");

  let currentTab = null;
  let currentIncident = null;

  // Initialize
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTab = tabs[0];

    if (!currentTab || !currentTab.url) {
      showUnavailable("Unable to access current browser tab.");
      return;
    }

    // Set Dashboard Link
    const dashboardUrl = (typeof ORION_CONFIG !== "undefined" && ORION_CONFIG.FRONTEND_URL)
      ? ORION_CONFIG.FRONTEND_URL
      : "http://localhost:5173";
    openDashboardBtn.href = dashboardUrl;

    // Handle non-HTTP pages (chrome://, about:, etc.)
    if (!currentTab.url.startsWith("http://") && !currentTab.url.startsWith("https://")) {
      hostnameEl.textContent = "Browser System Page";
      showSafe({
        risk_level: "SAFE",
        explanation: "Internal browser page is isolated and protected.",
      });
      return;
    }

    const parsedUrl = new URL(currentTab.url);
    hostnameEl.textContent = parsedUrl.hostname;
    if (currentTab.title && currentTab.title !== parsedUrl.hostname) {
      pageTitleEl.textContent = currentTab.title;
      pageTitleEl.style.display = "block";
    }

    // Load recent analyses from storage
    loadRecentAnalyses();

    // Query analysis from storage
    const tabKey = `tab_${currentTab.id}`;
    const storageData = await chrome.storage.local.get([tabKey, "latest_incident"]);
    const cachedIncident = storageData[tabKey];

    if (cachedIncident) {
      renderIncident(cachedIncident);
    } else {
      // Show analyzing while checking
      showAnalyzing();
      // Ask background worker for latest status
      chrome.runtime.sendMessage(
        { action: "GET_TAB_INCIDENT", tabId: currentTab.id },
        (response) => {
          if (response && !response.error) {
            renderIncident(response);
          } else if (response && response.error) {
            showUnavailable(response.explanation);
          } else {
            // If still no cache, wait or show unavailable
            setTimeout(async () => {
              const freshData = await chrome.storage.local.get([tabKey]);
              if (freshData[tabKey]) {
                renderIncident(freshData[tabKey]);
              } else {
                showUnavailable("Analysis pending or service temporarily offline.");
              }
            }, 1500);
          }
        }
      );
    }
  } catch (err) {
    console.error("ORION Shield Popup Init Error:", err);
    showUnavailable("Failed to initialize security assessment.");
  }

  // State Switching Functions
  function hideAllStates() {
    stateAnalyzing.style.display = "none";
    stateSafe.style.display = "none";
    stateSuspicious.style.display = "none";
    stateDanger.style.display = "none";
    stateUnavailable.style.display = "none";
    investigateBtn.style.display = "none";
    goBackBtn.style.display = "none";
    toggleDetailsBtn.style.display = "none";
  }

  function showAnalyzing() {
    hideAllStates();
    stateAnalyzing.style.display = "flex";
    pillEl.className = "protection-pill pill-protected";
    pillTextEl.textContent = "Scanning";
  }

  function showSafe(incident) {
    hideAllStates();
    stateSafe.style.display = "flex";
    pillEl.className = "protection-pill pill-protected";
    pillTextEl.textContent = "Protected";
    toggleDetailsBtn.style.display = "block";
  }

  function showSuspicious(incident) {
    hideAllStates();
    stateSuspicious.style.display = "flex";
    pillEl.className = "protection-pill pill-warning";
    pillTextEl.textContent = "Warning";
    investigateBtn.style.display = "block";
    toggleDetailsBtn.style.display = "block";
  }

  function showDanger(incident, isCritical) {
    hideAllStates();
    stateDanger.style.display = "flex";
    pillEl.className = "protection-pill pill-danger";
    pillTextEl.textContent = isCritical ? "Critical" : "High Risk";

    if (isCritical) {
      dangerHeadline.textContent = "CRITICAL RISK";
      dangerSubline.textContent = "Malicious or fraudulent website";
      dangerWarningMsg.textContent = "This website is attempting to steal sensitive credentials. Do not enter passwords or payment information.";
    } else {
      dangerHeadline.textContent = "HIGH RISK";
      dangerSubline.textContent = "Potential phishing website";
      dangerWarningMsg.textContent = "ORION detected significant threat indicators associated with credential harvesting.";
    }

    // Populate Threat Flags
    dangerFlagsList.innerHTML = "";
    const flags = [];
    if (incident.risk_drivers && incident.risk_drivers.length > 0) {
      incident.risk_drivers.forEach(d => flags.push(d));
    } else if (incident.evidence && incident.evidence.length > 0) {
      incident.evidence.slice(0, 3).forEach(e => flags.push(e.explanation));
    } else {
      flags.push("Suspicious domain lineage", "Deceptive page signals");
    }

    flags.slice(0, 3).forEach(text => {
      const li = document.createElement("li");
      li.textContent = text;
      dangerFlagsList.appendChild(li);
    });

    investigateBtn.style.display = "block";
    goBackBtn.style.display = "block";
    toggleDetailsBtn.style.display = "block";
  }

  function showUnavailable(msg) {
    hideAllStates();
    stateUnavailable.style.display = "flex";
    pillEl.className = "protection-pill pill-offline";
    pillTextEl.textContent = "Unavailable";
    const descEl = stateUnavailable.querySelector(".offline-note");
    if (descEl && msg) descEl.textContent = msg;
  }

  function renderIncident(incident) {
    currentIncident = incident;
    const level = (incident.risk_level || "SAFE").toUpperCase();

    // Update Details
    const scoreVal = (incident.risk_score || 0).toFixed(2);
    riskScoreDisplay.textContent = `Score: ${scoreVal}`;
    detailThreatType.textContent = (incident.threat_type || "None").replace(/_/g, " ").toUpperCase();

    detailEvidenceList.innerHTML = "";
    const evidence = incident.evidence || [];
    if (evidence.length === 0) {
      detailEvidenceList.innerHTML = '<li style="color: #64748b; font-style: italic;">No specific threat evidence recorded.</li>';
    } else {
      evidence.slice(0, 4).forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item.explanation || item.type;
        detailEvidenceList.appendChild(li);
      });
    }

    // Setup Investigate Deep Link
    if (incident.id) {
      const targetUrl = (typeof ORION_CONFIG !== "undefined" && ORION_CONFIG.getIncidentUrl)
        ? ORION_CONFIG.getIncidentUrl(incident.id)
        : `http://localhost:5173/?tab=incidents&id=${encodeURIComponent(incident.id)}`;
      investigateBtn.href = targetUrl;
    }

    // Route to appropriate state view
    if (level === "CRITICAL") {
      showDanger(incident, true);
    } else if (level === "HIGH") {
      showDanger(incident, false);
    } else if (level === "MEDIUM") {
      showSuspicious(incident);
    } else if (level === "UNAVAILABLE" || level === "ERROR") {
      showUnavailable(incident.explanation);
    } else {
      showSafe(incident);
    }
  }

  // Toggle Details
  toggleDetailsBtn.addEventListener("click", () => {
    const isShown = detailsSection.style.display === "block";
    detailsSection.style.display = isShown ? "none" : "block";
    toggleDetailsBtn.textContent = isShown ? "View Details" : "Hide Details";
  });

  // Go Back Action
  goBackBtn.addEventListener("click", async () => {
    if (currentTab && currentTab.id) {
      try {
        await chrome.tabs.goBack(currentTab.id);
        window.close();
      } catch (e) {
        // If no back history, navigate to safe blank
        await chrome.tabs.update(currentTab.id, { url: "about:blank" });
        window.close();
      }
    }
  });

  // Retry Action
  retryBtn.addEventListener("click", () => {
    showAnalyzing();
    if (currentTab && currentTab.id) {
      chrome.tabs.reload(currentTab.id);
      setTimeout(() => window.location.reload(), 1000);
    }
  });

  // Recent Analyses Loader
  async function loadRecentAnalyses() {
    try {
      const data = await chrome.storage.local.get(["recent_analyses"]);
      const recents = Array.isArray(data.recent_analyses) ? data.recent_analyses : [];
      if (recents.length === 0) return;

      recentList.innerHTML = "";
      recents.slice(0, 3).forEach((item) => {
        const li = document.createElement("li");
        li.className = "recent-item";

        const hostSpan = document.createElement("span");
        hostSpan.className = "recent-host";
        hostSpan.textContent = item.hostname;

        const badgeSpan = document.createElement("span");
        const lvl = (item.risk_level || "SAFE").toUpperCase();
        let badgeClass = "recent-safe";
        if (lvl === "CRITICAL" || lvl === "HIGH") badgeClass = "recent-danger";
        else if (lvl === "MEDIUM") badgeClass = "recent-warning";
        badgeSpan.className = `recent-badge ${badgeClass}`;
        badgeSpan.textContent = lvl;

        li.appendChild(hostSpan);
        li.appendChild(badgeSpan);
        recentList.appendChild(li);
      });

      recentSection.style.display = "block";
    } catch (err) {
      console.debug("ORION Shield: Could not load recent analyses:", err);
    }
  }
});
