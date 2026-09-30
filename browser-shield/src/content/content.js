/**
 * ORION Browser Shield — Content Script
 * 
 * Bounded Security DOM Extractor & Advisory Warning Banner
 * Strictly prohibited: passwords, keystrokes, cookies, session tokens, arbitrary form values.
 */

(function () {
  // Guard against re-execution on dynamic SPA transitions
  if (window.__orion_shield_injected) return;
  window.__orion_shield_injected = true;

  // Extract bounded non-sensitive security signals from CURRENT PAGE only
  const pageUrl = window.location.href;
  const pageTitle = document.title || "";

  // Check presence of password inputs without reading their contents
  const hasPasswordField = !!document.querySelector('input[type="password"]');

  // Collect form action targets (where data is dispatched)
  const forms = Array.from(document.querySelectorAll("form"));
  const formActions = forms.map((f) => f.getAttribute("action") || "").filter(Boolean);

  // Claimed brand cues from title or meta tags
  const ogSiteName = document.querySelector('meta[property="og:site_name"]')?.getAttribute("content");
  const metaAuthor = document.querySelector('meta[name="author"]')?.getAttribute("content");
  const claimedBrand = ogSiteName || metaAuthor || null;

  const payload = {
    action: "ANALYZE_PAGE",
    url: pageUrl,
    title: pageTitle,
    has_password_field: hasPasswordField,
    form_actions: formActions.slice(0, 5),
    claimed_brand: claimedBrand,
  };

  // Dispatch analysis request to background service worker
  chrome.runtime.sendMessage(payload, (response) => {
    if (chrome.runtime.lastError) {
      console.debug("ORION Shield: Background worker inactive or unreachable.");
      return;
    }

    if (response && (response.risk_level === "HIGH" || response.risk_level === "CRITICAL")) {
      renderSecurityBanner(response);
    }
  });

  function renderSecurityBanner(incident) {
    if (document.getElementById("orion-shield-banner")) return;

    const isCritical = incident.risk_level === "CRITICAL";
    const banner = document.createElement("div");
    banner.id = "orion-shield-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, ${isCritical ? '#2d0606' : '#1e0f05'} 0%, ${isCritical ? '#4a0808' : '#3d1a04'} 100%);
      color: #ffeded;
      border-bottom: 2px solid ${isCritical ? '#ef4444' : '#f59e0b'};
      box-shadow: 0 4px 25px rgba(0, 0, 0, 0.6);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      padding: 12px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      animation: orionSlideDown 0.3s ease-out;
    `;

    const headline = isCritical
      ? "ORION detected indicators associated with a potentially malicious or fraudulent website."
      : "ORION detected a potentially dangerous website.";

    const subtitle = isCritical
      ? "This website may be attempting to steal sensitive credentials. Do not enter passwords or payment information."
      : (incident.explanation || "Potential phishing indicators detected on this page.");

    const investigateUrl = (typeof ORION_CONFIG !== "undefined" && ORION_CONFIG.getIncidentUrl)
      ? ORION_CONFIG.getIncidentUrl(incident.id)
      : `http://localhost:5173/?tab=incidents&id=${encodeURIComponent(incident.id || '')}`;

    banner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 14px; flex: 1;">
        <span style="background: ${isCritical ? '#ef4444' : '#f59e0b'}; color: #fff; font-size: 11px; font-weight: 800; padding: 4px 8px; border-radius: 4px; letter-spacing: 0.5px; text-transform: uppercase;">
          ${incident.risk_level} RISK
        </span>
        <div style="flex: 1;">
          <strong style="font-size: 13px; color: #ffffff; display: block; margin-bottom: 2px;">${headline}</strong>
          <p style="margin: 0; font-size: 12px; color: ${isCritical ? '#fca5a5' : '#fcd34d'}; line-height: 1.3;">
            ${subtitle}
          </p>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 10px; flex-shrink: 0;">
        <a href="${investigateUrl}" target="_blank" style="background: #0284c7; color: #ffffff; text-decoration: none; font-size: 12px; font-weight: 700; padding: 7px 14px; border-radius: 6px; border: 1px solid #38bdf8; display: inline-flex; align-items: center; gap: 6px; box-shadow: 0 2px 8px rgba(2, 132, 199, 0.4);">
          Investigate in ORION
        </a>
        <button id="orion-dismiss-btn" title="Dismiss warning" style="background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); color: #fff; font-size: 14px; cursor: pointer; padding: 6px 10px; border-radius: 6px; font-weight: 600;">
          Dismiss
        </button>
      </div>
    `;

    // Inject slide-down keyframe animation if not already present
    if (!document.getElementById("orion-shield-styles")) {
      const style = document.createElement("style");
      style.id = "orion-shield-styles";
      style.textContent = `
        @keyframes orionSlideDown {
          from { transform: translateY(-100%); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      `;
      document.head.appendChild(style);
    }

    document.body.appendChild(banner);
    document.getElementById("orion-dismiss-btn").onclick = () => banner.remove();
  }
})();
