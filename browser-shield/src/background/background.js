/**
 * ORION Browser Shield — Background Service Worker
 * Communicates with ORION FastAPI Gateway (/api/v1/analyze/browser)
 */

try {
  importScripts('../config.js');
} catch (e) {
  console.debug('ORION Shield: importScripts config fallback');
}

const API_ENDPOINT = typeof ORION_CONFIG !== 'undefined'
  ? ORION_CONFIG.ANALYZE_BROWSER_URL
  : 'http://localhost:8000/api/v1/analyze/browser';

// Clean stale tab state on tab navigation or closure
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'loading') {
    chrome.action.setBadgeText({ tabId, text: '' });
    chrome.storage.local.remove([`tab_${tabId}`]);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove([`tab_${tabId}`]);
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'ANALYZE_PAGE') {
    handlePageAnalysis(request, sender.tab?.id, sendResponse);
    return true; // Keep message channel open for async response
  }
  if (request.action === 'GET_TAB_INCIDENT') {
    const tabId = request.tabId;
    chrome.storage.local.get([`tab_${tabId}`, 'latest_incident'], (data) => {
      sendResponse(data[`tab_${tabId}`] || data['latest_incident'] || null);
    });
    return true;
  }
});

async function handlePageAnalysis(pageData, tabId, sendResponse) {
  try {
    const payload = {
      url: pageData.url,
      title: pageData.title,
      has_password_field: pageData.has_password_field,
      form_actions: pageData.form_actions,
      claimed_brand: pageData.claimed_brand,
    };

    const res = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error(`ORION Gateway returned HTTP ${res.status}`);
    }

    const incident = await res.json();

    // Cache latest incident by TabId for popup
    if (tabId) {
      await chrome.storage.local.set({
        [`tab_${tabId}`]: incident,
        latest_incident: incident,
      });

      // Update badge based on actual risk level
      const level = (incident.risk_level || '').toUpperCase();
      if (level === 'CRITICAL') {
        chrome.action.setBadgeText({ tabId, text: '!' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#EF4444' });
      } else if (level === 'HIGH') {
        chrome.action.setBadgeText({ tabId, text: '!' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#DC2626' });
      } else if (level === 'MEDIUM') {
        chrome.action.setBadgeText({ tabId, text: '▲' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#F59E0B' });
      } else if (level === 'LOW') {
        chrome.action.setBadgeText({ tabId, text: '●' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#38BDF8' });
      } else {
        // Safe or benign
        chrome.action.setBadgeText({ tabId, text: '✓' });
        chrome.action.setBadgeBackgroundColor({ tabId, color: '#10B981' });
      }

      // Record bounded recent analysis item (max 5 items, only security metadata)
      try {
        const u = new URL(pageData.url);
        const existingData = await chrome.storage.local.get(['recent_analyses']);
        const recents = Array.isArray(existingData.recent_analyses) ? existingData.recent_analyses : [];
        const filtered = recents.filter(r => r.hostname !== u.hostname);
        const updatedRecents = [
          {
            hostname: u.hostname,
            risk_level: incident.risk_level || 'SAFE',
            threat_type: incident.threat_type || 'None',
            incident_id: incident.id || null,
            timestamp: new Date().toISOString(),
          },
          ...filtered,
        ].slice(0, 5);
        await chrome.storage.local.set({ recent_analyses: updatedRecents });
      } catch (e) {
        // Ignore URL parsing errors for non-standard schemes
      }
    }

    sendResponse(incident);
  } catch (err) {
    console.warn('ORION Shield: Analysis request failed:', err);
    if (tabId) {
      chrome.action.setBadgeText({ tabId, text: '?' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748B' });
    }
    // NEVER mask API failures as SAFE
    sendResponse({
      status: 'UNAVAILABLE',
      risk_level: 'UNAVAILABLE',
      error: true,
      explanation: 'Could not analyze this page. The ORION security service is currently unavailable.',
    });
  }
}
