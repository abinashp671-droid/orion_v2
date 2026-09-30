/**
 * ORION Browser Shield — Configuration
 * Single source of truth for API and Dashboard endpoints.
 */

const ORION_CONFIG = {
  // Backend API Gateway
  API_BASE: 'http://localhost:8000/api/v1',
  ANALYZE_BROWSER_URL: 'http://localhost:8000/api/v1/analyze/browser',

  // ORION Web Dashboard
  FRONTEND_URL: 'http://localhost:5173',

  // Incident Investigation Deep-Link Helper
  getIncidentUrl: function (incidentId) {
    if (!incidentId) return `${this.FRONTEND_URL}/?tab=incidents`;
    return `${this.FRONTEND_URL}/?tab=incidents&id=${encodeURIComponent(incidentId)}`;
  },

  // Fallback / General Dashboard URL
  getDashboardUrl: function () {
    return `${this.FRONTEND_URL}/?tab=analyze`;
  },
};

// Support both ES module and global script inclusion
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ORION_CONFIG;
} else if (typeof globalThis !== 'undefined') {
  globalThis.ORION_CONFIG = ORION_CONFIG;
}
