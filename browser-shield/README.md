# ORION Browser Shield (Manifest V3)
## Real-Time Phishing, Impersonation & Malicious Domain Interception Extension

ORION Browser Shield is the first-class browser protection client for the ORION Cyber Defence Platform. It intercepts web navigation events, extracts non-sensitive security DOM signals, and correlates them with the ORION backend intelligence engine.

---

### Security & Privacy Protections (Zero Credential Surveillance)
The extension enforces strict privacy boundaries:
- ✅ **Monitored:** Current URL, hostname, document title, presence of password input tags, form submission endpoints.
- ❌ **Strictly Prohibited:** Passwords, keystrokes, cookies, session tokens, arbitrary browsing history.

---

### Installation in Google Chrome or Microsoft Edge
1. Open your browser and navigate to:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
2. Toggle on **Developer mode** in the top right corner.
3. Click **Load unpacked**.
4. Select the `Orion_v2/browser-shield/` directory.
5. The extension icon (🛡️) will appear in your browser toolbar.

---

### Backend Integration
The extension communicates directly with the ORION API Gateway:
`POST http://localhost:8000/api/v1/analyze/browser`
