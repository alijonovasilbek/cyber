const API_HOST = typeof window !== 'undefined'
  ? `${window.location.protocol}//${window.location.hostname || '127.0.0.1'}:8000`
  : 'http://127.0.0.1:8000';
const BASE = `${API_HOST}/api`;
const WS_BASE = BASE.replace('http://', 'ws://').replace('https://', 'wss://').replace('/api', '');

function getApiKey() {
  return localStorage.getItem('cg_api_key') || 'cyberguard-demo-key';
}

async function request(url, options = {}) {
  const headers = {
    'X-API-Key': getApiKey(),
    ...(options.headers || {}),
  };
  const response = await fetch(`${BASE}${url}`, { ...options, headers });
  const text = await response.text();
  const data = text ? (() => {
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  })() : null;

  if (!response.ok) {
    const error = new Error(data?.detail || data?.error || `HTTP ${response.status}`);
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}

const get = url => request(url);
const post = (url, body) => request(url, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
});

export const api = {
  getDashboard: () => get('/dashboard/'),
  analyzeThreat: data => post('/analyze/', data),
  analyzeBehavior: data => post('/analyze/', data),
  getTargetIntel: data => post('/intel/', data),
  safeScan: data => post('/scan-ip/', data),
  simulateTraffic: data => post('/simulate-traffic/', data),
  predictThreat: data => post('/predict/', data),
  getInterfaces: () => get('/network/interfaces/'),
  getWifiStatus: () => get('/network/wifi/status/'),
  connectWifi: data => post('/network/wifi/connect/', data),
  scanNetwork: () => get('/network/scan/'),
  getProfiles: () => get('/network/profiles/'),
  createProfile: data => post('/network/profiles/', data),
  runProfileScan: (id, data) => post(`/network/profiles/${id}/scan/`, data),
  getScanSessions: () => get('/network/sessions/'),
  getAnalysisRecords: () => get('/ip-analysis/'),
  getReputation: ip => get(`/reputation/${ip}/`),
  getLiveLogs: () => get('/logs/live/'),
  getTrafficLogs: () => get('/logs/'),
  getThreats: () => get('/threats/'),
  blockThreat: id => post(`/threats/${id}/block/`, {}),
  getBlocked: () => get('/blocked/'),
  openLiveSocket: () => new WebSocket(`${WS_BASE}/ws/live`),
};
