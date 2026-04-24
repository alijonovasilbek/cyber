const ENV_API_ORIGIN = (import.meta.env.VITE_API_ORIGIN || '').trim();
const API_HOST = ENV_API_ORIGIN
  ? (ENV_API_ORIGIN === 'same-origin' ? '' : ENV_API_ORIGIN.replace(/\/$/, ''))
  : (typeof window !== 'undefined'
      ? `${window.location.protocol}//${window.location.hostname || '127.0.0.1'}:8000`
      : 'http://127.0.0.1:8000');
const BASE = API_HOST ? `${API_HOST}/api` : '/api';
const WS_BASE = API_HOST
  ? API_HOST.replace('http://', 'ws://').replace('https://', 'wss://')
  : (typeof window !== 'undefined'
      ? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`
      : 'ws://127.0.0.1:8000');
const LOCAL_AGENT_BASE = 'http://127.0.0.1:8765';
let localAgentCache = { value: false, expiresAt: 0 };

function getApiKey() {
  try {
    return localStorage.getItem('cg_api_key') || 'cyberguard-demo-key';
  } catch {
    return 'cyberguard-demo-key';
  }
}

async function hasLocalAgent(force = false) {
  const now = Date.now();
  if (!force && localAgentCache.expiresAt > now) {
    return localAgentCache.value;
  }

  const value = await fetch(`${LOCAL_AGENT_BASE}/health`)
    .then(response => response.ok)
    .catch(() => false);
  localAgentCache = { value, expiresAt: now + 2500 };
  return value;
}

function launchLocalAgent() {
  if (typeof window === 'undefined') return false;
  window.location.href = 'cyberguard-agent://start';
  return true;
}

async function waitForLocalAgent({ timeoutMs = 15000, intervalMs = 1000 } = {}) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const ready = await hasLocalAgent(true);
    if (ready) {
      return true;
    }
    await new Promise(resolve => window.setTimeout(resolve, intervalMs));
  }
  return false;
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

async function localAgentRequest(path, options = {}) {
  const response = await fetch(`${LOCAL_AGENT_BASE}${path}`, options);
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

async function getInterfaces() {
  if (await hasLocalAgent()) {
    return localAgentRequest('/network/interfaces');
  }
  return get('/network/interfaces/');
}

async function getWifiStatus() {
  if (await hasLocalAgent()) {
    return localAgentRequest('/network/wifi/status');
  }
  return get('/network/wifi/status/');
}

async function connectWifi(data) {
  if (await hasLocalAgent()) {
    return localAgentRequest('/network/wifi/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  }
  return post('/network/wifi/connect/', data);
}

async function scanNetwork() {
  if (await hasLocalAgent()) {
    return localAgentRequest('/network/scan');
  }
  return get('/network/scan/');
}

async function safeScan(data) {
  if (await hasLocalAgent()) {
    return localAgentRequest('/scan-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  }
  return post('/scan-ip/', data);
}

export const api = {
  getDashboard: () => get('/dashboard/'),
  analyzeThreat: data => post('/analyze/', data),
  analyzeBehavior: data => post('/analyze/', data),
  getTargetIntel: data => post('/intel/', data),
  safeScan,
  simulateTraffic: data => post('/simulate-traffic/', data),
  predictThreat: data => post('/predict/', data),
  getInterfaces,
  getWifiStatus,
  connectWifi,
  scanNetwork,
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
  hasLocalAgent,
  launchLocalAgent,
  waitForLocalAgent,
  getLocalAgentDownloadUrl: scriptName => `${BASE}/local-agent/download/${encodeURIComponent(scriptName)}/`,
};
