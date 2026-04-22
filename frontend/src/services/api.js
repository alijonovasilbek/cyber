const BASE = 'http://localhost:8000/api';

async function request(url, options = {}) {
  const response = await fetch(`${BASE}${url}`, options);
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const error = new Error(data?.error || `HTTP ${response.status}`);
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
  getInterfaces: () => get('/network/interfaces/'),
  getWifiStatus: () => get('/network/wifi/status/'),
  connectWifi: data => post('/network/wifi/connect/', data),
  scanNetwork: () => get('/network/scan/'),
  getProfiles: () => get('/network/profiles/'),
  createProfile: data => post('/network/profiles/', data),
  runProfileScan: (id, data) => post(`/network/profiles/${id}/scan/`, data),
  getScanSessions: () => get('/network/sessions/'),
  getReputation: ip => get(`/reputation/${ip}/`),
  getLiveLogs: () => get('/logs/live/'),
  getThreats: () => get('/threats/'),
  blockThreat: id => post(`/threats/${id}/block/`, {}),
  getBlocked: () => get('/blocked/'),
};
