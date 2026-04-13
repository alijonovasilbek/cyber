const BASE = 'http://localhost:8000/api';

const get  = (url) => fetch(`${BASE}${url}`).then(r => r.json());
const post = (url, body) => fetch(`${BASE}${url}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
}).then(r => r.json());

export const api = {
  getDashboard:    ()           => get('/dashboard/'),
  analyzeThreat:   (data)       => post('/analyze/', data),
  scanNetwork:     ()           => get('/network/scan/'),
  getReputation:   (ip)         => get(`/reputation/${ip}/`),
  getLiveLogs:     ()           => get('/logs/live/'),
  getThreats:      ()           => get('/threats/'),
  blockThreat:     (id)         => post(`/threats/${id}/block/`, {}),
  getBlocked:      ()           => get('/blocked/'),
};
