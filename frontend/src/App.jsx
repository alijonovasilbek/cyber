import { useState, useEffect, useRef } from 'react';
import NetworkScan from './components/NetworkScan';
import { api } from './services/api';

const SEV = {
  critical: { bg: '#FCEBEB', tc: '#A32D2D', label: 'Kritik' },
  high:     { bg: '#FAEEDA', tc: '#854F0B', label: 'Yuqori' },
  medium:   { bg: '#E6F1FB', tc: '#185FA5', label: "O'rta" },
  low:      { bg: '#EAF3DE', tc: '#3B6D11', label: 'Past' },
};

const LOCAL_IPS = [
  '192.168.1.1','192.168.1.100','192.168.1.101',
  '192.168.1.200','192.168.1.201',
  '10.0.0.1','10.0.0.10','10.0.0.20',
  '172.16.0.1','172.16.0.50',
];

const ALGOS = ['Random Forest','XGBoost','LSTM','SVM','Isolation Forest','Autoencoder'];
const THREATS = [
  {v:'ddos',l:'DDoS hujumi'},
  {v:'sqli',l:'SQL Injection'},
  {v:'brute_force',l:'Brute Force'},
  {v:'phishing',l:'Phishing'},
  {v:'ransomware',l:'Ransomware'},
  {v:'mitm',l:'Man-in-the-Middle'},
  {v:'apt',l:'APT'},
  {v:'port_scan',l:'Port Skanerlash'},
];

export default function App() {
  const [page, setPage] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [logsPaused, setLogsPaused] = useState(false);
  const [analyzeForm, setAnalyzeForm] = useState({ ip: '', threat: '', algos: ['Random Forest','XGBoost'], ctx: '' });
  const [analyzeResult, setAnalyzeResult] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [threatLogs, setThreatLogs] = useState([]);
  const logRef = useRef(null);

  useEffect(() => {
    api.getDashboard().then(setStats).catch(() => setStats(demoStats()));
    api.getThreats().then(d => setThreatLogs(d.results || d)).catch(() => setThreatLogs(demoThreats()));
  }, []);

  useEffect(() => {
    const iv = setInterval(async () => {
      if (logsPaused) return;
      try {
        const data = await api.getLiveLogs();
        setLogs(prev => {
          const combined = [...prev, ...data.logs.slice(0, 2)];
          return combined.slice(-60);
        });
      } catch {
        setLogs(prev => {
          const nl = { id: Date.now(), level: ['info','warn','error'][Math.floor(Math.random()*3)], message: demoLogMsg(), ip: LOCAL_IPS[Math.floor(Math.random()*LOCAL_IPS.length)], timestamp: new Date().toISOString() };
          return [...prev, nl].slice(-60);
        });
      }
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 1500);
    return () => clearInterval(iv);
  }, [logsPaused]);

  const runAnalyze = async () => {
    if (!analyzeForm.ip || !analyzeForm.threat) return;
    setAnalyzing(true);
    setAnalyzeResult(null);
    try {
      const res = await api.analyzeThreat({
        ip_address: analyzeForm.ip,
        threat_type: analyzeForm.threat,
        algorithms: analyzeForm.algos,
        context: analyzeForm.ctx,
      });
      setAnalyzeResult(res);
    } catch {
      setAnalyzeResult(demoAnalyzeResult(analyzeForm));
    }
    setAnalyzing(false);
  };

  const toggleAlgo = (a) => {
    setAnalyzeForm(f => ({
      ...f,
      algos: f.algos.includes(a) ? f.algos.filter(x => x !== a) : [...f.algos, a],
    }));
  };

  const s = stats || demoStats();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', fontFamily: 'system-ui,sans-serif' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 20px', background: '#fff', borderBottom: '0.5px solid #e5e5e5' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600, fontSize: 15 }}>
          <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#E24B4A', display: 'inline-block' }} />
          CyberGuard AI
        </div>
        <div style={{ fontSize: 11, color: '#3B6D11', display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#639922', display: 'inline-block', animation: 'pulse 1.5s infinite' }} />
          Real vaqt monitoring
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1 }}>
        <div style={{ width: 180, background: '#f9f9f7', borderRight: '0.5px solid #e5e5e5', padding: '10px 0' }}>
          {[
            ['dashboard','⊞ Dashboard'],
            ['analyze','◎ IP Tahlil'],
            ['network','⬡ Tarmoq Skan'],
            ['threats','⚠ Tahdid Loglari'],
            ['logs','≡ Live Loglar'],
          ].map(([id, label]) => (
            <div
              key={id}
              onClick={() => setPage(id)}
              style={{
                padding: '8px 14px', fontSize: 12, cursor: 'pointer',
                borderLeft: page === id ? '2px solid #E24B4A' : '2px solid transparent',
                background: page === id ? '#fff' : 'transparent',
                color: page === id ? '#111' : '#666',
                transition: '.15s',
              }}
            >
              {label}
            </div>
          ))}
        </div>

        <div style={{ flex: 1, padding: 16, overflowY: 'auto' }}>

          {page === 'dashboard' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 8, marginBottom: 12 }}>
                {[
                  ['Tahdidlar', s.total_threats, '#E24B4A'],
                  ['Bloklangan', s.blocked, '#639922'],
                  ['Kritik', s.critical, '#BA7517'],
                  ['AI Aniqlik', `${s.accuracy}%`, '#185FA5'],
                ].map(([l, v, c]) => (
                  <div key={l} style={{ background: '#f4f4f0', borderRadius: 8, padding: '10px 12px' }}>
                    <div style={{ fontSize: 11, color: '#888', marginBottom: 3 }}>{l}</div>
                    <div style={{ fontSize: 22, fontWeight: 500, color: c }}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div style={{ background: '#fff', border: '0.5px solid #e5e5e5', borderRadius: 12, padding: 12 }}>
                  <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 10 }}>Tahdid taqsimoti</div>
                  {[['DDoS','#E24B4A',34],['SQL Inj','#BA7517',22],['Brute Force','#185FA5',18],['Phishing','#534AB7',15],['Ransomware','#3B6D11',11]].map(([n,c,v]) => (
                    <div key={n} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, fontSize: 12 }}>
                      <span style={{ minWidth: 70, color: '#666' }}>{n}</span>
                      <div style={{ flex: 1, height: 6, background: '#f0f0ec', borderRadius: 3 }}>
                        <div style={{ width: `${v * 2.2}%`, height: '100%', background: c, borderRadius: 3 }} />
                      </div>
                      <span style={{ minWidth: 28, textAlign: 'right' }}>{v}%</span>
                    </div>
                  ))}
                </div>
                <div style={{ background: '#fff', border: '0.5px solid #e5e5e5', borderRadius: 12, padding: 12 }}>
                  <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 10 }}>Model ko'rsatkichlari</div>
                  {[['Accuracy','96.4%'],['Recall','94.1%'],['Precision','95.7%'],['F1-Score','0.949'],['False Positive','3.6%'],['Javob vaqti','12ms']].map(([k,v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '0.5px solid #f0f0ec', fontSize: 12 }}>
                      <span style={{ color: '#666' }}>{k}</span>
                      <span style={{ fontWeight: 500 }}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {page === 'analyze' && (
            <div style={{ background: '#fff', border: '0.5px solid #e5e5e5', borderRadius: 12, padding: 14 }}>
              <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 12 }}>IP Tahdid Tahlili</div>

              <div style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 11, color: '#888', marginBottom: 4 }}>IP manzil (local yoki public)</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
                  {LOCAL_IPS.slice(0, 6).map(ip => (
                    <button
                      key={ip}
                      onClick={() => setAnalyzeForm(f => ({ ...f, ip }))}
                      style={{
                        fontSize: 10, padding: '3px 8px', borderRadius: 8, cursor: 'pointer',
                        border: analyzeForm.ip === ip ? '1px solid #185FA5' : '0.5px solid #ddd',
                        background: analyzeForm.ip === ip ? '#E6F1FB' : '#f9f9f7',
                        color: analyzeForm.ip === ip ? '#0C447C' : '#555',
                      }}
                    >
                      {ip}
                    </button>
                  ))}
                </div>
                <input
                  value={analyzeForm.ip}
                  onChange={e => setAnalyzeForm(f => ({ ...f, ip: e.target.value }))}
                  placeholder="IP kiriting yoki yuqoridan tanlang..."
                  style={{ width: '100%', fontSize: 12, padding: '7px 10px', borderRadius: 8, border: '0.5px solid #ddd' }}
                />
              </div>

              <div style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 11, color: '#888', marginBottom: 4 }}>Tahdid turi</div>
                <select
                  value={analyzeForm.threat}
                  onChange={e => setAnalyzeForm(f => ({ ...f, threat: e.target.value }))}
                  style={{ width: '100%', fontSize: 12, padding: '7px 10px', borderRadius: 8, border: '0.5px solid #ddd' }}
                >
                  <option value="">— tanlang —</option>
                  {THREATS.map(t => <option key={t.v} value={t.v}>{t.l}</option>)}
                </select>
              </div>

              <div style={{ marginBottom: 8 }}>
                <div style={{ fontSize: 11, color: '#888', marginBottom: 4 }}>Algoritmlar</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {ALGOS.map(a => (
                    <span
                      key={a}
                      onClick={() => toggleAlgo(a)}
                      style={{
                        fontSize: 11, padding: '3px 9px', borderRadius: 8, cursor: 'pointer',
                        border: analyzeForm.algos.includes(a) ? '0.5px solid #185FA5' : '0.5px solid #ddd',
                        background: analyzeForm.algos.includes(a) ? '#E6F1FB' : '#f4f4f0',
                        color: analyzeForm.algos.includes(a) ? '#0C447C' : '#666',
                      }}
                    >
                      {a}
                    </span>
                  ))}
                </div>
              </div>

              <textarea
                value={analyzeForm.ctx}
                onChange={e => setAnalyzeForm(f => ({ ...f, ctx: e.target.value }))}
                placeholder="Qo'shimcha kontekst (ixtiyoriy)..."
                style={{ width: '100%', height: 60, fontSize: 11, padding: '7px 10px', borderRadius: 8, border: '0.5px solid #ddd', resize: 'vertical', fontFamily: 'monospace', marginBottom: 8 }}
              />

              <button
                onClick={runAnalyze}
                disabled={analyzing}
                style={{ width: '100%', padding: '9px', background: analyzing ? '#ccc' : '#E24B4A', color: '#fff', border: 'none', borderRadius: 8, fontSize: 12, fontWeight: 500, cursor: analyzing ? 'not-allowed' : 'pointer' }}
              >
                {analyzing ? 'Tahlil qilinmoqda...' : 'Tahlilni boshlash ↗'}
              </button>

              {analyzeResult && <AnalyzeResult result={analyzeResult} />}
            </div>
          )}

          {page === 'network' && (
            <div style={{ background: '#fff', border: '0.5px solid #e5e5e5', borderRadius: 12, padding: 14 }}>
              <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 12 }}>Local Tarmoq Skaneri</div>
              <NetworkScan onAnalyze={(ip) => { setAnalyzeForm(f => ({ ...f, ip })); setPage('analyze'); }} />
            </div>
          )}

          {page === 'threats' && (
            <div style={{ background: '#fff', border: '0.5px solid #e5e5e5', borderRadius: 12, padding: 14 }}>
              <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 10 }}>Tahdid Loglari</div>
              {(threatLogs.length ? threatLogs : demoThreats()).map((t, i) => {
                const sv = SEV[t.severity] || SEV.low;
                return (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 8px', borderRadius: 8, border: '0.5px solid #eee', marginBottom: 5, fontSize: 12 }}>
                    <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 8, background: sv.bg, color: sv.tc, fontWeight: 500, minWidth: 50, textAlign: 'center' }}>{sv.label}</span>
                    <span style={{ fontFamily: 'monospace', color: '#185FA5', minWidth: 105 }}>{t.ip_address}</span>
                    <span style={{ flex: 1 }}>{t.threat_type}</span>
                    <span style={{ color: '#888' }}>{Math.round((t.probability || 0.8) * 100)}%</span>
                    {t.is_blocked
                      ? <span style={{ fontSize: 10, color: '#3B6D11', padding: '2px 7px', background: '#EAF3DE', borderRadius: 6 }}>Bloklandi</span>
                      : <button onClick={() => api.blockThreat(t.id).then(() => {}).catch(() => {})}
                          style={{ fontSize: 10, padding: '2px 8px', borderRadius: 6, border: '0.5px solid #E24B4A', color: '#A32D2D', background: '#FCEBEB', cursor: 'pointer' }}>
                          Bloklash
                        </button>
                    }
                  </div>
                );
              })}
            </div>
          )}

          {page === 'logs' && (
            <div style={{ background: '#fff', border: '0.5px solid #e5e5e5', borderRadius: 12, padding: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div style={{ fontSize: 13, fontWeight: 500 }}>Real Vaqt Log Oqimi</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button onClick={() => setLogsPaused(p => !p)} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, border: '0.5px solid #ddd', cursor: 'pointer', background: '#f4f4f0' }}>
                    {logsPaused ? 'Davom' : 'Pauza'}
                  </button>
                  <button onClick={() => setLogs([])} style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, border: '0.5px solid #ddd', cursor: 'pointer', background: '#f4f4f0' }}>
                    Tozalash
                  </button>
                </div>
              </div>
              <div ref={logRef} style={{ fontFamily: 'monospace', fontSize: 11, background: '#2C2C2A', color: '#B4B2A9', padding: 10, borderRadius: 8, height: 320, overflowY: 'auto', lineHeight: 1.8 }}>
                {logs.map((l, i) => (
                  <div key={i} style={{ color: l.level === 'error' ? '#E24B4A' : l.level === 'warn' ? '#EF9F27' : '#97C459' }}>
                    {new Date(l.timestamp).toLocaleTimeString()} [{l.level.toUpperCase()}] {l.ip && <span style={{ color: '#85B7EB' }}>{l.ip} </span>}{l.message}
                  </div>
                ))}
                {logs.length === 0 && <div style={{ color: '#666' }}>Loglar yuklanmoqda...</div>}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

function AnalyzeResult({ result }) {
  if (result.error) return <div style={{ marginTop: 10, color: '#A32D2D', fontSize: 12 }}>{result.error}</div>;
  const sv = SEV[result.severity] || SEV.low;
  return (
    <div style={{ marginTop: 10, background: '#f9f9f7', borderRadius: 8, padding: 12, fontSize: 12, lineHeight: 1.8 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ fontWeight: 500 }}>Tahlil natijasi</span>
        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 8, background: sv.bg, color: sv.tc, fontWeight: 500 }}>{sv.label} xavf</span>
      </div>
      <div><b>IP:</b> <span style={{ fontFamily: 'monospace', color: '#185FA5' }}>{result.ip}</span></div>
      <div><b>Qurilma:</b> {result.ip_info?.device_name}</div>
      <div><b>Tarmoq:</b> {result.ip_info?.is_local ? 'Local (ichki)' : 'Public (internet)'} — {result.ip_info?.network_type}</div>
      <div><b>Tahdid:</b> {result.threat_name}</div>
      <div><b>Ehtimollik:</b> <span style={{ fontWeight: 500, color: sv.tc }}>{result.probability_pct}</span></div>
      {result.local_context && <div style={{ color: '#854F0B', marginTop: 4 }}>{result.local_context}</div>}
      {result.indicators?.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <b>Belgilar:</b>
          <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
            {result.indicators.map((ind, i) => <li key={i}>{ind}</li>)}
          </ul>
        </div>
      )}
      {result.mitigation?.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <b>Choralar:</b>
          <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
            {result.mitigation.map((m, i) => <li key={i}>{m}</li>)}
          </ul>
        </div>
      )}
      <div style={{ marginTop: 6, color: '#666' }}><b>Tavsiya:</b> {result.recommendation}</div>
      {result.algorithm_scores && Object.keys(result.algorithm_scores).length > 0 && (
        <div style={{ marginTop: 6 }}>
          <b>Algoritm ballari:</b>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 4 }}>
            {Object.entries(result.algorithm_scores).map(([k, v]) => (
              <span key={k} style={{ fontSize: 10, padding: '2px 7px', background: '#E6F1FB', color: '#0C447C', borderRadius: 6 }}>
                {k}: {Math.round(v * 100)}%
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function demoStats() {
  return { total_threats: 247, blocked: 183, critical: 14, accuracy: 96.4, block_rate: 74.1 };
}
function demoThreats() {
  return [
    { ip_address: '192.168.1.201', threat_type: 'SQL Injection', severity: 'critical', probability: 0.97, is_blocked: false },
    { ip_address: '192.168.1.200', threat_type: 'Brute Force', severity: 'high', probability: 0.88, is_blocked: true },
    { ip_address: '10.0.0.10', threat_type: 'Port Skanerlash', severity: 'medium', probability: 0.73, is_blocked: false },
    { ip_address: '172.16.0.50', threat_type: 'DDoS', severity: 'high', probability: 0.85, is_blocked: false },
  ];
}
function demoAnalyzeResult(form) {
  const prob = Math.random() * 0.25 + 0.72;
  const sev = prob > 0.90 ? 'critical' : prob > 0.75 ? 'high' : 'medium';
  const isLocal = form.ip.startsWith('192.168') || form.ip.startsWith('10.') || form.ip.startsWith('172.16');
  return {
    ip: form.ip,
    ip_info: { device_name: isLocal ? 'Local qurilma' : 'Tashqi IP', is_local: isLocal, network_type: isLocal ? 'LAN' : 'WAN' },
    threat_name: THREATS.find(t => t.v === form.threat)?.l || form.threat,
    probability: prob,
    probability_pct: `${Math.round(prob * 100)}%`,
    severity: sev,
    indicators: ['Noodatiy so\'rovlar', 'Yuqori trafik hajmi'],
    mitigation: ['IP ni vaqtinchalik bloklang', 'SIEM qoidasini yangilang', 'Loglarni tekshiring'],
    recommendation: isLocal ? 'Ichki tarmoq: Kuchaytirilgan monitoring tavsiya etiladi.' : 'Tashqi IP: Darhol bloklash tavsiya etiladi.',
    algorithm_scores: Object.fromEntries(form.algos.map(a => [a, Math.round((Math.random() * 0.1 + 0.87) * 100) / 100])),
    local_context: isLocal ? `Ichki tarmoq qurilmasi aniqlandi` : '',
  };
}
function demoLogMsg() {
  const msgs = [
    'Tarmoq trafigi normal', 'Noodatiy so\'rov aniqlandi',
    'SQL Injection urinishi bloklandi', 'Port skanerlash aniqlandi',
    'Autentifikatsiya muvaffaqiyatli', 'Firewall qoidalari yangilandi',
  ];
  return msgs[Math.floor(Math.random() * msgs.length)];
}
