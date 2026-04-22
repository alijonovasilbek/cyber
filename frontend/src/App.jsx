import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from './services/api';

// ── CONSTANTS ──────────────────────────────────────────────────────────────
const THREATS_LIST = [
  {v:'ddos',l:'DDoS hujumi'},{v:'sqli',l:'SQL Injection'},{v:'brute_force',l:'Brute Force'},
  {v:'phishing',l:'Phishing'},{v:'ransomware',l:'Ransomware'},{v:'mitm',l:'Man-in-the-Middle'},
  {v:'apt',l:'APT'},{v:'port_scan',l:'Port Skanerlash'},{v:'zero_day',l:'Zero-Day'},
];

const ALGOS_LIST = ['Random Forest','XGBoost','LSTM','SVM','Isolation Forest','Autoencoder'];

const THREAT_LIBRARY = [
  { key:'ddos',      sev:'critical', name:'DDoS hujumi',      desc:'Serverga katta hajmli so\'rovlar yuborib uni ishdan chiqaradi.', signs:'Trafik keskin oshishi, javob vaqti sekinlashishi, xizmat uzilishi.', algo:'Isolation Forest, K-Means, LSTM' },
  { key:'sqli',      sev:'critical', name:'SQL Injection',     desc:'Ma\'lumotlar bazasiga zararli SQL so\'rovlar kiritish orqali ma\'lumot o\'g\'irlash.', signs:'G\'ayrioddiy DB so\'rovlari, xato xabarlari, katta chiqish hajmi.', algo:'Random Forest, Naive Bayes, SVM' },
  { key:'ransomware',sev:'critical', name:'Ransomware',        desc:'Fayllarni shifrlaydi va qulfdan chiqarish uchun to\'lov talab qiladi.', signs:'Fayl kengaytmalarining ommaviy o\'zgarishi, CPU/disk faolligi oshishi.', algo:'Autoencoder, LSTM' },
  { key:'zero_day',  sev:'critical', name:'Zero-Day',          desc:'Hali noma\'lum yoki yamoqlanmagan zaifliklarni ishlatish.', signs:'Noodatiy dastur xatti-harakati, noma\'lum jarayonlar.', algo:'Autoencoder, Isolation Forest' },
  { key:'apt',       sev:'high',     name:'APT',               desc:'Davlat yoki katta guruhlar tomonidan olib boriladigan uzoq muddatli yashirin hujum.', signs:'Kichik noodatiy so\'rovlar, noma\'lum protokollar, uzoq sessiyalar.', algo:'Isolation Forest, Autoencoder, LSTM' },
  { key:'brute',     sev:'high',     name:'Brute Force',       desc:'Parolni ketma-ket urinishlar bilan topishga harakat.', signs:'Ko\'p muvaffaqiyatsiz login, bir IP dan ketma-ket urinish.', algo:'Random Forest, XGBoost' },
  { key:'phishing',  sev:'high',     name:'Phishing',          desc:'Soxta saytlar yoki emaillar orqali foydalanuvchi ma\'lumotlarini o\'g\'irlash.', signs:'Noma\'lum domenlar, o\'xshash URL\'lar, shubhali email manbalari.', algo:'Random Forest, XGBoost, Naive Bayes' },
  { key:'mitm',      sev:'medium',   name:'Man-in-the-Middle', desc:'Ikki tomon o\'rtasidagi aloqani tutib olish va o\'zgartirish.', signs:'Sertifikat xatolari, noodatiy tarmoq yo\'nalishlari.', algo:'SVM, CNN' },
];

const ALGO_LIBRARY = [
  { key:'rf',  name:'Random Forest',    type:'Supervised',    acc:96.4, sub:'Ensemble',      desc:'Ko\'plab qaror daraxti yig\'indisi. NSL-KDD va CICIDS2017 da 95-98% aniqlik. Tezkor, tushuntiriladigan, overfitting\'ga chidamli.' },
  { key:'xgb', name:'XGBoost',          type:'Supervised',    acc:95.1, sub:'Boosting',       desc:'Optimallashtirilgan boosting. Katta datasetda RF dan tezroq ishlaydi. F1-score ko\'rsatkichi yuqori.' },
  { key:'svm', name:'SVM',              type:'Supervised',    acc:91.2, sub:'Vector',          desc:'Yuqori o\'lchamli ma\'lumotlarda samarali. Ikkilik klassifikatsiya uchun ideal. RBF kernel bilan kuchli.' },
  { key:'lstm',name:'LSTM',             type:'Deep Learning', acc:94.1, sub:'RNN',             desc:'Recurrent neural network. Log ketma-ketliklarini tahlil. APT va doimiy hujumlarni aniqlashda eng samarali.' },
  { key:'ae',  name:'Autoencoder',      type:'Deep Learning', acc:88.9, sub:'Anomaly',         desc:'Normal trafik patternini o\'rganib, mos kelmaydigan narsani THREATS deb belgilaydi. Zero-day uchun eng yaxshi.' },
  { key:'iso', name:'Isolation Forest', type:'Unsupervised',  acc:87.4, sub:'Outlier',         desc:'Outlier\'larni izolyatsiya qilish orqali aniqlash. DDoS trafik THREATSlarini real vaqtda aniqlash uchun tezkor.' },
  { key:'cnn', name:'CNN',              type:'Deep Learning', acc:93.1, sub:'Pattern',         desc:'Tarmoq paket ma\'lumotlarini "rasm" sifatida o\'qib, pattern tahlili qiladi. Malware klassifikatsiya uchun kuchli.' },
  { key:'nb',  name:'Naive Bayes',      type:'Supervised',    acc:82.1, sub:'Probabilistic',   desc:'Phishing email aniqlashda kuchli. Katta hajmli log tahlilida haqiqiy vaqt uchun tanlangan.' },
];

const DATASETS = [
  { name:'NSL-KDD',    records:'125,973',   pct:10,  desc:'1999-KDD yaxshilangan versiyasi. 41 xususiyat, 4 hujum kategoriyasi: DoS, Probe, R2L, U2R.' },
  { name:'CICIDS2017', records:'2,830,743', pct:100, desc:'Canadian Institute for Cybersecurity. DDoS, PortScan, Botnet, Infiltration. 80+ feature.' },
  { name:'UNSW-NB15',  records:'2,540,047', pct:90,  desc:'UNSW Canberra. 9 hujum turi, 49 xususiyat. Fuzzers, Exploits, Backdoors va boshqalar.' },
  { name:'CAIDA DDoS', records:'~800,000',  pct:28,  desc:'Faqat DDoS hujumlarini tahlil qilish uchun. Real internet trafigi asosida yig\'ilgan.' },
];

const SIEM_TOOLS = [
  { key:'splunk',   name:'Splunk',     sub:'SPL tili, MLTK',      vendor:'Splunk Inc.',  detail:'SPL qidiruv tili, MLTK ML plaginlari va CIM modeli bilan enterprise SOC uchun kuchli real vaqt analitika beradi.', best:'Enterprise SOC', scores:{ realtime:94, ml:92, cost:38 } },
  { key:'qradar',   name:'IBM QRadar', sub:'Watson AI',           vendor:'IBM',          detail:'Log, flow va asset korrelyatsiyasini Watson AI yordamida boyitadi. Large-scale incident triage uchun qulay.', best:'Large enterprise', scores:{ realtime:86, ml:79, cost:48 } },
  { key:'sentinel', name:'MS Sentinel',sub:'Azure, KQL',          vendor:'Microsoft',    detail:'Azure-native SIEM/SOAR. KQL, Defender va Entra bilan juda yaxshi bog‘lanadi, cloud-first jamoalar uchun qulay.', best:'Cloud-first teams', scores:{ realtime:88, ml:84, cost:61 } },
  { key:'elk',      name:'ELK Stack',  sub:'Ochiq kodli',         vendor:'Elastic',      detail:'Elasticsearch, Logstash va Kibana kombinatsiyasi. Moslashuvchan, ammo tuning va operatsion yuk ko‘proq talab qiladi.', best:'Custom pipelines', scores:{ realtime:72, ml:58, cost:82 } },
  { key:'wazuh',    name:'Wazuh',      sub:'HIDS/SIEM',           vendor:'Wazuh',        detail:'Endpoint-centric monitoring, file integrity va rootkit aniqlash bilan kuchli. ELK bilan yaxshi tandem bo‘ladi.', best:'Endpoint visibility', scores:{ realtime:74, ml:52, cost:89 } },
  { key:'graylog',  name:'Graylog',    sub:'Log boshqaruvi',      vendor:'Graylog',      detail:'Structured log tahlili, routing va alerting uchun soddaroq stack. O‘rta hajmli jamoalarda tez joriy etiladi.', best:'Mid-size SOC', scores:{ realtime:69, ml:41, cost:85 } },
];

const SIEM_CAPABILITY_ROWS = [
  { key:'realtime', label:'Real vaqt', color:'#9fc2ea' },
  { key:'ml', label:'ML/AI', color:'#b5cef0' },
  { key:'cost', label:'Narx samaradorligi', color:'#94b7de' },
];

const TOPOLOGY_NODES = [
  { key:'attacker', label:'Attacker', x:12, y:42, tone:'hostile' },
  { key:'guard', label:'Firewall\nAI IDS', x:42, y:42, tone:'core' },
  { key:'web', label:'Web Server', x:70, y:18, tone:'service' },
  { key:'db', label:'DB Server', x:70, y:42, tone:'service' },
  { key:'mail', label:'Mail Server', x:70, y:66, tone:'service' },
  { key:'internal', label:'Internal', x:91, y:44, tone:'internal' },
  { key:'ai', label:'CyberGuard AI', x:18, y:78, tone:'observer' },
];

const TOPOLOGY_EDGES = [
  { from:'attacker', to:'guard', key:'ingress' },
  { from:'guard', to:'web', key:'web' },
  { from:'guard', to:'db', key:'db' },
  { from:'guard', to:'mail', key:'mail' },
  { from:'web', to:'internal', key:'web_internal' },
  { from:'db', to:'internal', key:'db_internal' },
  { from:'mail', to:'internal', key:'mail_internal' },
  { from:'ai', to:'guard', key:'telemetry', dashed:true },
];

const TOPOLOGY_SCENARIOS = {
  normal: {
    label:'Normal holat',
    summary:'Tarmoq normal ishlaydi. Barcha ulanishlar xavfsiz, CyberGuard AI barcha serverlarni kuzatmoqda.',
    linkStates:{ ingress:'idle', web:'ok', db:'ok', mail:'ok', web_internal:'ok', db_internal:'ok', mail_internal:'ok', telemetry:'monitor' },
  },
  attack: {
    label:'Hujum simulyatsiyasi',
    summary:'Tashqi manbadan shubhali trafik keldi. Firewall va AI IDS web hamda DB yo‘nalishlarida xavfli oqimlarni ko‘rmoqda.',
    linkStates:{ ingress:'attack', web:'attack', db:'warn', mail:'ok', web_internal:'warn', db_internal:'warn', mail_internal:'ok', telemetry:'monitor' },
  },
  blocked: {
    label:'Bloklangan',
    summary:'Hujum oqimi containment rejimiga o‘tdi. Firewall ingressni kesdi va faqat ichki servislar orasida minimal traffic qoldi.',
    linkStates:{ ingress:'blocked', web:'ok', db:'ok', mail:'ok', web_internal:'ok', db_internal:'ok', mail_internal:'ok', telemetry:'monitor' },
  },
};

const LIVE_TICKER_ITEMS = [
  'LOKAL TARMOQ SKANI FAQAT LIVE BACKEND NATIJALARINI KO\'RSATADI',
  'THREAT LOGLAR FAQAT SAQLANGAN ANALIZ VA BLOKLASH YOZUVLARIDAN OLINADI',
  'PUBLIC IP REPUTATSIYA UCHUN ABUSEIPDB API KEY KERAK',
  'SWAGGER HUJJATLARI /api/docs/swagger/ MANZILIDA OCHIQ',
];

const TICKER_ITEMS = [
  '[ALERT] DDOS HUJUMI ANIQLANDI | 240 GBPS | MANBA: TASHQI IP',
  '[BLOCK] SQL INJECTION BLOKLANDI | DB SERVER 192.168.1.201',
  '[WARN] BRUTE FORCE URINISHI | SSH PORT 22 | 500+ URINISH/MIN',
  '[INFO] AI MODEL YANGILANDI | TAHDID DB v4.2.1 | 14,847 YANGI IMZO',
  '[OK] HIMOYA FAOL | UPSTREAM RATE LIMITING YOQILDI',
  '[ALERT] RANSOMWARE IMZOSI ANIQLANDI | ENDPOINT KARANTINGA OLINDI',
];

const r   = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const fmtTime = d => new Date(d).toTimeString().slice(0, 8);

// ── HOOKS ──────────────────────────────────────────────────────────────────
function useClock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return time;
}

// ── REUSABLE COMPONENTS ────────────────────────────────────────────────────
function StatusDot({ color = '#39ff14', pulse = true, size = 6 }) {
  return (
    <span style={{
      display: 'inline-block', width: size, height: size, borderRadius: '50%',
      background: color, boxShadow: `0 0 6px ${color}`, flexShrink: 0,
      animation: pulse ? 'pulse 1.5s infinite' : 'none',
    }}/>
  );
}

function Badge({ sev }) {
  const s = (sev || '').toUpperCase();
  return <span className={`badge badge-${s}`}>{s}</span>;
}

function Panel({ title, color = '#00e5ff', children, style, extra }) {
  return (
    <div className="panel" style={style}>
      <div className="corner-tl"/><div className="corner-br"/>
      <div className="panel-header">
        <span className="panel-dot" style={{ background: color, boxShadow: `0 0 6px ${color}` }}/>
        <span className="panel-title">{title}</span>
        {extra}
      </div>
      {children}
    </div>
  );
}

function StatCard({ label, value, delta, color, icon }) {
  return (
    <div className={`stat-card c-${color}`}>
      <div className="stat-label">{label}</div>
      <div className={`stat-value c-${color}`}>{value}</div>
      {delta && <div className="stat-delta">{delta}</div>}
      <div className="stat-icon">{icon}</div>
    </div>
  );
}

// ── LOGIN PAGE ─────────────────────────────────────────────────────────────
function LoginPage({ onLogin }) {
  const [loading, setLoading] = useState(false);
  const handleLogin = () => {
    setLoading(true);
    setTimeout(() => { setLoading(false); onLogin(); }, 1600);
  };
  return (
    <div className="login-wrap">
      <div className="login-bg">
        <div className="hex-grid" style={{ backgroundSize: '56px 100px' }}/>
        <div className="scan-beam"/>
        {[...Array(5)].map((_, i) => (
          <div key={i} style={{
            position: 'absolute', width: 1,
            background: `linear-gradient(180deg,transparent,rgba(0,229,255,${0.06 + i * 0.02}),transparent)`,
            left: `${18 + i * 16}%`, top: 0, bottom: 0, animation: `pulse ${3 + i}s infinite`,
          }}/>
        ))}
      </div>
      <div className="login-card">
        <div className="corner-tl" style={{ width: 20, height: 20, borderWidth: '2px 0 0 2px', opacity: 1 }}/>
        <div className="corner-br" style={{ width: 20, height: 20, borderWidth: '0 2px 2px 0', opacity: 1 }}/>
        <div className="login-logo">
          <span className="shield">[CG]</span>
          <h1>CYBERGUARD AI</h1>
          <p>SECURITY OPERATIONS CENTER</p>
        </div>
        <div className="login-field">
          <label>OPERATOR ID</label>
          <input defaultValue="admin@cyberguard.ai"/>
        </div>
        <div className="login-field">
          <label>AUTHENTICATION KEY</label>
          <input type="password" defaultValue="************" onKeyDown={e => e.key === 'Enter' && handleLogin()}/>
        </div>
        <button className="login-btn" onClick={handleLogin} disabled={loading}>
          <span>{loading ? 'AUTHENTICATING...' : 'AUTHENTICATE'}</span>
        </button>
        <div className="login-status">
          <StatusDot/><span>ALL SYSTEMS OPERATIONAL | TLS 1.3 ENCRYPTED</span>
        </div>
      </div>
    </div>
  );
}

// ── SIDEBAR ────────────────────────────────────────────────────────────────
function Sidebar({ page, setPage, alertCount }) {
  const sections = [
    {
      title: 'ASOSIY',
      items: [
        { id: 'dashboard', label: 'Dashboard', ico: 'DB' },
        { id: 'analyze', label: 'IP Tahlil', ico: 'IP' },
        { id: 'network', label: 'Tarmoq Skan', ico: 'NW' },
      ],
    },
    {
      title: 'MODULLAR',
      items: [
        { id: 'threat_library', label: 'Tahdid turlari', ico: 'TT' },
        { id: 'algorithms', label: 'Algoritmlar', ico: 'AL' },
        { id: 'datasets', label: 'Datasetlar', ico: 'DS' },
        { id: 'siem', label: 'SIEM tizim', ico: 'SM' },
        { id: 'topology', label: 'Tarmoq xaritasi', ico: 'TP' },
        { id: 'logs', label: 'Live Loglar', ico: 'LG' },
        { id: 'threats', label: 'Tahdid Loglari', ico: 'TL', badge: alertCount },
      ],
    },
  ];
  return (
    <div className="sidebar">
      <div className="sb-logo">
        <div className="mark">CYBERGUARD</div>
        <div className="sub">AI SECURITY PLATFORM</div>
        <div className="sb-status">
          <span className="dot"/><span>SHIELDS ACTIVE</span>
        </div>
      </div>
      <div className="sb-nav">
        {sections.map(section => (
          <div key={section.title} style={{ marginBottom: 12 }}>
            <div style={{
              padding: '10px 20px 6px',
              color: '#4a6a84',
              fontSize: 10,
              letterSpacing: 2,
              fontWeight: 700,
            }}>
              {section.title}
            </div>
            {section.items.map(n => (
              <div key={n.id} className={`nav-item${page === n.id ? ' active' : ''}`} onClick={() => setPage(n.id)}>
                <span className="ico mono">{n.ico}</span>
                <span>{n.label}</span>
                {n.badge > 0 && <span className="nav-badge">{n.badge}</span>}
              </div>
            ))}
          </div>
        ))}
      </div>
      <div className="sb-bottom">
        <div className="user-row">
          <div className="user-avatar">SA</div>
          <div className="user-info">
            <div className="name">SOC Analyst</div>
            <div className="role mono">TIER-2 OPERATOR</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── TOPBAR ─────────────────────────────────────────────────────────────────
function TopBar({ page, time }) {
  const titles = {
    dashboard: 'THREAT DASHBOARD',
    threats: 'TAHDID LOGLARI',
    network: 'LOCAL NETWORK SCANNER',
    analyze: 'IP ANALYSIS ENGINE',
    logs: 'LIVE LOG STREAM',
    threat_library: 'THREAT KNOWLEDGE BASE',
    algorithms: 'ALGORITHM CATALOG',
    datasets: 'DATASET REFERENCE',
    siem: 'SIEM INTEGRATION CENTER',
    topology: 'NETWORK TOPOLOGY MAP',
    insights: 'AI INSIGHTS',
    settings: 'SETTINGS',
  };
  return (
    <div className="topbar">
      <div className="topbar-title">{titles[page] || 'DASHBOARD'}</div>
      <div className="topbar-time mono">{fmtTime(time)} UTC</div>
      <div className="topbar-pill pill-secure">
        <StatusDot color="#39ff14" size={5}/> SECURE
      </div>
    </div>
  );
}

// ── DASHBOARD PAGE ─────────────────────────────────────────────────────────
function DashboardPage() {
  const lineRef  = useRef();
  const donutRef = useRef();
  const lineChart  = useRef();
  const donutChart = useRef();
  const [stats, setStats]   = useState(null);
  const [logs, setLogs]     = useState([]);
  const [refreshAt, setRefreshAt] = useState(new Date());

  useEffect(() => {
    const loadData = async () => {
      try {
        const [dashboard, liveLogs] = await Promise.all([
          api.getDashboard(),
          api.getLiveLogs(),
        ]);
        setStats(dashboard);
        setLogs(liveLogs.logs || []);
        setRefreshAt(new Date());
      } catch {
        setStats(null);
        setLogs([]);
      }
    };

    loadData();
    const id = setInterval(loadData, 8000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (!lineRef.current || !window.Chart) return;
    const ctx = lineRef.current.getContext('2d');
    lineChart.current = new window.Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          { label: 'Threats', data: [], borderColor: '#00e5ff', backgroundColor: 'rgba(0,229,255,.08)', borderWidth: 1.5, tension: .35, pointRadius: 0, fill: true },
          { label: 'Blocked', data: [], borderColor: 'rgba(57,255,20,.75)', borderWidth: 1.2, tension: .35, pointRadius: 0, fill: false },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: { duration: 200 },
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: { grid: { color: 'rgba(26,58,92,.5)' }, ticks: { color: '#4a6a84', font: { family: 'Share Tech Mono', size: 10 } }, border: { display: false } },
        },
      },
    });
    return () => lineChart.current?.destroy();
  }, []);

  useEffect(() => {
    if (!donutRef.current || !window.Chart) return;
    const ctx = donutRef.current.getContext('2d');
    donutChart.current = new window.Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: ['rgba(255,23,68,.8)','rgba(255,171,0,.8)','rgba(251,146,60,.8)','rgba(168,85,247,.8)','rgba(0,229,255,.8)','rgba(74,222,128,.8)'],
          borderColor: '#08111e', borderWidth: 2,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '70%', animation: { duration: 300 },
        plugins: { legend: { position: 'right', labels: { color: '#7ab8d4', font: { family: 'Share Tech Mono', size: 10 }, boxWidth: 10, padding: 6 } } },
      },
    });
    return () => donutChart.current?.destroy();
  }, []);

  useEffect(() => {
    if (!lineChart.current) return;
    const trend = stats?.hourly_trend || [];
    lineChart.current.data.labels = trend.map(item => item.hour);
    lineChart.current.data.datasets[0].data = trend.map(item => item.threats);
    lineChart.current.data.datasets[1].data = trend.map(item => item.blocked);
    lineChart.current.update();
  }, [stats]);

  useEffect(() => {
    if (!donutChart.current) return;
    const entries = Object.entries(stats?.threat_distribution || {});
    donutChart.current.data.labels = entries.length ? entries.map(([key]) => key.toUpperCase()) : ['NO DATA'];
    donutChart.current.data.datasets[0].data = entries.length ? entries.map(([, value]) => value) : [1];
    donutChart.current.update();
  }, [stats]);

  useEffect(() => {
    return undefined;
  }, []);

  const s = stats || { total_threats: 0, blocked: 0, critical: 0, accuracy: 0, block_rate: 0, response_ms: 0, false_positive_rate: 0 };
  const riskScore = Math.min(100, Math.round((s.total_threats ? (s.critical / Math.max(s.total_threats, 1)) * 70 : 0) + (s.block_rate || 0) * 0.3));
  const gaugeColor = riskScore >= 70 ? '#ff1744' : riskScore >= 40 ? '#ffab00' : '#39ff14';
  const gaugeLabel = riskScore >= 70 ? 'YUQORI' : riskScore >= 40 ? "O'RTA" : 'PAST';
  const sysItems = [
    { name: 'Backend API',  val: stats ? 'ACTIVE' : 'OFFLINE', cls: stats ? 'ok' : 'crit' },
    { name: 'Threat Logs',  val: `${s.total_threats} ta`, cls: s.total_threats ? 'ok' : 'warn' },
    { name: 'Block Rate',   val: `${s.block_rate || 0}%`, cls: (s.block_rate || 0) >= 40 ? 'ok' : 'warn' },
    { name: 'Critical',     val: `${s.critical} ta`, cls: s.critical > 0 ? 'crit' : 'ok' },
    { name: 'Live Stream',  val: logs.length ? 'ACTIVE' : 'IDLE', cls: logs.length ? 'ok' : 'warn' },
    { name: 'Last Refresh', val: fmtTime(refreshAt), cls: 'ok' },
  ];
  const lvlColor = lvl => ({ error: '#ff1744', warn: '#ffab00', info: '#39ff14' }[lvl] || '#00e5ff');

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <div className="stat-grid">
        <StatCard label="TAHDIDLAR"    value={s.total_threats} delta={`live loglar: ${logs.length}`} color="red"   icon="!"/>
        <StatCard label="BLOKLANGAN" value={s.blocked} delta="saqlangan bloklashlar" color="cyan" icon="#"/>
        <StatCard label="KRITIK" value={s.critical} delta="yuqori ustuvorlik" color="amber" icon="*"/>
        <StatCard label="BLOCK RATE" value={`${s.block_rate || 0}%`} delta="real threat loglardan" color="green" icon=">"/>
      </div>

      <div className="charts-row">
        <Panel title="THREAT TREND - REAL VAQT SIGNALI" color="#00e5ff"
          extra={<span style={{ marginLeft: 'auto', fontFamily: 'Share Tech Mono', fontSize: 10, color: '#4a6a84' }}>SOURCE: BACKEND API</span>}>
          <div className="panel-body">
            <div className="chart-wrap"><canvas ref={lineRef}/></div>
            <div style={{ display: 'flex', gap: 20, marginTop: 10, fontSize: 11, fontFamily: 'Share Tech Mono', color: '#4a6a84' }}>
              <span style={{ color: '#00e5ff' }}>- THREATS</span>
              <span style={{ color: 'rgba(57,255,20,.7)' }}>--- BLOCKED</span>
              <span style={{ marginLeft: 'auto' }}>MODEL: LOCAL ANALYZER</span>
            </div>
          </div>
        </Panel>

        <Panel title="XAVF DARAJASI" color="#ff1744">
          <div className="risk-gauge">
            <svg width="130" height="130" viewBox="0 0 140 140">
              <circle cx="70" cy="70" r="58" fill="none" stroke="#1a3a5c" strokeWidth="10"/>
              <circle cx="70" cy="70" r="58" fill="none" stroke={gaugeColor}
                strokeWidth="10" strokeDasharray={`${Math.round((riskScore / 100) * 364)} 364`} strokeDashoffset="91"
                style={{ filter: `drop-shadow(0 0 6px ${gaugeColor})` }}
                transform="rotate(-90 70 70)"/>
              <text x="70" y="67" textAnchor="middle" fontFamily="Orbitron,monospace" fontSize="22" fontWeight="900" fill={gaugeColor}>{riskScore}</text>
              <text x="70" y="82" textAnchor="middle" fontFamily="Share Tech Mono,monospace" fontSize="9" fill="#4a6a84">XAVF BALI</text>
            </svg>
            <div className="gauge-label">
              <div className="gauge-level" style={{ color: gaugeColor }}>{gaugeLabel}</div>
              <div className="gauge-sub">TAHDID DARAJASI</div>
            </div>
          </div>
        </Panel>
      </div>

      <div className="bottom-row">
        <Panel title="HUJUM TURLARI" color="#a855f7">
          <div className="panel-body" style={{ paddingTop: 10 }}>
            <div className="chart-wrap-sm"><canvas ref={donutRef}/></div>
          </div>
        </Panel>

        <Panel title="JONLI OGOHLANTIRISH OQIMI" color="#ff1744"
          extra={<span style={{ marginLeft: 'auto', fontFamily: 'Share Tech Mono', fontSize: 10, color: '#ff1744', animation: 'pulse 1s infinite' }}>LIVE</span>}>
          <div className="alert-feed">
            {logs.slice(0, 12).map((l, i) => (
              <div className="alert-item" key={l.id || i}>
                <span className="time">{fmtTime(l.timestamp)}</span>
                <span style={{
                  fontSize: 9, padding: '1px 6px', border: '1px solid', fontFamily: 'Share Tech Mono',
                  borderColor: `${lvlColor(l.level)}44`, color: lvlColor(l.level),
                  background: `${lvlColor(l.level)}11`,
                }}>{l.level?.toUpperCase()}</span>
                <span style={{ flex: 1, fontSize: 12, color: '#94b4c8' }}>{l.message}</span>
                <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#4a6a84' }}>{l.ip}</span>
              </div>
            ))}
            {logs.length === 0 && (
              <div style={{ padding: 16, textAlign: 'center', color: '#4a6a84', fontFamily: 'Share Tech Mono', fontSize: 11 }}>
                Backend dan loglar kutilmoqda...
              </div>
            )}
          </div>
        </Panel>
      </div>

      <div style={{ height: 14 }}/>
      <Panel title="TIZIM HOLATI" color="#39ff14"
        extra={<span style={{ marginLeft: 'auto', fontFamily: 'Share Tech Mono', fontSize: 10, color: '#4a6a84' }}>SO'NGI YANGILASH: {fmtTime(refreshAt)}</span>}>
        <div className="sys-status-list" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 24px' }}>
          {sysItems.map(s => (
            <div className="sys-row" key={s.name}>
              <span className="sys-name">{s.name}</span>
              <span className={`sys-val ${s.cls}`}>
                <StatusDot color={s.cls === 'ok' ? '#39ff14' : s.cls === 'warn' ? '#ffab00' : '#ff1744'} size={5}/>
                {' '}{s.val}
              </span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ── THREATS PAGE ───────────────────────────────────────────────────────────
function ThreatsPage() {
  const [threats, setThreats]   = useState([]);
  const [filter, setFilter]     = useState('ALL');
  const [loading, setLoading]   = useState(true);

  const fetchThreats = useCallback(() => {
    api.getThreats()
      .then(d => { setThreats(d.results || d || []); setLoading(false); })
      .catch(() => { setThreats([]); setLoading(false); });
  }, []);

  useEffect(() => { fetchThreats(); }, [fetchThreats]);

  const blockIP = async (id) => {
    await api.blockThreat(id).catch(() => {});
    fetchThreats();
  };

  const types = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const filtered = filter === 'ALL' ? threats : threats.filter(t => t.severity?.toUpperCase() === filter);

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <div className="filter-bar">
        {types.map(t => (
          <button key={t} className={`filter-btn${filter === t ? ' active' : ''}`} onClick={() => setFilter(t)}>{t}</button>
        ))}
        <button className="filter-btn" style={{ marginLeft: 'auto' }} onClick={fetchThreats}>YANGILASH</button>
      </div>
      <Panel title={`TAHDID LOGLARI | ${filtered.length} VOQEA`} color="#ff1744">
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><div className="spinner"/></div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>JIDDIYLIK</th><th>IP MANZIL</th><th>TAHDID TURI</th>
                  <th>QURILMA</th><th>AI EHTIMOL</th><th>ALGORITM</th><th>HOLAT</th><th>AMAL</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 30).map((t, i) => (
                  <tr key={t.id || i}>
                    <td><Badge sev={t.severity}/></td>
                    <td className="td-mono">{t.ip_address}</td>
                    <td style={{ fontWeight: 600 }}>{t.threat_type}</td>
                    <td style={{ fontSize: 12, color: '#4a6a84' }}>{t.device_name || '-'}</td>
                    <td>
                      <div className="conf-bar-wrap">
                        <div className="conf-bar" style={{ width: 70 }}>
                          <div className="conf-bar-fill" style={{ width: `${Math.round((t.probability || 0.8) * 100)}%` }}/>
                        </div>
                        <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#00e5ff' }}>
                          {Math.round((t.probability || 0.8) * 100)}%
                        </span>
                      </div>
                    </td>
                    <td className="td-mono" style={{ fontSize: 10, color: '#4a6a84' }}>{t.algorithm || '-'}</td>
                    <td>
                      <span style={{
                        fontFamily: 'Share Tech Mono', fontSize: 10,
                        color: t.is_blocked ? '#39ff14' : '#ffab00',
                      }}>
                        <StatusDot color={t.is_blocked ? '#39ff14' : '#ffab00'} size={5}/>
                        {' '}{t.is_blocked ? 'BLOKLANDI' : 'KUZATILMOQDA'}
                      </span>
                    </td>
                    <td>
                      {!t.is_blocked && (
                        <button className="action-btn" onClick={() => blockIP(t.id)}
                          style={{ borderColor: 'rgba(255,23,68,.5)', color: '#ff1744' }}>
                          BLOKLASH
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr><td colSpan={8} style={{ textAlign: 'center', padding: 30, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>
                    Tahdid loglari topilmadi
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

// ── NETWORK PAGE ───────────────────────────────────────────────────────────
function NetworkPage({ onAnalyze }) {
  const getDefaultProfilePort = type => ({ ssh: 22, telnet: 23, snmp: 161 }[type] || 22);
  const [devices, setDevices] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  const [wifiStatus, setWifiStatus] = useState(null);
  const [profiles, setProfiles] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [profileBusyId, setProfileBusyId] = useState(null);
  const [wifiBusy, setWifiBusy] = useState(false);
  const [selected, setSelected] = useState(null);
  const [selectedInterface, setSelectedInterface] = useState('');
  const [selectedWifi, setSelectedWifi] = useState('');
  const [repInfo, setRepInfo] = useState(null);
  const [profileError, setProfileError] = useState('');
  const [wifiError, setWifiError] = useState('');
  const [profileForm, setProfileForm] = useState({
    name: '',
    profile_type: 'ssh',
    target_host: '',
    port: getDefaultProfilePort('ssh'),
    username: '',
    secret: '',
    snmp_version: '2c',
    network_label: '',
    notes: '',
  });
  const [wifiForm, setWifiForm] = useState({
    ssid: '',
    password: '',
    authentication: '',
    encryption: '',
  });

  const loadNetworkContext = useCallback(async () => {
    try {
      const [scanData, interfaceData, wifiData, profileData, sessionData] = await Promise.all([
        api.scanNetwork(),
        api.getInterfaces(),
        api.getWifiStatus(),
        api.getProfiles(),
        api.getScanSessions(),
      ]);
      setDevices(scanData.devices || []);
      setInterfaces(interfaceData.interfaces || []);
      setWifiStatus(wifiData);
      setProfiles(profileData.results || profileData || []);
      setSessions(sessionData.results || sessionData || []);

      const nextInterface = wifiData?.connected_interface
        || selectedInterface
        || (interfaceData.interfaces || [])[0]?.name
        || '';
      if (nextInterface) {
        setSelectedInterface(nextInterface);
      }

      if (wifiData?.connected_ssid) {
        setSelectedWifi(wifiData.connected_ssid);
        setWifiForm(form => ({ ...form, ssid: wifiData.connected_ssid }));
      }
    } catch {
      setDevices([]);
      setInterfaces([]);
      setWifiStatus(null);
      setProfiles([]);
      setSessions([]);
    } finally {
      setLoading(false);
      setScanning(false);
    }
  }, [selectedInterface]);

  const scan = () => {
    setScanning(true);
    loadNetworkContext();
  };

  const checkRep = async (ip) => {
    setSelected(ip);
    setRepInfo(null);
    try {
      const d = await api.getReputation(ip);
      setRepInfo(d);
    } catch {
      setRepInfo({ ip, message: 'Reputatsiya tekshirib bo\'lmadi' });
    }
  };

  const createProfile = async () => {
    setProfileError('');
    try {
      await api.createProfile(profileForm);
      setProfileForm({
        name: '',
        profile_type: profileForm.profile_type,
        target_host: '',
        port: getDefaultProfilePort(profileForm.profile_type),
        username: '',
        secret: '',
        snmp_version: '2c',
        network_label: '',
        notes: '',
      });
      loadNetworkContext();
    } catch (err) {
      setProfileError(err.message || 'Profil yaratib bo\'lmadi');
    }
  };

  const connectWifi = async () => {
    setWifiError('');
    setWifiBusy(true);
    try {
      const response = await api.connectWifi({
        ssid: wifiForm.ssid,
        password: wifiForm.password,
        interface_name: selectedInterface,
        authentication: wifiForm.authentication,
        encryption: wifiForm.encryption,
      });
      setWifiStatus(response);
      setSelectedWifi(response.connected_ssid || wifiForm.ssid);
      setWifiForm(form => ({ ...form, password: '' }));
      await loadNetworkContext();
    } catch (err) {
      setWifiError(err.message || 'Wi-Fi ga ulanib bo\'lmadi');
    } finally {
      setWifiBusy(false);
    }
  };

  const runProfileScan = async (profile) => {
    setProfileBusyId(profile.id);
    try {
      const selectedInterfaceInfo = interfaces.find(item => item.name === selectedInterface);
      await api.runProfileScan(profile.id, {
        interface_name: selectedInterfaceInfo?.name || '',
        network_name: selectedInterfaceInfo?.ssid || selectedInterfaceInfo?.subnet_cidr || '',
      });
      await loadNetworkContext();
    } catch (err) {
      setProfileError(err.message || 'Credentialed scan xatolik bilan tugadi');
    } finally {
      setProfileBusyId(null);
    }
  };

  const buildSessionContext = session => {
    const parts = [
      `Profile: ${session.profile_name || '-'}`,
      `Protocol: ${session.profile_type || '-'}`,
      `Target: ${session.target_host || '-'}`,
      `Status: ${session.status || '-'}`,
      session.network_name ? `Network: ${session.network_name}` : '',
      session.interface_name ? `Interface: ${session.interface_name}` : '',
      session.error_message ? `Error: ${session.error_message}` : '',
      session.result?.prompt ? `Prompt: ${session.result.prompt}` : '',
      session.result?.login_transcript ? `Login Transcript:\n${session.result.login_transcript}` : '',
      session.result?.device_description ? `Collected Data:\n${session.result.device_description}` : '',
    ];
    return parts.filter(Boolean).join('\n');
  };

  const analyzeSession = session => {
    onAnalyze(session.target_host, { context: buildSessionContext(session) });
  };

  useEffect(() => { loadNetworkContext(); }, [loadNetworkContext]);

  const riskColor = risk => ({ low: '#39ff14', medium: '#ffab00', high: '#fb923c', critical: '#ff1744' }[risk] || '#39ff14');
  const deviceStats = {
    online: devices.filter(device => device.status === 'online').length,
    risky: devices.filter(device => ['high', 'critical'].includes(device.risk)).length,
    exposed: devices.filter(device => (device.open_ports || []).length >= 4).length,
  };
  const inputStyle = {
    width: '100%',
    background: 'rgba(0,229,255,.04)',
    border: '1px solid var(--border)',
    color: 'var(--text)',
    padding: '9px 12px',
    fontFamily: 'Share Tech Mono',
    fontSize: 12,
    outline: 'none',
  };

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <Panel title={`LOCAL TARMOQ SKANERI | ${devices.length} TOPILDI`} color="#00e5ff"
        extra={
          <button className="action-btn" style={{ marginLeft: 'auto' }} onClick={scan} disabled={scanning}>
            {scanning ? 'SKANLANMOQDA...' : 'QAYTA SKAN'}
          </button>
        }>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><div className="spinner"/></div>
        ) : (
          <div style={{ padding: 14 }}>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0, 1fr))', gap:10, marginBottom: 12 }}>
              {[
                ['Onlayn hostlar', `${deviceStats.online}/${devices.length}`, '#39ff14'],
                ['Yuqori xavf', `${deviceStats.risky} ta`, '#ffab00'],
                ['Ko‘p port ochiq', `${deviceStats.exposed} ta`, '#9fc2ea'],
              ].map(([label, value, color]) => (
                <div key={label} style={{ padding: 12, border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)' }}>
                  <div style={{ fontSize: 10, color: '#4a6a84', letterSpacing: 2, marginBottom: 6 }}>{label}</div>
                  <div style={{ color, fontSize: 22, fontWeight: 700, fontFamily: 'Orbitron,monospace' }}>{value}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {devices.map((d, i) => {
              const rc = riskColor(d.risk);
              const isSel = selected === d.ip;
              return (
                <div key={i} onClick={() => checkRep(d.ip)} style={{
                  background: isSel ? 'rgba(0,229,255,.06)' : 'linear-gradient(180deg, rgba(13,27,46,.72), rgba(8,15,28,.92))',
                  border: `1px solid ${isSel ? 'var(--cyan)' : `${rc}44`}`,
                  boxShadow: isSel ? '0 0 18px rgba(0,229,255,.15)' : 'none',
                  padding: 16, cursor: 'pointer', transition: 'all .2s', minHeight: 180,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 17, color: 'var(--text)', marginBottom: 4 }}>{d.name}</div>
                      <div style={{ fontFamily: 'Share Tech Mono', fontSize: 12, color: '#00e5ff' }}>{d.ip}</div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                      <StatusDot color={d.status === 'online' ? '#39ff14' : '#4a6a84'} size={8}/>
                      <span style={{ fontSize: 9, fontFamily: 'Share Tech Mono', color: d.status === 'online' ? '#39ff14' : '#4a6a84' }}>
                        {d.status?.toUpperCase()}
                      </span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
                    <span style={{
                      fontSize: 10, padding: '3px 9px', border: '1px solid', fontFamily: 'Share Tech Mono',
                      borderColor: `${rc}44`, color: rc, background: `${rc}11`,
                    }}>{d.risk?.toUpperCase()} XAVF</span>
                    <span style={{ fontSize: 10, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>{d.network_type}</span>
                  </div>
                  <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, marginBottom: 12, fontSize: 11 }}>
                    <div style={{ color:'#7ab8d4', fontFamily:'Share Tech Mono' }}>Portlar: {(d.open_ports || []).join(', ') || '-'}</div>
                    <div style={{ color:'#4a6a84', fontFamily:'Share Tech Mono', textAlign:'right' }}>{d.open_ports?.length || 0} ta ochiq</div>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="action-btn" style={{ flex: 1,
                      borderColor: (d.risk === 'critical' || d.risk === 'high') ? 'rgba(255,23,68,.5)' : 'var(--border)',
                      color: (d.risk === 'critical' || d.risk === 'high') ? '#ff1744' : 'var(--text-dim)',
                    }} onClick={e => { e.stopPropagation(); onAnalyze(d.ip); }}>
                      TAHLIL
                    </button>
                    <button className="action-btn" onClick={e => { e.stopPropagation(); checkRep(d.ip); }}>
                      REP
                    </button>
                  </div>
                </div>
              );
            })}
            </div>
          </div>
        )}
      </Panel>

      {repInfo && (
        <Panel title={`IP REPUTATSIYA | ${repInfo.ip}`} color="#ffab00" style={{ marginTop: 14 }}>
          <div className="panel-body" style={{ fontSize: 13 }}>
            {repInfo.is_local ? (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><span style={{ color: '#4a6a84' }}>Turi: </span><span style={{ fontFamily: 'Share Tech Mono', color: '#39ff14' }}>LOCAL (ICHKI TARMOQ)</span></div>
                <div><span style={{ color: '#4a6a84' }}>Qurilma: </span><span>{repInfo.local_info?.device_name}</span></div>
                <div><span style={{ color: '#4a6a84' }}>Tarmoq: </span><span>{repInfo.local_info?.network_type}</span></div>
                <div><span style={{ color: '#4a6a84' }}>Xabar: </span><span style={{ color: '#4a6a84' }}>{repInfo.message}</span></div>
              </div>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><span style={{ color: '#4a6a84' }}>AbuseIPDB Ball: </span>
                  <span style={{ fontFamily: 'Orbitron,monospace', fontSize: 18, color: (repInfo.abuse_score || 0) > 50 ? '#ff1744' : '#39ff14' }}>
                    {repInfo.abuse_score ?? 0}/100
                  </span>
                </div>
                {repInfo.country && <div><span style={{ color: '#4a6a84' }}>Mamlakat: </span><span>{repInfo.country}</span></div>}
                {repInfo.isp && <div><span style={{ color: '#4a6a84' }}>ISP: </span><span style={{ fontFamily: 'Share Tech Mono', fontSize: 11 }}>{repInfo.isp}</span></div>}
                {repInfo.message && <div style={{ color: '#4a6a84' }}>{repInfo.message}</div>}
              </div>
            )}
          </div>
        </Panel>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14 }}>
        <Panel title="WIFI HOLATI" color="#00e5ff">
          <div className="panel-body">
            {!wifiStatus && <div style={{ color: '#4a6a84' }}>Wi-Fi holati yuklanmoqda...</div>}
            {wifiStatus && (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 12, fontSize: 12 }}>
                  <div><span style={{ color: '#4a6a84' }}>Adapter: </span>{wifiStatus.wifi_adapter_available ? 'BOR' : 'YOQ'}</div>
                  <div><span style={{ color: '#4a6a84' }}>Service: </span>{wifiStatus.service_running ? 'RUNNING' : 'STOPPED'}</div>
                  <div><span style={{ color: '#4a6a84' }}>Connected SSID: </span>{wifiStatus.connected_ssid || '-'}</div>
                  <div><span style={{ color: '#4a6a84' }}>Interface: </span>{wifiStatus.connected_interface || '-'}</div>
                </div>
                <div style={{ color: '#94b4c8', fontSize: 12, marginBottom: 12 }}>{wifiStatus.message}</div>

                {!wifiStatus.wifi_adapter_available && (
                  <div style={{ color: '#ffab00', fontSize: 12 }}>
                    Wi-Fi adapter yo&apos;q. Ethernet yoki virtual adapter ma&apos;lumotlari orqali scan davom etadi.
                  </div>
                )}

                {wifiStatus.wifi_adapter_available && !wifiStatus.service_running && (
                  <div style={{ color: '#ffab00', fontSize: 12 }}>
                    Wireless AutoConfig xizmati o&apos;chiq. Wi-Fi scan/connect uchun Windows&apos;da `wlansvc` yoqilishi kerak.
                  </div>
                )}

                {wifiStatus.wifi_adapter_available && wifiStatus.service_running && (
                  <>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10, marginBottom: 12 }}>
                      {(wifiStatus.available_networks || []).map(net => {
                        const active = selectedWifi === net.ssid || wifiForm.ssid === net.ssid;
                        return (
                          <div key={net.ssid} onClick={() => {
                            setSelectedWifi(net.ssid);
                            setWifiForm(form => ({
                              ...form,
                              ssid: net.ssid,
                              authentication: net.authentication || '',
                              encryption: net.encryption || '',
                            }));
                          }} style={{
                            padding: 10,
                            border: `1px solid ${active ? 'var(--cyan)' : 'var(--border2)'}`,
                            background: active ? 'rgba(0,229,255,.06)' : 'transparent',
                            cursor: 'pointer',
                          }}>
                            <div style={{ color: 'var(--text)', fontWeight: 700, fontSize: 13 }}>{net.ssid || '(hidden)'}</div>
                            <div style={{ color: '#4a6a84', fontSize: 11, fontFamily: 'Share Tech Mono' }}>
                              {net.signal || '-'} | {net.authentication || '-'}
                            </div>
                            <div style={{ color: '#4a6a84', fontSize: 11, fontFamily: 'Share Tech Mono' }}>
                              {net.encryption || '-'} | BSSID {net.bssid_count}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1fr', gap: 10 }}>
                      <input value={wifiForm.ssid} onChange={e => setWifiForm(form => ({ ...form, ssid: e.target.value }))} placeholder="SSID" style={inputStyle}/>
                      <input value={wifiForm.authentication} onChange={e => setWifiForm(form => ({ ...form, authentication: e.target.value }))} placeholder="Authentication" style={inputStyle}/>
                      <input value={wifiForm.encryption} onChange={e => setWifiForm(form => ({ ...form, encryption: e.target.value }))} placeholder="Encryption" style={inputStyle}/>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, marginTop: 10, alignItems: 'center' }}>
                      <input value={wifiForm.password} onChange={e => setWifiForm(form => ({ ...form, password: e.target.value }))} placeholder="Wi-Fi password" type="password" style={inputStyle}/>
                      <button className="action-btn" onClick={connectWifi} disabled={wifiBusy || !wifiForm.ssid}>
                        {wifiBusy ? 'ULANMOQDA...' : 'WIFI CONNECT'}
                      </button>
                    </div>
                    {wifiError && <div style={{ color: '#ff8fa0', fontSize: 12, marginTop: 10 }}>{wifiError}</div>}
                  </>
                )}
              </>
            )}
          </div>
        </Panel>

        <Panel title="ULANISH VA TAHLIL" color="#39ff14">
          <div className="panel-body" style={{ fontSize: 12, color: '#94b4c8', lineHeight: 1.8 }}>
            <div>1. Wi-Fi adapter bo&apos;lsa SSID tanlanadi yoki qo&apos;lda kiritiladi.</div>
            <div>2. Password kiritilib Windows darajasida ulanishga urinish qilinadi.</div>
            <div>3. Ulangan tarmoq yoki Ethernet interfeys bo&apos;yicha subnet aniqlanadi.</div>
            <div>4. Local hostlar, portlar va credentialed scan natijalari yig&apos;iladi.</div>
            <div>5. IP Analysis sahifasi shu ma&apos;lumotlar asosida ehtimoliy threat score qaytaradi.</div>
            <div style={{ marginTop: 10, color: '#4a6a84' }}>
              Eslatma: dashboard va IP analysis sonlari heuristik/model confidence bo&apos;lib, forensik isbot emas.
            </div>
          </div>
        </Panel>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 14, marginTop: 14 }}>
        <Panel title={`INTERFACES / SSID | ${interfaces.length}`} color="#39ff14">
          <div className="panel-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {interfaces.map(item => {
                const isActive = selectedInterface === item.name;
                return (
                  <div key={item.name} onClick={() => setSelectedInterface(item.name)} style={{
                    padding: 12,
                    border: `1px solid ${isActive ? 'var(--cyan)' : 'var(--border2)'}`,
                    background: isActive ? 'rgba(0,229,255,.06)' : 'transparent',
                    cursor: 'pointer',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                      <div>
                        <div style={{ color: 'var(--text)', fontWeight: 700 }}>{item.name}</div>
                        <div style={{ fontSize: 11, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>{item.adapter_type}</div>
                      </div>
                      <div style={{ textAlign: 'right', fontFamily: 'Share Tech Mono', fontSize: 11, color: '#7ab8d4' }}>
                        {item.ssid || item.subnet_cidr || '-'}
                      </div>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 10, fontSize: 12 }}>
                      <div><span style={{ color: '#4a6a84' }}>IP: </span>{item.ip || '-'}</div>
                      <div><span style={{ color: '#4a6a84' }}>Gateway: </span>{item.gateway || '-'}</div>
                      <div><span style={{ color: '#4a6a84' }}>Mask: </span>{item.subnet_mask || '-'}</div>
                      <div><span style={{ color: '#4a6a84' }}>State: </span>{item.state || '-'}</div>
                      <div><span style={{ color: '#4a6a84' }}>DNS Suffix: </span>{item.dns_suffix || '-'}</div>
                      <div><span style={{ color: '#4a6a84' }}>Link-local IPv6: </span>{item.link_local_ipv6 || '-'}</div>
                    </div>
                    {item.ipv6_addresses?.length > 0 && (
                      <div style={{ marginTop: 8, fontSize: 12 }}>
                        <span style={{ color: '#4a6a84' }}>IPv6: </span>{item.ipv6_addresses.join(', ')}
                      </div>
                    )}
                    {item.temporary_ipv6_addresses?.length > 0 && (
                      <div style={{ marginTop: 6, fontSize: 12 }}>
                        <span style={{ color: '#4a6a84' }}>Temp IPv6: </span>{item.temporary_ipv6_addresses.join(', ')}
                      </div>
                    )}
                    {item.gateways?.length > 1 && (
                      <div style={{ marginTop: 6, fontSize: 12 }}>
                        <span style={{ color: '#4a6a84' }}>All gateways: </span>{item.gateways.join(', ')}
                      </div>
                    )}
                  </div>
                );
              })}
              {interfaces.length === 0 && <span style={{ color: '#4a6a84' }}>Interfeyslar topilmadi.</span>}
            </div>
          </div>
        </Panel>

        <Panel title="CONNECTION PROFILE" color="#a855f7">
          <div className="panel-body">
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <input value={profileForm.name} onChange={e => setProfileForm(p => ({ ...p, name: e.target.value }))} placeholder="Profile nomi" style={inputStyle}/>
              <select value={profileForm.profile_type} onChange={e => setProfileForm(p => ({ ...p, profile_type: e.target.value, port: getDefaultProfilePort(e.target.value) }))} style={inputStyle}>
                <option value="ssh">SSH</option>
                <option value="telnet">Telnet</option>
                <option value="snmp">SNMP</option>
              </select>
              <input value={profileForm.target_host} onChange={e => setProfileForm(p => ({ ...p, target_host: e.target.value }))} placeholder="Target host/IP" style={inputStyle}/>
              <input value={profileForm.port} onChange={e => setProfileForm(p => ({ ...p, port: Number(e.target.value || 0) }))} placeholder="Port" type="number" style={inputStyle}/>
              <input value={profileForm.username} onChange={e => setProfileForm(p => ({ ...p, username: e.target.value }))} placeholder={profileForm.profile_type === 'snmp' ? 'Username (ixtiyoriy)' : 'Username (SSH/Telnet)'} style={inputStyle}/>
              <input value={profileForm.secret} onChange={e => setProfileForm(p => ({ ...p, secret: e.target.value }))} placeholder={profileForm.profile_type === 'snmp' ? 'Community' : 'Password'} type="password" style={inputStyle}/>
              <input value={profileForm.network_label} onChange={e => setProfileForm(p => ({ ...p, network_label: e.target.value }))} placeholder="Tarmoq label/SSID" style={inputStyle}/>
              <select value={profileForm.snmp_version} onChange={e => setProfileForm(p => ({ ...p, snmp_version: e.target.value }))} style={inputStyle} disabled={profileForm.profile_type !== 'snmp'}>
                <option value="2c">SNMP v2c</option>
              </select>
            </div>
            <textarea value={profileForm.notes} onChange={e => setProfileForm(p => ({ ...p, notes: e.target.value }))} placeholder="Izoh" style={{ ...inputStyle, marginTop: 10, height: 70, resize: 'vertical' }}/>
            <div style={{ display: 'flex', gap: 10, marginTop: 12, alignItems: 'center' }}>
              <button className="action-btn" onClick={createProfile}>PROFIL SAQLASH</button>
              <span style={{ color: '#4a6a84', fontSize: 12 }}>
                Credential tanlangan interface bilan ishlatiladi: {selectedInterface || '-'}
              </span>
            </div>
            {profileError && <div style={{ color: '#ff8fa0', fontSize: 12, marginTop: 10 }}>{profileError}</div>}
          </div>
        </Panel>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14 }}>
        <Panel title={`SAQLANGAN PROFILLAR | ${profiles.length}`} color="#ffab00">
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {profiles.map(profile => (
              <div key={profile.id} style={{ padding: 12, border: '1px solid var(--border2)', background: 'var(--panel2)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                  <div>
                    <div style={{ color: 'var(--text)', fontWeight: 700 }}>{profile.name}</div>
                    <div style={{ color: '#4a6a84', fontSize: 11, fontFamily: 'Share Tech Mono' }}>
                      {profile.profile_type.toUpperCase()} | {profile.target_host}:{profile.port}
                    </div>
                  </div>
                  <button className="action-btn" onClick={() => runProfileScan(profile)} disabled={profileBusyId === profile.id}>
                    {profileBusyId === profile.id ? 'SCAN...' : 'RUN SCAN'}
                  </button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 10, fontSize: 12 }}>
                  <div><span style={{ color: '#4a6a84' }}>User: </span>{profile.username || '-'}</div>
                  <div><span style={{ color: '#4a6a84' }}>Secret: </span>{profile.has_secret ? 'saved' : 'missing'}</div>
                  <div><span style={{ color: '#4a6a84' }}>Label: </span>{profile.network_label || '-'}</div>
                  <div><span style={{ color: '#4a6a84' }}>Last used: </span>{profile.last_used_at ? fmtTime(profile.last_used_at) : '-'}</div>
                </div>
              </div>
            ))}
            {profiles.length === 0 && <span style={{ color: '#4a6a84' }}>Hali connection profile yo&apos;q.</span>}
          </div>
        </Panel>

        <Panel title={`SCAN SESSIONS | ${sessions.length}`} color="#ff1744">
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {sessions.map(session => (
              <div key={session.id} style={{ padding: 12, border: '1px solid var(--border2)', background: 'var(--panel2)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                  <div>
                    <div style={{ color: 'var(--text)', fontWeight: 700 }}>{session.profile_name}</div>
                    <div style={{ color: '#4a6a84', fontSize: 11, fontFamily: 'Share Tech Mono' }}>
                      {session.profile_type?.toUpperCase()} | {session.target_host} | {session.status?.toUpperCase()}
                    </div>
                  </div>
                  <div style={{ color: session.status === 'success' ? '#39ff14' : session.status === 'failed' ? '#ff1744' : '#ffab00', fontFamily: 'Share Tech Mono', fontSize: 11 }}>
                    {session.network_name || session.interface_name || '-'}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <button className="action-btn" onClick={() => analyzeSession(session)}>
                    ANALYZE
                  </button>
                </div>
                <div style={{ fontSize: 12, color: '#94b4c8', marginTop: 8 }}>
                  {session.status === 'failed'
                    ? (session.error_message || session.summary || 'Natija kutilmoqda')
                    : (session.summary || session.error_message || 'Natija kutilmoqda')}
                </div>
                {session.result?.hostname && (
                  <div style={{ marginTop: 8, fontSize: 12 }}>
                    <span style={{ color: '#4a6a84' }}>Hostname: </span>{session.result.hostname}
                  </div>
                )}
                {session.result?.prompt && (
                  <div style={{ marginTop: 6, fontSize: 12 }}>
                    <span style={{ color: '#4a6a84' }}>Prompt: </span>{session.result.prompt}
                  </div>
                )}
                {session.result?.device_description && (
                  <div style={{
                    marginTop: 8,
                    padding: '10px 12px',
                    border: '1px solid var(--border2)',
                    background: 'rgba(0,229,255,.03)',
                    fontSize: 11,
                    color: '#7ab8d4',
                    fontFamily: 'Share Tech Mono',
                    whiteSpace: 'pre-wrap',
                    lineHeight: 1.6,
                    maxHeight: 180,
                    overflowY: 'auto',
                  }}>
                    {session.result.device_description}
                  </div>
                )}
                {session.result?.open_ports_detected?.length > 0 && (
                  <div style={{ marginTop: 6, fontSize: 12 }}>
                    <span style={{ color: '#4a6a84' }}>Portlar: </span>{session.result.open_ports_detected.join(', ')}
                  </div>
                )}
              </div>
            ))}
            {sessions.length === 0 && <span style={{ color: '#4a6a84' }}>Credentialed scan sessiyalari hali yo&apos;q.</span>}
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ── ANALYZE PAGE ───────────────────────────────────────────────────────────
function AnalyzePage({ initialIP, initialContext = '', initialThreat = '' }) {
  const [form, setForm]     = useState({ ip: initialIP || '', threat: initialThreat || '', algos: ['Random Forest', 'XGBoost'], ctx: initialContext || '' });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [quickIps, setQuickIps] = useState([]);

  useEffect(() => { if (initialIP) setForm(f => ({ ...f, ip: initialIP })); }, [initialIP]);
  useEffect(() => { if (initialContext) setForm(f => ({ ...f, ctx: initialContext })); }, [initialContext]);
  useEffect(() => { if (initialThreat) setForm(f => ({ ...f, threat: initialThreat })); }, [initialThreat]);

  useEffect(() => {
    let active = true;
    api.scanNetwork()
      .then(d => {
        if (!active) return;
        setQuickIps((d.devices || []).map(device => device.ip));
      })
      .catch(() => {
        if (!active) return;
        setQuickIps([]);
      });
    return () => { active = false; };
  }, []);

  const analyze = async () => {
    if (!form.ip || !form.threat) return;
    setLoading(true); setResult(null); setError('');
    try {
      const res = await api.analyzeThreat({ ip_address: form.ip, threat_type: form.threat, algorithms: form.algos, context: form.ctx });
      setResult(res);
    } catch (err) {
      setError(err?.message || 'Tahlilni bajarib bo\'lmadi');
    }
    setLoading(false);
  };

  const sevColor = sev => ({ critical: '#ff1744', high: '#fb923c', medium: '#ffab00', low: '#39ff14' }[sev] || '#00e5ff');

  return (
    <div style={{ animation: 'fadeUp .3s ease', display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, alignItems: 'start' }}>
      <Panel title="TAHLIL SHAKLI" color="#00e5ff">
        <div className="panel-body">
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 8, fontWeight: 700 }}>TEZKOR TANLASH:</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 14 }}>
            {quickIps.map(ip => (
              <span key={ip} onClick={() => setForm(f => ({ ...f, ip }))} style={{
                fontSize: 10, padding: '3px 8px', cursor: 'pointer', fontFamily: 'Share Tech Mono',
                border: `1px solid ${form.ip === ip ? 'var(--cyan)' : 'var(--border)'}`,
                color: form.ip === ip ? 'var(--cyan)' : 'var(--text-dim)',
                background: form.ip === ip ? 'rgba(0,229,255,.08)' : 'transparent',
                transition: 'all .15s',
              }}>{ip}</span>
            ))}
            {quickIps.length === 0 && (
              <span style={{ fontSize: 10, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>
                Tarmoq scan natijalari hali mavjud emas
              </span>
            )}
          </div>

          {[
            { label: 'IP MANZIL', key: 'ip', type: 'text', placeholder: '192.168.1.1' },
          ].map(f => (
            <div key={f.key} style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', display: 'block', marginBottom: 6, fontWeight: 700 }}>{f.label}</label>
              <input value={form[f.key]} onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))}
                placeholder={f.placeholder} style={{
                  width: '100%', background: 'rgba(0,229,255,.04)', border: '1px solid var(--border)',
                  color: 'var(--text)', padding: '9px 12px', fontFamily: 'Share Tech Mono', fontSize: 13, outline: 'none',
                }}/>
            </div>
          ))}

          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', display: 'block', marginBottom: 6, fontWeight: 700 }}>TAHDID TURI</label>
            <select value={form.threat} onChange={e => setForm(f => ({ ...f, threat: e.target.value }))} style={{
              width: '100%', background: 'rgba(0,229,255,.04)', border: '1px solid var(--border)',
              color: form.threat ? 'var(--text)' : '#4a6a84', padding: '9px 12px',
              fontFamily: 'Share Tech Mono', fontSize: 12, outline: 'none',
            }}>
              <option value="">- Tanlang -</option>
              {THREATS_LIST.map(t => <option key={t.v} value={t.v}>{t.l}</option>)}
            </select>
          </div>

          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', display: 'block', marginBottom: 6, fontWeight: 700 }}>ALGORITMLAR</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {ALGOS_LIST.map(a => (
                <span key={a} onClick={() => setForm(f => ({ ...f, algos: f.algos.includes(a) ? f.algos.filter(x => x !== a) : [...f.algos, a] }))} style={{
                  fontSize: 10, padding: '3px 9px', cursor: 'pointer', fontFamily: 'Share Tech Mono',
                  border: `1px solid ${form.algos.includes(a) ? 'var(--cyan)' : 'var(--border)'}`,
                  color: form.algos.includes(a) ? 'var(--cyan)' : 'var(--text-dim)',
                  background: form.algos.includes(a) ? 'rgba(0,229,255,.08)' : 'transparent',
                  transition: 'all .15s',
                }}>{a}</span>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', display: 'block', marginBottom: 6, fontWeight: 700 }}>KONTEKST</label>
            <textarea value={form.ctx} onChange={e => setForm(f => ({ ...f, ctx: e.target.value }))}
              placeholder="Qo'shimcha ma'lumot (ixtiyoriy)..." style={{
                width: '100%', height: 60, background: 'rgba(0,229,255,.04)', border: '1px solid var(--border)',
                color: 'var(--text)', padding: '9px 12px', fontFamily: 'Share Tech Mono', fontSize: 11,
                outline: 'none', resize: 'vertical',
              }}/>
            {form.ctx && (
              <div style={{ marginTop: 8, fontSize: 11, color: '#4a6a84' }}>
                Scan sessiyadan yoki qo&apos;lda yig&apos;ilgan ma&apos;lumot shu yerga tushadi va algoritmlar aynan shu kontekst bilan hisoblaydi.
              </div>
            )}
          </div>

          <button onClick={analyze} disabled={loading || !form.ip || !form.threat} style={{
            width: '100%', padding: 11, background: 'transparent',
            border: `1px solid ${!form.ip || !form.threat ? 'var(--border)' : 'var(--cyan)'}`,
            color: !form.ip || !form.threat ? 'var(--text-dim)' : 'var(--cyan)',
            fontFamily: 'Orbitron,monospace', fontSize: 12, letterSpacing: 2, cursor: 'pointer',
            opacity: !form.ip || !form.threat ? 0.4 : 1, transition: 'all .2s',
          }}>
            {loading ? 'TAHLIL QILINMOQDA...' : 'TAHLILNI BOSHLASH'}
          </button>
          {error && (
            <div style={{ marginTop: 12, color: '#ff8fa0', fontSize: 12 }}>
              {error}
            </div>
          )}
        </div>
      </Panel>

      <div>
        {loading && (
          <Panel title="TAHLIL QILINMOQDA..." color="#00e5ff">
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 60, gap: 16 }}>
              <div className="spinner"/>
              <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#4a6a84', letterSpacing: 2 }}>AI MODEL ISHLAMOQDA...</span>
            </div>
          </Panel>
        )}

        {result && !loading && (
          <Panel title="TAHLIL NATIJASI" color={sevColor(result.severity)}>
            <div className="panel-body">
              <div style={{
                background: `${sevColor(result.severity)}11`, border: `1px solid ${sevColor(result.severity)}44`,
                padding: 16, marginBottom: 16,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
                  <Badge sev={result.severity}/>
                  <span style={{ fontFamily: 'Orbitron,monospace', fontSize: 22, color: sevColor(result.severity), fontWeight: 700 }}>
                    {result.probability_pct}
                  </span>
                  <span style={{ color: 'var(--text)', fontSize: 15, fontWeight: 600 }}>{result.threat_name}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 13 }}>
                  <div><span style={{ color: '#4a6a84' }}>IP: </span><span style={{ fontFamily: 'Share Tech Mono', color: '#00e5ff' }}>{result.ip}</span></div>
                  <div><span style={{ color: '#4a6a84' }}>Qurilma: </span><span>{result.ip_info?.device_name}</span></div>
                  <div><span style={{ color: '#4a6a84' }}>Tarmoq: </span><span>{result.ip_info?.network_type}</span></div>
                  <div><span style={{ color: '#4a6a84' }}>Tur: </span><span style={{ fontFamily: 'Share Tech Mono', color: result.ip_info?.is_local ? '#39ff14' : '#ffab00' }}>
                    {result.ip_info?.is_local ? 'LOCAL' : 'PUBLIC'}
                  </span></div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
                <div>
                  <div className="panel-title" style={{ marginBottom: 10 }}>BELGILAR</div>
                  {result.indicators?.map((x, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                      <span style={{ color: '#00e5ff', fontFamily: 'Share Tech Mono', fontSize: 10, minWidth: 24 }}>[{String(i+1).padStart(2,'0')}]</span>
                      <span style={{ fontSize: 13, color: '#94b4c8' }}>{x}</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div className="panel-title" style={{ marginBottom: 10 }}>CHORALAR</div>
                  {result.mitigation?.map((x, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8, padding: '8px 10px', border: '1px solid var(--border2)', background: 'rgba(0,229,255,.02)' }}>
                      <span style={{ fontFamily: 'Orbitron,monospace', fontSize: 10, color: '#00e5ff', minWidth: 22 }}>{String(i+1).padStart(2,'0')}</span>
                      <span style={{ fontSize: 12, color: '#94b4c8' }}>{x}</span>
                    </div>
                  ))}
                </div>
              </div>

              {result.algorithm_scores && (
                <div>
                  <div className="panel-title" style={{ marginBottom: 10 }}>ALGORITM BALLARI</div>
                  {Object.entries(result.algorithm_scores).map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
                      <span style={{ minWidth: 130, fontSize: 13, color: '#94b4c8' }}>{k}</span>
                      <div style={{ flex: 1, height: 4, background: 'var(--border2)' }}>
                        <div style={{ width: `${Math.round(v * 100)}%`, height: '100%', background: 'linear-gradient(90deg,var(--cyan2),var(--cyan))' }}/>
                      </div>
                      <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#00e5ff', minWidth: 40 }}>{Math.round(v * 100)}%</span>
                    </div>
                  ))}
                </div>
              )}

              {result.recommendation && (
                <div style={{ marginTop: 14, padding: 12, background: 'rgba(168,85,247,.06)', border: '1px solid rgba(168,85,247,.25)' }}>
                  <div style={{ fontSize: 10, letterSpacing: 2, color: '#a855f7', fontWeight: 700, marginBottom: 6 }}>AI TAVSIYA</div>
                  <div style={{ fontSize: 13, color: '#94b4c8' }}>{result.recommendation}</div>
                </div>
              )}
            </div>
          </Panel>
        )}

        {!result && !loading && (
          <Panel title="TAHLIL KUTILMOQDA" color="#4a6a84">
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 80, gap: 16 }}>
              <span style={{ fontSize: 64, opacity: .15 }}>[ ]</span>
              <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#4a6a84', letterSpacing: 2, textAlign: 'center' }}>
                CHAP TARAFDAN IP MANZIL VA TAHDID TURINI TANLANG
              </span>
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}

// ── LOGS PAGE ──────────────────────────────────────────────────────────────
function LogsPage() {
  const [logs, setLogs]     = useState([]);
  const [paused, setPaused] = useState(false);
  const logRef = useRef();

  useEffect(() => {
    const fetchLogs = async () => {
      if (paused) return;
      try {
        const d = await api.getLiveLogs();
        setLogs(d.logs || []);
      } catch {
        setLogs([]);
      }
    };
    fetchLogs();
    const id = setInterval(fetchLogs, 1800);
    return () => clearInterval(id);
  }, [paused]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = 0;
  }, [logs.length]);

  const lvlColor = lvl => ({ error: '#ff1744', warn: '#ffab00', info: '#39ff14' }[lvl] || '#00e5ff');

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <Panel title="REAL VAQT LOG OQIMI" color="#39ff14"
        extra={
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <button className="action-btn" onClick={() => setPaused(p => !p)}
              style={{ color: paused ? '#ffab00' : 'var(--text-dim)', borderColor: paused ? 'rgba(255,171,0,.5)' : 'var(--border)' }}>
              {paused ? 'DAVOM' : 'PAUZA'}
            </button>
            <button className="action-btn" onClick={() => setLogs([])}>TOZALASH</button>
          </div>
        }>
        <div ref={logRef} style={{
          fontFamily: 'Share Tech Mono', fontSize: 12,
          background: 'rgba(0,3,10,.9)', padding: '12px 16px',
          height: 520, overflowY: 'auto', lineHeight: 1.9,
          scrollbarWidth: 'thin', scrollbarColor: 'var(--border2) transparent',
        }}>
          {logs.map((l, i) => (
            <div key={l.id || i} style={{ marginBottom: 1, borderBottom: '1px solid rgba(26,58,92,.2)', paddingBottom: 1 }}>
              <span style={{ color: '#1a3a5c' }}>{fmtTime(l.timestamp)} </span>
              <span style={{ color: lvlColor(l.level) }}>[{(l.level || 'info').toUpperCase().padEnd(5, ' ')}] </span>
              {l.ip && <span style={{ color: '#00b4cc' }}>{l.ip} </span>}
              <span style={{ color: l.level === 'error' ? '#ff8fa0' : l.level === 'warn' ? '#ffd066' : '#a0d8a0' }}>{l.message}</span>
            </div>
          ))}
          {logs.length === 0 && <span style={{ color: '#1a3a5c' }}>Haqiqiy threat loglari hali yo'q...</span>}
        </div>
      </Panel>
    </div>
  );
}

// ── INSIGHTS PAGE ──────────────────────────────────────────────────────────
function InsightsPage({ initialTab = 'threats' }) {
  const [selThreat, setSelThreat] = useState(THREAT_LIBRARY[0]);
  const [selAlgo,   setSelAlgo]   = useState(ALGO_LIBRARY[0]);
  const [selSiem,   setSelSiem]   = useState(SIEM_TOOLS[0]);
  const [tab, setTab] = useState(initialTab);

  const sevColor = sev => ({ critical:'#ff1744', high:'#fb923c', medium:'#ffab00', low:'#39ff14' }[sev] || '#39ff14');
  const algoColor = t => ({ Supervised:'#00e5ff', Unsupervised:'#ffab00', 'Deep Learning':'#a855f7' }[t] || '#00e5ff');

  useEffect(() => {
    setTab(initialTab);
  }, [initialTab]);

  const tabs = [
    { id:'threats',   label:'Tahdid Turlari' },
    { id:'algorithms',label:'Algoritmlar'    },
    { id:'datasets',  label:'Datasetlar'     },
    { id:'siem',      label:'SIEM Tizimlar'  },
  ];

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <div className="filter-bar" style={{ marginBottom: 14 }}>
        {tabs.map(t => (
          <button key={t.id} className={`filter-btn${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'threats' && (
        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 14 }}>
          <Panel title="TAHDID TURLARI" color="#ff1744">
            <div style={{ padding: '6px 0' }}>
              {THREAT_LIBRARY.map(t => (
                <div key={t.key} onClick={() => setSelThreat(t)} style={{
                  display: 'flex', alignItems: 'center', gap: 10, padding: '10px 16px', cursor: 'pointer',
                  borderLeft: `2px solid ${selThreat?.key === t.key ? sevColor(t.sev) : 'transparent'}`,
                  background: selThreat?.key === t.key ? `${sevColor(t.sev)}0d` : 'transparent',
                  transition: 'all .15s',
                }}>
                  <StatusDot color={sevColor(t.sev)} size={6} pulse={t.sev === 'critical'}/>
                  <span style={{ fontSize: 13, flex: 1, color: selThreat?.key === t.key ? 'var(--text)' : 'var(--text-dim)', fontWeight: selThreat?.key === t.key ? 600 : 400 }}>
                    {t.name}
                  </span>
                  <span style={{ fontSize: 9, fontFamily: 'Share Tech Mono', color: sevColor(t.sev), padding: '1px 5px', border: `1px solid ${sevColor(t.sev)}44` }}>
                    {t.sev.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>
          </Panel>
          <Panel title={selThreat?.name?.toUpperCase() || ''} color={sevColor(selThreat?.sev)}>
            <div className="panel-body">
              <div style={{ background: `${sevColor(selThreat?.sev)}0d`, border: `1px solid ${sevColor(selThreat?.sev)}33`, padding: 16, marginBottom: 16 }}>
                <p style={{ fontSize: 14, color: 'var(--text)', lineHeight: 1.7 }}>{selThreat?.desc}</p>
              </div>
              <div style={{ marginBottom: 16 }}>
                <div className="panel-title" style={{ marginBottom: 8 }}>ALOMATLAR</div>
                <p style={{ fontSize: 13, color: '#94b4c8', lineHeight: 1.7 }}>{selThreat?.signs}</p>
              </div>
              <div>
                <div className="panel-title" style={{ marginBottom: 8 }}>AI YONDASHUVI</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {selThreat?.algo?.split(', ').map(a => (
                    <span key={a} style={{ padding: '4px 12px', border: '1px solid rgba(0,229,255,.3)', color: 'var(--cyan)', fontFamily: 'Share Tech Mono', fontSize: 11, background: 'rgba(0,229,255,.05)' }}>{a}</span>
                  ))}
                </div>
              </div>
            </div>
          </Panel>
        </div>
      )}

      {tab === 'algorithms' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 14 }}>
          <Panel title="ML ALGORITMLAR" color="#a855f7">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, padding: 14 }}>
              {ALGO_LIBRARY.map(a => (
                <div key={a.key} onClick={() => setSelAlgo(a)} style={{
                  border: `1px solid ${selAlgo?.key === a.key ? algoColor(a.type) : 'var(--border2)'}`,
                  padding: 12, cursor: 'pointer',
                  background: selAlgo?.key === a.key ? `${algoColor(a.type)}11` : 'transparent',
                  transition: 'all .15s',
                }}>
                  <div style={{ fontSize: 9, padding: '1px 6px', border: `1px solid ${algoColor(a.type)}44`, color: algoColor(a.type), display: 'inline-block', marginBottom: 6, fontFamily: 'Share Tech Mono' }}>
                    {a.type.toUpperCase()}
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', marginBottom: 2 }}>{a.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-dim)', fontFamily: 'Share Tech Mono' }}>{a.sub} · {a.acc}%</div>
                  <div style={{ marginTop: 8, height: 3, background: 'var(--border2)' }}>
                    <div style={{ width: `${a.acc}%`, height: '100%', background: algoColor(a.type) }}/>
                  </div>
                </div>
              ))}
            </div>
          </Panel>
          <Panel title="TAFSILOTLAR" color={algoColor(selAlgo?.type)}>
            <div className="panel-body">
              <div style={{ fontFamily: 'Orbitron,monospace', fontSize: 16, fontWeight: 700, color: algoColor(selAlgo?.type), marginBottom: 4 }}>{selAlgo?.name}</div>
              <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: 'var(--text-dim)', marginBottom: 14 }}>{selAlgo?.type} · {selAlgo?.sub}</div>
              <p style={{ fontSize: 13, color: '#94b4c8', lineHeight: 1.7, marginBottom: 16 }}>{selAlgo?.desc}</p>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '14px 0', borderTop: '1px solid var(--border2)' }}>
                <span style={{ color: 'var(--text-dim)', fontSize: 13 }}>Aniqlik</span>
                <span style={{ fontFamily: 'Orbitron,monospace', fontSize: 20, color: algoColor(selAlgo?.type) }}>{selAlgo?.acc}%</span>
              </div>
            </div>
          </Panel>
        </div>
      )}

      {tab === 'datasets' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
          {DATASETS.map(d => (
            <Panel key={d.name} title={d.name} color="#ffab00">
              <div className="panel-body">
                <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 10 }}>
                  <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#ffab00', padding: '2px 10px', border: '1px solid rgba(255,171,0,.4)', background: 'rgba(255,171,0,.08)' }}>
                    {d.records} yozuv
                  </span>
                </div>
                <p style={{ fontSize: 13, color: '#94b4c8', lineHeight: 1.7, marginBottom: 14 }}>{d.desc}</p>
                <div style={{ height: 4, background: 'var(--border2)' }}>
                  <div style={{ width: `${d.pct}%`, height: '100%', background: 'linear-gradient(90deg,#ffab00,#ff1744)', boxShadow: '0 0 6px rgba(255,171,0,.4)' }}/>
                </div>
              </div>
            </Panel>
          ))}
        </div>
      )}

      {tab === 'siem' && (
        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 14 }}>
          <Panel title="SIEM TIZIMLAR" color="#00e5ff">
            <div style={{ padding: '6px 0' }}>
              {SIEM_TOOLS.map(s => (
                <div key={s.key} onClick={() => setSelSiem(s)} style={{
                  padding: '12px 16px', cursor: 'pointer',
                  borderLeft: `2px solid ${selSiem?.key === s.key ? 'var(--cyan)' : 'transparent'}`,
                  background: selSiem?.key === s.key ? 'rgba(0,229,255,.08)' : 'transparent',
                  transition: 'all .15s',
                }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: selSiem?.key === s.key ? 'var(--cyan)' : 'var(--text)', marginBottom: 2 }}>{s.name}</div>
                  <div style={{ fontSize: 10, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>{s.sub}</div>
                </div>
              ))}
            </div>
          </Panel>
          <Panel title={selSiem?.name?.toUpperCase() || ''} color="#00e5ff">
            <div className="panel-body">
              <p style={{ fontSize: 14, color: '#94b4c8', lineHeight: 1.8 }}>{selSiem?.detail}</p>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}

function SIEMPage() {
  const [selected, setSelected] = useState(SIEM_TOOLS[0]);

  return (
    <div style={{ animation: 'fadeUp .3s ease', display: 'grid', gap: 14 }}>
      <Panel title="SIEM TIZIMLAR INTEGRATSIYASI" color="#00e5ff">
        <div className="panel-body">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10, marginBottom: 10 }}>
            {SIEM_TOOLS.map(tool => {
              const active = selected.key === tool.key;
              return (
                <div
                  key={tool.key}
                  onClick={() => setSelected(tool)}
                  style={{
                    padding: 14,
                    border: `1px solid ${active ? 'rgba(159,194,234,.85)' : 'var(--border2)'}`,
                    background: active ? 'rgba(159,194,234,.14)' : 'rgba(13,27,46,.55)',
                    cursor: 'pointer',
                    transition: 'all .18s',
                    minHeight: 86,
                  }}
                >
                  <div style={{ fontSize: 18, fontWeight: 700, color: active ? '#d9e9fb' : 'var(--text)' }}>{tool.name}</div>
                  <div style={{ fontSize: 11, color: '#8eb6db', marginTop: 4, fontFamily: 'Share Tech Mono' }}>{tool.sub}</div>
                  <div style={{ fontSize: 11, color: '#4a6a84', marginTop: 10 }}>{tool.vendor}</div>
                </div>
              );
            })}
          </div>
          <div style={{ padding: 18, border: '1px solid var(--border2)', background: 'rgba(13,27,46,.48)' }}>
            <div style={{ fontSize: 24, fontWeight: 700, marginBottom: 6 }}>{selected.name}</div>
            <div style={{ fontSize: 12, color: '#7ab8d4', fontFamily: 'Share Tech Mono', marginBottom: 14 }}>{selected.best}</div>
            <div style={{ fontSize: 14, color: '#a5c2d8', lineHeight: 1.8 }}>{selected.detail}</div>
          </div>
        </div>
      </Panel>

      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr .8fr', gap: 14 }}>
        <Panel title="SIEM QOBILIYATLARI" color="#9fc2ea">
          <div className="panel-body">
            {SIEM_CAPABILITY_ROWS.map(row => (
              <div key={row.key} style={{ marginBottom: 18 }}>
                <div style={{ marginBottom: 8, color: 'var(--text)', fontSize: 13, fontWeight: 700 }}>{row.label}</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(0, 1fr))', gap: 6 }}>
                  {SIEM_TOOLS.map(tool => (
                    <div key={`${row.key}-${tool.key}`} style={{ background: 'rgba(13,27,46,.55)', border: '1px solid var(--border2)', padding: 6 }}>
                      <div style={{ height: 42, background: 'rgba(255,255,255,.04)', position: 'relative', overflow: 'hidden' }}>
                        <div style={{
                          position: 'absolute',
                          left: 0,
                          right: 0,
                          bottom: 0,
                          height: `${tool.scores[row.key]}%`,
                          background: `linear-gradient(180deg, ${row.color}, rgba(159,194,234,.75))`,
                        }}/>
                      </div>
                      <div style={{ marginTop: 6, fontSize: 10, color: '#7b9dbd', textAlign: 'center', fontFamily: 'Share Tech Mono' }}>{tool.name.split(' ')[0]}</div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="LOYIHA MOSLIGI" color="#39ff14">
          <div className="panel-body" style={{ display: 'grid', gap: 10 }}>
            {[
              ['Katta korxona', 'Splunk / QRadar'],
              ['Azure infra', 'MS Sentinel'],
              ['Ochiq kod', 'ELK / Wazuh'],
              ['Yengil SOC', 'Graylog'],
            ].map(([k, v]) => (
              <div key={k} style={{ padding: 12, border: '1px solid var(--border2)', background: 'rgba(13,27,46,.5)' }}>
                <div style={{ fontSize: 11, color: '#4a6a84', marginBottom: 4 }}>{k}</div>
                <div style={{ fontSize: 14, color: 'var(--text)', fontWeight: 700 }}>{v}</div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}

function TopologyPage() {
  const [scenarioKey, setScenarioKey] = useState('normal');
  const scenario = TOPOLOGY_SCENARIOS[scenarioKey];
  const nodeMap = Object.fromEntries(TOPOLOGY_NODES.map(node => [node.key, node]));
  const stateStyle = state => ({
    ok: { color:'#6bd214', width:2.2 },
    warn: { color:'#e1c246', width:2.2 },
    attack: { color:'#ff6b57', width:2.6 },
    blocked: { color:'#9fc2ea', width:2.6 },
    monitor: { color:'#8a7cf5', width:1.8 },
    idle: { color:'#627790', width:1.4 },
  }[state] || { color:'#627790', width:1.4 });
  const nodeTone = tone => ({
    hostile: { border:'rgba(255,107,87,.55)', bg:'rgba(255,107,87,.12)', color:'#ffd5cf' },
    core: { border:'rgba(107,210,20,.55)', bg:'rgba(107,210,20,.12)', color:'#def8cf' },
    service: { border:'rgba(159,194,234,.6)', bg:'rgba(159,194,234,.11)', color:'#d9e9fb' },
    internal: { border:'rgba(189,232,153,.5)', bg:'rgba(189,232,153,.12)', color:'#ebf8dc' },
    observer: { border:'rgba(138,124,245,.65)', bg:'rgba(138,124,245,.14)', color:'#e3dcff' },
  }[tone]);

  return (
    <div style={{ animation: 'fadeUp .3s ease', display: 'grid', gap: 14 }}>
      <Panel title="TARMOQ TOPOLOGIYASI" color="#39ff14">
        <div className="panel-body">
          <div style={{ position: 'relative', minHeight: 380, border: '1px solid var(--border2)', background: 'radial-gradient(circle at top, rgba(13,27,46,.7), rgba(3,7,18,.95))', overflow: 'hidden' }}>
            <svg viewBox="0 0 100 100" style={{ position:'absolute', inset:0, width:'100%', height:'100%' }}>
              {TOPOLOGY_EDGES.map(edge => {
                const from = nodeMap[edge.from];
                const to = nodeMap[edge.to];
                const style = stateStyle(scenario.linkStates[edge.key]);
                return (
                  <line
                    key={edge.key}
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    stroke={style.color}
                    strokeWidth={style.width}
                    strokeDasharray={edge.dashed ? '3 2' : undefined}
                    opacity={0.95}
                  />
                );
              })}
            </svg>
            {TOPOLOGY_NODES.map(node => {
              const tone = nodeTone(node.tone);
              return (
                <div key={node.key} style={{
                  position:'absolute',
                  left:`calc(${node.x}% - 48px)`,
                  top:`calc(${node.y}% - 22px)`,
                  width:96,
                  minHeight:44,
                  padding:'10px 8px',
                  border:`1px solid ${tone.border}`,
                  background:tone.bg,
                  color:tone.color,
                  textAlign:'center',
                  fontSize:12,
                  lineHeight:1.35,
                  boxShadow:`0 0 20px ${tone.bg}`,
                  whiteSpace:'pre-line',
                }}>
                  {node.label}
                </div>
              );
            })}
          </div>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginTop: 14 }}>
            {Object.entries(TOPOLOGY_SCENARIOS).map(([key, item]) => (
              <button key={key} className={`filter-btn${scenarioKey === key ? ' active' : ''}`} onClick={() => setScenarioKey(key)}>
                {item.label}
              </button>
            ))}
          </div>
          <div style={{ marginTop: 12, padding: 14, border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)', color:'#a5c2d8', fontSize:13, lineHeight:1.8 }}>
            {scenario.summary}
          </div>
        </div>
      </Panel>
    </div>
  );
}

// ── SETTINGS PAGE ──────────────────────────────────────────────────────────
function SettingsPage() {
  const [toggles, setToggles] = useState({ realtime:true, sound:false, email:true, autoBlock:true, twofa:true });
  const toggle = k => setToggles(p => ({ ...p, [k]: !p[k] }));

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <div className="settings-grid">
        <Panel title="BILDIRISHNOMALAR" color="#00e5ff">
          <div className="panel-body">
            <div className="settings-section">ALERT KANALLARI</div>
            {[['realtime','Real-time Push Alertlar'],['sound','Audio Signallar'],['email','Email Bildirishnoma']].map(([k, l]) => (
              <div className="toggle-row" key={k}>
                <span style={{ fontSize: 13 }}>{l}</span>
                <div className={`toggle${toggles[k] ? ' on' : ''}`} onClick={() => toggle(k)}/>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="XAVFSIZLIK SOZLAMALARI" color="#a855f7">
          <div className="panel-body">
            <div className="settings-section">AVTOMATLASHTIRISH</div>
            {[['autoBlock','Kritik Tahdidlarni Avtomatik Bloklash'],['twofa','2FA Majburiy (Barcha Operatorlar)']].map(([k, l]) => (
              <div className="toggle-row" key={k}>
                <span style={{ fontSize: 13 }}>{l}</span>
                <div className={`toggle${toggles[k] ? ' on' : ''}`} onClick={() => toggle(k)}/>
              </div>
            ))}
            <div style={{ height: 14 }}/>
            <div className="settings-section">AI SEZGIRLIK</div>
            {['Aniqlash Chegarasi','Ogohlantirish Tezligi','Eskalatsiya Kechikishi'].map(label => (
              <div className="slider-row" key={label}>
                <label>{label.toUpperCase()}</label>
                <input type="range" min={1} max={10} defaultValue={r(4, 8)} style={{ accentColor: 'var(--cyan)', width: '100%' }}/>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="TIZIM MA'LUMOTLARI" color="#39ff14">
          <div className="panel-body">
            {[
              ['Platforma','CyberGuard AI v4.2.1'],
              ['AI Dvigatel','Neural Threat Engine v2.3'],
              ['Model Yangilash','20-Apr-2026 · 02:14 UTC'],
              ['Faol Sensorlar','1,247 endpoint'],
              ['Log Saqlash','90 kun'],
              ['Shifrlash','AES-256 · TLS 1.3'],
              ['Backend','Django DRF · SQLite'],
              ['Frontend','React 18 · Vite'],
            ].map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid var(--border2)', fontSize: 13 }}>
                <span style={{ color: '#4a6a84' }}>{k}</span>
                <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#7ab8d4' }}>{v}</span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="API INTEGRATSIYALAR" color="#ffab00">
          <div className="panel-body">
            {[
              { name:'Django Backend',           status:'ULANGAN',     ok:true  },
              { name:'Tahdid Loglari API',        status:'FAOL',        ok:true  },
              { name:'Tarmoq Skan API',           status:'FAOL',        ok:true  },
              { name:'AbuseIPDB',                status:'SOZLANMAGAN', ok:false },
              { name:'SIEM Integratsiya',         status:'KUTILMOQDA',  ok:false },
              { name:'Live Log Stream',           status:'FAOL',        ok:true  },
            ].map(item => (
              <div key={item.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '9px 0', borderBottom: '1px solid var(--border2)' }}>
                <span style={{ fontSize: 13 }}>{item.name}</span>
                <span style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: item.ok ? '#39ff14' : '#ffab00', display: 'flex', alignItems: 'center', gap: 5 }}>
                  <StatusDot color={item.ok ? '#39ff14' : '#ffab00'} size={5}/>{item.status}
                </span>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ── HELPERS ────────────────────────────────────────────────────────────────
function demoThreats() {
  return [
    { id:1, ip_address:'192.168.1.201', threat_type:'SQL Injection', severity:'critical', probability:0.97, is_blocked:false, device_name:'Noma\'lum qurilma', algorithm:'Random Forest' },
    { id:2, ip_address:'192.168.1.200', threat_type:'Brute Force',   severity:'high',     probability:0.88, is_blocked:true,  device_name:'Shubhali qurilma',  algorithm:'XGBoost'       },
    { id:3, ip_address:'10.0.0.10',     threat_type:'Port Scan',     severity:'medium',   probability:0.73, is_blocked:false, device_name:'Web Server',        algorithm:'Isolation Forest' },
    { id:4, ip_address:'172.16.0.50',   threat_type:'DDoS',          severity:'high',     probability:0.85, is_blocked:false, device_name:'Test Server',       algorithm:'LSTM'          },
  ];
}

function demoDevices() {
  return [
    { ip:'192.168.1.1',   name:'Router/Gateway',   risk:'low',      network_type:'LAN', status:'online',  open_ports:[22,80,443]            },
    { ip:'192.168.1.100', name:'Admin PC',          risk:'low',      network_type:'LAN', status:'online',  open_ports:[22,3389]              },
    { ip:'192.168.1.200', name:'Shubhali qurilma',  risk:'high',     network_type:'LAN', status:'online',  open_ports:[22,80,8080,3389,445]  },
    { ip:'192.168.1.201', name:'Noma\'lum qurilma', risk:'critical', network_type:'LAN', status:'online',  open_ports:[21,23,3306,1433]      },
    { ip:'10.0.0.10',     name:'Web Server',        risk:'medium',   network_type:'LAN', status:'online',  open_ports:[80,443,8080]          },
    { ip:'10.0.0.20',     name:'Database Server',   risk:'medium',   network_type:'LAN', status:'online',  open_ports:[3306,5432]            },
    { ip:'172.16.0.1',    name:'VPN Gateway',       risk:'low',      network_type:'VPN', status:'online',  open_ports:[1194,443]             },
    { ip:'172.16.0.50',   name:'Test Server',       risk:'medium',   network_type:'VPN', status:'offline', open_ports:[22,80]                },
  ];
}

// ── ROOT APP ───────────────────────────────────────────────────────────────
export default function App() {
  const [loggedIn, setLoggedIn] = useState(() => !!localStorage.getItem('cg_auth'));
  const [page, setPage]         = useState(() => {
    const stored = localStorage.getItem('cg_page') || 'dashboard';
    return stored === 'insights' ? 'threat_library' : stored;
  });
  const [analyzeIP, setAnalyzeIP] = useState('');
  const [analyzeContext, setAnalyzeContext] = useState('');
  const [analyzeThreat, setAnalyzeThreat] = useState('');
  const [alertCount, setAlertCount] = useState(0);
  const time = useClock();

  useEffect(() => {
    if (!loggedIn) return undefined;

    const loadAlerts = async () => {
      try {
        const d = await api.getThreats();
        const items = d.results || d || [];
        setAlertCount(items.filter(item => !item.is_blocked).length);
      } catch {
        setAlertCount(0);
      }
    };

    loadAlerts();
    const id = setInterval(loadAlerts, 8000);
    return () => clearInterval(id);
  }, [loggedIn]);

  const navTo = p => { setPage(p); localStorage.setItem('cg_page', p); };
  const handleLogin = () => { localStorage.setItem('cg_auth', '1'); setLoggedIn(true); };

  const handleNetworkAnalyze = (ip, options = {}) => {
    setAnalyzeIP(ip);
    setAnalyzeContext(options.context || '');
    setAnalyzeThreat(options.threat || '');
    navTo('analyze');
  };

  if (!loggedIn) return <LoginPage onLogin={handleLogin}/>;

  return (
    <div className="app">
      <Sidebar page={page} setPage={navTo} alertCount={alertCount}/>
      <div className="main">
        <TopBar page={page} time={time}/>
        <div className="content">
          {page === 'dashboard' && <DashboardPage/>}
          {page === 'threats'   && <ThreatsPage/>}
          {page === 'network'   && <NetworkPage onAnalyze={handleNetworkAnalyze}/>}
          {page === 'analyze'   && <AnalyzePage initialIP={analyzeIP} initialContext={analyzeContext} initialThreat={analyzeThreat}/>}
          {page === 'threat_library' && <InsightsPage initialTab="threats"/>}
          {page === 'algorithms' && <InsightsPage initialTab="algorithms"/>}
          {page === 'datasets' && <InsightsPage initialTab="datasets"/>}
          {page === 'siem' && <SIEMPage/>}
          {page === 'topology' && <TopologyPage/>}
          {page === 'logs'      && <LogsPage/>}
          {page === 'insights'  && <InsightsPage initialTab="threats"/>}
          {page === 'settings'  && <SettingsPage/>}
        </div>
        <div className="ticker-wrap">
          <div className="ticker-inner">
            {[...LIVE_TICKER_ITEMS, ...LIVE_TICKER_ITEMS].map((t, i) => (
              <span key={i} className="ticker-item">{t}<span className="ticker-sep"> ·· </span></span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}




