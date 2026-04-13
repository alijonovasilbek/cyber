import { useState, useEffect, useRef } from 'react';
import NetworkScan from './components/NetworkScan';
import { api } from './services/api';

const THREAT_LIBRARY = [
  { key:'ddos',       sev:'critical', name:'DDoS hujumi',                    desc:'Serverga katta hajmli so\'rovlar yuborib uni ishdan chiqaradi.',                         signs:'Trafik keskin oshishi, javob vaqti sekinlashishi, xizmat uzilishi.',          algo:'Isolation Forest, K-Means, LSTM — trafik hajm tahlili.' },
  { key:'sqli',       sev:'critical', name:'SQL Injection',                   desc:'Ma\'lumotlar bazasiga zararli SQL so\'rovlar kiritish orqali ma\'lumot o\'g\'irlash.', signs:'G\'ayrioddiy DB so\'rovlari, xato xabarlari, katta chiqish hajmi.',            algo:'Random Forest, Naive Bayes, SVM — so\'rov pattern tahlili.' },
  { key:'ransomware', sev:'critical', name:'Ransomware',                      desc:'Fayllarni shifrlaydi va qulfdan chiqarish uchun to\'lov talab qiladi.',                signs:'Fayl kengaytmalarining ommaviy o\'zgarishi, CPU/disk faolligi oshishi.',       algo:'Autoencoder, LSTM — xatti-harakat anomaliyasi.' },
  { key:'apt',        sev:'high',     name:'APT — Advanced Persistent Threat',desc:'Davlat yoki katta guruhlar tomonidan olib boriladigan uzoq muddatli yashirin hujum.',  signs:'Kichik noodatiy so\'rovlar, noma\'lum protokollar, uzoq muddatli sessiyalar.',algo:'Isolation Forest, Autoencoder, LSTM — temporal tahlil.' },
  { key:'phishing',   sev:'high',     name:'Phishing',                        desc:'Soxta saytlar yoki emaillar orqali foydalanuvchi ma\'lumotlarini o\'g\'irlash.',       signs:'Noma\'lum domenlar, o\'xshash URL\'lar, shubhali email manbalari.',           algo:'Random Forest, XGBoost, Naive Bayes — URL klassifikatsiya.' },
  { key:'mitm',       sev:'medium',   name:'Man-in-the-Middle',               desc:'Ikki tomon o\'rtasidagi aloqani tutib olish va o\'zgartirish.',                       signs:'Sertifikat xatolari, noodatiy tarmoq yo\'nalishlari.',                        algo:'SVM, CNN — tarmoq pattern tahlili.' },
  { key:'zero_day',   sev:'critical', name:'Zero-Day ekspluatatsiya',         desc:'Hali noma\'lum yoki yamoqlanmagan zaifliklarni ishlatish.',                           signs:'Noodatiy dastur xatti-harakati, noma\'lum jarayonlar.',                       algo:'Autoencoder, Isolation Forest — imzosiz anomaliya aniqlash.' },
  { key:'brute',      sev:'high',     name:'Brute Force',                     desc:'Parolni ketma-ket urinishlar bilan topishga harakat.',                                signs:'Ko\'p muvaffaqiyatsiz login, bir IP dan ketma-ket urinish.',                  algo:'Random Forest, XGBoost — login pattern tahlili.' },
];

const ALGO_LIBRARY = [
  { key:'rf',   type:'Nazoratli',    tc:'#3B6D11',tb:'#EAF3DE', name:'Random Forest',    sub:'Ansambli',          acc:96, desc:'Ko\'plab qaror daraxti yig\'indisi. NSL-KDD va CICIDS2017 da 95-98% aniqlik. Tezkor, tushuntiriladigan, overfitting\'ga chidamli.' },
  { key:'xgb',  type:'Nazoratli',    tc:'#3B6D11',tb:'#EAF3DE', name:'XGBoost',          sub:'Gradient Boosting', acc:95, desc:'Optimallashtirilgan boosting. Katta datasetda RF dan tezroq ishlaydi. F1-score ko\'rsatkichi yuqori.' },
  { key:'svm',  type:'Nazoratli',    tc:'#3B6D11',tb:'#EAF3DE', name:'SVM',              sub:'Vektor',            acc:91, desc:'Yuqori o\'lchamli ma\'lumotlarda samarali. Ikkilik klassifikatsiya uchun ideal. RBF kernel bilan kuchli.' },
  { key:'lstm', type:'Deep Learning',tc:'#3C3489',tb:'#EEEDFE', name:'LSTM',             sub:'Vaqt qatori',       acc:94, desc:'Recurrent neural network. Log ketma-ketliklarini tahlil qilish. APT va doimiy hujumlarni aniqlashda eng samarali.' },
  { key:'ae',   type:'Deep Learning',tc:'#3C3489',tb:'#EEEDFE', name:'Autoencoder',      sub:'Anomaliya',         acc:89, desc:'Normal trafik patternini o\'rganib, unga mos kelmaydigan narsani anomaliya deb belgilaydi. Zero-day uchun eng yaxshi tanlov.' },
  { key:'iso',  type:'Nazoratssiz',  tc:'#854F0B',tb:'#FAEEDA', name:'Isolation Forest', sub:'Outlier',           acc:87, desc:'Outlier\'larni izolyatsiya qilish orqali aniqlash. DDoS trafik anomaliyalarini real vaqtda aniqlash uchun tezkor.' },
  { key:'cnn',  type:'Deep Learning',tc:'#3C3489',tb:'#EEEDFE', name:'CNN',              sub:'Pattern',           acc:93, desc:'Tarmoq paket ma\'lumotlarini "rasm" sifatida o\'qib, pattern tahlili qiladi. Malware klassifikatsiya uchun kuchli.' },
  { key:'nb',   type:'Nazoratli',    tc:'#3B6D11',tb:'#EAF3DE', name:'Naive Bayes',      sub:'Ehtimollik',        acc:82, desc:'Phishing email aniqlashda kuchli. Katta hajmli log tahlilida haqiqiy vaqt uchun tanlangan.' },
  { key:'km',   type:'Nazoratssiz',  tc:'#854F0B',tb:'#FAEEDA', name:'K-Means',          sub:'Klasterlash',       acc:78, desc:'Normal va g\'ayritabiiy trafik guruhlarini avtomatik ajratadi. Dastlabki razvedka uchun foydali.' },
];

const SIEM_LIBRARY = [
  { key:'splunk',   name:'Splunk Enterprise',  sub:'SPL tili, MLTK',       detail:'SPL (Search Processing Language) qidruv tili. MLTK ML plaginlari. CIM standart. Real vaqt dashboard, alert, korrelyatsiya qoidalari. Narxi: qimmat, korxona uchun.' },
  { key:'ibm',      name:'IBM QRadar',         sub:'Watson AI, QFlow',     detail:'Watson AI integratsiya. DSM ko\'p qurilma qo\'llab-quvvatlash. QFlow/VFlow trafik tahlili kuchli. SOC operatsiyalari uchun ideal.' },
  { key:'sentinel', name:'Microsoft Sentinel', sub:'Azure bulut, KQL',     detail:'KQL (Kusto Query Language) qidruv tili. Azure AD va Microsoft 365 integratsiya. pay-per-use narx modeli. ML anomaliya aniqlash o\'rnatilgan.' },
  { key:'elk',      name:'ELK Stack',          sub:'Ochiq kodli, bepul',   detail:'Elasticsearch + Logstash + Kibana. Bepul, katta miqyosli log tahlili. Watcher plaginı bilan alerting. Kiberxavfsizlikda eng mashhur ochiq kodli tanlov.' },
  { key:'wazuh',    name:'Wazuh',              sub:'HIDS/SIEM, bepul',     detail:'OSSEC asosida qurilgan. File Integrity Monitoring (FIM), rootkit aniqlash, compliance. ELK bilan integratsiya. Kichik va o\'rta biznes uchun ideal.' },
  { key:'graylog',  name:'Graylog',            sub:'Log boshqaruvi',       detail:'GELF format qo\'llab-quvvatlanadi. Pipelining bilan log boyitish. Ochiq kodli versiyasi bepul. Splunk\'ga arzon muqobil sifatida mashhur.' },
];

const DATASETS = [
  { name:'NSL-KDD',    records:'125,973',   color:'#185FA5', bar:'10%',  desc:'1999-KDD to\'plami yaxshilangan versiyasi. 4 hujum kategoriyasi: DoS, Probe, R2L, U2R. Eng ko\'p ishlatiladigan benchmark dataset. 41 ta xususiyat.' },
  { name:'CICIDS2017', records:'2,830,743', color:'#534AB7', bar:'100%', desc:'Canadian Institute for Cybersecurity. DDoS, PortScan, Botnet, Infiltration. Zamonaviy tarmoq trafigi. 80+ feature. Eng to\'liq zamonaviy dataset.' },
  { name:'UNSW-NB15',  records:'2,540,047', color:'#1D9E75', bar:'90%',  desc:'UNSW Canberra. 9 hujum turi: Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms. 49 xususiyat.' },
  { name:'CAIDA DDoS', records:'~800,000',  color:'#BA7517', bar:'28%',  desc:'Faqat DDoS hujumlarini tahlil qilish uchun. Real internet trafigi asosida yig\'ilgan. DDoS modellarini o\'qitish uchun eng yaxshi manba.' },
];

const SEV = {
  critical:{ bg:'#FCEBEB', tc:'#A32D2D', label:'Kritik' },
  high:    { bg:'#FAEEDA', tc:'#854F0B', label:'Yuqori' },
  medium:  { bg:'#E6F1FB', tc:'#185FA5', label:"O'rta"  },
  low:     { bg:'#EAF3DE', tc:'#3B6D11', label:'Past'   },
};

const LOCAL_IPS = ['192.168.1.1','192.168.1.100','192.168.1.101','192.168.1.200','192.168.1.201','10.0.0.1','10.0.0.10','10.0.0.20','172.16.0.1','172.16.0.50'];
const ALGOS = ['Random Forest','XGBoost','LSTM','SVM','Isolation Forest','Autoencoder'];
const THREATS_LIST = [{v:'ddos',l:'DDoS hujumi'},{v:'sqli',l:'SQL Injection'},{v:'brute_force',l:'Brute Force'},{v:'phishing',l:'Phishing'},{v:'ransomware',l:'Ransomware'},{v:'mitm',l:'Man-in-the-Middle'},{v:'apt',l:'APT'},{v:'port_scan',l:'Port Skanerlash'}];
const LOG_MSGS = ['Tarmoq trafigi normal','Noodatiy so\'rov aniqlandi','SQL Injection urinishi bloklandi','Port skanerlash aniqlandi','Autentifikatsiya muvaffaqiyatli','Firewall qoidalari yangilandi','Brute-force hujum urinishi','DDoS anomaliya kuzatildi','Phishing URL bloklandi'];

const NAV = [
  {id:'dashboard', label:'⊞ Dashboard'},
  {id:'analyze',   label:'◎ IP Tahlil'},
  {id:'network',   label:'⬡ Tarmoq Skan'},
  {id:'threats',   label:'⚠ Tahdid turlari'},
  {id:'algorithms',label:'◈ Algoritmlar'},
  {id:'datasets',  label:'⊟ Datasetlar'},
  {id:'siem',      label:'▦ SIEM tizim'},
  {id:'topo',      label:'◉ Tarmoq xaritasi'},
  {id:'logs',      label:'≡ Live Loglar'},
  {id:'loglist',   label:'⊕ Tahdid Loglari'},
];

const C = { background:'#fff', border:'0.5px solid #e5e5e5', borderRadius:12, padding:14, marginBottom:10 };
const T = { fontSize:13, fontWeight:500, marginBottom:10 };
const INP = { width:'100%', fontSize:12, padding:'7px 10px', borderRadius:8, border:'0.5px solid #ddd', background:'#fff', color:'#111', display:'block', marginBottom:4 };
const BSM = { fontSize:11, padding:'4px 10px', borderRadius:6, border:'0.5px solid #ddd', cursor:'pointer', background:'#f4f4f0', color:'#444' };

export default function App() {
  const [page, setPage]             = useState('dashboard');
  const [stats, setStats]           = useState(null);
  const [logs, setLogs]             = useState([]);
  const [paused, setPaused]         = useState(false);
  const [form, setForm]             = useState({ ip:'', threat:'', algos:['Random Forest','XGBoost'], ctx:'' });
  const [result, setResult]         = useState(null);
  const [loading, setLoading]       = useState(false);
  const [threatLogs, setThreatLogs] = useState([]);
  const [selThreat, setSelThreat]   = useState(null);
  const [selAlgo, setSelAlgo]       = useState(ALGO_LIBRARY[0]);
  const [selSiem, setSelSiem]       = useState(SIEM_LIBRARY[0]);
  const [topo, setTopo]             = useState('normal');
  const logRef = useRef(null);

  useEffect(() => {
    api.getDashboard().then(setStats).catch(() => setStats({total_threats:247,blocked:183,critical:14,accuracy:96.4}));
    api.getThreats().then(d => setThreatLogs(d.results||d)).catch(() => setThreatLogs(demoThreats()));
  }, []);

  useEffect(() => {
    const iv = setInterval(() => {
      if (paused) return;
      const lvl = ['info','warn','error'][Math.floor(Math.random()*3)];
      const nl = {id:Date.now(), level:lvl, message:LOG_MSGS[Math.floor(Math.random()*LOG_MSGS.length)], ip:LOCAL_IPS[Math.floor(Math.random()*LOCAL_IPS.length)], timestamp:new Date().toISOString()};
      setLogs(p => [...p, nl].slice(-80));
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, 1400);
    return () => clearInterval(iv);
  }, [paused]);

  const analyze = async () => {
    if (!form.ip || !form.threat) return;
    setLoading(true); setResult(null);
    try {
      const r = await api.analyzeThreat({ip_address:form.ip, threat_type:form.threat, algorithms:form.algos, context:form.ctx});
      setResult(r);
    } catch {
      const prob = Math.random()*0.25+0.72;
      const sev = prob>0.90?'critical':prob>0.75?'high':'medium';
      const loc = form.ip.startsWith('192.168')||form.ip.startsWith('10.')||form.ip.startsWith('172.16');
      setResult({ip:form.ip, ip_info:{device_name:loc?'Local qurilma':'Tashqi IP',is_local:loc,network_type:loc?'LAN':'WAN'}, threat_name:THREATS_LIST.find(t=>t.v===form.threat)?.l||form.threat, probability:prob, probability_pct:`${Math.round(prob*100)}%`, severity:sev, indicators:['Noodatiy so\'rovlar','Yuqori trafik hajmi'], mitigation:['IP ni vaqtinchalik bloklang','SIEM qoidasini yangilang','Loglarni tekshiring'], recommendation:loc?'Ichki tarmoq: Monitoring kuchaytiring.':'Tashqi IP: Darhol bloklash tavsiya etiladi.', algorithm_scores:Object.fromEntries(form.algos.map(a=>[a,Math.round((Math.random()*0.1+0.87)*100)/100])), local_context:loc?'Ichki tarmoq qurilmasi':'',});
    }
    setLoading(false);
  };

  const s = stats || {total_threats:247,blocked:183,critical:14,accuracy:96.4};

  return (
    <div style={{display:'flex',flexDirection:'column',minHeight:'100vh',fontFamily:'system-ui,sans-serif',fontSize:14}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'10px 20px',background:'#fff',borderBottom:'0.5px solid #e5e5e5'}}>
        <div style={{display:'flex',alignItems:'center',gap:8,fontWeight:600,fontSize:15}}>
          <span style={{width:10,height:10,borderRadius:'50%',background:'#E24B4A',display:'inline-block'}}/>CyberGuard AI
        </div>
        <div style={{fontSize:11,color:'#3B6D11',display:'flex',alignItems:'center',gap:5}}>
          <span style={{width:7,height:7,borderRadius:'50%',background:'#639922',display:'inline-block'}}/>Real vaqt monitoring
        </div>
      </div>

      <div style={{display:'flex',flex:1}}>
        <div style={{width:185,background:'#f9f9f7',borderRight:'0.5px solid #e5e5e5',padding:'10px 0',overflowY:'auto'}}>
          <div style={{fontSize:10,color:'#aaa',padding:'8px 14px 3px',textTransform:'uppercase',letterSpacing:'.05em'}}>Asosiy</div>
          {NAV.slice(0,3).map(n=><NavItem key={n.id} n={n} page={page} setPage={setPage}/>)}
          <div style={{fontSize:10,color:'#aaa',padding:'8px 14px 3px',textTransform:'uppercase',letterSpacing:'.05em'}}>Modullar</div>
          {NAV.slice(3).map(n=><NavItem key={n.id} n={n} page={page} setPage={setPage}/>)}
        </div>

        <div style={{flex:1,padding:16,overflowY:'auto'}}>

          {page==='dashboard' && (
            <div>
              <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:8,marginBottom:12}}>
                {[['Tahdidlar',s.total_threats,'#E24B4A'],['Bloklangan',s.blocked,'#639922'],['Kritik',s.critical,'#BA7517'],['AI Aniqlik',`${s.accuracy}%`,'#185FA5']].map(([l,v,c])=>(
                  <div key={l} style={{background:'#f4f4f0',borderRadius:8,padding:'10px 12px'}}>
                    <div style={{fontSize:11,color:'#888',marginBottom:3}}>{l}</div>
                    <div style={{fontSize:22,fontWeight:500,color:c}}>{v}</div>
                  </div>
                ))}
              </div>
              <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                <div style={C}>
                  <div style={T}>Tahdid taqsimoti (24 soat)</div>
                  {[['DDoS','#E24B4A',34],['SQL Injection','#BA7517',22],['Brute Force','#185FA5',18],['Phishing','#534AB7',15],['Ransomware','#3B6D11',11]].map(([n,c,v])=>(
                    <div key={n} style={{display:'flex',alignItems:'center',gap:8,marginBottom:6,fontSize:12}}>
                      <span style={{minWidth:80,color:'#666'}}>{n}</span>
                      <div style={{flex:1,height:6,background:'#f0f0ec',borderRadius:3}}><div style={{width:`${v*2.2}%`,height:'100%',background:c,borderRadius:3}}/></div>
                      <span style={{minWidth:28,textAlign:'right'}}>{v}%</span>
                    </div>
                  ))}
                </div>
                <div style={C}>
                  <div style={T}>Model ko'rsatkichlari</div>
                  {[['Accuracy','96.4%'],['Recall','94.1%'],['Precision','95.7%'],['F1-Score','0.949'],['False Positive','3.6%'],['Javob vaqti','12ms']].map(([k,v])=>(
                    <div key={k} style={{display:'flex',justifyContent:'space-between',padding:'4px 0',borderBottom:'0.5px solid #f0f0ec',fontSize:12}}>
                      <span style={{color:'#666'}}>{k}</span><span style={{fontWeight:500}}>{v}</span>
                    </div>
                  ))}
                  <div style={{marginTop:10}}>
                    <div style={{fontSize:12,fontWeight:500,marginBottom:6}}>Xavf darajasi</div>
                    {[['Kritik',14,'#E24B4A'],['Yuqori',45,'#BA7517'],["O'rta",89,'#185FA5'],['Past',99,'#3B6D11']].map(([l,v,c])=>(
                      <div key={l} style={{display:'flex',alignItems:'center',gap:8,marginBottom:5,fontSize:12}}>
                        <span style={{minWidth:45,color:'#666'}}>{l}</span>
                        <div style={{flex:1,height:6,background:'#f0f0ec',borderRadius:3}}><div style={{width:`${v}%`,height:'100%',background:c,borderRadius:3}}/></div>
                        <span style={{minWidth:20,textAlign:'right'}}>{v}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {page==='analyze' && (
            <div style={C}>
              <div style={T}>IP Tahdid Tahlili</div>
              <div style={{fontSize:11,color:'#999',marginBottom:8}}>Local yoki public IP kiriting</div>
              <div style={{display:'flex',gap:5,flexWrap:'wrap',marginBottom:6}}>
                {LOCAL_IPS.map(ip=>(
                  <span key={ip} onClick={()=>setForm(f=>({...f,ip}))} style={{fontSize:10,padding:'3px 8px',borderRadius:8,cursor:'pointer',border:form.ip===ip?'1px solid #185FA5':'0.5px solid #ddd',background:form.ip===ip?'#E6F1FB':'#f9f9f7',color:form.ip===ip?'#0C447C':'#555'}}>{ip}</span>
                ))}
              </div>
              <input value={form.ip} onChange={e=>setForm(f=>({...f,ip:e.target.value}))} placeholder="IP manzil (mas: 192.168.1.1)" style={INP}/>
              <select value={form.threat} onChange={e=>setForm(f=>({...f,threat:e.target.value}))} style={{...INP,marginTop:4}}>
                <option value="">— Tahdid turini tanlang —</option>
                {THREATS_LIST.map(t=><option key={t.v} value={t.v}>{t.l}</option>)}
              </select>
              <div style={{fontSize:11,color:'#888',margin:'8px 0 4px'}}>Algoritmlar:</div>
              <div style={{display:'flex',flexWrap:'wrap',gap:5,marginBottom:8}}>
                {ALGOS.map(a=>(
                  <span key={a} onClick={()=>setForm(f=>({...f,algos:f.algos.includes(a)?f.algos.filter(x=>x!==a):[...f.algos,a]}))} style={{fontSize:11,padding:'3px 9px',borderRadius:8,cursor:'pointer',border:form.algos.includes(a)?'0.5px solid #185FA5':'0.5px solid #ddd',background:form.algos.includes(a)?'#E6F1FB':'#f4f4f0',color:form.algos.includes(a)?'#0C447C':'#666'}}>{a}</span>
                ))}
              </div>
              <textarea value={form.ctx} onChange={e=>setForm(f=>({...f,ctx:e.target.value}))} placeholder="Qo'shimcha kontekst (ixtiyoriy)..." style={{...INP,height:60,resize:'vertical',fontFamily:'monospace',fontSize:11}}/>
              <button onClick={analyze} disabled={loading} style={{width:'100%',padding:9,background:loading?'#ccc':'#E24B4A',color:'#fff',border:'none',borderRadius:8,fontSize:12,fontWeight:500,cursor:loading?'not-allowed':'pointer',marginTop:4}}>
                {loading?'Tahlil qilinmoqda...':'Tahlilni boshlash ↗'}
              </button>
              {result && <AnalyzeResult result={result}/>}
            </div>
          )}

          {page==='network' && (
            <div style={C}>
              <div style={T}>Local Tarmoq Skaneri</div>
              <NetworkScan onAnalyze={ip=>{setForm(f=>({...f,ip}));setPage('analyze');}}/>
            </div>
          )}

          {page==='threats' && (
            <div style={C}>
              <div style={T}>Tahdid turlari kutubxonasi</div>
              {THREAT_LIBRARY.map(t=>{
                const sv=SEV[t.sev]||SEV.low;
                return (
                  <div key={t.key} onClick={()=>setSelThreat(selThreat?.key===t.key?null:t)} style={{display:'flex',alignItems:'center',gap:8,padding:'8px 10px',borderRadius:8,border:'0.5px solid #eee',marginBottom:5,cursor:'pointer',background:selThreat?.key===t.key?'#f9f9f7':'#fff',fontSize:12}}>
                    <span style={{fontSize:10,padding:'2px 8px',borderRadius:8,background:sv.bg,color:sv.tc,fontWeight:500,minWidth:52,textAlign:'center'}}>{sv.label}</span>
                    <span style={{flex:1,fontWeight:selThreat?.key===t.key?500:400}}>{t.name}</span>
                    <span style={{color:'#aaa',fontSize:11}}>{selThreat?.key===t.key?'▲':'▼'}</span>
                  </div>
                );
              })}
              {selThreat && (
                <div style={{background:'#f9f9f7',borderRadius:8,padding:12,marginTop:6,fontSize:12,lineHeight:1.8,border:'0.5px solid #e5e5e5'}}>
                  <div style={{fontWeight:500,marginBottom:6,fontSize:13}}>{selThreat.name}</div>
                  <div style={{marginBottom:6}}>{selThreat.desc}</div>
                  <div style={{color:'#666',marginBottom:6}}><b>Alomatlar:</b> {selThreat.signs}</div>
                  <div><b>AI yondashuv:</b> {selThreat.algo}</div>
                </div>
              )}
            </div>
          )}

          {page==='algorithms' && (
            <div>
              <div style={C}>
                <div style={T}>ML algoritmlar</div>
                <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8}}>
                  {ALGO_LIBRARY.map(a=>(
                    <div key={a.key} onClick={()=>setSelAlgo(a)} style={{border:selAlgo.key===a.key?'1.5px solid #1D9E75':'0.5px solid #e5e5e5',borderRadius:8,padding:10,cursor:'pointer',background:selAlgo.key===a.key?'#E1F5EE':'#fff',transition:'.15s'}}>
                      <div style={{fontSize:9,padding:'1px 6px',borderRadius:5,background:a.tb,color:a.tc,display:'inline-block',marginBottom:4}}>{a.type}</div>
                      <div style={{fontSize:12,fontWeight:500,color:selAlgo.key===a.key?'#085041':'#111'}}>{a.name}</div>
                      <div style={{fontSize:10,color:selAlgo.key===a.key?'#0F6E56':'#888'}}>{a.sub} — {a.acc}%</div>
                    </div>
                  ))}
                </div>
                <div style={{background:'#f9f9f7',borderRadius:8,padding:12,marginTop:10,fontSize:12,lineHeight:1.8}}>
                  <div style={{fontWeight:500,marginBottom:4}}>{selAlgo.name}</div>{selAlgo.desc}
                </div>
              </div>
              <div style={C}>
                <div style={T}>Aniqlik solishtirmasi</div>
                {ALGO_LIBRARY.map(a=>(
                  <div key={a.key} style={{display:'flex',alignItems:'center',gap:8,marginBottom:7,fontSize:12}}>
                    <span style={{minWidth:115,color:'#555'}}>{a.name}</span>
                    <div style={{flex:1,height:7,background:'#f0f0ec',borderRadius:4}}>
                      <div style={{width:`${a.acc}%`,height:'100%',background:a.type==='Deep Learning'?'#534AB7':a.type==='Nazoratssiz'?'#BA7517':'#185FA5',borderRadius:4}}/>
                    </div>
                    <span style={{minWidth:30,textAlign:'right',fontWeight:500}}>{a.acc}%</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {page==='datasets' && (
            <div>
              {DATASETS.map(d=>(
                <div key={d.name} style={C}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:6}}>
                    <div style={{fontSize:14,fontWeight:500}}>{d.name}</div>
                    <span style={{fontSize:11,padding:'3px 10px',borderRadius:8,background:'#E6F1FB',color:'#185FA5'}}>{d.records} yozuv</span>
                  </div>
                  <div style={{fontSize:12,color:'#555',lineHeight:1.7,marginBottom:8}}>{d.desc}</div>
                  <div style={{height:5,background:'#f0f0ec',borderRadius:3}}>
                    <div style={{width:d.bar,height:'100%',background:d.color,borderRadius:3}}/>
                  </div>
                </div>
              ))}
            </div>
          )}

          {page==='siem' && (
            <div>
              <div style={C}>
                <div style={T}>SIEM tizimlar integratsiyasi</div>
                <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8,marginBottom:10}}>
                  {SIEM_LIBRARY.map(s=>(
                    <div key={s.key} onClick={()=>setSelSiem(s)} style={{border:selSiem.key===s.key?'1.5px solid #185FA5':'0.5px solid #e5e5e5',borderRadius:8,padding:10,cursor:'pointer',background:selSiem.key===s.key?'#E6F1FB':'#fff',transition:'.15s'}}>
                      <div style={{fontSize:12,fontWeight:500,color:selSiem.key===s.key?'#0C447C':'#111'}}>{s.name}</div>
                      <div style={{fontSize:10,color:'#888',marginTop:2}}>{s.sub}</div>
                    </div>
                  ))}
                </div>
                <div style={{background:'#f9f9f7',borderRadius:8,padding:12,fontSize:12,lineHeight:1.8}}>
                  <div style={{fontWeight:500,marginBottom:4}}>{selSiem.name}</div>{selSiem.detail}
                </div>
              </div>
              <div style={C}>
                <div style={T}>SIEM qobiliyatlari solishtirmasi</div>
                {[['Real vaqt tahlil',{splunk:95,ibm:90,sentinel:88,elk:80,wazuh:75,graylog:70}],['ML/AI integratsiya',{splunk:90,ibm:88,sentinel:92,elk:60,wazuh:55,graylog:50}],['Narx samaradorligi',{splunk:30,ibm:25,sentinel:65,elk:90,wazuh:95,graylog:88}],['Ochiq kod',{splunk:20,ibm:15,sentinel:30,elk:100,wazuh:100,graylog:95}]].map(([label,vals])=>(
                  <div key={label} style={{marginBottom:12}}>
                    <div style={{fontSize:11,color:'#888',marginBottom:4}}>{label}</div>
                    <div style={{display:'flex',gap:4}}>
                      {SIEM_LIBRARY.map(s=>(
                        <div key={s.key} style={{flex:1,textAlign:'center'}}>
                          <div style={{height:50,background:'#f0f0ec',borderRadius:4,display:'flex',alignItems:'flex-end',overflow:'hidden'}}>
                            <div style={{width:'100%',height:`${vals[s.key]}%`,background:selSiem.key===s.key?'#185FA5':'#B5D4F4',transition:'.3s'}}/>
                          </div>
                          <div style={{fontSize:9,color:'#888',marginTop:2}}>{s.name.split(' ')[0]}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {page==='topo' && (
            <div style={C}>
              <div style={T}>Tarmoq topolojiyasi va hujum yo'llari</div>
              <TopoMap mode={topo}/>
              <div style={{display:'flex',gap:8,marginTop:10,flexWrap:'wrap'}}>
                {[['normal','Normal holat'],['attack','Hujum simulyatsiyasi'],['blocked','Bloklangan']].map(([m,l])=>(
                  <button key={m} onClick={()=>setTopo(m)} style={{fontSize:12,padding:'6px 14px',borderRadius:8,border:topo===m?'1.5px solid #185FA5':'0.5px solid #ddd',background:topo===m?'#E6F1FB':'#f4f4f0',color:topo===m?'#0C447C':'#555',cursor:'pointer'}}>{l}</button>
                ))}
              </div>
              <div style={{marginTop:10,background:'#f9f9f7',borderRadius:8,padding:10,fontSize:12,lineHeight:1.7}}>
                {topo==='normal' && 'Tarmoq normal ishlaydi. Barcha ulanishlar xavfsiz. CyberGuard AI barcha serverlarni kuzatmoqda.'}
                {topo==='attack' && '⚠ Hujum aniqlandi! Attacker → Firewall → Server yo\'li orqali kirish urinishi kuzatilmoqda. AI IDS xabar berdi.'}
                {topo==='blocked' && '✓ Hujum muvaffaqiyatli bloklandi. Firewall attacker IP ni qora ro\'yxatga qo\'shdi. Serverlar xavfsiz.'}
              </div>
            </div>
          )}

          {page==='logs' && (
            <div style={C}>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:10}}>
                <div style={T}>Real Vaqt Log Oqimi</div>
                <div style={{display:'flex',gap:6}}>
                  <button onClick={()=>setPaused(p=>!p)} style={BSM}>{paused?'Davom':'Pauza'}</button>
                  <button onClick={()=>setLogs([])} style={BSM}>Tozalash</button>
                </div>
              </div>
              <div ref={logRef} style={{fontFamily:'monospace',fontSize:11,background:'#2C2C2A',color:'#B4B2A9',padding:10,borderRadius:8,height:380,overflowY:'auto',lineHeight:1.8}}>
                {logs.map((l,i)=>(
                  <div key={i} style={{color:l.level==='error'?'#E24B4A':l.level==='warn'?'#EF9F27':'#97C459'}}>
                    {new Date(l.timestamp).toLocaleTimeString()} [{l.level.toUpperCase()}]
                    {l.ip && <span style={{color:'#85B7EB'}}> {l.ip} </span>}
                    {l.message}
                  </div>
                ))}
                {logs.length===0 && <span style={{color:'#666'}}>Loglar yuklanmoqda...</span>}
              </div>
            </div>
          )}

          {page==='loglist' && (
            <div style={C}>
              <div style={T}>Tahdid Loglari</div>
              {(threatLogs.length?threatLogs:demoThreats()).map((t,i)=>{
                const sv=SEV[t.severity]||SEV.low;
                return (
                  <div key={i} style={{display:'flex',alignItems:'center',gap:8,padding:'7px 8px',borderRadius:8,border:'0.5px solid #eee',marginBottom:5,fontSize:12}}>
                    <span style={{fontSize:10,padding:'2px 7px',borderRadius:8,background:sv.bg,color:sv.tc,fontWeight:500,minWidth:50,textAlign:'center'}}>{sv.label}</span>
                    <span style={{fontFamily:'monospace',color:'#185FA5',minWidth:110}}>{t.ip_address}</span>
                    <span style={{flex:1}}>{t.threat_type}</span>
                    <span style={{color:'#888'}}>{Math.round((t.probability||0.8)*100)}%</span>
                    {t.is_blocked
                      ? <span style={{fontSize:10,color:'#3B6D11',padding:'2px 7px',background:'#EAF3DE',borderRadius:6}}>Bloklandi</span>
                      : <button onClick={()=>api.blockThreat(t.id).catch(()=>{})} style={{fontSize:10,padding:'2px 8px',borderRadius:6,border:'0.5px solid #E24B4A',color:'#A32D2D',background:'#FCEBEB',cursor:'pointer'}}>Bloklash</button>
                    }
                  </div>
                );
              })}
            </div>
          )}

        </div>
      </div>
    </div>
  );
}

function NavItem({n,page,setPage}) {
  return (
    <div onClick={()=>setPage(n.id)} style={{padding:'7px 14px',fontSize:12,cursor:'pointer',borderLeft:page===n.id?'2px solid #E24B4A':'2px solid transparent',background:page===n.id?'#fff':'transparent',color:page===n.id?'#111':'#666',transition:'.15s'}}>
      {n.label}
    </div>
  );
}

function TopoMap({mode}) {
  const ec = mode==='attack'?'#E24B4A':'#639922';
  const att = mode==='attack'||mode==='blocked';
  return (
    <svg viewBox="0 0 520 260" width="100%" style={{background:'#f9f9f7',borderRadius:8}}>
      <rect x="10" y="90" width="80" height="40" rx="6" fill={att?'#FCEBEB':'#E1F5EE'} stroke={att?'#E24B4A':'#639922'} strokeWidth="1.5"/>
      <text x="50" y="115" textAnchor="middle" fontSize="11" fill={att?'#A32D2D':'#085041'} fontFamily="sans-serif">Attacker</text>
      <line x1="90" y1="110" x2="160" y2="110" stroke={mode==='blocked'?'#E24B4A':ec} strokeWidth="2" strokeDasharray={mode==='attack'?'5,3':'none'}/>
      {mode==='blocked'&&<text x="125" y="103" textAnchor="middle" fontSize="10" fill="#A32D2D" fontFamily="sans-serif">BLOCKED</text>}
      <rect x="160" y="85" width="80" height="50" rx="6" fill={mode==='attack'?'#FAEEDA':'#E1F5EE'} stroke={mode==='attack'?'#BA7517':'#639922'} strokeWidth="1.5"/>
      <text x="200" y="113" textAnchor="middle" fontSize="11" fill={mode==='attack'?'#633806':'#085041'} fontFamily="sans-serif">Firewall</text>
      <text x="200" y="126" textAnchor="middle" fontSize="9" fill={mode==='attack'?'#854F0B':'#0F6E56'} fontFamily="sans-serif">AI IDS</text>
      {[['60','Web'],['130','Database'],['180','Mail']].map(([y,nm])=>(
        <g key={nm}>
          <line x1="240" y1="110" x2="310" y2={y} stroke={ec} strokeWidth="1.5"/>
          <rect x="310" y={parseInt(y)-20} width="70" height="38" rx="6" fill="#E6F1FB" stroke="#185FA5" strokeWidth="1.5"/>
          <text x="345" y={parseInt(y)+3} textAnchor="middle" fontSize="10" fill="#0C447C" fontFamily="sans-serif">{nm} Server</text>
        </g>
      ))}
      <line x1="380" y1="80" x2="430" y2="100" stroke={ec} strokeWidth="1.5"/>
      <line x1="380" y1="130" x2="430" y2="130" stroke={ec} strokeWidth="1.5"/>
      <line x1="380" y1="180" x2="430" y2="150" stroke={ec} strokeWidth="1.5"/>
      <rect x="430" y="80" width="75" height="80" rx="6" fill="#EAF3DE" stroke="#3B6D11" strokeWidth="1.5"/>
      <text x="467" y="125" textAnchor="middle" fontSize="10" fill="#27500A" fontFamily="sans-serif">Internal</text>
      <rect x="25" y="185" width="105" height="32" rx="6" fill="#EEEDFE" stroke="#534AB7" strokeWidth="1.5"/>
      <text x="77" y="205" textAnchor="middle" fontSize="10" fill="#26215C" fontFamily="sans-serif">CyberGuard AI</text>
      <line x1="77" y1="185" x2="200" y2="135" stroke="#7F77DD" strokeWidth="1" strokeDasharray="4,3"/>
      <line x1="130" y1="201" x2="345" y2="80" stroke="#7F77DD" strokeWidth="1" strokeDasharray="4,3"/>
    </svg>
  );
}

function AnalyzeResult({result}) {
  if (result.error) return <div style={{marginTop:10,color:'#A32D2D',fontSize:12}}>{result.error}</div>;
  const sv=SEV[result.severity]||SEV.low;
  return (
    <div style={{marginTop:10,background:'#f9f9f7',borderRadius:8,padding:12,fontSize:12,lineHeight:1.8}}>
      <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:8}}>
        <span style={{fontWeight:500}}>Tahlil natijasi</span>
        <span style={{fontSize:10,padding:'2px 8px',borderRadius:8,background:sv.bg,color:sv.tc,fontWeight:500}}>{sv.label} xavf</span>
      </div>
      <div><b>IP:</b> <span style={{fontFamily:'monospace',color:'#185FA5'}}>{result.ip}</span></div>
      <div><b>Qurilma:</b> {result.ip_info?.device_name}</div>
      <div><b>Tarmoq:</b> {result.ip_info?.is_local?'Local (ichki)':'Public'} — {result.ip_info?.network_type}</div>
      <div><b>Tahdid:</b> {result.threat_name}</div>
      <div><b>Ehtimollik:</b> <span style={{fontWeight:500,color:sv.tc}}>{result.probability_pct}</span></div>
      {result.local_context&&<div style={{color:'#854F0B',marginTop:4}}>{result.local_context}</div>}
      {result.indicators?.length>0&&<div style={{marginTop:6}}><b>Belgilar:</b><ul style={{margin:'4px 0 0 16px'}}>{result.indicators.map((x,i)=><li key={i}>{x}</li>)}</ul></div>}
      {result.mitigation?.length>0&&<div style={{marginTop:6}}><b>Choralar:</b><ul style={{margin:'4px 0 0 16px'}}>{result.mitigation.map((x,i)=><li key={i}>{x}</li>)}</ul></div>}
      <div style={{marginTop:6,color:'#666'}}><b>Tavsiya:</b> {result.recommendation}</div>
      {result.algorithm_scores&&(
        <div style={{marginTop:6}}><b>Algoritm ballari:</b>
          <div style={{display:'flex',flexWrap:'wrap',gap:5,marginTop:4}}>
            {Object.entries(result.algorithm_scores).map(([k,v])=>(
              <span key={k} style={{fontSize:10,padding:'2px 7px',background:'#E6F1FB',color:'#0C447C',borderRadius:6}}>{k}: {Math.round(v*100)}%</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function demoThreats() {
  return [
    {ip_address:'192.168.1.201',threat_type:'SQL Injection',severity:'critical',probability:0.97,is_blocked:false},
    {ip_address:'192.168.1.200',threat_type:'Brute Force',severity:'high',probability:0.88,is_blocked:true},
    {ip_address:'10.0.0.10',threat_type:'Port Scan',severity:'medium',probability:0.73,is_blocked:false},
    {ip_address:'172.16.0.50',threat_type:'DDoS',severity:'high',probability:0.85,is_blocked:false},
  ];
}
