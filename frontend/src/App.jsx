import React, { useState, useEffect, useRef, useCallback } from 'react';
import { api } from './services/api';

function safeStorageGet(key, fallback = '') {
  try {
    const value = window.localStorage.getItem(key);
    return value ?? fallback;
  } catch {
    return fallback;
  }
}

function safeStorageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    return;
  }
}

function displayText(value, fallback = '-') {
  if (value == null || value === '') return fallback;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map(item => displayText(item, '')).filter(Boolean).join(', ') || fallback;
  }
  if (typeof value === 'object') {
    const preferred = value.message || value.name || value.label || value.title || value.ip || value.value;
    if (preferred) return String(preferred);
    try {
      return JSON.stringify(value);
    } catch {
      return fallback;
    }
  }
  return fallback;
}

function themeAccent(name, fallback) {
  if (typeof document === 'undefined') return fallback;
  const mode = document.documentElement.getAttribute('data-theme') || 'classic';
  if (mode !== 'hacker') return fallback;
  const map = {
    cyan: '#5dff4a',
    cyanSoft: '#b8ffab',
    cyanDim: '#76c76b',
    purple: '#5dff4a',
    purpleSoft: '#b8ffab',
    amber: '#ffb703',
    red: '#ff4d6d',
    redSoft: '#ff9db0',
    panelGlow: 'rgba(2,8,2,.88)',
    panelGlowStrong: 'rgba(4,16,4,.96)',
    panelBorder: 'rgba(57,255,20,.24)',
  };
  return map[name] || fallback;
}

// ── CONSTANTS ──────────────────────────────────────────────────────────────
const THREATS_LIST = [
  {v:'ddos',l:'DDoS hujumi'},{v:'sqli',l:'SQL Injection'},{v:'brute_force',l:'Brute Force'},
  {v:'phishing',l:'Phishing'},{v:'ransomware',l:'Ransomware'},{v:'mitm',l:'Man-in-the-Middle'},
  {v:'apt',l:'APT'},{v:'port_scan',l:'Port Skanerlash'},{v:'zero_day',l:'Zero-Day'},
];

const ALGOS_LIST = ['Random Forest','XGBoost','LSTM','SVM','Isolation Forest','Autoencoder'];

const THREAT_LIBRARY = [
  { key:'ddos', sev:'critical', name:'DDoS hujumi', desc:'Katta hajmdagi trafik yoki ko\'p concurrent request orqali xizmatni sekinlashtirish yoki to\'xtatish.', signs:'Trafik keskin oshishi, RTT ko\'tarilishi, 5xx xatolar, upstream saturation.', algo:'Isolation Forest, K-Means, LSTM', impact:'Public servislar ishlamay qoladi, mijozlar ulana olmaydi, bandwidth to\'ladi.', detect:['Traffic baseline buzilishi','Connection burst','Source entropy keskin oshishi'], stages:['Botnet tayyorlash','Traffic flood','Service degradation','Mitigation / scrubbing'], metrics:{ detect:94, contain:78, business:97 }, usecases:['Public API','Web portal','Game/backend ingress'] },
  { key:'sqli', sev:'critical', name:'SQL Injection', desc:'Input parametrlari orqali backend query qatlamiga zararli SQL yuborib ma\'lumotlarni o\'qish yoki o\'zgartirish.', signs:'UNION/SELECT payloadlar, DB xatolari, auth bypass, jadval enumeratsiyasi.', algo:'Random Forest, Naive Bayes, SVM', impact:'Ma\'lumotlar sizishi, admin bypass, DB integritetiga zarar.', detect:['WAF signature','DB response anomaly','App log pattern'], stages:['Recon payload','Input exploit','Data extraction','Persistence / cleanup'], metrics:{ detect:91, contain:83, business:96 }, usecases:['Legacy admin panel','Search/filter endpoint','Login forms'] },
  { key:'ransomware', sev:'critical', name:'Ransomware', desc:'Endpoint yoki serverga tushib fayllarni shifrlaydi va tiklash uchun to\'lov talab qiladi.', signs:'Mass file rename, shadow copy o\'chishi, CPU/disk spike, lateral movement.', algo:'Autoencoder, LSTM', impact:'Fayl serverlar, endpointlar va backup jarayoni falaj bo\'ladi.', detect:['File entropy spike','Suspicious process tree','SMB lateral move'], stages:['Initial access','Privilege escalation','Encryption wave','Ransom demand'], metrics:{ detect:88, contain:71, business:99 }, usecases:['File server','Endpoint fleet','Backup infra'] },
  { key:'zero_day', sev:'critical', name:'Zero-Day', desc:'Hali imzosi yoki ommaviy patchi yo\'q zaifliklardan foydalanadigan hujum turi.', signs:'Noodatiy process/traffic pattern, no known signature, patch gap.', algo:'Autoencoder, Isolation Forest', impact:'Signature-based himoyani chetlab o\'tadi, tez privilege gain beradi.', detect:['Behavior anomaly','Memory artefact','Rare process chain'], stages:['Unknown exploit','Silent foothold','Stealth execution','Analyst validation'], metrics:{ detect:79, contain:58, business:95 }, usecases:['Fresh CVE window','Vendor appliance','Custom app stack'] },
  { key:'apt', sev:'high', name:'APT', desc:'Uzoq muddatli, yashirin va ko\'p bosqichli maqsadli hujum kampaniyasi.', signs:'Beaconing, credential theft, lateral move, off-hours activity, covert exfil.', algo:'Isolation Forest, Autoencoder, LSTM', impact:'Ichki segmentlar komprometi, uzoq yashirin presence, data exfiltration.', detect:['Beacon interval','Rare admin path','Cross-host chain'], stages:['Initial foothold','Persistence','Lateral movement','Exfiltration'], metrics:{ detect:82, contain:67, business:93 }, usecases:['Enterprise AD','Hybrid cloud','Crown-jewel DB'] },
  { key:'brute', sev:'high', name:'Brute Force', desc:'Ko\'p martalik login urinishlari bilan credentialni topishga harakat qiladigan hujum.', signs:'Bir IP dan ko\'p auth fail, account lock, password spray pattern.', algo:'Random Forest, XGBoost', impact:'VPN, SSH yoki admin account compromise xavfi yuqori.', detect:['Failed auth burst','Multi-user password spray','Geo anomaly'], stages:['Username gather','Password spray','Credential hit','Privilege use'], metrics:{ detect:96, contain:86, business:74 }, usecases:['VPN portal','SSH gateway','SSO login'] },
  { key:'phishing', sev:'high', name:'Phishing', desc:'Soxta email, domen yoki login forma orqali foydalanuvchi credentialini olishga qaratilgan usul.', signs:'Lookalike domain, spoofed sender, urgent CTA, fake login form.', algo:'Random Forest, XGBoost, Naive Bayes', impact:'Credential theft, session hijack, malware delivery.', detect:['Domain similarity','Sender reputation','Landing page fingerprint'], stages:['Lure creation','Delivery','Credential capture','Reuse / pivot'], metrics:{ detect:89, contain:77, business:87 }, usecases:['Corporate email','Brand impersonation','Fake M365 login'] },
  { key:'mitm', sev:'medium', name:'Man-in-the-Middle', desc:'Aloqa oralig\'ida turib trafikni kuzatish, o\'zgartirish yoki soxta sertifikat bilan tutib olish.', signs:'TLS warning, ARP spoof, cert mismatch, transparent proxy traces.', algo:'SVM, CNN', impact:'Session interception, token theft, trafik manipulyatsiyasi.', detect:['ARP inconsistency','Cert mismatch','Proxy chain anomaly'], stages:['Positioning','Traffic interception','Modification','Session theft'], metrics:{ detect:76, contain:72, business:68 }, usecases:['Open Wi-Fi','Flat LAN','Weak certificate pinning'] },
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

const ALGO_VISUAL_METRICS = {
  rf: { speed: 88, explain: 91, zeroDay: 64, stream: 78 },
  xgb: { speed: 84, explain: 73, zeroDay: 69, stream: 81 },
  svm: { speed: 70, explain: 62, zeroDay: 66, stream: 58 },
  lstm: { speed: 61, explain: 38, zeroDay: 79, stream: 74 },
  ae: { speed: 75, explain: 49, zeroDay: 94, stream: 71 },
  iso: { speed: 93, explain: 68, zeroDay: 88, stream: 89 },
  cnn: { speed: 64, explain: 35, zeroDay: 72, stream: 67 },
  nb: { speed: 96, explain: 85, zeroDay: 42, stream: 92 },
};

const DATASETS = [
  {
    name:'NSL-KDD',
    records:'125,973',
    pct:10,
    desc:'1999-KDD yaxshilangan versiyasi. 41 xususiyat, 4 hujum kategoriyasi: DoS, Probe, R2L, U2R.',
    source:'University of New Brunswick / KDDCup lineage',
    fit:'Boshlang\'ich intrusion detection modeli va klassik supervised baseline uchun qulay.',
    attacks:['DoS','Probe','R2L','U2R'],
    features:['duration','protocol_type','service','src_bytes','dst_bytes'],
    models:['Random Forest','SVM','XGBoost'],
    sample:'tcp | http | src_bytes=181 | dst_bytes=5450 | label=normal',
    caution:'Eski dataset. Zamonaviy SaaS, cloud va encrypted traffic patternlarini to\'liq qamrab olmaydi.',
  },
  {
    name:'CICIDS2017',
    records:'2,830,743',
    pct:100,
    desc:'Canadian Institute for Cybersecurity. DDoS, PortScan, Botnet, Infiltration. 80+ feature.',
    source:'CICFlowMeter asosidagi zamonaviy enterprise traffic capture',
    fit:'Real SOC demo, network flow tahlili va ko\'p turdagi attack sinflari uchun eng tushunarli dataset.',
    attacks:['DDoS','PortScan','Botnet','Infiltration','Brute Force','Web Attack'],
    features:['flow_duration','tot_fwd_pkts','flow_byts/s','pkt_len_mean','syn_flag_cnt'],
    models:['Random Forest','XGBoost','LSTM'],
    sample:'flow_duration=51234 | pkt_len_mean=824 | syn_flag_cnt=17 | label=ddos',
    caution:'Feature soni ko\'p. Noto\'g\'ri preprocessing bo\'lsa leakage yoki class imbalance muammosi paydo bo\'ladi.',
  },
  {
    name:'UNSW-NB15',
    records:'2,540,047',
    pct:90,
    desc:'UNSW Canberra. 9 hujum turi, 49 xususiyat. Fuzzers, Exploits, Backdoors va boshqalar.',
    source:'IXIA traffic generator bilan laboratoriya + normal enterprise aralash trafiki',
    fit:'Modern attack taxonomy va anomaliya/klassifikatsiya kombinatsiyasi uchun yaxshi.',
    attacks:['Fuzzers','Exploits','Backdoors','Worms','Reconnaissance','Shellcode'],
    features:['sbytes','dbytes','sttl','dttl','ct_srv_src'],
    models:['XGBoost','Isolation Forest','Autoencoder'],
    sample:'sbytes=2240 | dttl=29 | ct_srv_src=9 | service=http | label=exploit',
    caution:'Ba\'zi sinflar kam uchraydi. Stratified split va class weighting ishlatish kerak.',
  },
  {
    name:'CAIDA DDoS',
    records:'~800,000',
    pct:28,
    desc:'Faqat DDoS hujumlarini tahlil qilish uchun. Real internet trafigi asosida yig\'ilgan.',
    source:'CAIDA backbone traffic traces / anonymized packet-level capture',
    fit:'DDoS detection, volumetric anomaly va threshold tuning uchun kuchli maxsus dataset.',
    attacks:['DDoS','Flood','Reflection-like burst'],
    features:['packet_rate','byte_rate','burstiness','src_entropy','ttl_distribution'],
    models:['Isolation Forest','LSTM','Autoencoder'],
    sample:'pps=182000 | byte_rate=910Mbps | src_entropy=0.18 | label=attack',
    caution:'Tor yo\'nalishli dataset. SQLi, phishing yoki endpoint hujumlari uchun mos emas.',
  },
  {
    name:'TON_IoT',
    records:'~20,000,000+',
    pct:76,
    desc:'IoT, telemetry, operating system va network layer ma\'lumotlarini birlashtiradi. Smart device muhitlari uchun foydali.',
    source:'UNSW Canberra Cyber Range / IoT + IIoT lab environment',
    fit:'IoT kamera, sensor, gateway va edge monitoring senariylari uchun tushunarli tanlov.',
    attacks:['Scanning','DDoS','Password attack','Ransomware','Backdoor'],
    features:['cpu','memory','network_rate','mqtt_flow','device_type'],
    models:['LSTM','Autoencoder','Random Forest'],
    sample:'device=camera | mqtt_flow=high | cpu=93% | network_rate=18MB/s | label=ddos',
    caution:'Oddiy enterprise LAN dan farq qiladi. IoT bo\'lmagan muhitga to\'g\'ridan-to\'g\'ri ko\'chirish noto\'g\'ri xulosa berishi mumkin.',
  },
  {
    name:'Bot-IoT',
    records:'72,000,000+',
    pct:84,
    desc:'Botnet, DoS, DDoS va probing hodisalariga urg\'u berilgan juda katta hajmli IoT-centric dataset.',
    source:'UNSW Cyber Range synthetic large-scale botnet traffic',
    fit:'Massive flow analytics, botnet behaviour va stream-processing demo uchun yaxshi.',
    attacks:['Botnet','DoS','DDoS','Probe','Information Theft'],
    features:['pkts','bytes','rate','dur','state'],
    models:['Isolation Forest','XGBoost','CNN'],
    sample:'pkts=6480 | bytes=5.1MB | rate=high | state=CON | label=botnet',
    caution:'Hajmi katta. Sampling, parquet/columnar storage va batch pipeline talab qiladi.',
  },
];

const SIEM_TOOLS = [
  { key:'splunk',   name:'Splunk',     sub:'SPL tili, MLTK',      vendor:'Splunk Inc.',  detail:'SPL qidiruv tili, MLTK ML plaginlari va CIM modeli bilan enterprise SOC uchun kuchli real vaqt analitika beradi.', best:'Enterprise SOC', scores:{ realtime:94, ml:92, cost:38 } },
  { key:'qradar',   name:'IBM QRadar', sub:'Watson AI',           vendor:'IBM',          detail:'Log, flow va asset korrelyatsiyasini Watson AI yordamida boyitadi. Large-scale incident triage uchun qulay.', best:'Large enterprise', scores:{ realtime:86, ml:79, cost:48 } },
  { key:'sentinel', name:'MS Sentinel',sub:'Azure, KQL',          vendor:'Microsoft',    detail:"Azure-native SIEM/SOAR. KQL, Defender va Entra bilan juda yaxshi bog'lanadi, cloud-first jamoalar uchun qulay.", best:'Cloud-first teams', scores:{ realtime:88, ml:84, cost:61 } },
  { key:'elk',      name:'ELK Stack',  sub:'Ochiq kodli',         vendor:'Elastic',      detail:"Elasticsearch, Logstash va Kibana kombinatsiyasi. Moslashuvchan, ammo tuning va operatsion yuk ko'proq talab qiladi.", best:'Custom pipelines', scores:{ realtime:72, ml:58, cost:82 } },
  { key:'wazuh',    name:'Wazuh',      sub:'HIDS/SIEM',           vendor:'Wazuh',        detail:"Endpoint-centric monitoring, file integrity va rootkit aniqlash bilan kuchli. ELK bilan yaxshi tandem bo'ladi.", best:'Endpoint visibility', scores:{ realtime:74, ml:52, cost:89 } },
  { key:'graylog',  name:'Graylog',    sub:'Log boshqaruvi',      vendor:'Graylog',      detail:"Structured log tahlili, routing va alerting uchun soddaroq stack. O'rta hajmli jamoalarda tez joriy etiladi.", best:'Mid-size SOC', scores:{ realtime:69, ml:41, cost:85 } },
];

const SIEM_CAPABILITY_ROWS = [
  { key:'realtime', label:'Real vaqt', color:'#9fc2ea', desc:'Log kelishi, parse bo\'lishi va alert chiqishi qanchalik tez sodir bo\'ladi.' },
  { key:'ml', label:'ML/AI', color:'#b5cef0', desc:'Anomaliya topish, korrelyatsiya va behavior analytics qobiliyati darajasi.' },
  { key:'cost', label:'Narx samaradorligi', color:'#94b7de', desc:'Litsenziya, infra va operator xarajati hisobga olingandagi foyda.' },
];

const THREAT_DETAIL_MAP = Object.fromEntries(THREAT_LIBRARY.map(item => [item.key, item]));

const SIEM_DETAIL_MAP = {
  splunk: {
    sources:['Syslog','Windows Event','EDR','Cloud audit'],
    pipeline:['Ingest','Normalize','Search','Alert','SOAR'],
    strengths:['Kuchli qidiruv tili','Mature app ecosystem','Large-scale retention'],
    fit:['Enterprise SOC','Regulated env','MSSP'],
    ops:{ deploy:72, tuning:84, learning:79 },
  },
  qradar: {
    sources:['NetFlow','Syslog','Vuln scanner','IAM'],
    pipeline:['Collect','Correlate','Offense','Enrich','Respond'],
    strengths:['Asset-aware correlation','Flow analytics','Offense model'],
    fit:['Large enterprise','NOC+SOC','On-prem heavy'],
    ops:{ deploy:67, tuning:76, learning:68 },
  },
  sentinel: {
    sources:['Azure AD','M365','Defender','AWS/GCP'],
    pipeline:['Connector','KQL','Analytics','Incident','Playbook'],
    strengths:['Cloud-native scaling','Strong Microsoft integration','Fast onboarding'],
    fit:['Azure infra','Modern SaaS','Lean SOC'],
    ops:{ deploy:88, tuning:71, learning:74 },
  },
  elk: {
    sources:['Beats','Syslog','APM','Custom app logs'],
    pipeline:['Ship','Parse','Index','Visualize','Alert'],
    strengths:['Flexible schema','Open ecosystem','Custom dashboards'],
    fit:['Custom pipelines','DevSecOps','Observability-heavy'],
    ops:{ deploy:74, tuning:63, learning:66 },
  },
  wazuh: {
    sources:['Agents','Syscheck','Auditd','Vuln feed'],
    pipeline:['Agent','Rule engine','Indexer','Dashboards','Response'],
    strengths:['FIM','Compliance packs','Endpoint telemetry'],
    fit:['SMB SOC','Endpoint-first','Compliance'],
    ops:{ deploy:81, tuning:69, learning:77 },
  },
  graylog: {
    sources:['Syslog','JSON app logs','Firewall','NGINX'],
    pipeline:['Ingest','Extract','Stream','Alert','Case'],
    strengths:['Simple streams','Fast deployment','Good operator UX'],
    fit:['Mid-size SOC','IT ops + Sec','Budget aware'],
    ops:{ deploy:86, tuning:73, learning:84 },
  },
};

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
    summary:"Tashqi manbadan shubhali trafik keldi. Firewall va AI IDS web hamda DB yo'nalishlarida xavfli oqimlarni ko'rmoqda.",
    linkStates:{ ingress:'attack', web:'attack', db:'warn', mail:'ok', web_internal:'warn', db_internal:'warn', mail_internal:'ok', telemetry:'monitor' },
  },
  blocked: {
    label:'Bloklangan',
    summary:"Hujum oqimi containment rejimiga o'tdi. Firewall ingressni kesdi va faqat ichki servislar orasida minimal traffic qoldi.",
    linkStates:{ ingress:'blocked', web:'ok', db:'ok', mail:'ok', web_internal:'ok', db_internal:'ok', mail_internal:'ok', telemetry:'monitor' },
  },
};

const NETWORK_TYPE_GUIDES = [
  {
    key: 'star',
    name: 'Star Topology',
    fit: 'Ofis LAN, switch-markazli tarmoq',
    summary: 'Barcha endpointlar bitta markaziy switch yoki firewallga ulanadi. Monitoring va segmentlash oson.',
    pros: ['Fault isolation oson', "Yangi host qo'shish qulay", 'Central ACL / IDS uchun yaxshi'],
  },
  {
    key: 'mesh',
    name: 'Mesh Topology',
    fit: 'Data center, high-availability segment',
    summary: "Node-lar bir nechta yo'l orqali bog'langan bo'ladi. Redundancy kuchli, lekin murakkab.",
    pros: ['Single point of failure past', "Qo'shimcha redundant path", 'Traffic engineering kuchli'],
  },
  {
    key: 'tree',
    name: 'Tree / Hierarchical',
    fit: 'Campus, enterprise branch arxitekturasi',
    summary: "Core, distribution va access qatlamlaridan tuzilgan ko'p bosqichli model.",
    pros: ['Katta tarmoqni boshqarish qulay', 'Policy qatlamlab beriladi', 'VLAN va zone segmentlash aniq'],
  },
  {
    key: 'hybrid',
    name: 'Hybrid / Zero Trust Overlay',
    fit: 'Cloud + on-prem + remote users',
    summary: "LAN, VPN, cloud va SaaS resurslari birga ishlaydi. Identity va telemetry markaziy rol o'ynaydi.",
    pros: ['Cloud integratsiya oson', 'Remote access moslashuvchan', 'Telemetry-driven access control'],
  },
  {
    key: 'ring',
    name: 'Ring Topology',
    fit: 'Industrial loop, metro ethernet, token-style segment',
    summary: 'Har bir node ikkita qo\'shni bilan ulanadi va trafik halqa bo\'ylab aylanadi.',
    pros: ['Predictable path', 'Loop protection bilan barqaror', 'Industrial tarmoqlarda uchraydi'],
  },
  {
    key: 'bus',
    name: 'Bus Topology',
    fit: 'Legacy segment, oddiy shared-medium lab',
    summary: 'Barcha hostlar bitta umumiy backbone liniyaga ulangan bo\'ladi.',
    pros: ['Tuzilishi sodda', 'Kichik lab uchun arzon', 'Shared medium tamoyilini tushuntirishga qulay'],
  },
];

const TOPOLOGY_VISUALS = {
  star: {
    nodes: [
      { key:'core', label:'Switch / Firewall', x:50, y:30, tone:'core' },
      { key:'pc1', label:'PC-1', x:24, y:16, tone:'internal' },
      { key:'pc2', label:'PC-2', x:24, y:46, tone:'internal' },
      { key:'srv1', label:'Server', x:76, y:16, tone:'service' },
      { key:'srv2', label:'Printer / IoT', x:76, y:46, tone:'service' },
      { key:'soc', label:'CyberGuard', x:50, y:72, tone:'observer' },
    ],
    edges: [['core','pc1'], ['core','pc2'], ['core','srv1'], ['core','srv2'], ['soc','core']],
    caption: 'Markaziy qurilma orqali barcha hostlar bog\'lanadi. Kichik va o\'rta ofislar uchun eng ko\'p uchraydi.',
  },
  mesh: {
    nodes: [
      { key:'n1', label:'Core-1', x:32, y:22, tone:'core' },
      { key:'n2', label:'Core-2', x:68, y:22, tone:'core' },
      { key:'n3', label:'DB Cluster', x:68, y:58, tone:'service' },
      { key:'n4', label:'App Cluster', x:32, y:58, tone:'service' },
      { key:'n5', label:'CyberGuard', x:50, y:80, tone:'observer' },
    ],
    edges: [['n1','n2'], ['n2','n3'], ['n3','n4'], ['n4','n1'], ['n1','n3'], ['n2','n4'], ['n5','n1'], ['n5','n3']],
    caption: 'Har bir muhim node bir nechta yo\'l bilan bog\'langan. Data center va HA segmentlarda ishlatiladi.',
  },
  tree: {
    nodes: [
      { key:'core', label:'Core', x:50, y:14, tone:'core' },
      { key:'dist1', label:'Distribution A', x:32, y:34, tone:'service' },
      { key:'dist2', label:'Distribution B', x:68, y:34, tone:'service' },
      { key:'acc1', label:'Access 1', x:20, y:58, tone:'internal' },
      { key:'acc2', label:'Access 2', x:44, y:58, tone:'internal' },
      { key:'acc3', label:'Access 3', x:56, y:58, tone:'internal' },
      { key:'acc4', label:'Access 4', x:80, y:58, tone:'internal' },
      { key:'soc', label:'CyberGuard', x:50, y:80, tone:'observer' },
    ],
    edges: [['core','dist1'], ['core','dist2'], ['dist1','acc1'], ['dist1','acc2'], ['dist2','acc3'], ['dist2','acc4'], ['soc','core']],
    caption: 'Core -> distribution -> access qatlamli korporativ yoki kampus arxitekturasi.',
  },
  hybrid: {
    nodes: [
      { key:'fw', label:'ZT Gateway', x:50, y:28, tone:'core' },
      { key:'lan', label:'Office LAN', x:24, y:52, tone:'internal' },
      { key:'cloud', label:'Cloud VPC', x:76, y:22, tone:'service' },
      { key:'remote', label:'Remote User', x:18, y:18, tone:'observer' },
      { key:'saas', label:'SaaS', x:80, y:52, tone:'service' },
      { key:'soc', label:'CyberGuard', x:50, y:78, tone:'observer' },
    ],
    edges: [['fw','lan'], ['fw','cloud'], ['fw','remote'], ['fw','saas'], ['soc','fw'], ['cloud','saas']],
    caption: 'On-prem, remote va cloud bitta identity/telemetry qatlamiga bog\'langan.',
  },
  ring: {
    nodes: [
      { key:'r1', label:'Node A', x:28, y:20, tone:'internal' },
      { key:'r2', label:'Node B', x:50, y:12, tone:'service' },
      { key:'r3', label:'Node C', x:72, y:20, tone:'internal' },
      { key:'r4', label:'Node D', x:72, y:52, tone:'service' },
      { key:'r5', label:'Node E', x:50, y:64, tone:'core' },
      { key:'r6', label:'Node F', x:28, y:52, tone:'internal' },
      { key:'soc', label:'CyberGuard', x:50, y:82, tone:'observer' },
    ],
    edges: [['r1','r2'], ['r2','r3'], ['r3','r4'], ['r4','r5'], ['r5','r6'], ['r6','r1'], ['soc','r5']],
    caption: 'Trafik halqa bo\'ylab aylanadi. Industrial yoki metro tarmoqlarda uchraydi.',
  },
  bus: {
    nodes: [
      { key:'backbone', label:'Backbone', x:50, y:42, tone:'core' },
      { key:'b1', label:'Host-1', x:18, y:18, tone:'internal' },
      { key:'b2', label:'Host-2', x:34, y:18, tone:'internal' },
      { key:'b3', label:'Host-3', x:50, y:18, tone:'service' },
      { key:'b4', label:'Host-4', x:66, y:18, tone:'internal' },
      { key:'b5', label:'Host-5', x:82, y:18, tone:'service' },
      { key:'soc', label:'CyberGuard', x:50, y:74, tone:'observer' },
    ],
    edges: [['b1','backbone'], ['b2','backbone'], ['b3','backbone'], ['b4','backbone'], ['b5','backbone'], ['soc','backbone']],
    caption: 'Bitta umumiy liniyaga barcha hostlar ulanadi. Legacy yoki lab tushuntirishlari uchun mos.',
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

function useViewport(maxWidth = 900) {
  const getValue = () => (typeof window !== 'undefined' ? window.innerWidth <= maxWidth : false);
  const [isMobile, setIsMobile] = useState(getValue);

  useEffect(() => {
    const onResize = () => setIsMobile(getValue());
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [maxWidth]);

  return isMobile;
}

function useLiveFeed() {
  const [logs, setLogs] = useState([]);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let active = true;
    let socket;
    let retryId;

    const mergeEvent = event => {
      setEvents(prev => [event, ...prev].slice(0, 40));
      if (event?.kind === 'threat.detected') {
        setLogs(prev => [{
          id: `evt-${event.timestamp}`,
          level: event.payload?.threat_level === 'HIGH' ? 'error' : event.payload?.threat_level === 'MEDIUM' ? 'warn' : 'info',
          message: `${event.payload?.attack_type || 'Threat'} aniqlandi`,
          timestamp: event.timestamp,
          ip: event.payload?.ip || event.payload?.scope || '-',
        }, ...prev].slice(0, 20));
      }
    };

    const loadInitial = async () => {
      try {
        const response = await api.getLiveLogs();
        if (!active) return;
        setLogs(response.logs || []);
        setEvents(response.events || []);
      } catch {
        if (!active) return;
        setLogs([]);
        setEvents([]);
      }
    };

    const connect = () => {
      try {
        socket = api.openLiveSocket();
      } catch {
        return;
      }

      socket.onopen = () => {
        if (!active) return;
        setConnected(true);
      };

      socket.onmessage = event => {
        if (!active) return;
        try {
          mergeEvent(JSON.parse(event.data));
        } catch {
          return;
        }
      };

      socket.onclose = () => {
        if (!active) return;
        setConnected(false);
        retryId = setTimeout(connect, 2500);
      };

      socket.onerror = () => {
        if (!active) return;
        setConnected(false);
      };
    };

    loadInitial();
    connect();

    return () => {
      active = false;
      if (retryId) clearTimeout(retryId);
      if (socket && socket.readyState < 2) socket.close();
    };
  }, []);

  return { logs, events, connected };
}

const threatLevelColor = level => ({ HIGH: '#ff1744', MEDIUM: '#ffab00', LOW: '#39ff14' }[String(level || '').toUpperCase()] || '#00e5ff');

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
function Sidebar({ page, setPage, alertCount, mobileOpen, onClose, themeMode, onToggleTheme }) {
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
    {
      title: 'AI KENGAYTIRILGAN',
      items: [
        { id: 'ai_lab', label: 'AI Laboratoriya', ico: 'AI' },
        { id: 'visualization', label: 'Vizualizatsiya', ico: 'VZ' },
        { id: 'mitre', label: 'MITRE ATT&CK', ico: 'MT' },
        { id: 'reports', label: 'Hisobotlar', ico: 'HR' },
      ],
    },
  ];
  return (
    <div className={`sidebar${mobileOpen ? ' open' : ''}`}>
      <div className="sb-logo">
        <div className="sidebar-head-row">
          <div>
            <div className="mark">CYBERGUARD</div>
            <div className="sub">AI SECURITY PLATFORM</div>
          </div>
          <button className="sidebar-close" onClick={onClose}>×</button>
        </div>
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
              <div key={n.id} className={`nav-item${page === n.id ? ' active' : ''}`} onClick={() => { setPage(n.id); onClose?.(); }}>
                <span className="ico mono">{n.ico}</span>
                <span>{n.label}</span>
                {n.badge > 0 && <span className="nav-badge">{n.badge}</span>}
              </div>
            ))}
          </div>
        ))}
      </div>
      <div className="sb-bottom">
        <button className={`theme-toggle-btn${themeMode === 'hacker' ? ' hacker' : ''}`} onClick={onToggleTheme}>
          {themeMode === 'hacker' ? 'HACKER MODE: ON' : 'CLASSIC MODE'}
        </button>
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
function TopBar({ page, time, onMenuToggle, themeMode, onToggleTheme }) {
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
    ai_lab: 'AI LABORATORIYA — MODEL PERFORMANCE & CLUSTERING',
    visualization: 'VIZUALIZATSIYA — TIMELINE & HEATMAP',
    mitre: 'MITRE ATT&CK FRAMEWORK',
    reports: 'HISOBOTLAR & EKSPORT',
  };
  return (
    <div className="topbar">
      <button className="mobile-menu-btn" onClick={onMenuToggle}>≡</button>
      <div className="topbar-title">{titles[page] || 'DASHBOARD'}</div>
      <div className="topbar-time mono">{fmtTime(time)} UTC</div>
      <button className={`topbar-theme-btn${themeMode === 'hacker' ? ' hacker' : ''}`} onClick={onToggleTheme}>
        {themeMode === 'hacker' ? 'HACKER' : 'CLASSIC'}
      </button>
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
  const { logs, events, connected } = useLiveFeed();
  const [prediction, setPrediction] = useState(null);
  const [refreshAt, setRefreshAt] = useState(new Date());

  useEffect(() => {
    const loadData = async () => {
      try {
        const [dashboard, predictionData] = await Promise.all([
          api.getDashboard(),
          api.predictThreat({}),
        ]);
        setStats(dashboard);
        setPrediction(predictionData);
        setRefreshAt(new Date());
      } catch {
        setStats(null);
        setPrediction(null);
      }
    };

    loadData();
    const id = setInterval(loadData, 12000);
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
    { name: 'Live Stream',  val: connected ? 'STREAMING' : (logs.length ? 'BUFFERED' : 'IDLE'), cls: connected || logs.length ? 'ok' : 'warn' },
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

      <div style={{ display:'grid', gridTemplateColumns:'1.15fr .85fr', gap:14, marginTop:14 }}>
        <Panel title="NEXT 5 MIN THREAT PREDICTION" color={threatLevelColor(prediction?.predicted_threat_level)}>
          <div className="panel-body">
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4, minmax(0, 1fr))', gap:10, marginBottom:14 }}>
              {[
                ['Threat level', prediction?.predicted_threat_level || 'LOW', threatLevelColor(prediction?.predicted_threat_level)],
                ['Attack type', prediction?.predicted_attack_type || 'Normal', '#00e5ff'],
                ['Confidence', prediction ? `${prediction.confidence}%` : '0%', '#9fc2ea'],
                ['Window', prediction ? `${prediction.next_window_minutes} min` : '-', '#39ff14'],
              ].map(([label, value, color]) => (
                <div key={label} style={{ padding:12, border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)' }}>
                  <div style={{ fontSize:10, color:'#4a6a84', letterSpacing:2, marginBottom:6 }}>{label}</div>
                  <div style={{ color, fontFamily:'Orbitron,monospace', fontSize:16 }}>{value}</div>
                </div>
              ))}
            </div>
            <div style={{ display:'grid', gap:8 }}>
              {(prediction?.reasoning || ['Prediction engine ishlamoqda...']).map(item => (
                <div key={item} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:'rgba(0,229,255,.03)', color:'#94b4c8', fontSize:12 }}>
                  {item}
                </div>
              ))}
            </div>
          </div>
        </Panel>

        <Panel title="REAL-TIME EVENT BUS" color="#39ff14"
          extra={<span style={{ marginLeft: 'auto', fontFamily: 'Share Tech Mono', fontSize: 10, color: connected ? '#39ff14' : '#ffab00' }}>{connected ? 'WS CONNECTED' : 'WS RETRYING'}</span>}>
          <div className="panel-body" style={{ maxHeight: 240, overflowY: 'auto', display:'grid', gap:8 }}>
            {(events.length ? events : [{ kind:'system', timestamp:new Date().toISOString(), payload:{ message:'Live eventlar kutilmoqda' } }]).slice(0, 8).map((event, index) => (
              <div key={`${event.kind}-${event.timestamp}-${index}`} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)' }}>
                <div style={{ display:'flex', justifyContent:'space-between', gap:10, marginBottom:6 }}>
                  <span style={{ color:'#00e5ff', fontFamily:'Share Tech Mono', fontSize:11 }}>{String(event.kind || 'event').toUpperCase()}</span>
                  <span style={{ color:'#4a6a84', fontFamily:'Share Tech Mono', fontSize:10 }}>{fmtTime(event.timestamp)}</span>
                </div>
                <div style={{ color:'#94b4c8', fontSize:12, lineHeight:1.6 }}>
                  {event.payload?.attack_type || event.payload?.summary || event.payload?.message || event.payload?.ip || 'Realtime event'}
                </div>
              </div>
            ))}
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
  const [blockMsg, setBlockMsg] = useState('');

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

  const sysBlockIP = async (ip) => {
    setBlockMsg('');
    try {
      const res = await api.autoBlockIp(ip);
      setBlockMsg(res.success ? `✓ ${ip} tizim Firewall orqali bloklandi` : `⚠ ${res.error || res.output || 'Xato'}`);
      if (res.success) fetchThreats();
    } catch (e) { setBlockMsg('Xato: ' + e.message); }
    setTimeout(() => setBlockMsg(''), 5000);
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
      {blockMsg && (
        <div style={{ marginBottom: 10, padding: '8px 12px', fontFamily: 'Share Tech Mono', fontSize: 11, color: blockMsg.startsWith('✓') ? '#39ff14' : '#ffab00', background: blockMsg.startsWith('✓') ? 'rgba(57,255,20,.08)' : 'rgba(255,171,0,.08)', border: `1px solid ${blockMsg.startsWith('✓') ? '#39ff1444' : '#ffab0044'}` }}>
          {blockMsg}
        </div>
      )}
      <Panel title={`TAHDID LOGLARI | ${filtered.length} VOQEA`} color="#ff1744">
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><div className="spinner"/></div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="alerts-table">
              <thead>
                <tr>
                  <th>JIDDIYLIK</th><th>IP MANZIL</th><th>TAHDID TURI</th>
                  <th>QURILMA</th><th>AI EHTIMOL</th><th>ALGORITM</th><th>HOLAT</th><th>AMAL</th><th>TIZIM</th>
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
                    <td>
                      <button className="action-btn" onClick={() => sysBlockIP(t.ip_address)}
                        style={{ borderColor: 'rgba(255,100,0,.5)', color: '#ff6400', fontSize: 10, padding: '4px 8px' }}
                        title="Windows Firewall / iptables orqali bloklash">
                        FW BLOCK
                      </button>
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
  const getDefaultProfilePort = type => ({ ssh: 22, telnet: 23, snmp: 161, web: 80 }[type] || 22);
  const [devices, setDevices] = useState([]);
  const [interfaces, setInterfaces] = useState([]);
  const [wifiStatus, setWifiStatus] = useState(null);
  const [agentMode, setAgentMode] = useState(false);
  const [agentBusy, setAgentBusy] = useState(false);
  const [agentError, setAgentError] = useState('');
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
  const [safeScanForm, setSafeScanForm] = useState({ ip: '', ports: '21,22,23,80,443', timeout: 0.35 });
  const [safeScanBusy, setSafeScanBusy] = useState(false);
  const [safeScanResult, setSafeScanResult] = useState(null);

    const loadNetworkContext = useCallback(async () => {
      try {
        setAgentMode(await api.hasLocalAgent(true));
        const [scanData, interfaceData, wifiData, profileData, sessionData] = await Promise.allSettled([
          api.scanNetwork(),
          api.getInterfaces(),
        api.getWifiStatus(),
        api.getProfiles(),
        api.getScanSessions(),
      ]);

      const scanPayload = scanData.status === 'fulfilled' ? scanData.value : { devices: [] };
      const interfacePayload = interfaceData.status === 'fulfilled' ? interfaceData.value : { interfaces: [] };
      const wifiPayload = wifiData.status === 'fulfilled' ? wifiData.value : null;
      const profilePayload = profileData.status === 'fulfilled' ? profileData.value : [];
      const sessionPayload = sessionData.status === 'fulfilled' ? sessionData.value : [];

      setDevices(scanPayload.devices || []);
      setInterfaces(interfacePayload.interfaces || []);
      setWifiStatus(wifiPayload);
      setProfiles(profilePayload.results || profilePayload || []);
      setSessions(sessionPayload.results || sessionPayload || []);

      const nextInterface = wifiPayload?.connected_interface
        || selectedInterface
        || (interfacePayload.interfaces || [])[0]?.name
        || '';
      if (nextInterface) {
        setSelectedInterface(nextInterface);
      }

      if (wifiPayload?.connected_ssid) {
        setSelectedWifi(wifiPayload.connected_ssid);
        setWifiForm(form => ({ ...form, ssid: wifiPayload.connected_ssid }));
      }

      // ── Default fieldlarni avtomatik to'ldirish ──────────────────────────
      const firstIface = (interfacePayload.interfaces || [])[0];
      if (firstIface) {
        const myIP   = firstIface.ip || '';
        const gateway = (firstIface.gateways || [])[0] || '';
        const label  = wifiPayload?.connected_ssid || firstIface.name || '';
        // Safe IP Collector: o'z IP sini yoki gateway ni taklif qilish
        setSafeScanForm(f => f.ip ? f : { ...f, ip: gateway || myIP });
        // Connection Profile: gateway IP va tarmoq nomini oldin to'ldirish
        setProfileForm(p => ({
          ...p,
          target_host: p.target_host || gateway || myIP,
          network_label: p.network_label || label,
        }));
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

    const enableLocalScan = async () => {
      setAgentBusy(true);
      setAgentError('');
      try {
        api.launchLocalAgent();
        const ready = await api.waitForLocalAgent({ timeoutMs: 15000, intervalMs: 1000 });
        if (!ready) {
          throw new Error("Local agent topilmadi. Shu kompyuterda `install_local_scan_protocol.bat` ni bir marta ishga tushiring yoki `start_local_agent.bat` ni yoqing.");
        }
        setAgentMode(true);
        await loadNetworkContext();
      } catch (err) {
        setAgentError(err.message || 'Local agent ishga tushmadi');
      } finally {
        setAgentBusy(false);
      }
    };

  const checkRep = async (ip) => {
    setSelected(ip);
    setRepInfo(null);
    setSafeScanForm(form => ({ ...form, ip }));
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

  const runSafeScan = async () => {
    if (!safeScanForm.ip) return;
    setSafeScanBusy(true);
    setProfileError('');
    try {
      const ports = safeScanForm.ports
        .split(',')
        .map(item => Number(item.trim()))
        .filter(item => Number.isFinite(item));
      const response = await api.safeScan({
        ip_address: safeScanForm.ip,
        ports,
        timeout: Number(safeScanForm.timeout || 0.35),
      });
      setSafeScanResult(response);
    } catch (err) {
      setProfileError(err.message || 'Safe scan bajarilmadi');
      setSafeScanResult(null);
    } finally {
      setSafeScanBusy(false);
    }
  };

    useEffect(() => { loadNetworkContext(); }, [loadNetworkContext]);
    useEffect(() => {
      const id = setInterval(async () => {
        setAgentMode(await api.hasLocalAgent(true));
      }, 4000);
      return () => clearInterval(id);
    }, []);
    useEffect(() => {
      if (!devices.length) return;
    const firstIp = selected || devices[0]?.ip || '';
    if (firstIp) {
      setSafeScanForm(form => form.ip ? form : { ...form, ip: firstIp });
    }
  }, [devices, selected]);

  const riskColor = risk => ({ low: '#39ff14', medium: '#ffab00', high: '#fb923c', critical: '#ff1744' }[risk] || '#39ff14');
  const deviceStats = {
    online: devices.filter(device => device.status === 'online').length,
    risky: devices.filter(device => ['high', 'critical'].includes(device.risk)).length,
    exposed: devices.filter(device => (device.open_ports || []).length >= 4).length,
  };
  const localScanSteps = [
    {
      title: '1. Birinchi sozlash',
      text: "Shu kompyuterda faqat bir marta local protocol o'rnating.",
      bat: 'install_local_scan_protocol.bat',
      action: "Protocolni o'rnatish",
    },
    {
      title: '2. Local agentni yoqing',
      text: "Agent shu kompyuterning Wi-Fi, interface va lokal hostlarini o'qiydi.",
      bat: 'start_local_agent.bat',
      action: 'Agentni ishga tushirish',
    },
    {
      title: '3. Saytdan ishga tushiring',
      text: "RUN LOCAL SCAN bosilganda sayt localhost agentga ulanadi va server emas, shu kompyuter tarmog'ini ishlatadi.",
      bat: 'enable_local_scan.bat',
      action: 'Ikkalasini birga yoqish',
    },
  ];
  const currentScanSourceText = agentMode
    ? "Hozir ko'rinayotgan hostlar local agent orqali aynan shu kompyuterdan olingan."
    : "Hozir ko'rinayotgan hostlar local agentdan emas, backend ishlayotgan muhitdan olingan. Agar backend shu kompyuterda ishlayotgan bo'lsa ular real bo'lishi mumkin; agar backend serverda bo'lsa bu shu kompyuter tarmog'i emas.";
  const cyan = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fe8ff');
  const cyanDim = themeAccent('cyanDim', '#7ab8d4');
  const purple = themeAccent('purple', '#8b5cf6');
  const purpleSoft = themeAccent('purpleSoft', '#d8b4fe');
  const amberTone = themeAccent('amber', '#ffab00');
  const redTone = themeAccent('red', '#ff1744');
  const redSoft = themeAccent('redSoft', '#ff8fa0');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');
  const panelGlowStrong = themeAccent('panelGlowStrong', 'rgba(0,229,255,.08)');
  const panelBorder = themeAccent('panelBorder', 'rgba(0,229,255,.22)');
  const inputStyle = {
    width: '100%',
    background: panelGlow,
    border: '1px solid var(--border)',
    color: 'var(--text)',
    padding: '9px 12px',
    fontFamily: 'Share Tech Mono',
    fontSize: 12,
    outline: 'none',
  };

  return (
      <div style={{ animation: 'fadeUp .3s ease' }}>
        <Panel title={`LOCAL TARMOQ SKANERI | ${devices.length} TOPILDI`} color={cyan}
          extra={
            <div style={{ display:'flex', alignItems:'center', gap:10, marginLeft:'auto' }}>
              <span style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: agentMode ? '#39ff14' : amberTone }}>
                {agentMode ? 'LOCAL AGENT: ACTIVE' : 'LOCAL AGENT: OFF'}
              </span>
              {!agentMode && (
                <button className="action-btn" onClick={enableLocalScan} disabled={agentBusy}>
                  {agentBusy ? 'STARTING AGENT...' : 'RUN LOCAL SCAN'}
                </button>
              )}
              <button className="action-btn" onClick={scan} disabled={scanning}>
                {scanning ? 'SKANLANMOQDA...' : 'QAYTA SKAN'}
              </button>
            </div>
          }>
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><div className="spinner"/></div>
          ) : (
            <div style={{ padding: 14 }}>
              {!agentMode && (
                <div style={{
                  marginBottom: 12,
                  padding: 12,
                  border: `1px solid ${amberTone}55`,
                  background: `${amberTone}14`,
                  color: amberTone,
                  fontSize: 12,
                  lineHeight: 1.7,
                }}>
                  Shu kompyuter tarmog'ini ko'rish uchun local agent kerak. `RUN LOCAL SCAN` tugmasini bosing.
                  Agar birinchi urinishda ishga tushmasa, shu kompyuterda `install_local_scan_protocol.bat` ni bir marta ishga tushiring.
                </div>
              )}
              <div style={{
                marginBottom: 12,
                padding: 12,
                border: `1px solid ${panelBorder}`,
                background: panelGlow,
                color: cyanSoft,
                fontSize: 12,
                lineHeight: 1.7,
              }}>
                {currentScanSourceText}
              </div>
              {agentError && (
                <div style={{
                  marginBottom: 12,
                  padding: 12,
                  border: `1px solid ${redTone}55`,
                  background: `${redTone}14`,
                  color: redSoft,
                  fontSize: 12,
                  lineHeight: 1.7,
                }}>
                  {agentError}
                </div>
              )}
              <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0, 1fr))', gap:10, marginBottom: 12 }}>
              {[
                ['Onlayn hostlar', `${deviceStats.online}/${devices.length}`, '#39ff14'],
                ['Yuqori xavf', `${deviceStats.risky} ta`, amberTone],
                ["Ko'p port ochiq", `${deviceStats.exposed} ta`, cyanSoft],
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
                  background: isSel ? panelGlowStrong : 'linear-gradient(180deg, rgba(13,27,46,.72), rgba(8,15,28,.92))',
                  border: `1px solid ${isSel ? 'var(--cyan)' : `${rc}44`}`,
                  boxShadow: isSel ? `0 0 18px ${panelGlowStrong}` : 'none',
                  padding: 16, cursor: 'pointer', transition: 'all .2s', minHeight: 180,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: 17, color: 'var(--text)', marginBottom: 4 }}>{d.name}</div>
                      <div style={{ fontFamily: 'Share Tech Mono', fontSize: 12, color: cyan }}>{d.ip}</div>
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
                    <div style={{ color:cyanDim, fontFamily:'Share Tech Mono' }}>Portlar: {(d.open_ports || []).join(', ') || '-'}</div>
                    <div style={{ color:'#4a6a84', fontFamily:'Share Tech Mono', textAlign:'right' }}>{d.open_ports?.length || 0} ta ochiq</div>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button className="action-btn" style={{ flex: 1,
                      borderColor: (d.risk === 'critical' || d.risk === 'high') ? `${redTone}88` : 'var(--border)',
                      color: (d.risk === 'critical' || d.risk === 'high') ? redTone : 'var(--text-dim)',
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

      <Panel title="LOCAL SCAN GUIDE" color={purple} style={{ marginTop: 14 }}>
        <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 14 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10 }}>
            {localScanSteps.map(step => (
              <div key={step.title} style={{
                border: `1px solid ${purple}55`,
                background: `linear-gradient(180deg, ${purple}16, rgba(10,14,28,.94))`,
                padding: 14,
                minHeight: 146,
              }}>
                <div style={{ color: purpleSoft, fontSize: 11, letterSpacing: 2, marginBottom: 8 }}>{step.title}</div>
                <div style={{ color: 'var(--text)', fontSize: 12, lineHeight: 1.75, marginBottom: 12 }}>{step.text}</div>
                <div style={{
                  border: `1px solid ${purple}66`,
                  background: `${purple}14`,
                  color: purpleSoft,
                  padding: '8px 10px',
                  fontSize: 11,
                  fontFamily: 'Share Tech Mono',
                  marginBottom: 12,
                }}>
                  {step.bat}
                </div>
                <a
                  href={api.getLocalAgentDownloadUrl(step.bat)}
                  download
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    minHeight: 34,
                    padding: '0 12px',
                    border: `1px solid ${cyan}66`,
                    color: cyan,
                    textDecoration: 'none',
                    fontSize: 11,
                    fontFamily: 'Share Tech Mono',
                    letterSpacing: 1,
                  }}
                >
                  {step.action} | YUKLAB OLISH
                </a>
              </div>
            ))}
          </div>
          <div style={{
            border: '1px solid var(--border2)',
            background: 'rgba(8,15,28,.72)',
            padding: 14,
          }}>
            <div style={{ color: cyan, fontSize: 11, letterSpacing: 2, marginBottom: 10 }}>BAT FAYLLAR</div>
            {[
              ['setup_project.bat', "Birinchi o'rnatish: venv, migrate, npm install"],
              ['start_backend.bat', 'Django/ASGI backendni yoqadi'],
              ['start_frontend.bat', 'Vite frontendni yoqadi'],
              ['start_all.bat', 'Backend va frontendni birga yoqadi'],
              ['enable_local_scan.bat', 'Protocol install + local agent start'],
            ].map(([name, desc]) => (
              <div key={name} style={{ marginBottom: 12, paddingBottom: 12, borderBottom: `1px solid ${panelBorder}` }}>
                <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: cyan, marginBottom: 4 }}>{name}</div>
                <div style={{ color: cyanDim, fontSize: 12, lineHeight: 1.65 }}>{desc}</div>
              </div>
            ))}
            <div style={{
              marginTop: 8,
              padding: 10,
              border: `1px solid ${cyan}44`,
              background: panelGlow,
              color: cyanSoft,
              fontSize: 12,
              lineHeight: 1.75,
            }}>
              Frontenddagi `YUKLAB OLISH` tugmasi `.bat` faylni brauzer orqali yuklab beradi.
              <br />
              1. <span style={{ fontFamily: 'Share Tech Mono' }}>Protocolni o&apos;rnatish</span> faylini ishga tushiring.
              <br />
              2. <span style={{ fontFamily: 'Share Tech Mono' }}>Agentni ishga tushirish</span> faylini ishga tushiring.
              <br />
              3. Sahifaga qaytib <span style={{ fontFamily: 'Share Tech Mono' }}>RUN LOCAL SCAN</span> ni bosing.
            </div>
            <div style={{
              marginTop: 8,
              padding: 10,
              border: '1px solid rgba(57,255,20,.18)',
              background: 'rgba(57,255,20,.05)',
              color: cyanSoft,
              fontSize: 12,
              lineHeight: 1.7,
            }}>
              Kurs ishi uchun tavsiya oqim:
              <br />
              <span style={{ fontFamily: 'Share Tech Mono' }}>setup_project.bat</span> → <span style={{ fontFamily: 'Share Tech Mono' }}>start_all.bat</span> → <span style={{ fontFamily: 'Share Tech Mono' }}>enable_local_scan.bat</span>
            </div>
          </div>
        </div>
      </Panel>

      {repInfo && (
        <Panel title={`IP REPUTATSIYA | ${repInfo.ip}`} color={amberTone} style={{ marginTop: 14 }}>
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

      <div style={{ display:'grid', gridTemplateColumns:'1fr', gap:14, marginTop:14 }}>
        <Panel title="SAFE IP COLLECTOR — PORT SKANER" color={cyan}>
          <div className="panel-body">
            {/* Tushuntirish satrlari */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10, marginBottom: 14 }}>
              {[
                { icon: '①', title: 'IP MANZIL', desc: 'Tekshiriladigan IP: router (gateway), tarmog\'ingizda ko\'ringan qurilma yoki istalgan IP.' },
                { icon: '②', title: 'PORTLAR', desc: 'Vergul bilan ajratilgan portlar. 21=FTP, 22=SSH, 23=Telnet, 80=HTTP, 443=HTTPS, 3389=RDP.' },
                { icon: '③', title: 'TIMEOUT', desc: 'Har bir port uchun kutish vaqti (soniya). 0.35s — tezlik va aniqlik muvozanati.' },
              ].map(({ icon, title, desc }) => (
                <div key={title} style={{ padding: '10px 12px', background: 'rgba(0,229,255,.04)', border: '1px solid rgba(0,229,255,.15)' }}>
                  <div style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: cyan, marginBottom: 4 }}>{icon} {title}</div>
                  <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.6 }}>{desc}</div>
                </div>
              ))}
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1.1fr .9fr .6fr auto', gap:10, alignItems:'center' }}>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>IP MANZIL (gateway yoki qurilma)</div>
                <input value={safeScanForm.ip} onChange={e => setSafeScanForm(form => ({ ...form, ip: e.target.value }))} placeholder="192.168.0.1" style={inputStyle}/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>PORTLAR (vergul bilan)</div>
                <input value={safeScanForm.ports} onChange={e => setSafeScanForm(form => ({ ...form, ports: e.target.value }))} placeholder="21,22,80,443" style={inputStyle}/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>TIMEOUT (s)</div>
                <input value={safeScanForm.timeout} onChange={e => setSafeScanForm(form => ({ ...form, timeout: e.target.value }))} type="number" step="0.05" min="0.05" max="0.5" style={inputStyle}/>
              </div>
              <button className="action-btn" onClick={runSafeScan} disabled={safeScanBusy || !safeScanForm.ip} style={{ marginTop: 18 }}>
                {safeScanBusy ? 'SCANNING...' : 'SCAN-IP'}
              </button>
            </div>
            <div style={{ marginTop:8, color:'#4a6a84', fontSize:11, lineHeight:1.7 }}>
              Safe mode: maksimal 10 port, timeout 0.5s dan oshmaydi. Aggressive probing qilinmaydi.
              Natija: qaysi portlar <span style={{ color: '#39ff14' }}>OPEN</span> yoki <span style={{ color: '#ff4444' }}>CLOSED</span> — IP Tahlilga yuboriladi.
            </div>
            {safeScanResult && (
              <div style={{ marginTop:12, display:'grid', gap:10 }}>
                <div style={{ display:'grid', gridTemplateColumns:'repeat(4, minmax(0, 1fr))', gap:10 }}>
                  {[
                    ['Target', safeScanResult.ip, cyan],
                    ['Open ports', `${safeScanResult.open_ports?.length || 0} ta`, '#39ff14'],
                    ['Timeout', `${safeScanResult.timeout_seconds}s`, cyanSoft],
                    ['Cache', safeScanResult.cached ? 'HIT' : 'MISS', safeScanResult.cached ? amberTone : '#4ade80'],
                  ].map(([label, value, color]) => (
                    <div key={label} style={{ padding:12, border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)' }}>
                      <div style={{ fontSize:10, color:'#4a6a84', letterSpacing:2, marginBottom:6 }}>{label}</div>
                      <div style={{ color, fontFamily:'Orbitron,monospace', fontSize:15 }}>{value}</div>
                    </div>
                  ))}
                </div>
                <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(150px, 1fr))', gap:8 }}>
                  {(safeScanResult.port_details || []).map(item => (
                    <div key={item.port} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:item.open ? 'rgba(57,255,20,.05)' : 'rgba(255,255,255,.02)' }}>
                      <div style={{ color:cyanDim, fontFamily:'Share Tech Mono', fontSize:11, marginBottom:4 }}>PORT {item.port}</div>
                      <div style={{ color:item.open ? '#39ff14' : '#4a6a84', fontFamily:'Share Tech Mono', fontSize:12 }}>{item.open ? 'OPEN' : 'CLOSED'}</div>
                      <div style={{ color:cyanSoft, fontSize:11, marginTop:4 }}>{item.latency_ms} ms</div>
                    </div>
                  ))}
                </div>
                <div style={{ display:'flex', gap:8 }}>
                  <button className="action-btn" onClick={() => onAnalyze(safeScanResult.ip, { threat: 'port_scan', context: `Safe scan open ports: ${(safeScanResult.open_ports || []).join(', ') || 'none'}` })}>
                    ANALYZE SAFE SCAN
                  </button>
                </div>
              </div>
            )}
          </div>
        </Panel>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14 }}>
        <Panel title="WIFI HOLATI" color={cyan}>
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
                <div style={{ color: cyanSoft, fontSize: 12, marginBottom: 12 }}>{displayText(wifiStatus.message)}</div>

                {!wifiStatus.wifi_adapter_available && (
                  <div style={{ color: amberTone, fontSize: 12 }}>
                    Wi-Fi adapter yo&apos;q. Ethernet yoki virtual adapter ma&apos;lumotlari orqali scan davom etadi.
                  </div>
                )}

                {wifiStatus.wifi_adapter_available && !wifiStatus.service_running && (
                  <div style={{ color: amberTone, fontSize: 12 }}>
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
                            border: `1px solid ${active ? panelBorder : 'var(--border2)'}`,
                            background: active ? panelGlowStrong : 'transparent',
                            cursor: 'pointer',
                          }}>
                            <div style={{ color: 'var(--text)', fontWeight: 700, fontSize: 13 }}>{net.ssid || '(hidden)'}</div>
                            <div style={{ color: cyanDim, fontSize: 11, fontFamily: 'Share Tech Mono' }}>
                              {net.signal || '-'} | {net.authentication || '-'}
                            </div>
                            <div style={{ color: cyanDim, fontSize: 11, fontFamily: 'Share Tech Mono' }}>
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
                    {wifiError && <div style={{ color: redSoft, fontSize: 12, marginTop: 10 }}>{wifiError}</div>}
                  </>
                )}
              </>
            )}
          </div>
        </Panel>

        <Panel title="ULANISH VA TAHLIL" color="#39ff14">
          <div className="panel-body" style={{ fontSize: 12, color: cyanSoft, lineHeight: 1.8 }}>
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
                    border: `1px solid ${isActive ? panelBorder : 'var(--border2)'}`,
                    background: isActive ? panelGlow : 'transparent',
                    cursor: 'pointer',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                      <div>
                        <div style={{ color: 'var(--text)', fontWeight: 700 }}>{displayText(item.name)}</div>
                        <div style={{ fontSize: 11, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>{displayText(item.adapter_type)}</div>
                      </div>
                      <div style={{ textAlign: 'right', fontFamily: 'Share Tech Mono', fontSize: 11, color: cyanDim }}>
                        {displayText(item.ssid || item.subnet_cidr)}
                      </div>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 10, fontSize: 12 }}>
                      <div><span style={{ color: '#4a6a84' }}>IP: </span>{displayText(item.ip)}</div>
                      <div><span style={{ color: '#4a6a84' }}>Gateway: </span>{displayText(item.gateway)}</div>
                      <div><span style={{ color: '#4a6a84' }}>Mask: </span>{displayText(item.subnet_mask)}</div>
                      <div><span style={{ color: '#4a6a84' }}>State: </span>{displayText(item.state)}</div>
                      <div><span style={{ color: '#4a6a84' }}>DNS Suffix: </span>{displayText(item.dns_suffix)}</div>
                      <div><span style={{ color: '#4a6a84' }}>Link-local IPv6: </span>{displayText(item.link_local_ipv6)}</div>
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

        <Panel title="CONNECTION PROFILE — CREDENTIALED SCAN" color={purple}>
          <div className="panel-body">
            {/* Protokol tushuntirish */}
            <div style={{ marginBottom: 12, padding: '8px 12px', background: 'rgba(168,85,247,.05)', border: '1px solid rgba(168,85,247,.2)', fontSize: 11, color: '#94b4c8', lineHeight: 1.7 }}>
              {profileForm.profile_type === 'ssh'    && <><span style={{ color: purple }}>SSH</span> — Router/server ga SSH kirish. Username+password bilan ulanib qurilma ma'lumotini yig'adi (hostname, versiya, config). Ko'p Linux routerlarda ishlaydi.</>}
              {profileForm.profile_type === 'telnet' && <><span style={{ color: purple }}>Telnet</span> — Eski Cisco/Mikrotik routerlarda qo'llanadi. SSH xavfsizroq, lekin ba'zi qurilmalar faqat Telnet qabul qiladi.</>}
              {profileForm.profile_type === 'snmp'   && <><span style={{ color: purple }}>SNMP v2c</span> — Tarmoq monitoringi protokoli. Community string (odatda "public") bilan router/switch dan statistika o'qiydi. Parol talab qilmaydi.</>}
              {profileForm.profile_type === 'web'    && <><span style={{ color: purple }}>WEB/HTTP</span> — Router admin panelini (192.168.0.1:80) probe qiladi. Sarlavha, auth turi, HTTP status va latency qaytaradi.</>}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>PROFIL NOMI</div>
                <input value={profileForm.name}
                  onChange={e => setProfileForm(p => ({ ...p, name: e.target.value }))}
                  placeholder={`Mening ${profileForm.profile_type.toUpperCase()} profilim`}
                  style={inputStyle}/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>PROTOKOL TURI</div>
                <select value={profileForm.profile_type}
                  onChange={e => setProfileForm(p => ({ ...p, profile_type: e.target.value, port: getDefaultProfilePort(e.target.value) }))}
                  style={inputStyle}>
                  <option value="ssh">SSH (port 22) — Linux/router</option>
                  <option value="telnet">Telnet (port 23) — Eski qurilmalar</option>
                  <option value="snmp">SNMP (port 161) — Monitoring</option>
                  <option value="web">WEB/HTTP (port 80) — Admin panel</option>
                </select>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>
                  TARGET IP (router yoki qurilma IP si)
                </div>
                <input value={profileForm.target_host}
                  onChange={e => setProfileForm(p => ({ ...p, target_host: e.target.value }))}
                  placeholder="192.168.0.1"
                  style={inputStyle}/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>PORT</div>
                <input value={profileForm.port}
                  onChange={e => setProfileForm(p => ({ ...p, port: Number(e.target.value || 0) }))}
                  placeholder={String(getDefaultProfilePort(profileForm.profile_type))}
                  type="number" style={inputStyle}/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>
                  {profileForm.profile_type === 'snmp' ? 'USERNAME (ixtiyoriy)' : 'USERNAME / LOGIN'}
                </div>
                <input value={profileForm.username}
                  onChange={e => setProfileForm(p => ({ ...p, username: e.target.value }))}
                  placeholder={profileForm.profile_type === 'snmp' ? 'ixtiyoriy' : profileForm.profile_type === 'web' ? 'admin' : 'root yoki admin'}
                  style={inputStyle}/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>
                  {profileForm.profile_type === 'snmp' ? 'COMMUNITY STRING' : 'PASSWORD'}
                </div>
                <input value={profileForm.secret}
                  onChange={e => setProfileForm(p => ({ ...p, secret: e.target.value }))}
                  placeholder={profileForm.profile_type === 'snmp' ? 'public' : '••••••••'}
                  type="password" style={inputStyle}/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>TARMOQ LABEL / SSID</div>
                <input value={profileForm.network_label}
                  onChange={e => setProfileForm(p => ({ ...p, network_label: e.target.value }))}
                  placeholder={selectedInterface || 'Wi-Fi yoki LAN nomi'}
                  style={inputStyle}/>
              </div>
              {profileForm.profile_type === 'snmp' && (
                <div>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 3 }}>SNMP VERSIYASI</div>
                  <select value={profileForm.snmp_version}
                    onChange={e => setProfileForm(p => ({ ...p, snmp_version: e.target.value }))}
                    style={inputStyle}>
                    <option value="2c">SNMP v2c</option>
                  </select>
                </div>
              )}
            </div>
            <textarea value={profileForm.notes}
              onChange={e => setProfileForm(p => ({ ...p, notes: e.target.value }))}
              placeholder="Izoh: masalan 'Uy routeri', 'Ofis switch #2'..."
              style={{ ...inputStyle, marginTop: 10, height: 55, resize: 'vertical' }}/>
            <div style={{ display: 'flex', gap: 10, marginTop: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <button className="action-btn" onClick={createProfile}>PROFIL SAQLASH</button>
              <span style={{ color: '#4a6a84', fontSize: 11 }}>
                Saqlangandan keyin → <span style={{ color: purple }}>"RUN SCAN"</span> bosib ulanish tekshiriladi
              </span>
              <span style={{ color: '#4a6a84', fontSize: 11 }}>| Interface: <span style={{ color: cyan }}>{selectedInterface || '-'}</span></span>
            </div>
            {profileError && <div style={{ color: redSoft, fontSize: 12, marginTop: 10 }}>{profileError}</div>}
          </div>
        </Panel>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14 }}>
        <Panel title={`SAQLANGAN PROFILLAR | ${profiles.length}`} color={amberTone}>
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
                    <div><span style={{ color: '#4a6a84' }}>User: </span>{displayText(profile.username)}</div>
                    <div><span style={{ color: '#4a6a84' }}>Secret: </span>{profile.has_secret ? 'saved' : 'missing'}</div>
                    <div><span style={{ color: '#4a6a84' }}>Label: </span>{displayText(profile.network_label)}</div>
                    <div><span style={{ color: '#4a6a84' }}>Last used: </span>{profile.last_used_at ? fmtTime(profile.last_used_at) : '-'}</div>
                </div>
              </div>
            ))}
            {profiles.length === 0 && <span style={{ color: '#4a6a84' }}>Hali connection profile yo&apos;q.</span>}
          </div>
        </Panel>

        <Panel title={`SCAN SESSIONS | ${sessions.length}`} color={redTone}>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {sessions.map(session => (
              <div key={session.id} style={{ padding: 12, border: '1px solid var(--border2)', background: 'var(--panel2)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
                  <div>
                    <div style={{ color: 'var(--text)', fontWeight: 700 }}>{displayText(session.profile_name)}</div>
                    <div style={{ color: '#4a6a84', fontSize: 11, fontFamily: 'Share Tech Mono' }}>
                      {displayText(session.profile_type)?.toUpperCase()} | {displayText(session.target_host)} | {displayText(session.status)?.toUpperCase()}
                    </div>
                  </div>
                  <div style={{ color: session.status === 'success' ? '#39ff14' : session.status === 'failed' ? '#ff1744' : '#ffab00', fontFamily: 'Share Tech Mono', fontSize: 11 }}>
                    {displayText(session.network_name || session.interface_name)}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <button className="action-btn" onClick={() => analyzeSession(session)}>
                    ANALYZE
                  </button>
                </div>
                <div style={{ fontSize: 12, color: cyanSoft, marginTop: 8 }}>
                  {session.status === 'failed'
                    ? displayText(session.error_message || session.summary || 'Natija kutilmoqda')
                    : displayText(session.summary || session.error_message || 'Natija kutilmoqda')}
                </div>
                {session.result?.hostname && (
                  <div style={{ marginTop: 8, fontSize: 12 }}>
                    <span style={{ color: '#4a6a84' }}>Hostname: </span>{displayText(session.result.hostname)}
                  </div>
                )}
                {session.result?.prompt && (
                  <div style={{ marginTop: 6, fontSize: 12 }}>
                    <span style={{ color: '#4a6a84' }}>Prompt: </span>{displayText(session.result.prompt)}
                  </div>
                )}
                {session.result?.device_description && (
                  <div style={{
                    marginTop: 8,
                    padding: '10px 12px',
                    border: '1px solid var(--border2)',
                    background: panelGlow,
                    fontSize: 11,
                    color: cyanDim,
                    fontFamily: 'Share Tech Mono',
                    whiteSpace: 'pre-wrap',
                    lineHeight: 1.6,
                    maxHeight: 180,
                    overflowY: 'auto',
                  }}>
                    {displayText(session.result.device_description)}
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

function GlobalThreatMapPanel({ compact = false }) {
  const cyan = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const cyanDim = themeAccent('cyanDim', '#7ab8d4');
  const amberTone = themeAccent('amber', '#ffab00');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');
  const panelBorder = themeAccent('panelBorder', 'rgba(0,229,255,.22)');
  const origins = [
    { x: 12, y: 20, region: 'North America', type: 'Botnet C2', severity: 82 },
    { x: 18, y: 58, region: 'South America', type: 'Phishing relay', severity: 61 },
    { x: 31, y: 64, region: 'South Atlantic', type: 'Recon node', severity: 54 },
    { x: 49, y: 30, region: 'Europe', type: 'Exploit scan', severity: 74 },
    { x: 54, y: 24, region: 'Northern Europe', type: 'Credential attack', severity: 88 },
    { x: 60, y: 35, region: 'Middle East', type: 'Proxy chain', severity: 67 },
    { x: 69, y: 29, region: 'South Asia', type: 'DDoS reflector', severity: 79 },
    { x: 74, y: 23, region: 'East Asia', type: 'Malware delivery', severity: 91 },
  ];
  const protectedNode = { x: 46, y: 46 };
  const height = compact ? 240 : 320;
  const topOrigins = [...origins].sort((a, b) => b.severity - a.severity).slice(0, compact ? 3 : 5);
  const avgSeverity = Math.round(origins.reduce((sum, item) => sum + item.severity, 0) / origins.length);

  return (
    <div style={{ border: '1px solid var(--border2)', background: `linear-gradient(180deg, ${panelGlow}, rgba(4,11,24,.98))` }}>
      <svg viewBox="0 0 100 60" style={{ display: 'block', width: '100%', height }}>
        {[10, 20, 30, 40, 50, 60, 70, 80, 90].map(x => <line key={`vx-${x}`} x1={x} y1="0" x2={x} y2="60" stroke="rgba(57,255,20,.12)" strokeWidth="0.25"/>)}
        {[10, 20, 30, 40, 50].map(y => <line key={`hy-${y}`} x1="0" y1={y} x2="100" y2={y} stroke="rgba(57,255,20,.12)" strokeWidth="0.25"/>)}
        <path d="M6 9 L18 6 L21 12 L18 22 L12 27 L7 21 Z" fill="rgba(12,26,12,.82)" stroke="rgba(57,255,20,.2)" strokeWidth="0.3"/>
        <path d="M15 27 L26 25 L30 30 L28 44 L18 47 L12 40 Z" fill="rgba(12,26,12,.82)" stroke="rgba(57,255,20,.2)" strokeWidth="0.3"/>
        <path d="M38 6 L49 5 L49 14 L37 15 L35 10 Z" fill="rgba(12,26,12,.82)" stroke="rgba(57,255,20,.2)" strokeWidth="0.3"/>
        <path d="M36 16 L50 15 L52 20 L49 38 L42 41 L36 34 L34 22 Z" fill="rgba(12,26,12,.82)" stroke="rgba(57,255,20,.2)" strokeWidth="0.3"/>
        <path d="M49 5 L81 5 L83 12 L76 22 L64 26 L50 20 L49 14 Z" fill="rgba(12,26,12,.82)" stroke="rgba(57,255,20,.2)" strokeWidth="0.3"/>
        <path d="M64 29 L81 28 L83 40 L74 44 L64 41 Z" fill="rgba(12,26,12,.82)" stroke="rgba(57,255,20,.2)" strokeWidth="0.3"/>
        {origins.map((origin, index) => (
          <g key={index}>
            <line x1={origin.x} y1={origin.y} x2={protectedNode.x} y2={protectedNode.y} stroke={index % 2 ? 'rgba(255,59,92,.7)' : 'rgba(255,88,122,.55)'} strokeWidth="0.35"/>
            <circle cx={origin.x} cy={origin.y} r="0.65" fill="#ff335c"/>
            <circle cx={origin.x} cy={origin.y} r="1.35" fill="rgba(255,51,92,.18)"/>
          </g>
        ))}
        <circle cx={protectedNode.x} cy={protectedNode.y} r="1.25" fill="#39ff14"/>
        <circle cx={protectedNode.x} cy={protectedNode.y} r="3" fill="rgba(57,255,20,.12)"/>
        <circle cx={protectedNode.x + 1.4} cy={protectedNode.y - 1.6} r="0.9" fill="#74ff5c"/>
      </svg>
      {!compact && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, padding: '0 12px 12px' }}>
          <div style={{ padding: 12, border: '1px solid rgba(255,23,68,.18)', background: 'rgba(255,23,68,.06)' }}>
            <div style={{ color: '#ff8fa0', fontSize: 10, letterSpacing: 2, marginBottom: 6 }}>THREAT SUMMARY</div>
            <div style={{ color: 'var(--text)', fontSize: 18, fontFamily: 'Orbitron,monospace', marginBottom: 4 }}>{origins.length} ACTIVE ORIGINS</div>
            <div style={{ color: cyanSoft, fontSize: 12, lineHeight: 1.6 }}>
              O&apos;rtacha xavf darajasi <span style={{ color: amberTone, fontFamily: 'Share Tech Mono' }}>{avgSeverity}%</span>.
              Karta qaysi regionlardan traffic kelayotganini va protected node&apos;ga oqimini ko&apos;rsatadi.
            </div>
          </div>
          <div style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
            <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 8 }}>TOP SOURCES</div>
            {topOrigins.map(item => (
              <div key={`${item.region}-${item.type}`} style={{ padding: '8px 0', borderBottom: `1px solid ${panelBorder}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                  <span style={{ color: 'var(--text)', fontSize: 12 }}>{item.region}</span>
                  <span style={{ color: '#ff4668', fontFamily: 'Share Tech Mono', fontSize: 11 }}>{item.severity}%</span>
                </div>
                <div style={{ color: cyanDim, fontSize: 12 }}>{item.type}</div>
              </div>
            ))}
          </div>
        </div>
      )}
      <div style={{ display: 'flex', gap: 16, padding: '0 12px 12px', fontSize: 10, color: cyanDim, fontFamily: 'Share Tech Mono', flexWrap: 'wrap' }}>
        <span style={{ color: '#ff4668' }}>● ATTACK ORIGIN</span>
        <span style={{ color: '#39ff14' }}>● PROTECTED NODE</span>
        <span style={{ color: cyan }}>— THREAT VECTOR</span>
      </div>
    </div>
  );
}

function ThreatFlowPanel({ threat, color }) {
  const item = threat || {};
  const stages = item.stages || [];
  const detect = item.detect || [];
  const usecases = item.usecases || [];
  const metrics = item.metrics || {};
  const cyan = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr .8fr', gap: 12 }}>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>ATTACK FLOW</div>
          <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.max(stages.length, 1)}, minmax(0, 1fr))`, gap: 8 }}>
            {stages.map((stage, index) => (
              <div key={stage} style={{ padding: 10, border: `1px solid ${color}33`, background: `${color}10`, minHeight: 74 }}>
                <div style={{ color, fontFamily: 'Share Tech Mono', fontSize: 10, marginBottom: 6 }}>{String(index + 1).padStart(2, '0')}</div>
                <div style={{ color: 'var(--text)', fontSize: 12, lineHeight: 1.5 }}>{stage}</div>
              </div>
            ))}
          </div>
        </div>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>IMPACT SCORE</div>
          {[
            ['Aniqlash', metrics.detect || 0, cyan],
            ['Containment', metrics.contain || 0, '#ffab00'],
            ['Biznes zarar', metrics.business || 0, color],
          ].map(([label, value, tone]) => (
            <div key={label} style={{ marginBottom: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                <span style={{ color: cyanSoft }}>{label}</span>
                <span style={{ color: tone, fontFamily: 'Share Tech Mono' }}>{value}%</span>
              </div>
              <div style={{ height: 5, background: 'var(--border2)' }}>
                <div style={{ width: `${value}%`, height: '100%', background: `linear-gradient(90deg, ${tone}, rgba(255,255,255,.85))` }}/>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>DETECTION CUES</div>
          {detect.map(point => (
            <div key={point} style={{ color: cyanSoft, fontSize: 12, lineHeight: 1.6, marginBottom: 6 }}>{point}</div>
          ))}
        </div>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>BUSINESS IMPACT</div>
          <div style={{ color: '#dce8f5', fontSize: 13, lineHeight: 1.7 }}>{item.impact}</div>
        </div>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>TYPICAL TARGETS</div>
          {usecases.map(point => (
            <div key={point} style={{ color: cyanSoft, fontSize: 12, lineHeight: 1.6, marginBottom: 6 }}>{point}</div>
          ))}
        </div>
      </div>
    </div>
  );
}

function DatasetIntelCard({ dataset }) {
  const amberTone = themeAccent('amber', '#ffab00');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const cyanDim = themeAccent('cyanDim', '#7ab8d4');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');

  return (
    <Panel key={dataset.name} title={dataset.name} color={amberTone}>
      <div className="panel-body">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, alignItems: 'start', marginBottom: 12 }}>
          <div>
            <div style={{ color: cyanDim, fontSize: 11, fontFamily: 'Share Tech Mono', marginBottom: 6 }}>{dataset.source}</div>
            <div style={{ color: cyanSoft, fontSize: 13, lineHeight: 1.7 }}>{dataset.desc}</div>
          </div>
          <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: amberTone, padding: '2px 10px', border: `1px solid ${amberTone}66`, background: `${amberTone}14` }}>
            {dataset.records} yozuv
          </span>
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
            <span style={{ color: cyanSoft }}>Demo ichidagi foydalilik</span>
            <span style={{ color: amberTone, fontFamily: 'Share Tech Mono' }}>{dataset.pct}%</span>
          </div>
          <div style={{ height: 4, background: 'var(--border2)' }}>
            <div style={{ width: `${dataset.pct}%`, height: '100%', background: `linear-gradient(90deg,${amberTone},#39ff14)`, boxShadow: `0 0 6px ${amberTone}66` }}/>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
          <div style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
            <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 8 }}>QACHON ISHLATILADI</div>
            <div style={{ color: '#dce8f5', fontSize: 12, lineHeight: 1.7 }}>{dataset.fit}</div>
          </div>
          <div style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
            <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 8 }}>NAMUNA YOZUV</div>
            <div style={{ color: cyanSoft, fontSize: 11, lineHeight: 1.7, fontFamily: 'Share Tech Mono' }}>{dataset.sample}</div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
          <div style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
            <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 8 }}>HUJUM TURLARI</div>
            {dataset.attacks.map(item => (
              <div key={item} style={{ color: '#dce8f5', fontSize: 12, marginBottom: 6 }}>{item}</div>
            ))}
          </div>
          <div style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
            <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 8 }}>MUHIM FEATURELAR</div>
            {dataset.features.map(item => (
              <div key={item} style={{ color: cyanSoft, fontSize: 12, marginBottom: 6, fontFamily: 'Share Tech Mono' }}>{item}</div>
            ))}
          </div>
          <div style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
            <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 8 }}>MOS MODELLAR</div>
            {dataset.models.map(item => (
              <div key={item} style={{ color: '#b4ff9d', fontSize: 12, marginBottom: 6 }}>{item}</div>
            ))}
          </div>
        </div>

        <div style={{ marginTop: 12, padding: 12, border: '1px solid rgba(255,23,68,.2)', background: 'rgba(255,23,68,.05)', color: '#ffb3bf', fontSize: 12, lineHeight: 1.7 }}>
          <span style={{ color: '#ff8fa0', fontFamily: 'Share Tech Mono' }}>CHEKLOV:</span> {dataset.caution}
        </div>
      </div>
    </Panel>
  );
}

function SIEMArchitecturePanel({ tool }) {
  const detail = SIEM_DETAIL_MAP[tool?.key] || { sources: [], pipeline: [], strengths: [], fit: [], ops: {} };
  const cyan = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');
  const panelBorder = themeAccent('panelBorder', 'rgba(0,229,255,.22)');
  const snapshotRows = [
    ['Ingest', detail.ops.deploy || 0, `${cyan}22`, cyanSoft],
    ['Parse', detail.ops.tuning || 0, 'rgba(57,255,20,.12)', '#39ff14'],
    ['Detect', Math.round(((detail.ops.deploy || 0) + (detail.ops.learning || 0)) / 2), 'rgba(255,171,0,.12)', '#ffab00'],
    ['Respond', detail.ops.learning || 0, 'rgba(255,23,68,.1)', '#ff6b7f'],
  ];
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1.15fr .85fr', gap: 12 }}>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>DATA FLOW</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 8 }}>
            {detail.pipeline.map((step, index) => (
              <div key={step} style={{ padding: 10, border: `1px solid ${panelBorder}`, background: panelGlow, minHeight: 72 }}>
                <div style={{ color: cyan, fontFamily: 'Share Tech Mono', fontSize: 10, marginBottom: 6 }}>{String(index + 1).padStart(2, '0')}</div>
                <div style={{ color: 'var(--text)', fontSize: 12, lineHeight: 1.4 }}>{step}</div>
              </div>
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 8, marginTop: 12 }}>
            {detail.sources.map(source => (
              <div key={source} style={{ padding: '8px 10px', border: '1px solid var(--border2)', background: panelGlow, color: '#cfe0f5', fontSize: 12 }}>
                {source}
              </div>
            ))}
          </div>
        </div>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>OPERATIONS</div>
          {[
            ['Deploy', detail.ops.deploy || 0, '#39ff14'],
            ['Tuning', detail.ops.tuning || 0, '#ffab00'],
            ['Learning', detail.ops.learning || 0, '#9fc2ea'],
          ].map(([label, value, tone]) => (
            <div key={label} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                <span style={{ color: cyanSoft }}>{label}</span>
                <span style={{ color: tone, fontFamily: 'Share Tech Mono' }}>{value}%</span>
              </div>
              <div style={{ height: 5, background: 'var(--border2)' }}>
                <div style={{ width: `${value}%`, height: '100%', background: `linear-gradient(90deg, ${tone}, rgba(255,255,255,.82))` }}/>
              </div>
            </div>
          ))}
          <div style={{ marginTop: 16 }}>
            <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 8 }}>BEST FIT</div>
            {detail.fit.map(item => (
              <div key={item} style={{ color: '#dce8f5', fontSize: 12, lineHeight: 1.6, marginBottom: 6 }}>{item}</div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>STRONG SIDES</div>
          {detail.strengths.map(item => (
            <div key={item} style={{ color: cyanSoft, fontSize: 12, lineHeight: 1.6, marginBottom: 6 }}>{item}</div>
          ))}
        </div>
        <div style={{ border: '1px solid var(--border2)', background: panelGlow, padding: 14 }}>
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 10 }}>VISUAL SNAPSHOT</div>
          <div style={{ display: 'grid', gridTemplateColumns: '96px 1fr', gap: 10, alignItems: 'stretch' }}>
            <div style={{
              border: `1px solid ${panelBorder}`,
              background: `linear-gradient(180deg, ${cyan}22, ${panelGlow})`,
              padding: 10,
              display: 'grid',
              alignContent: 'center',
              justifyItems: 'center',
              minHeight: 142,
            }}>
              <div style={{ width: 38, height: 38, borderRadius: '50%', border: `1px solid ${panelBorder}`, background: `${cyan}18`, boxShadow: `0 0 18px ${cyan}22` }}/>
              <div style={{ marginTop: 10, color: cyan, fontSize: 10, fontFamily: 'Share Tech Mono', textAlign: 'center', lineHeight: 1.5 }}>
                CORE
                <br />
                ENGINE
              </div>
            </div>
            <div style={{ display: 'grid', gap: 8 }}>
              {snapshotRows.map(([label, value, bg, tone]) => (
                <div key={label} style={{ border: '1px solid var(--border2)', background: bg, padding: '8px 10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                    <span style={{ color: '#dce8f5', fontSize: 12 }}>{label}</span>
                    <span style={{ color: tone, fontFamily: 'Share Tech Mono', fontSize: 11 }}>{value}%</span>
                  </div>
                  <div style={{ height: 5, background: `${cyan}22` }}>
                    <div style={{ width: `${value}%`, height: '100%', background: `linear-gradient(90deg, ${tone}, rgba(255,255,255,.85))` }}/>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 10, color: cyanSoft, fontSize: 12, lineHeight: 1.7 }}>
            Mini snapshot tanlangan SIEM stack&apos;ning ingest, parse, detect va respond bosqichlaridagi nisbiy tayyorlik darajasini ko&apos;rsatadi.
          </div>
        </div>
      </div>
    </div>
  );
}

// ── ANALYZE PAGE ───────────────────────────────────────────────────────────
function AnalyzePage({ initialIP, initialContext = '', initialThreat = '' }) {
  const [form, setForm] = useState({ ip: initialIP || '', threat: initialThreat || '', algos: ['Random Forest', 'XGBoost'], ctx: initialContext || '', target: initialIP || '' });
  const [result, setResult] = useState(null);
  const [intel, setIntel] = useState(null);
  const [behavior, setBehavior] = useState(null);
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(false);
  const [intelLoading, setIntelLoading] = useState(false);
  const [behaviorLoading, setBehaviorLoading] = useState(false);
  const [predictionLoading, setPredictionLoading] = useState(false);
  const [error, setError] = useState('');
  const [quickIps, setQuickIps] = useState([]);

  useEffect(() => { if (initialIP) setForm(f => ({ ...f, ip: initialIP, target: initialIP })); }, [initialIP]);
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
    setLoading(true);
    setResult(null);
    setError('');
    try {
      const res = await api.analyzeThreat({ ip_address: form.ip, threat_type: form.threat, algorithms: form.algos, context: form.ctx });
      setResult(res);
    } catch (err) {
      setError(err?.message || 'Tahlilni bajarib bo\'lmadi');
    }
    setLoading(false);
  };

  const probeTarget = async () => {
    if (!form.target) return;
    setIntelLoading(true);
    setError('');
    try {
      const response = await api.getTargetIntel({ target: form.target });
      setIntel(response);
      if (!form.ip && response.primary_ip) {
        setForm(f => ({ ...f, ip: response.primary_ip }));
      }
    } catch (err) {
      setError(err?.message || 'Target probe bajarilmadi');
      setIntel(null);
    }
    setIntelLoading(false);
  };

  const analyzeBehavior = async () => {
    if (!form.ip) return;
    setBehaviorLoading(true);
    setError('');
    try {
      const response = await api.analyzeBehavior({ ip_address: form.ip, auto_response: true });
      setBehavior(response);
    } catch (err) {
      setError(err?.message || 'Behavior analysis bajarilmadi');
      setBehavior(null);
    }
    setBehaviorLoading(false);
  };

  const predictWindow = async () => {
    if (!form.ip) return;
    setPredictionLoading(true);
    setError('');
    try {
      const response = await api.predictThreat({ ip_address: form.ip });
      setPrediction(response);
    } catch (err) {
      setError(err?.message || 'Prediction bajarilmadi');
      setPrediction(null);
    }
    setPredictionLoading(false);
  };

  const sevColor = sev => ({ critical: '#ff1744', high: '#fb923c', medium: '#ffab00', low: '#39ff14' }[sev] || '#00e5ff');

  return (
    <div style={{ animation: 'fadeUp .3s ease', display: 'grid', gridTemplateColumns: '320px 1fr', gap: 14, alignItems: 'start' }}>
      <Panel title="TAHLIL SHAKLI" color="#00e5ff">
        <div className="panel-body">
          <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 8, fontWeight: 700 }}>TEZKOR TANLASH:</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 14 }}>
            {quickIps.map(ip => (
              <span key={ip} onClick={() => setForm(f => ({ ...f, ip, target: ip }))} style={{
                fontSize: 10, padding: '3px 8px', cursor: 'pointer', fontFamily: 'Share Tech Mono',
                border: `1px solid ${form.ip === ip ? 'var(--cyan)' : 'var(--border)'}`,
                color: form.ip === ip ? 'var(--cyan)' : 'var(--text-dim)',
                background: form.ip === ip ? 'rgba(0,229,255,.08)' : 'transparent',
                transition: 'all .15s',
              }}>{ip}</span>
            ))}
            {quickIps.length === 0 && <span style={{ fontSize: 10, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>Tarmoq scan natijalari hali mavjud emas</span>}
          </div>

          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', display: 'block', marginBottom: 6, fontWeight: 700 }}>TARGET / DOMEN</label>
            <input value={form.target} onChange={e => setForm(p => ({ ...p, target: e.target.value }))}
              placeholder="192.168.1.1 yoki example.com" style={{
                width: '100%', background: 'rgba(0,229,255,.04)', border: '1px solid var(--border)',
                color: 'var(--text)', padding: '9px 12px', fontFamily: 'Share Tech Mono', fontSize: 13, outline: 'none',
              }}/>
            <button className="action-btn" onClick={probeTarget} disabled={intelLoading || !form.target} style={{ width: '100%', marginTop: 10 }}>
              {intelLoading ? 'PROBE...' : 'SAFE PROBE / DOMAIN INFO'}
            </button>
            <div style={{ marginTop: 8, fontSize: 11, color: '#4a6a84', lineHeight: 1.6 }}>
              Bu yerda faqat cheklangan diagnostik probe ishlatiladi. Hujum yoki DDoS yuborilmaydi.
            </div>
          </div>

          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', display: 'block', marginBottom: 6, fontWeight: 700 }}>IP MANZIL</label>
            <input value={form.ip} onChange={e => setForm(p => ({ ...p, ip: e.target.value }))}
              placeholder="192.168.1.1" style={{
                width: '100%', background: 'rgba(0,229,255,.04)', border: '1px solid var(--border)',
                color: 'var(--text)', padding: '9px 12px', fontFamily: 'Share Tech Mono', fontSize: 13, outline: 'none',
              }}/>
          </div>

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
                width: '100%', height: 80, background: 'rgba(0,229,255,.04)', border: '1px solid var(--border)',
                color: 'var(--text)', padding: '9px 12px', fontFamily: 'Share Tech Mono', fontSize: 11,
                outline: 'none', resize: 'vertical',
              }}/>
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

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, marginTop:10 }}>
            <button className="action-btn" onClick={analyzeBehavior} disabled={behaviorLoading || !form.ip}>
              {behaviorLoading ? 'BEHAVIOR...' : 'SAFE BEHAVIOR'}
            </button>
            <button className="action-btn" onClick={predictWindow} disabled={predictionLoading || !form.ip}>
              {predictionLoading ? 'PREDICT...' : 'NEXT 5 MIN'}
            </button>
          </div>

          {error && <div style={{ marginTop: 12, color: '#ff8fa0', fontSize: 12 }}>{error}</div>}
        </div>
      </Panel>

      <div style={{ display: 'grid', gap: 14 }}>
        {intel && (
          <Panel title={`TARGET INTEL | ${intel.normalized_target}`} color="#39ff14">
            <div className="panel-body">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10, marginBottom: 14 }}>
                {[
                  ['Turi', (intel.target_type || '-').toUpperCase(), '#00e5ff'],
                  ['Resolved IP', intel.primary_ip || '-', '#9fc2ea'],
                  ['Open service', `${(intel.service_ports || []).filter(item => item.open).length} ta`, '#39ff14'],
                  ['Web endpoint', `${(intel.web_checks || []).length} ta`, '#ffab00'],
                ].map(([label, value, color]) => (
                  <div key={label} style={{ padding: 12, border: '1px solid var(--border2)', background: 'rgba(13,27,46,.45)' }}>
                    <div style={{ fontSize: 10, color: '#4a6a84', letterSpacing: 2, marginBottom: 6 }}>{label}</div>
                    <div style={{ fontFamily: 'Orbitron,monospace', fontSize: 18, color }}>{value}</div>
                  </div>
                ))}
              </div>

              {intel.resolved_ips?.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <div className="panel-title" style={{ marginBottom: 8 }}>RESOLVED IP LAR</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {intel.resolved_ips.map(ip => (
                      <span key={ip} onClick={() => setForm(f => ({ ...f, ip }))}
                        style={{ padding: '4px 10px', border: `1px solid ${form.ip === ip ? 'var(--cyan)' : 'var(--border2)'}`, cursor: 'pointer', fontFamily: 'Share Tech Mono', fontSize: 11, color: form.ip === ip ? 'var(--cyan)' : '#94b4c8' }}>
                        {ip}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <div>
                  <div className="panel-title" style={{ marginBottom: 8 }}>SERVICE PORTLAR</div>
                  {(intel.service_ports || []).map(item => (
                    <div key={item.port} style={{ display: 'grid', gridTemplateColumns: '64px 1fr auto', gap: 10, marginBottom: 8, fontSize: 12 }}>
                      <span style={{ color: '#7ab8d4', fontFamily: 'Share Tech Mono' }}>{item.port}</span>
                      <span style={{ color: '#94b4c8' }}>{item.label}</span>
                      <span style={{ color: item.open ? '#39ff14' : '#4a6a84', fontFamily: 'Share Tech Mono' }}>{item.open ? `OPEN ${item.latency_ms}ms` : 'CLOSED'}</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div className="panel-title" style={{ marginBottom: 8 }}>WEB / DOMAIN INFO</div>
                  {(intel.web_checks || []).map(item => (
                    <div key={`${item.scheme}-${item.port}`} style={{ marginBottom: 10, padding: 10, border: '1px solid var(--border2)', background: 'rgba(0,229,255,.03)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 6 }}>
                        <span style={{ color: '#00e5ff', fontFamily: 'Share Tech Mono' }}>{item.scheme.toUpperCase()}:{item.port}</span>
                        <span style={{ color: '#39ff14', fontFamily: 'Share Tech Mono' }}>{item.status_code}</span>
                      </div>
                      <div style={{ fontSize: 12, color: '#94b4c8', lineHeight: 1.6 }}>{item.title || item.url}</div>
                      <div style={{ fontSize: 11, color: '#4a6a84', marginTop: 6 }}>Server: {item.server || '-'} | Avg latency: {item.avg_latency_ms} ms</div>
                    </div>
                  ))}
                  {intel.tls_info?.subject && (
                    <div style={{ marginTop: 12, fontSize: 12, color: '#94b4c8', lineHeight: 1.7 }}>
                      <div><span style={{ color: '#4a6a84' }}>TLS Subject: </span>{intel.tls_info.subject}</div>
                      <div><span style={{ color: '#4a6a84' }}>Issuer: </span>{intel.tls_info.issuer || '-'}</div>
                      <div><span style={{ color: '#4a6a84' }}>Expires: </span>{intel.tls_info.expires_at || '-'}</div>
                    </div>
                  )}
                </div>
              </div>

              {intel.recommendations?.length > 0 && (
                <div style={{ marginTop: 14, padding: 12, border: '1px solid rgba(57,255,20,.18)', background: 'rgba(57,255,20,.05)' }}>
                  <div style={{ fontSize: 10, letterSpacing: 2, color: '#39ff14', fontWeight: 700, marginBottom: 8 }}>SAFE PROBE TAVSIYALARI</div>
                  {intel.recommendations.map((item, index) => (
                    <div key={index} style={{ fontSize: 12, color: '#94b4c8', marginBottom: 6 }}>{item}</div>
                  ))}
                </div>
              )}
            </div>
          </Panel>
        )}

        {(behavior || prediction) && (
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14 }}>
            <Panel title="BEHAVIOR ANALYSIS" color={threatLevelColor(behavior?.threat_level)}>
              <div className="panel-body">
                {!behavior && <div style={{ color:'#4a6a84' }}>Behavior natija hali yo&apos;q.</div>}
                {behavior && (
                  <>
                    <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0, 1fr))', gap:10, marginBottom:12 }}>
                      {[
                        ['Threat', behavior.threat_level, threatLevelColor(behavior.threat_level)],
                        ['Attack', behavior.attack_type, '#00e5ff'],
                        ['Confidence', `${behavior.confidence}%`, '#9fc2ea'],
                      ].map(([label, value, color]) => (
                        <div key={label} style={{ padding:12, border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)' }}>
                          <div style={{ fontSize:10, color:'#4a6a84', letterSpacing:2, marginBottom:6 }}>{label}</div>
                          <div style={{ color, fontFamily:'Orbitron,monospace', fontSize:15 }}>{value}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ display:'grid', gap:8 }}>
                      {(behavior.signals || []).map(item => (
                        <div key={item} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:'rgba(0,229,255,.03)', color:'#94b4c8', fontSize:12 }}>{item}</div>
                      ))}
                    </div>
                    {behavior.features && (
                      <div style={{ marginTop:12, display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
                        {Object.entries(behavior.features).slice(0, 6).map(([key, value]) => (
                          <div key={key} style={{ display:'flex', justifyContent:'space-between', padding:'8px 10px', border:'1px solid var(--border2)', background:'rgba(255,255,255,.02)', fontSize:12 }}>
                            <span style={{ color:'#4a6a84' }}>{key}</span>
                            <span style={{ color:'#9fc2ea', fontFamily:'Share Tech Mono' }}>{String(value)}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            </Panel>

            <Panel title="THREAT PREDICTION" color={threatLevelColor(prediction?.predicted_threat_level)}>
              <div className="panel-body">
                {!prediction && <div style={{ color:'#4a6a84' }}>Prediction natija hali yo&apos;q.</div>}
                {prediction && (
                  <>
                    <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0, 1fr))', gap:10, marginBottom:12 }}>
                      {[
                        ['Level', prediction.predicted_threat_level, threatLevelColor(prediction.predicted_threat_level)],
                        ['Attack', prediction.predicted_attack_type, '#00e5ff'],
                        ['Confidence', `${prediction.confidence}%`, '#9fc2ea'],
                      ].map(([label, value, color]) => (
                        <div key={label} style={{ padding:12, border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)' }}>
                          <div style={{ fontSize:10, color:'#4a6a84', letterSpacing:2, marginBottom:6 }}>{label}</div>
                          <div style={{ color, fontFamily:'Orbitron,monospace', fontSize:15 }}>{value}</div>
                        </div>
                      ))}
                    </div>
                    <div style={{ display:'grid', gap:8 }}>
                      {(prediction.reasoning || []).map(item => (
                        <div key={item} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:'rgba(57,255,20,.04)', color:'#94b4c8', fontSize:12 }}>{item}</div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </Panel>
          </div>
        )}

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
              <div style={{ background: `${sevColor(result.severity)}11`, border: `1px solid ${sevColor(result.severity)}44`, padding: 16, marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
                  <Badge sev={result.severity}/>
                  <span style={{ fontFamily: 'Orbitron,monospace', fontSize: 22, color: sevColor(result.severity), fontWeight: 700 }}>{result.probability_pct}</span>
                  <span style={{ color: 'var(--text)', fontSize: 15, fontWeight: 600 }}>{result.threat_name}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 13 }}>
                  <div><span style={{ color: '#4a6a84' }}>IP: </span><span style={{ fontFamily: 'Share Tech Mono', color: '#00e5ff' }}>{result.ip}</span></div>
                  <div><span style={{ color: '#4a6a84' }}>Qurilma: </span><span>{result.ip_info?.device_name}</span></div>
                  <div><span style={{ color: '#4a6a84' }}>Tarmoq: </span><span>{result.ip_info?.network_type}</span></div>
                  <div><span style={{ color: '#4a6a84' }}>Tur: </span><span style={{ fontFamily: 'Share Tech Mono', color: result.ip_info?.is_local ? '#39ff14' : '#ffab00' }}>{result.ip_info?.is_local ? 'LOCAL' : 'PUBLIC'}</span></div>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
                <div>
                  <div className="panel-title" style={{ marginBottom: 10 }}>BELGILAR</div>
                  {result.indicators?.map((x, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                      <span style={{ color: '#00e5ff', fontFamily: 'Share Tech Mono', fontSize: 10, minWidth: 24 }}>[{String(i + 1).padStart(2, '0')}]</span>
                      <span style={{ fontSize: 13, color: '#94b4c8' }}>{x}</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div className="panel-title" style={{ marginBottom: 10 }}>CHORALAR</div>
                  {result.mitigation?.map((x, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 8, padding: '8px 10px', border: '1px solid var(--border2)', background: 'rgba(0,229,255,.02)' }}>
                      <span style={{ fontFamily: 'Orbitron,monospace', fontSize: 10, color: '#00e5ff', minWidth: 22 }}>{String(i + 1).padStart(2, '0')}</span>
                      <span style={{ fontSize: 12, color: '#94b4c8' }}>{x}</span>
                    </div>
                  ))}
                </div>
              </div>

              {result.algorithm_scores && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 280px', gap: 14 }}>
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
                  <div style={{ border: '1px solid var(--border2)', padding: 12, background: 'rgba(13,27,46,.42)' }}>
                    <div style={{ fontSize: 10, letterSpacing: 2, color: '#4a6a84', marginBottom: 8 }}>TELEMETRY</div>
                    {Object.entries(result.telemetry || {}).slice(0, 6).map(([key, value]) => (
                      <div key={key} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8, fontSize: 12 }}>
                        <span style={{ color: '#4a6a84' }}>{key}</span>
                        <span style={{ color: '#9fc2ea', fontFamily: 'Share Tech Mono' }}>{Array.isArray(value) ? value.join(', ') || '-' : String(value)}</span>
                      </div>
                    ))}
                  </div>
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

        {!result && !loading && !intel && (
          <Panel title="TAHLIL KUTILMOQDA" color="#4a6a84">
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 80, gap: 16 }}>
              <span style={{ fontSize: 64, opacity: .15 }}>[ ]</span>
              <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#4a6a84', letterSpacing: 2, textAlign: 'center' }}>
                TARGET YOKI IP KIRITING, SAFE PROBE QILING, SO&apos;NG THREAT TAHLILNI BOSHLANG
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
  const { logs: liveLogs, events, connected } = useLiveFeed();
  const [logs, setLogs]     = useState([]);
  const [trafficLogs, setTrafficLogs] = useState([]);
  const [paused, setPaused] = useState(false);
  const logRef = useRef();

  useEffect(() => {
    const fetchLogs = async () => {
      if (paused) return;
      try {
        const [live, traffic] = await Promise.all([
          api.getLiveLogs(),
          api.getTrafficLogs(),
        ]);
        setLogs(live.logs || []);
        setTrafficLogs(traffic.results || traffic || []);
      } catch {
        setLogs([]);
        setTrafficLogs([]);
      }
    };
    fetchLogs();
    const id = setInterval(fetchLogs, 4000);
    return () => clearInterval(id);
  }, [paused]);

  useEffect(() => {
    if (!paused && liveLogs.length) {
      setLogs(liveLogs);
    }
  }, [liveLogs, paused]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = 0;
  }, [logs.length]);

  const lvlColor = lvl => ({ error: '#ff1744', warn: '#ffab00', info: '#39ff14' }[lvl] || '#00e5ff');

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <Panel title="REAL VAQT LOG OQIMI" color="#39ff14"
        extra={
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <span style={{ alignSelf:'center', color: connected ? '#39ff14' : '#ffab00', fontFamily:'Share Tech Mono', fontSize:10 }}>
              {connected ? 'WS LIVE' : 'POLL MODE'}
            </span>
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
  const cyan = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const cyanDim = themeAccent('cyanDim', '#7ab8d4');
  const purple = themeAccent('purple', '#a855f7');
  const amberTone = themeAccent('amber', '#ffab00');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');
  const panelGlowStrong = themeAccent('panelGlowStrong', 'rgba(0,229,255,.08)');
  const panelBorder = themeAccent('panelBorder', 'rgba(0,229,255,.22)');

  const sevColor = sev => ({ critical:'#ff1744', high:'#fb923c', medium:'#ffab00', low:'#39ff14' }[sev] || '#39ff14');
  const algoColor = t => ({ Supervised:cyan, Unsupervised:amberTone, 'Deep Learning':purple }[t] || cyan);

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
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10, marginBottom: 16 }}>
                {[
                  ['Severity', selThreat?.sev?.toUpperCase(), sevColor(selThreat?.sev)],
                  ['Detectability', `${selThreat?.metrics?.detect || 0}%`, cyan],
                  ['Business Impact', `${selThreat?.metrics?.business || 0}%`, amberTone],
                ].map(([label, value, tone]) => (
                  <div key={label} style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
                    <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 6 }}>{label}</div>
                    <div style={{ color: tone, fontFamily: 'Orbitron,monospace', fontSize: 18 }}>{value}</div>
                  </div>
                ))}
              </div>
              <div style={{ marginBottom: 16 }}>
                <div className="panel-title" style={{ marginBottom: 8 }}>ALOMATLAR</div>
                <p style={{ fontSize: 13, color: cyanSoft, lineHeight: 1.7 }}>{selThreat?.signs}</p>
              </div>
              <div style={{ marginBottom: 16 }}>
                <div className="panel-title" style={{ marginBottom: 8 }}>AI YONDASHUVI</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {selThreat?.algo?.split(', ').map(a => (
                    <span key={a} style={{ padding: '4px 12px', border: `1px solid ${panelBorder}`, color: cyan, fontFamily: 'Share Tech Mono', fontSize: 11, background: panelGlow }}>{a}</span>
                  ))}
                </div>
              </div>
              <ThreatFlowPanel threat={selThreat} color={sevColor(selThreat?.sev)}/>
            </div>
          </Panel>
        </div>
      )}

      {tab === 'algorithms' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 14 }}>
          <Panel title="ML ALGORITMLAR" color={purple}>
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
              <p style={{ fontSize: 13, color: cyanSoft, lineHeight: 1.7, marginBottom: 16 }}>{selAlgo?.desc}</p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
                {[
                  ['Speed', ALGO_VISUAL_METRICS[selAlgo?.key]?.speed, '#39ff14'],
                  ['Explain', ALGO_VISUAL_METRICS[selAlgo?.key]?.explain, amberTone],
                  ['Zero-day', ALGO_VISUAL_METRICS[selAlgo?.key]?.zeroDay, '#ff1744'],
                  ['Stream', ALGO_VISUAL_METRICS[selAlgo?.key]?.stream, cyanSoft],
                ].map(([label, value, color]) => (
                  <div key={label} style={{ padding: 10, border: '1px solid var(--border2)', background: panelGlow }}>
                    <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 5 }}>{label}</div>
                    <div style={{ color, fontFamily: 'Orbitron,monospace', fontSize: 18 }}>{value}%</div>
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '14px 0', borderTop: '1px solid var(--border2)' }}>
                <span style={{ color: 'var(--text-dim)', fontSize: 13 }}>Aniqlik</span>
                <span style={{ fontFamily: 'Orbitron,monospace', fontSize: 20, color: algoColor(selAlgo?.type) }}>{selAlgo?.acc}%</span>
              </div>
            </div>
          </Panel>
        </div>
      )}

      {tab === 'algorithms' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14 }}>
          <Panel title="MODEL FIT" color="#39ff14">
            <div className="panel-body">
              {THREATS_LIST.map(item => {
                const threatFit = Math.max(38, Math.min(98, Math.round((selAlgo?.acc || 0) - (item.v === 'zero_day' ? 8 : 0) + (item.v === 'ddos' && selAlgo?.key === 'iso' ? 7 : 0) + (item.v === 'apt' && selAlgo?.key === 'lstm' ? 5 : 0))));
                return (
                  <div key={item.v} style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 4, fontSize: 12 }}>
                      <span style={{ color: cyanSoft }}>{item.l}</span>
                      <span style={{ color: '#39ff14', fontFamily: 'Share Tech Mono' }}>{threatFit}%</span>
                    </div>
                    <div style={{ height: 4, background: 'var(--border2)' }}>
                      <div style={{ width: `${threatFit}%`, height: '100%', background: `linear-gradient(90deg,#39ff14,${cyanSoft})` }}/>
                    </div>
                  </div>
                );
              })}
              <div style={{ marginTop: 16 }}>
                {Object.entries(ALGO_VISUAL_METRICS[selAlgo?.key] || {}).map(([metric, value]) => (
                  <div key={metric} style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 10 }}>
                    <span style={{ minWidth: 120, color: cyanSoft, fontSize: 12 }}>{metric}</span>
                    <div style={{ flex: 1, height: 6, background: 'var(--border2)' }}>
                      <div style={{ width: `${value}%`, height: '100%', background: `linear-gradient(90deg, ${algoColor(selAlgo?.type)}, rgba(255,255,255,.9))` }}/>
                    </div>
                    <span style={{ minWidth: 36, color: cyanSoft, fontFamily: 'Share Tech Mono', fontSize: 11 }}>{value}%</span>
                  </div>
                ))}
              </div>
            </div>
          </Panel>

          <Panel title="GLOBAL THREAT MAP" color="#ff1744">
            <div className="panel-body">
              <GlobalThreatMapPanel compact/>
            </div>
          </Panel>
        </div>
      )}

      {tab === 'datasets' && (
        <div style={{ display: 'grid', gap: 14 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr .8fr', gap: 14 }}>
            <Panel title="DATASET TUSHUNCHASI" color={amberTone}>
              <div className="panel-body" style={{ display: 'grid', gap: 12 }}>
                <div style={{ color: '#dce8f5', fontSize: 14, lineHeight: 1.8 }}>
                  Bu bo&apos;lim qaysi dataset nimaga kerakligini sodda qilib ko&apos;rsatadi:
                  qaysi hujumlar bor, qaysi featurelar muhim, qaysi model bilan ishlatish qulay va amaliy cheklovlari nimaligini.
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10 }}>
                  {[
                    ['Klassik baseline', 'NSL-KDD'],
                    ['Eng muvozanatli tanlov', 'CICIDS2017'],
                    ['Modern attack taxonomy', 'UNSW-NB15'],
                    ['IoT va botnet', 'TON_IoT / Bot-IoT'],
                  ].map(([label, value]) => (
                    <div key={label} style={{ padding: 12, border: '1px solid var(--border2)', background: panelGlow }}>
                      <div style={{ color: '#4a6a84', fontSize: 10, letterSpacing: 2, marginBottom: 6 }}>{label}</div>
                      <div style={{ color: 'var(--text)', fontSize: 14, fontWeight: 700 }}>{value}</div>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
            <Panel title="QANDAY TANLASH KERAK" color="#39ff14">
              <div className="panel-body" style={{ display: 'grid', gap: 10, fontSize: 12, color: cyanSoft, lineHeight: 1.7 }}>
                <div>1. Agar demo uchun eng tushunarli va boy dataset kerak bo&apos;lsa: <span style={{ color: '#dce8f5' }}>CICIDS2017</span>.</div>
                <div>2. Agar sizga eski IDS benchmark kerak bo&apos;lsa: <span style={{ color: '#dce8f5' }}>NSL-KDD</span>.</div>
                <div>3. Agar zero-day yoki anomaly yondashuvini ko&apos;rsatmoqchi bo&apos;lsangiz: <span style={{ color: '#dce8f5' }}>UNSW-NB15</span> yoki <span style={{ color: '#dce8f5' }}>TON_IoT</span>.</div>
                <div>4. Agar faqat DDoS va volumetric trafficni ko&apos;rsatmoqchi bo&apos;lsangiz: <span style={{ color: '#dce8f5' }}>CAIDA DDoS</span>.</div>
              </div>
            </Panel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 14 }}>
            {DATASETS.map(d => (
              <DatasetIntelCard key={d.name} dataset={d} />
            ))}
          </div>
        </div>
      )}

      {tab === 'siem' && (
        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 14 }}>
          <Panel title="SIEM TIZIMLAR" color={cyan}>
            <div style={{ padding: '6px 0' }}>
              {SIEM_TOOLS.map(s => (
                <div key={s.key} onClick={() => setSelSiem(s)} style={{
                  padding: '12px 16px', cursor: 'pointer',
                  borderLeft: `2px solid ${selSiem?.key === s.key ? cyan : 'transparent'}`,
                  background: selSiem?.key === s.key ? panelGlowStrong : 'transparent',
                  transition: 'all .15s',
                }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: selSiem?.key === s.key ? cyan : 'var(--text)', marginBottom: 2 }}>{s.name}</div>
                  <div style={{ fontSize: 10, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>{s.sub}</div>
                </div>
              ))}
            </div>
          </Panel>
          <Panel title={selSiem?.name?.toUpperCase() || ''} color={cyan}>
            <div className="panel-body">
              <div style={{ marginBottom: 14, padding: 14, border: '1px solid var(--border2)', background: panelGlow }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>{selSiem?.name}</div>
                <div style={{ fontSize: 11, color: cyanDim, fontFamily: 'Share Tech Mono', marginBottom: 10 }}>{selSiem?.best}</div>
                <p style={{ fontSize: 14, color: cyanSoft, lineHeight: 1.8 }}>{selSiem?.detail}</p>
              </div>
              <SIEMArchitecturePanel tool={selSiem}/>
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}

function SIEMPage() {
  const [selected, setSelected] = useState(SIEM_TOOLS[0]);
  const cyan  = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const cyanDim  = themeAccent('cyanDim', '#7ab8d4');
  const green = '#39ff14';
  const panelGlow   = themeAccent('panelGlow',   'rgba(0,229,255,.05)');
  const panelBorder = themeAccent('panelBorder', 'rgba(0,229,255,.22)');

  const toolType  = { splunk:'Enterprise', qradar:'Enterprise', sentinel:'Cloud', elk:'Open-source', wazuh:'Open-source', graylog:'Open-source' };
  const typeColor = { Enterprise:'#ffab00', Cloud:'#00e5ff', 'Open-source':'#39ff14' };
  const detail    = SIEM_DETAIL_MAP[selected.key] || { sources:[], pipeline:[], strengths:[], fit:[], ops:{} };

  const FLOW_STEPS = [
    { n:'01', title:'Log Yig\'ish',       desc:'Server, firewall, endpoint va cloud\'dan xavfsizlik hodisalari yig\'iladi' },
    { n:'02', title:'Normallashtirish',   desc:'Turli formatlardagi loglar yagona standart ko\'rinishga o\'tkaziladi' },
    { n:'03', title:'Korrelyatsiya',      desc:'AI va qoidalar orqali bog\'liq hodisalar birlashtiriladi va pattern topiladi' },
    { n:'04', title:'Ogohlantirish',      desc:'Xavfli harakatlar uchun avtomatik alert va ticket yaratiladi' },
    { n:'05', title:'Javob Berish',       desc:'SOC jamoasi yoki SOAR avtomatik tizimi tahdidni bartaraf etadi' },
  ];

  return (
    <div style={{ animation:'fadeUp .3s ease', display:'grid', gap:14 }}>

      {/* ── 1. SIEM NIMA? ──────────────────────────────────────── */}
      <Panel title="SIEM — Security Information and Event Management" color={cyan}>
        <div className="panel-body">
          <div style={{ display:'grid', gridTemplateColumns:'1.2fr 1fr', gap:14 }}>
            <div style={{ padding:16, border:`1px solid ${panelBorder}`, background:panelGlow }}>
              <div style={{ fontSize:14, color:cyanSoft, lineHeight:2, marginBottom:10 }}>
                <span style={{ color:cyan, fontWeight:700 }}>SIEM</span> — tashkilotdagi barcha qurilmalar, serverlar va
                ilovalardan xavfsizlik hodisalarini <span style={{ color:green }}>yig'uvchi</span>,{' '}
                <span style={{ color:'#ffab00' }}>tahlil qiluvchi</span> va real vaqtda{' '}
                <span style={{ color:'#ff6b7f' }}>ogohlantirish beruvchi</span> markaziy platforma.
              </div>
              <div style={{ fontSize:12, color:cyanDim, lineHeight:1.8 }}>
                SOC (Security Operations Center) mutaxassislari SIEM yordamida yuzlab tizimni
                bitta konsoldan kuzatadi va kiberhujumlarni erta bosqichda aniqlaydi.
              </div>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
              {[
                { label:'SIEM nima qiladi?',  val:"Log yig'ish + tahlil",   color:cyan },
                { label:'Kim foydalanadi?',   val:'SOC jamoalari',           color:green },
                { label:'Asosiy maqsad',      val:'Tahdidni erta aniqlash',  color:'#ffab00' },
                { label:'Natija',             val:'Alert + Incident',        color:'#ff6b7f' },
              ].map(({ label, val, color }) => (
                <div key={label} style={{ padding:12, border:'1px solid var(--border2)', background:`${color}08` }}>
                  <div style={{ fontSize:10, color:'#4a6a84', marginBottom:5 }}>{label}</div>
                  <div style={{ fontSize:13, color, fontFamily:'Share Tech Mono', lineHeight:1.4 }}>{val}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      {/* ── 2. SIEM QANDAY ISHLAYDI? ───────────────────────────── */}
      <Panel title="SIEM QANDAY ISHLAYDI? — 5 ta ketma-ket bosqich" color={green}>
        <div className="panel-body">
          <div style={{ display:'grid', gridTemplateColumns:'repeat(5, 1fr)', gap:6, position:'relative' }}>
            {FLOW_STEPS.map((step, i) => (
              <div key={step.n} style={{ position:'relative' }}>
                <div style={{
                  padding:'14px 12px', border:`1px solid ${green}44`, background:`${green}07`,
                  minHeight:130, display:'flex', flexDirection:'column', gap:8,
                }}>
                  <div style={{
                    width:28, height:28, border:`1px solid ${green}88`, background:`${green}15`,
                    display:'flex', alignItems:'center', justifyContent:'center',
                    fontFamily:'Share Tech Mono', fontSize:12, color:green,
                  }}>{step.n}</div>
                  <div style={{ fontSize:13, fontWeight:700, color:'var(--text)' }}>{step.title}</div>
                  <div style={{ fontSize:11, color:cyanDim, lineHeight:1.6, flex:1 }}>{step.desc}</div>
                </div>
                {i < 4 && (
                  <div style={{
                    position:'absolute', top:'50%', right:-10, transform:'translateY(-50%)',
                    color:green, fontSize:20, zIndex:2, lineHeight:1,
                  }}>›</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </Panel>

      {/* ── 3. TOOL TANLASH + DETAIL ───────────────────────────── */}
      <div style={{ display:'grid', gridTemplateColumns:'280px 1fr', gap:14 }}>
        <Panel title="SIEM VOSITALARINI TANLANG" color={cyan}>
          <div className="panel-body" style={{ display:'grid', gap:6 }}>
            <div style={{ padding:'8px 10px', background:panelGlow, border:`1px solid ${panelBorder}`, fontSize:11, color:cyanDim, lineHeight:1.6, marginBottom:4 }}>
              Bosib tanlang — o'ngda batafsil ma'lumot ko'rsatiladi
            </div>
            {SIEM_TOOLS.map(tool => {
              const active = selected.key === tool.key;
              const ttype  = toolType[tool.key];
              const tcolor = typeColor[ttype];
              return (
                <div
                  key={tool.key}
                  onClick={() => setSelected(tool)}
                  style={{
                    padding:'10px 12px', border:`1px solid ${active ? panelBorder : 'var(--border2)'}`,
                    background: active ? `${cyan}0e` : panelGlow,
                    cursor:'pointer', transition:'all .18s',
                    display:'flex', alignItems:'center', gap:10,
                  }}
                >
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:13, fontWeight:700, color: active ? cyanSoft : 'var(--text)' }}>{tool.name}</div>
                    <div style={{ fontSize:10, color:cyanDim, marginTop:2, fontFamily:'Share Tech Mono' }}>{tool.sub}</div>
                  </div>
                  <div style={{
                    fontSize:9, padding:'2px 7px', border:`1px solid ${tcolor}55`,
                    background:`${tcolor}12`, color:tcolor, fontFamily:'Share Tech Mono', whiteSpace:'nowrap',
                  }}>{ttype}</div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title={`TANLANGAN: ${selected.name.toUpperCase()}`} color={cyanSoft}>
          <div className="panel-body" style={{ display:'grid', gap:10 }}>

            {/* Tavsif */}
            <div style={{ padding:14, border:`1px solid ${panelBorder}`, background:panelGlow }}>
              <div style={{ fontSize:13, color:cyanSoft, lineHeight:1.85 }}>{selected.detail}</div>
              <div style={{ marginTop:8, fontSize:12, color:'#4a6a84' }}>
                Eng mos: <span style={{ color:cyan }}>{selected.best}</span>
                <span style={{ marginLeft:16, color:typeColor[toolType[selected.key]] }}>[ {toolType[selected.key]} ]</span>
              </div>
            </div>

            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
              {/* Ma'lumot manbalari */}
              <div style={{ border:'1px solid var(--border2)', background:panelGlow, padding:14 }}>
                <div style={{ fontSize:10, letterSpacing:2, color:'#4a6a84', marginBottom:10 }}>
                  MA'LUMOT MANBALARI — qayerdan log keladi
                </div>
                <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
                  {detail.sources.map(s => (
                    <span key={s} style={{
                      padding:'4px 10px', border:`1px solid ${cyan}33`,
                      background:`${cyan}0a`, color:cyanSoft, fontSize:11, fontFamily:'Share Tech Mono',
                    }}>{s}</span>
                  ))}
                </div>
              </div>

              {/* Ishlash zanjiri */}
              <div style={{ border:'1px solid var(--border2)', background:panelGlow, padding:14 }}>
                <div style={{ fontSize:10, letterSpacing:2, color:'#4a6a84', marginBottom:10 }}>
                  ISHLASH ZANJIRI — ma'lumot ichida qanday oqadi
                </div>
                <div style={{ display:'flex', alignItems:'center', flexWrap:'wrap', gap:4 }}>
                  {detail.pipeline.map((step, i) => (
                    <React.Fragment key={step}>
                      <span style={{
                        padding:'5px 10px', border:`1px solid ${panelBorder}`,
                        background:`${cyan}0d`, color:cyan, fontSize:11, fontFamily:'Share Tech Mono',
                      }}>{step}</span>
                      {i < detail.pipeline.length - 1 && (
                        <span style={{ color:cyanDim, fontSize:14 }}>→</span>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            </div>

            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
              {/* Operatsion ko'rsatkichlar */}
              <div style={{ border:'1px solid var(--border2)', background:panelGlow, padding:14 }}>
                <div style={{ fontSize:10, letterSpacing:2, color:'#4a6a84', marginBottom:12 }}>
                  OPERATSION KO'RSATKICHLAR
                </div>
                {[
                  { label:"Tezkor joylash",  key:'deploy',   color:'#39ff14', hint:'qanchalik tez ishga tushadi' },
                  { label:"Sozlash osonligi",key:'tuning',   color:'#ffab00', hint:'konfiguratsiya qanchalik oson' },
                  { label:"O'rganish egri",  key:'learning', color:'#9fc2ea', hint:'xodim qanchalik tez o\'rganadi' },
                ].map(({ label, key, color, hint }) => (
                  <div key={key} style={{ marginBottom:14 }}>
                    <div style={{ display:'flex', justifyContent:'space-between', marginBottom:2, fontSize:12 }}>
                      <span style={{ color:cyanSoft }}>{label}</span>
                      <span style={{ color, fontFamily:'Share Tech Mono' }}>{detail.ops[key] || 0}%</span>
                    </div>
                    <div style={{ fontSize:10, color:'#4a6a84', marginBottom:4 }}>{hint}</div>
                    <div style={{ height:4, background:'var(--border2)' }}>
                      <div style={{ width:`${detail.ops[key]||0}%`, height:'100%', background:`linear-gradient(90deg,${color},rgba(255,255,255,.7))` }}/>
                    </div>
                  </div>
                ))}
              </div>

              {/* Kuchli tomonlar + mos tashkilotlar */}
              <div style={{ border:'1px solid var(--border2)', background:panelGlow, padding:14 }}>
                <div style={{ fontSize:10, letterSpacing:2, color:'#4a6a84', marginBottom:10 }}>KUCHLI TOMONLARI</div>
                {detail.strengths.map(item => (
                  <div key={item} style={{ display:'flex', gap:8, marginBottom:8, alignItems:'flex-start' }}>
                    <span style={{ color:green, fontFamily:'Share Tech Mono', fontSize:13 }}>+</span>
                    <span style={{ color:cyanSoft, fontSize:12, lineHeight:1.5 }}>{item}</span>
                  </div>
                ))}
                <div style={{ marginTop:12, borderTop:'1px solid var(--border2)', paddingTop:10 }}>
                  <div style={{ fontSize:10, color:'#4a6a84', marginBottom:6 }}>USHBU TASHKILOTLAR UCHUN QULAY:</div>
                  {detail.fit.map(item => (
                    <div key={item} style={{ color:cyan, fontSize:12, lineHeight:1.7 }}>• {item}</div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </Panel>
      </div>

      {/* ── 4. QOBILIYAT TAQQOSLASH ─────────────────────────────── */}
      <Panel title="BARCHA 6 TA SIEM NI SOLISHTIRING — qobiliyat reytingi" color={cyanSoft}>
        <div className="panel-body">
          <div style={{ marginBottom:14, padding:12, border:'1px solid var(--border2)', background:panelGlow, fontSize:12, color:cyanSoft, lineHeight:1.8 }}>
            Ustun qanchalik <span style={{ color:green }}>baland</span> bo'lsa, o'sha SIEM shu yo'nalishda shunchalik kuchli.{' '}
            <span style={{ color:cyan }}>Real vaqt</span> — alert qanchalik tez chiqadi &nbsp;|&nbsp;
            <span style={{ color:'#9fc2ea' }}>ML/AI</span> — anomaliya va xulq tahlili darajasi &nbsp;|&nbsp;
            <span style={{ color:'#ffab00' }}>Narx samaradorligi</span> — xarajatga nisbatan foyda
          </div>
          {SIEM_CAPABILITY_ROWS.map(row => (
            <div key={row.key} style={{ marginBottom:20 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'baseline', marginBottom:8 }}>
                <div style={{ color:'var(--text)', fontSize:13, fontWeight:700 }}>{row.label}</div>
                <div style={{ color:cyanDim, fontSize:11 }}>{row.desc}</div>
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'repeat(6, minmax(0,1fr))', gap:6 }}>
                {SIEM_TOOLS.map(tool => (
                  <div
                    key={`${row.key}-${tool.key}`}
                    style={{
                      background: selected.key === tool.key ? `${row.color}15` : panelGlow,
                      border:`1px solid ${selected.key === tool.key ? `${row.color}66` : 'var(--border2)'}`,
                      padding:8,
                    }}
                  >
                    <div style={{ height:56, background:'rgba(255,255,255,.04)', position:'relative', overflow:'hidden', marginBottom:6 }}>
                      <div style={{
                        position:'absolute', left:0, right:0, bottom:0,
                        height:`${tool.scores[row.key]}%`,
                        background:`linear-gradient(180deg,${row.color},${cyanSoft})`,
                      }}/>
                      <div style={{
                        position:'absolute', bottom:3, left:0, right:0,
                        textAlign:'center', fontSize:10, color:'#fff', fontFamily:'Share Tech Mono',
                      }}>{tool.scores[row.key]}%</div>
                    </div>
                    <div style={{ fontSize:10, color:cyanDim, textAlign:'center', fontFamily:'Share Tech Mono' }}>
                      {tool.name.split(' ')[0]}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </Panel>

      {/* ── 5. QAYSI LOYIHA UCHUN QAYSI SIEM? ─────────────────── */}
      <Panel title="QAYSI LOYIHA UCHUN QAYSI SIEM? — tez qaror qabul qiling" color={green}>
        <div className="panel-body">
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10 }}>
            {[
              { type:'Katta korxona',     best:'Splunk / QRadar', why:'Yuzlab server, compliance va audit talablari mavjud',        color:'#ffab00' },
              { type:'Azure / Cloud',     best:'MS Sentinel',     why:'Azure AD va Microsoft 365 bilan chuqur integratsiya kerak', color:'#00e5ff' },
              { type:'Ochiq kod yechim',  best:'ELK / Wazuh',     why:'Byudjet cheklangan, IT jamoasi o\'zi sozlay oladi',         color:'#39ff14' },
              { type:"O'rta hajmli SOC",  best:'Graylog',         why:'Tez deploy, kam operatsion yuk, sodda interfeys kerak',     color:'#9fc2ea' },
            ].map(({ type, best, why, color }) => (
              <div key={type} style={{ padding:16, border:`1px solid ${color}44`, background:`${color}07` }}>
                <div style={{ fontSize:10, color:'#4a6a84', marginBottom:4, fontFamily:'Share Tech Mono' }}>HOLAT</div>
                <div style={{ fontSize:13, color:'var(--text)', fontWeight:700, marginBottom:10 }}>{type}</div>
                <div style={{ fontSize:10, color:'#4a6a84', marginBottom:4 }}>TAVSIYA</div>
                <div style={{ fontSize:16, color, fontWeight:700, fontFamily:'Share Tech Mono', marginBottom:10 }}>{best}</div>
                <div style={{ fontSize:11, color:cyanDim, lineHeight:1.6, borderTop:`1px solid ${color}22`, paddingTop:8, marginTop:4 }}>{why}</div>
              </div>
            ))}
          </div>
        </div>
      </Panel>

    </div>
  );
}

function estimateTopology(interfaces = [], devices = []) {
  const activeInterfaces = interfaces.filter(item => item.ip || item.gateway || item.ssid);
  const gatewayCount = activeInterfaces.filter(item => item.gateway).length;
  const wifiCount = activeInterfaces.filter(item => item.adapter_type?.toLowerCase() === 'wireless lan').length;
  const deviceCount = devices.length;

  if (gatewayCount >= 2 || activeInterfaces.length >= 3) {
    return {
      name: 'Hybrid / Tree (taxminiy)',
      reason: 'Bir nechta interface yoki gateway topildi. Bu ko\'p qatlamli yoki aralash segment borligini ko\'rsatadi.',
      color: '#a78bfa',
    };
  }
  if (wifiCount >= 1 && deviceCount >= 5) {
    return {
      name: 'Star Topology (taxminiy)',
      reason: 'Ko\'p qurilma bitta gateway orqali ko\'rinmoqda. Uy/ofis Wi-Fi va switch-markazli LAN uchun odatiy holat.',
      color: '#39ff14',
    };
  }
  if (deviceCount <= 2) {
    return {
      name: 'Bus / Point Segment (taxminiy)',
      reason: 'Qurilmalar kam ko\'rinmoqda. Bu kichik segment, lab yoki shared-medium qism bo\'lishi mumkin.',
      color: '#ffab00',
    };
  }
  return {
    name: 'Star Topology (taxminiy)',
    reason: 'Ko\'p lokal tarmoqlarda endpointlar markaziy switch yoki routerga ulanadi. Shu sabab eng ehtimoliy shakl shu.',
    color: '#39ff14',
  };
}

function TopologyVisualPanel({ guideKey }) {
  const visual = TOPOLOGY_VISUALS[guideKey] || TOPOLOGY_VISUALS.star;
  const cyan = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const cyanDim = themeAccent('cyanDim', '#7ab8d4');
  const purple = themeAccent('purple', '#8a7cf5');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');
  const panelBorder = themeAccent('panelBorder', 'rgba(0,229,255,.22)');
  const nodeTone = tone => ({
    hostile: { border:'rgba(255,107,87,.55)', bg:'rgba(255,107,87,.12)', color:'#ffd5cf' },
    core: { border:'rgba(107,210,20,.55)', bg:'rgba(107,210,20,.12)', color:'#def8cf' },
    service: { border:panelBorder, bg:panelGlow, color:cyanSoft },
    internal: { border:'rgba(189,232,153,.5)', bg:'rgba(189,232,153,.12)', color:'#ebf8dc' },
    observer: { border:`${purple}88`, bg:`${purple}14`, color:cyanSoft },
  }[tone]);
  const visualNodeMap = Object.fromEntries(visual.nodes.map(node => [node.key, node]));

  return (
    <div style={{ border: '1px solid var(--border2)', background: `radial-gradient(circle at top, ${panelGlow}, rgba(3,7,18,.98))`, minHeight: 420, position: 'relative', overflow: 'hidden', perspective: 1200 }}>
      <div style={{ position:'absolute', inset:18, border:`1px solid ${panelBorder}`, transform:'rotateX(68deg) translateY(135px)', transformStyle:'preserve-3d', boxShadow:`0 0 80px ${panelGlow} inset` }}/>
      <div style={{ position:'absolute', inset:'10% 8%', background:`linear-gradient(180deg, ${panelGlow}, transparent)`, transform:'rotateX(62deg) translateY(112px)', transformStyle:'preserve-3d' }}/>
      <svg viewBox="0 0 100 100" style={{ position:'absolute', inset:0, width:'100%', height:'100%' }}>
        {[...Array(9)].map((_, index) => (
          <line key={`visual-grid-v-${index}`} x1={8 + index * 10} y1="8" x2={8 + index * 10} y2="92" stroke="rgba(57,255,20,.12)" strokeWidth="0.15"/>
        ))}
        {[...Array(5)].map((_, index) => (
          <line key={`visual-grid-h-${index}`} x1="6" y1={16 + index * 16} x2="94" y2={16 + index * 16} stroke="rgba(57,255,20,.1)" strokeWidth="0.15"/>
        ))}
        {visual.edges.map(([fromKey, toKey], index) => {
          const from = visualNodeMap[fromKey];
          const to = visualNodeMap[toKey];
          const edgeTone = index % 2 === 0 ? '#7df542' : purple;
          return (
            <g key={`${fromKey}-${toKey}`}>
              <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke={edgeTone} strokeWidth="1.4" opacity="0.92"/>
              <circle r="0.65" fill={edgeTone} style={{ filter:`drop-shadow(0 0 6px ${edgeTone})`, animation:`packetTravel ${2.2 + (index % 3) * .3}s linear ${index * .18}s infinite` }}>
                <animateMotion dur={`${2.2 + (index % 3) * .3}s`} begin={`${index * .18}s`} repeatCount="indefinite" path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`}/>
              </circle>
            </g>
          );
        })}
      </svg>
      {visual.nodes.map((node, index) => {
        const tone = nodeTone(node.tone);
        return (
          <div key={node.key} style={{
            position:'absolute',
            left:`calc(${node.x}% - 54px)`,
            top:`calc(${node.y}% - 24px)`,
            width:108,
            minHeight:48,
            padding:'10px 8px',
            border:`1px solid ${tone.border}`,
            background:`linear-gradient(180deg, ${tone.bg}, rgba(3,7,18,.92))`,
            color:tone.color,
            textAlign:'center',
            fontSize:12,
            lineHeight:1.35,
            boxShadow:`0 14px 32px rgba(0,0,0,.28), 0 0 20px ${tone.bg}`,
            whiteSpace:'pre-line',
            transform:'translateZ(28px)',
            animation:`float3d ${4.8 + (index % 3) * .6}s ease-in-out infinite`,
          }}>
            {node.label}
          </div>
        );
      })}
      <div style={{ position:'absolute', left:18, right:18, bottom:14, padding:'10px 12px', border:`1px solid ${panelBorder}`, background:'rgba(3,7,18,.45)', color:cyanDim, fontSize:12, lineHeight:1.7 }}>
        {visual.caption}
      </div>
    </div>
  );
}

function TopologyPage() {
  const { events } = useLiveFeed();
  const [interfaces, setInterfaces] = useState([]);
  const [devices, setDevices] = useState([]);
  const [scenarioKey, setScenarioKey] = useState('normal');
  const [guideKey, setGuideKey] = useState('star');
  const scenario = TOPOLOGY_SCENARIOS[scenarioKey];
  const guide = NETWORK_TYPE_GUIDES.find(item => item.key === guideKey) || NETWORK_TYPE_GUIDES[0];
  const estimatedTopology = estimateTopology(interfaces, devices);
  const cyan = themeAccent('cyan', '#00e5ff');
  const cyanSoft = themeAccent('cyanSoft', '#9fc2ea');
  const cyanDim = themeAccent('cyanDim', '#7ab8d4');
  const purple = themeAccent('purple', '#8a7cf5');
  const panelGlow = themeAccent('panelGlow', 'rgba(0,229,255,.05)');
  const panelBorder = themeAccent('panelBorder', 'rgba(0,229,255,.22)');
  const nodeMap = Object.fromEntries(TOPOLOGY_NODES.map(node => [node.key, node]));
  const stateStyle = state => ({
    ok: { color:'#6bd214', width:2.2 },
    warn: { color:'#e1c246', width:2.2 },
    attack: { color:'#ff6b57', width:2.6 },
    blocked: { color:cyanSoft, width:2.6 },
    monitor: { color:purple, width:1.8 },
    idle: { color:cyanDim, width:1.4 },
  }[state] || { color:cyanDim, width:1.4 });
  const nodeTone = tone => ({
    hostile: { border:'rgba(255,107,87,.55)', bg:'rgba(255,107,87,.12)', color:'#ffd5cf' },
    core: { border:'rgba(107,210,20,.55)', bg:'rgba(107,210,20,.12)', color:'#def8cf' },
    service: { border:panelBorder, bg:panelGlow, color:cyanSoft },
    internal: { border:'rgba(189,232,153,.5)', bg:'rgba(189,232,153,.12)', color:'#ebf8dc' },
    observer: { border:`${purple}88`, bg:`${purple}14`, color:cyanSoft },
  }[tone]);
  const packetCount = scenarioKey === 'attack' ? 8 : scenarioKey === 'blocked' ? 3 : 5;

  useEffect(() => {
    let active = true;
    const loadLocalShape = async () => {
      try {
        const [interfacePayload, devicePayload] = await Promise.all([
          api.getInterfaces(),
          api.scanNetwork(),
        ]);
        if (!active) return;
        setInterfaces(interfacePayload.interfaces || []);
        setDevices(devicePayload.devices || []);
      } catch {
        if (!active) return;
        setInterfaces([]);
        setDevices([]);
      }
    };
    loadLocalShape();
    return () => { active = false; };
  }, []);

  return (
    <div style={{ animation: 'fadeUp .3s ease', display: 'grid', gap: 14 }}>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:14 }}>
        <Panel title="HOZIRGI ULANISHINGIZ TAXMINIY TOPOLOGIYASI" color={estimatedTopology.color}>
          <div className="panel-body" style={{ display:'grid', gap:12 }}>
            <div style={{ padding:14, border:'1px solid var(--border2)', background:panelGlow }}>
              <div style={{ color: estimatedTopology.color, fontFamily:'Orbitron,monospace', fontSize:18, marginBottom:6 }}>{estimatedTopology.name}</div>
              <div style={{ color:cyanSoft, fontSize:13, lineHeight:1.8 }}>{estimatedTopology.reason}</div>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0, 1fr))', gap:10 }}>
              {[
                ['Interfeyslar', interfaces.length || 0, cyan],
                ['Topilgan qurilmalar', devices.length || 0, '#39ff14'],
                ['Gatewayli interface', interfaces.filter(item => item.gateway).length || 0, '#ffab00'],
              ].map(([label, value, tone]) => (
                <div key={label} style={{ padding:12, border:'1px solid var(--border2)', background:'rgba(3,7,18,.45)' }}>
                  <div style={{ color:'#4a6a84', fontSize:10, letterSpacing:2, marginBottom:5 }}>{label}</div>
                  <div style={{ color:tone, fontFamily:'Orbitron,monospace', fontSize:18 }}>{value}</div>
                </div>
              ))}
            </div>
            <div style={{ display:'grid', gap:8 }}>
              {interfaces.slice(0, 3).map(item => (
                <div key={item.name} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:'rgba(3,7,18,.45)' }}>
                  <div style={{ color:'#dce8f5', fontSize:12, marginBottom:4 }}>{displayText(item.name)}</div>
                  <div style={{ color:cyanDim, fontSize:11, fontFamily:'Share Tech Mono' }}>
                    {displayText(item.ip)} | GW {displayText(item.gateway)} | {displayText(item.ssid || item.adapter_type)}
                  </div>
                </div>
              ))}
            </div>
            <div style={{ color:cyanDim, fontSize:12, lineHeight:1.7 }}>
              Bu avtomatik taxmin. Real topologiya managed switch, VLAN, AP controller yoki router ortida murakkabroq bo&apos;lishi mumkin.
            </div>
          </div>
        </Panel>

        <Panel title="TOPOLOGY VISUAL LAB" color={purple}>
          <div className="panel-body" style={{ display:'grid', gap:12 }}>
            <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
              {NETWORK_TYPE_GUIDES.map(item => (
                <button key={item.key} className={`filter-btn${guideKey === item.key ? ' active' : ''}`} onClick={() => setGuideKey(item.key)}>
                  {item.name}
                </button>
              ))}
            </div>
            <TopologyVisualPanel guideKey={guideKey}/>
          </div>
        </Panel>
      </div>

      <Panel title="LIVE SECURITY FLOW SCENE" color="#39ff14">
        <div className="panel-body">
          <div style={{ marginBottom: 14, padding: 12, border:'1px solid var(--border2)', background:panelGlow, color:cyanSoft, fontSize:13, lineHeight:1.75 }}>
            Bu sahna aniq fizik topologiyani emas, balki tarmoq ichida threat oqimi qanday harakatlanishini ko&apos;rsatadi:
            <span style={{ fontFamily:'Share Tech Mono', color:'#dce8f5' }}> attacker to firewall/AI IDS to servislar to ichki segment</span>.
            Yuqoridagi <span style={{ fontFamily:'Share Tech Mono', color:'#dce8f5' }}>Topology Visual Lab</span> esa sof topologiya turlarini tushuntiradi.
          </div>
          <div style={{ position: 'relative', minHeight: 430, border: '1px solid var(--border2)', background: `radial-gradient(circle at top, ${panelGlow}, rgba(3,7,18,.98))`, overflow: 'hidden', perspective: 1200 }}>
            <div style={{ position:'absolute', inset:18, border:`1px solid ${panelBorder}`, transform:'rotateX(68deg) translateY(135px)', transformStyle:'preserve-3d', boxShadow:`0 0 80px ${panelGlow} inset` }}/>
            <div style={{ position:'absolute', inset:'10% 8%', background:`linear-gradient(180deg, ${panelGlow}, transparent)`, transform:'rotateX(62deg) translateY(112px)', transformStyle:'preserve-3d' }}/>
            <svg viewBox="0 0 100 100" style={{ position:'absolute', inset:0, width:'100%', height:'100%' }}>
              {[...Array(9)].map((_, index) => (
                <line key={`grid-v-${index}`} x1={8 + index * 10} y1="8" x2={8 + index * 10} y2="92" stroke="rgba(57,255,20,.12)" strokeWidth="0.15"/>
              ))}
              {[...Array(5)].map((_, index) => (
                <line key={`grid-h-${index}`} x1="6" y1={16 + index * 16} x2="94" y2={16 + index * 16} stroke="rgba(57,255,20,.1)" strokeWidth="0.15"/>
              ))}
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
              {TOPOLOGY_EDGES.filter(edge => scenario.linkStates[edge.key] !== 'idle').map((edge, edgeIndex) => {
                const from = nodeMap[edge.from];
                const to = nodeMap[edge.to];
                const style = stateStyle(scenario.linkStates[edge.key]);
                return [...Array(Math.max(1, Math.floor(packetCount / 3)))].map((_, index) => (
                  <circle key={`${edge.key}-${index}`} r="0.7" fill={style.color} style={{ filter:`drop-shadow(0 0 6px ${style.color})`, animation:`packetTravel ${2.2 + index * .35}s linear ${(edgeIndex * .18) + index * .3}s infinite` }}>
                    <animateMotion dur={`${2.2 + index * .35}s`} begin={`${(edgeIndex * .18) + index * .3}s`} repeatCount="indefinite" path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`}/>
                  </circle>
                ));
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
                  background:`linear-gradient(180deg, ${tone.bg}, rgba(3,7,18,.92))`,
                  color:tone.color,
                  textAlign:'center',
                  fontSize:12,
                  lineHeight:1.35,
                  boxShadow:`0 14px 32px rgba(0,0,0,.28), 0 0 20px ${tone.bg}`,
                  whiteSpace:'pre-line',
                  transform:'translateZ(28px)',
                  animation:'float3d 5.5s ease-in-out infinite',
                }}>
                  {node.label}
                </div>
              );
            })}
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'1.2fr .8fr', gap:12, marginTop: 14 }}>
            <div style={{ border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)', padding:14 }}>
              <div style={{ fontSize:10, letterSpacing:2, color:'#4a6a84', marginBottom:10 }}>TANLANGAN TOPOLOGIYA IZOHI</div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
                <div>
                  <div style={{ fontSize:18, color:'#dce8f5', fontWeight:700, marginBottom:6 }}>{guide.name}</div>
                  <div style={{ fontSize:11, color:cyanDim, fontFamily:'Share Tech Mono', marginBottom:10 }}>{guide.fit}</div>
                  <div style={{ fontSize:13, color:cyanSoft, lineHeight:1.7 }}>{guide.summary}</div>
                </div>
                <div style={{ display:'grid', gap:8 }}>
                  {guide.pros.map(point => (
                    <div key={point} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:panelGlow, color:cyanSoft, fontSize:12 }}>
                      {point}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div style={{ border:'1px solid var(--border2)', background:'rgba(13,27,46,.45)', padding:14 }}>
              <div style={{ fontSize:10, letterSpacing:2, color:'#4a6a84', marginBottom:10 }}>LIVE SCENE METRICS</div>
              {[ 
                ['Nodes', Object.keys(nodeMap).length, cyan],
                ['Active links', Object.values(scenario.linkStates).filter(value => value !== 'idle').length, '#39ff14'],
                ['Threat intensity', scenarioKey === 'attack' ? '92%' : scenarioKey === 'blocked' ? '26%' : '14%', scenarioKey === 'attack' ? '#ff1744' : scenarioKey === 'blocked' ? '#ffab00' : cyanSoft],
                ['Selected topology', guide.name, '#dce8f5'],
              ].map(([label, value, color]) => (
                <div key={label} style={{ display:'flex', justifyContent:'space-between', gap:10, padding:'10px 0', borderBottom:'1px solid var(--border2)', fontSize:12 }}>
                  <span style={{ color:'#4a6a84' }}>{label}</span>
                  <span style={{ color, fontFamily:'Share Tech Mono' }}>{displayText(value)}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginTop: 14 }}>
            {Object.entries(TOPOLOGY_SCENARIOS).map(([key, item]) => (
              <button key={key} className={`filter-btn${scenarioKey === key ? ' active' : ''}`} onClick={() => setScenarioKey(key)}>
                {item.label}
              </button>
            ))}
          </div>
          <div style={{ marginTop: 12, padding: 14, border:'1px solid var(--border2)', background:panelGlow, color:cyanSoft, fontSize:13, lineHeight:1.8 }}>
            {scenario.summary}
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0, 1fr))', gap:12, marginTop:12 }}>
              {[
                ['Ingress', scenario.linkStates.ingress, stateStyle(scenario.linkStates.ingress).color],
                ['Core services', `${['web','db','mail'].filter(key => scenario.linkStates[key] !== 'ok').length || 0} ta alert`, cyanSoft],
                ['AI telemetry', scenario.linkStates.telemetry, purple],
              ].map(([label, value, tone]) => (
                <div key={label} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:'rgba(3,7,18,.45)' }}>
                  <div style={{ color:'#4a6a84', fontSize:10, letterSpacing:2, marginBottom:5 }}>{label}</div>
                  <div style={{ color:tone, fontFamily:'Orbitron,monospace', fontSize:15 }}>{String(value).toUpperCase()}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      <div style={{ display:'grid', gridTemplateColumns:'1fr', gap:14, marginTop:14 }}>
        <Panel title="EVENT BUS" color={cyan}>
          <div className="panel-body" style={{ maxHeight: 260, overflowY:'auto', display:'grid', gap:8 }}>
            {events.slice(0, 12).map((event, index) => (
              <div key={`${event.kind}-${event.timestamp}-${index}`} style={{ padding:'10px 12px', border:'1px solid var(--border2)', background:panelGlow }}>
                <div style={{ display:'flex', justifyContent:'space-between', gap:8, marginBottom:6 }}>
                  <span style={{ color:cyan, fontFamily:'Share Tech Mono', fontSize:11 }}>{String(event.kind || 'event').toUpperCase()}</span>
                  <span style={{ color:'#4a6a84', fontFamily:'Share Tech Mono', fontSize:10 }}>{fmtTime(event.timestamp)}</span>
                </div>
                <div style={{ color:cyanSoft, fontSize:12, lineHeight:1.6 }}>
                  {displayText(event.payload?.attack_type || event.payload?.summary || event.payload?.message || event.payload?.ip || 'Event')}
                </div>
              </div>
            ))}
            {events.length === 0 && <div style={{ color:'#4a6a84', fontSize:12 }}>Hozircha real event kelmagan.</div>}
          </div>
        </Panel>
      </div>
    </div>
  );
}

// ── SETTINGS PAGE ──────────────────────────────────────────────────────────
function SettingsPage() {
  const [toggles, setToggles] = useState({ realtime:true, sound:false, email:true, autoBlock:true, twofa:true });
  const toggle = k => setToggles(p => ({ ...p, [k]: !p[k] }));
  const [tgToken, setTgToken] = useState(() => localStorage.getItem('cg_tg_token') || '');
  const [tgChat, setTgChat] = useState(() => localStorage.getItem('cg_tg_chat') || '');
  const [tgMsg, setTgMsg] = useState('');
  const [tgLoading, setTgLoading] = useState(false);
  const [migrateMsg, setMigrateMsg] = useState('');
  const [migrateLoading, setMigrateLoading] = useState(false);

  const runMigrate = async () => {
    setMigrateLoading(true); setMigrateMsg('');
    try {
      const res = await api.runMigration();
      setMigrateMsg(res.success ? `✓ Muvaffaqiyatli:\n${res.output || 'Barcha migrationlar qo\'llandi'}` : `⚠ Xato: ${res.error}`);
    } catch (e) { setMigrateMsg('Xato: ' + e.message); }
    setMigrateLoading(false);
  };

  const saveTelegram = () => {
    localStorage.setItem('cg_tg_token', tgToken);
    localStorage.setItem('cg_tg_chat', tgChat);
    setTgMsg('✓ Saqlandi (faqat brauzer localStorage)');
    setTimeout(() => setTgMsg(''), 3000);
  };

  const testTelegram = async () => {
    setTgLoading(true); setTgMsg('');
    try {
      const res = await api.testTelegram({ token: tgToken, chat_id: tgChat });
      setTgMsg(res.success ? `✓ Xabar yuborildi! ID: ${res.message_id}` : `⚠ ${res.error}`);
    } catch (e) { setTgMsg('Xato: ' + e.message); }
    setTgLoading(false);
  };

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
            <div style={{ marginBottom: 14, padding: '10px 12px', background: '#39ff1408', border: '1px solid #39ff1433' }}>
              <div style={{ fontSize: 11, color: '#94b4c8', marginBottom: 8 }}>
                Agar "relation does not exist" xatosi chiqsa — quyidagi tugmani bosib database migrationlarini qo'llang.
              </div>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <button className="action-btn" style={{ padding: '6px 14px', fontSize: 11, borderColor: '#39ff1466', color: '#39ff14' }} onClick={runMigrate} disabled={migrateLoading}>
                  {migrateLoading ? 'QABUL QILINMOQDA...' : 'DB MIGRATIONLARNI QABUL QILISH'}
                </button>
                {migrateMsg && <span style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: migrateMsg.startsWith('✓') ? '#39ff14' : '#ffab00', whiteSpace: 'pre-line' }}>{migrateMsg}</span>}
              </div>
            </div>
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

        <Panel title="TELEGRAM XABARDORLIK BOTI" color="#00aaff" style={{ gridColumn: '1 / -1' }}>
          <div className="panel-body">
            <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.8, marginBottom: 14 }}>
              Kritik tahdidlar aniqlanganda Telegram bot orqali darhol xabardorlik oling.
              <span style={{ color: '#00aaff' }}> @BotFather</span> dan yangi bot yarating, token va chat ID ni kiriting.
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>BOT TOKEN</div>
                <input className="form-input" type="password" value={tgToken} onChange={e => setTgToken(e.target.value)} placeholder="1234567890:ABCdefGHI..."/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>CHAT ID</div>
                <input className="form-input" value={tgChat} onChange={e => setTgChat(e.target.value)} placeholder="-1001234567890 yoki @username"/>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <button className="action-btn" style={{ padding: '8px 16px', fontSize: 12 }} onClick={saveTelegram}>SAQLASH</button>
              <button className="action-btn" style={{ padding: '8px 16px', fontSize: 12, borderColor: '#00aaff66', color: '#00aaff' }} onClick={testTelegram} disabled={tgLoading || !tgToken || !tgChat}>
                {tgLoading ? 'YUBORILMOQDA...' : 'TEST XABAR YUBORISH'}
              </button>
              {tgMsg && <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: tgMsg.startsWith('✓') ? '#39ff14' : '#ffab00' }}>{tgMsg}</span>}
            </div>
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

// ── ISO alpha-2 → numeric country code (topojson world-atlas IDs) ────────
const ISO_A2_TO_N = {
  AF:4,AX:8,AL:8,DZ:12,AS:16,AD:20,AO:24,AI:660,AQ:10,AG:28,AR:32,AM:51,AW:533,AU:36,AT:40,AZ:31,
  BS:44,BH:48,BD:50,BB:52,BY:112,BE:56,BZ:84,BJ:204,BM:60,BT:64,BO:68,BQ:535,BA:70,BW:72,BV:74,
  BR:76,IO:86,BN:96,BG:100,BF:854,BI:108,CV:132,KH:116,CM:120,CA:124,KY:136,CF:140,TD:148,CL:152,
  CN:156,CX:162,CC:166,CO:170,KM:174,CG:178,CD:180,CK:184,CR:188,CI:384,HR:191,CU:192,CW:531,
  CY:196,CZ:203,DK:208,DJ:262,DM:212,DO:214,EC:218,EG:818,SV:222,GQ:226,ER:232,EE:233,SZ:748,
  ET:231,FK:238,FO:234,FJ:242,FI:246,FR:250,GF:254,PF:258,TF:260,GA:266,GM:270,GE:268,DE:276,
  GH:288,GI:292,GR:300,GL:304,GD:308,GP:312,GU:316,GT:320,GG:831,GN:324,GW:624,GY:328,HT:332,
  HM:334,VA:336,HN:340,HK:344,HU:348,IS:352,IN:356,ID:360,IR:364,IQ:368,IE:372,IM:833,IL:376,
  IT:380,JM:388,JP:392,JE:832,JO:400,KZ:398,KE:404,KI:296,KP:408,KR:410,KW:414,KG:417,LA:418,
  LV:428,LB:422,LS:426,LR:430,LY:434,LI:438,LT:440,LU:442,MO:446,MG:450,MW:454,MY:458,MV:462,
  ML:466,MT:470,MH:584,MQ:474,MR:478,MU:480,YT:175,MX:484,FM:583,MD:498,MC:492,MN:496,ME:499,
  MS:500,MA:504,MZ:508,MM:104,NA:516,NR:520,NP:524,NL:528,NC:540,NZ:554,NI:558,NE:562,NG:566,
  NU:570,NF:574,MK:807,MP:580,NO:578,OM:512,PK:586,PW:585,PS:275,PA:591,PG:598,PY:600,PE:604,
  PH:608,PN:612,PL:616,PT:620,PR:630,QA:634,RE:638,RO:642,RU:643,RW:646,BL:652,SH:654,KN:659,
  LC:662,MF:663,PM:666,VC:670,WS:882,SM:674,ST:678,SA:682,SN:686,RS:688,SC:690,SL:694,SG:702,
  SX:534,SK:703,SI:705,SB:90,SO:706,ZA:710,GS:239,SS:728,ES:724,LK:144,SD:729,SR:740,SJ:744,
  SE:752,CH:756,SY:760,TW:158,TJ:762,TZ:834,TH:764,TL:626,TG:768,TK:772,TO:776,TT:780,TN:788,
  TR:792,TM:795,TC:796,TV:798,UG:800,UA:804,AE:784,GB:826,US:840,UM:581,UY:858,UZ:860,VU:548,
  VE:862,VN:704,VG:92,VI:850,WF:876,EH:732,YE:887,ZM:894,ZW:716,
};

// ── 3D GLOBE CANVAS ───────────────────────────────────────────────────────
function GlobeCanvas({ countryCode, lat, lon }) {
  const canvasRef = React.useRef(null);
  const centerRef = React.useRef({ lat: 20, lon: 0 });
  const dragRef = React.useRef(null);
  const topoRef = React.useRef(null);
  const animRef = React.useRef(null);
  const targetNumeric = ISO_A2_TO_N[countryCode] ? String(ISO_A2_TO_N[countryCode]) : null;

  React.useEffect(() => {
    if (lat != null && lon != null) {
      centerRef.current = { lat: lat * 0.8, lon: lon };
    }
  }, [lat, lon]);

  React.useEffect(() => {
    let mounted = true;

    async function loadTopo() {
      if (topoRef.current) return topoRef.current;
      // Load topojson-client from CDN
      if (!window.topojson) {
        await new Promise((res, rej) => {
          const s = document.createElement('script');
          s.src = 'https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js';
          s.onload = res; s.onerror = rej;
          document.head.appendChild(s);
        });
      }
      const resp = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
      const topo = await resp.json();
      topoRef.current = window.topojson.feature(topo, topo.objects.countries);
      return topoRef.current;
    }

    function project(centerLat, centerLon, featureLat, featureLon, cx, cy, r) {
      const cLat = centerLat * Math.PI / 180;
      const cLon = centerLon * Math.PI / 180;
      const fLat = featureLat * Math.PI / 180;
      const fLon = featureLon * Math.PI / 180;
      const cosC = Math.sin(cLat) * Math.sin(fLat) + Math.cos(cLat) * Math.cos(fLat) * Math.cos(fLon - cLon);
      if (cosC < 0) return null;
      const x = Math.cos(fLat) * Math.sin(fLon - cLon);
      const y = Math.cos(cLat) * Math.sin(fLat) - Math.sin(cLat) * Math.cos(fLat) * Math.cos(fLon - cLon);
      return [cx + r * x, cy - r * y];
    }

    function drawFrame(geoJson) {
      const canvas = canvasRef.current;
      if (!canvas || !mounted) return;
      const ctx = canvas.getContext('2d');
      const W = canvas.width, H = canvas.height;
      const cx = W / 2, cy = H / 2;
      const r = Math.min(W, H) / 2 - 8;
      const cLat = centerRef.current.lat;
      const cLon = centerRef.current.lon;

      ctx.clearRect(0, 0, W, H);

      // Ocean
      const grad = ctx.createRadialGradient(cx, cy, r * 0.1, cx, cy, r);
      grad.addColorStop(0, '#0a1628');
      grad.addColorStop(1, '#000a14');
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.fillStyle = grad;
      ctx.fill();

      // Grid lines
      ctx.strokeStyle = '#0d2a3a';
      ctx.lineWidth = 0.5;
      for (let gridLat = -80; gridLat <= 80; gridLat += 20) {
        ctx.beginPath();
        let first = true;
        for (let gridLon = -180; gridLon <= 180; gridLon += 2) {
          const p = project(cLat, cLon, gridLat, gridLon, cx, cy, r);
          if (!p) { first = true; continue; }
          first ? ctx.moveTo(p[0], p[1]) : ctx.lineTo(p[0], p[1]);
          first = false;
        }
        ctx.stroke();
      }
      for (let gridLon = -180; gridLon <= 180; gridLon += 30) {
        ctx.beginPath();
        let first = true;
        for (let gridLat = -90; gridLat <= 90; gridLat += 2) {
          const p = project(cLat, cLon, gridLat, gridLon, cx, cy, r);
          if (!p) { first = true; continue; }
          first ? ctx.moveTo(p[0], p[1]) : ctx.lineTo(p[0], p[1]);
          first = false;
        }
        ctx.stroke();
      }

      // Countries
      geoJson.features.forEach(feature => {
        const isTarget = targetNumeric && feature.id === targetNumeric;
        ctx.fillStyle = isTarget ? 'rgba(255,23,68,0.85)' : '#0d3a1e';
        ctx.strokeStyle = isTarget ? '#ff1744' : '#39ff1433';
        ctx.lineWidth = isTarget ? 1.2 : 0.6;

        const geom = feature.geometry;
        const polys = geom.type === 'Polygon' ? [geom.coordinates] : geom.coordinates;
        polys.forEach(poly => {
          poly.forEach(ring => {
            ctx.beginPath();
            let first = true;
            ring.forEach(([pLon, pLat]) => {
              const p = project(cLat, cLon, pLat, pLon, cx, cy, r);
              if (!p) { first = true; return; }
              first ? ctx.moveTo(p[0], p[1]) : ctx.lineTo(p[0], p[1]);
              first = false;
            });
            ctx.closePath();
            ctx.fill();
            ctx.stroke();
          });
        });
      });

      // Globe border
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = '#39ff1422';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Pulsing dot at target location
      if (lat != null && lon != null) {
        const p = project(cLat, cLon, lat, lon, cx, cy, r);
        if (p) {
          const pulse = (Math.sin(Date.now() / 400) + 1) / 2;
          const dotR = 5 + pulse * 4;
          ctx.beginPath();
          ctx.arc(p[0], p[1], dotR, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(255,23,68,${0.3 + pulse * 0.4})`;
          ctx.fill();
          ctx.beginPath();
          ctx.arc(p[0], p[1], 4, 0, Math.PI * 2);
          ctx.fillStyle = '#ff1744';
          ctx.fill();
        }
      }
    }

    let geoJson = null;
    loadTopo().then(geo => {
      if (!mounted) return;
      geoJson = geo;
      function loop() {
        if (!mounted) return;
        if (!dragRef.current) {
          centerRef.current = { ...centerRef.current, lon: centerRef.current.lon + 0.15 };
        }
        if (geoJson) drawFrame(geoJson);
        animRef.current = requestAnimationFrame(loop);
      }
      loop();
    }).catch(() => {});

    return () => {
      mounted = false;
      if (animRef.current) cancelAnimationFrame(animRef.current);
    };
  }, [countryCode, lat, lon]);

  function onMouseDown(e) {
    dragRef.current = { x: e.clientX, y: e.clientY, lat: centerRef.current.lat, lon: centerRef.current.lon };
  }
  function onMouseMove(e) {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.x;
    const dy = e.clientY - dragRef.current.y;
    centerRef.current = {
      lon: dragRef.current.lon + dx * 0.4,
      lat: Math.max(-85, Math.min(85, dragRef.current.lat - dy * 0.4)),
    };
  }
  function onMouseUp() { dragRef.current = null; }

  function onTouchStart(e) {
    const t = e.touches[0];
    dragRef.current = { x: t.clientX, y: t.clientY, lat: centerRef.current.lat, lon: centerRef.current.lon };
  }
  function onTouchMove(e) {
    if (!dragRef.current) return;
    const t = e.touches[0];
    const dx = t.clientX - dragRef.current.x;
    const dy = t.clientY - dragRef.current.y;
    centerRef.current = {
      lon: dragRef.current.lon + dx * 0.4,
      lat: Math.max(-85, Math.min(85, dragRef.current.lat - dy * 0.4)),
    };
  }
  function onTouchEnd() { dragRef.current = null; }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '12px 0' }}>
      <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 8, fontFamily: 'Share Tech Mono' }}>
        SICHQONCHA BILAN AYLANTIRING · {countryCode ? `JOYLASHUV: ${countryCode}` : ''}
      </div>
      <canvas
        ref={canvasRef}
        width={420}
        height={420}
        style={{ cursor: 'grab', borderRadius: '50%', display: 'block', boxShadow: '0 0 40px #39ff1422' }}
        onMouseDown={onMouseDown}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
        onTouchStart={onTouchStart}
        onTouchMove={onTouchMove}
        onTouchEnd={onTouchEnd}
      />
    </div>
  );
}

// ── WORLD SUBMARINE CABLE MAP ─────────────────────────────────────────────
function WorldCableMap() {
  const W = 960, H = 500;
  const MAX_LAT = 83;
  const [countryPaths, setCountryPaths] = React.useState([]);
  const [loaded, setLoaded] = React.useState(false);

  // Proper Mercator: fits ±83° exactly into H
  const mercMax = Math.log(Math.tan(Math.PI / 4 + MAX_LAT * Math.PI / 360));
  function px(lon, lat) {
    const clat = Math.max(-MAX_LAT, Math.min(MAX_LAT, lat));
    const x = ((lon + 180) / 360) * W;
    const mercN = Math.log(Math.tan(Math.PI / 4 + clat * Math.PI / 360));
    const y = H / 2 - (mercN / (2 * mercMax)) * H * 0.98;
    return [+x.toFixed(1), +y.toFixed(1)];
  }

  React.useEffect(() => {
    async function load() {
      try {
        if (!window.topojson) {
          await new Promise((res, rej) => {
            const s = document.createElement('script');
            s.src = 'https://cdn.jsdelivr.net/npm/topojson-client@3/dist/topojson-client.min.js';
            s.onload = res; s.onerror = rej;
            document.head.appendChild(s);
          });
        }
        const resp = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
        const topo = await resp.json();
        const geo = window.topojson.feature(topo, topo.objects.countries);
        const built = geo.features.map(f => {
          const polys = f.geometry.type === 'Polygon' ? [f.geometry.coordinates] : f.geometry.coordinates;
          return polys.map(poly =>
            poly.map(ring =>
              ring.map(([lon, lat], i) => {
                const [x, y] = px(lon, lat);
                return `${i === 0 ? 'M' : 'L'}${x},${y}`;
              }).join(' ') + ' Z'
            ).join(' ')
          ).join(' ');
        });
        setCountryPaths(built);
        setLoaded(true);
      } catch (e) { setLoaded(true); }
    }
    load();
  }, []);

  const cables = [
    // ─── Atlantic ─────────────────────────────────────────────────────
    { pts: [[-74,40],[-10,53],[-6,53]] },
    { pts: [[-76,37],[-8,38]] },
    { pts: [[-74,41],[-8,51]] },
    { pts: [[-52,47],[-8,52]] },
    { pts: [[-74,40],[-46,-23]] },
    { pts: [[-74,40],[-67,17],[-46,-23],[-70,-33]] },
    // ─── Pacific ──────────────────────────────────────────────────────
    { pts: [[-118,34],[139,35]] },
    { pts: [[-122,37],[135,35]] },
    { pts: [[-118,34],[-157,21],[-175,-38],[153,-33]] },
    { pts: [[-119,37],[-157,21],[-170,-14],[174,-37],[153,-33]] },
    { pts: [[-118,34],[-157,21],[121,22]] },
    { pts: [[103,1],[121,14],[135,35],[139,35],[-157,21],[-118,34]] },
    { pts: [[103,1],[130,30],[139,35]] },
    { pts: [[103,1],[114,22],[121,24],[130,33],[135,35]] },
    // ─── Indian Ocean / Middle East ───────────────────────────────────
    { pts: [[103,1],[80,9],[70,22],[43,12],[33,12],[28,30],[18,38],[8,37],[-6,35]] },
    { pts: [[103,1],[85,13],[72,18],[55,20],[43,12],[33,12],[29,41],[25,37],[12,37],[-6,35]] },
    { pts: [[72,22],[55,20],[43,12],[30,30],[25,37]] },
    { pts: [[57,24],[43,12],[40,12],[50,23],[57,24]] },
    { pts: [[28,33],[18,-34],[40,-22],[55,24]] },
    // ─── East / South Africa ──────────────────────────────────────────
    { pts: [[40,11],[37,-3],[33,-26],[28,-34]] },
    { pts: [[43,12],[35,-4],[33,-26],[28,-33],[18,-34]] },
    // ─── West Africa / Atlantic ───────────────────────────────────────
    { pts: [[-17,14],[0,4],[-13,-8],[18,-34]] },
    { pts: [[-8,37],[3,5],[-13,-8]] },
    { pts: [[-9,38],[3,5],[-13,-8],[18,-34]] },
    // ─── Intra-Asia ───────────────────────────────────────────────────
    { pts: [[103,1],[80,13],[72,22]] },
    { pts: [[100,20],[110,20],[121,25],[139,35]] },
  ];

  const labels = [
    [[-100,40],'N.AMERICA'],[[-58,-15],'S.AMERICA'],[[15,50],'EUROPE'],
    [[22,5],'AFRICA'],[[85,40],'ASIA'],[[134,-25],'AUSTRALIA'],
  ];

  return (
    <div style={{ position: 'relative', background: '#000', borderRadius: 6, overflow: 'hidden', border: '1px solid #1e1e1e' }}>
      {!loaded && (
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2 }}>
          <div className="spinner"/>
        </div>
      )}
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', display: 'block' }}>
        {/* Ocean */}
        <rect width={W} height={H} fill="#020c18"/>

        {/* Graticule */}
        {[-60,-30,0,30,60].map(lat => {
          const [,y] = px(0, lat);
          return <line key={lat} x1={0} y1={y} x2={W} y2={y} stroke="#0c1e2a" strokeWidth="0.6"/>;
        })}
        {[-150,-120,-90,-60,-30,0,30,60,90,120,150,180].map(lon => {
          const [x] = px(lon, 0);
          return <line key={lon} x1={x} y1={0} x2={x} y2={H} stroke="#0c1e2a" strokeWidth="0.6"/>;
        })}

        {/* Countries from real topojson */}
        {countryPaths.map((d, i) => (
          <path key={i} d={d} fill="#0c1f0e" stroke="#1a3a1a" strokeWidth="0.45"/>
        ))}

        {/* Cables — glow layer then solid */}
        {cables.map((c, i) => {
          const d = c.pts.map(([lon, lat], j) => {
            const [x, y] = px(lon, lat);
            return `${j === 0 ? 'M' : 'L'}${x},${y}`;
          }).join(' ');
          return (
            <g key={i}>
              <path d={d} fill="none" stroke="#ff1744" strokeWidth="3" strokeOpacity="0.15" strokeLinecap="round" strokeLinejoin="round"/>
              <path d={d} fill="none" stroke="#ff1744" strokeWidth="1.3" strokeOpacity="0.82" strokeLinecap="round" strokeLinejoin="round"/>
            </g>
          );
        })}

        {/* Landing station dots */}
        {cables.map((c, i) =>
          [c.pts[0], c.pts[c.pts.length - 1]].map(([lon, lat], j) => {
            const [x, y] = px(lon, lat);
            return <circle key={`${i}-${j}`} cx={x} cy={y} r="2.8" fill="#ff1744" fillOpacity="0.95"/>;
          })
        )}

        {/* Continent labels */}
        {labels.map(([[lon,lat],label]) => {
          const [x, y] = px(lon, lat);
          return <text key={label} x={x} y={y} fill="#2a3a2a" fontSize="11" fontFamily="Share Tech Mono" textAnchor="middle" fontWeight="bold">{label}</text>;
        })}

        {/* Legend */}
        <rect x="8" y="8" width="196" height="26" fill="#000" fillOpacity="0.75" stroke="#1e1e1e" rx="2"/>
        <line x1="14" y1="21" x2="42" y2="21" stroke="#ff1744" strokeWidth="1.5"/>
        <circle cx="14" cy="21" r="2.5" fill="#ff1744"/>
        <circle cx="42" cy="21" r="2.5" fill="#ff1744"/>
        <text x="48" y="25" fill="#4a4a4a" fontSize="9" fontFamily="Share Tech Mono">SUBMARINE CABLE ROUTES ({cables.length})</text>
      </svg>
    </div>
  );
}

// ── AI LABORATORIYA PAGE ──────────────────────────────────────────────────
function AILabPage() {
  const [tab, setTab] = useState('performance');
  const [perfData, setPerfData] = useState(null);
  const [perfLoading, setPerfLoading] = useState(false);
  const [attrData, setAttrData] = useState(null);
  const [attrLoading, setAttrLoading] = useState(false);
  const [attrIP, setAttrIP] = useState('192.168.1.201');
  const [attrThreat, setAttrThreat] = useState('brute_force');
  const [attrCtx, setAttrCtx] = useState('');
  const [aeData, setAeData] = useState(null);
  const [aeLoading, setAeLoading] = useState(false);
  const [aeIP, setAeIP] = useState('192.168.1.201');
  const [clusterData, setClusterData] = useState(null);
  const [clusterLoading, setClusterLoading] = useState(false);
  const [datasets, setDatasets] = useState([]);
  const [uploadMsg, setUploadMsg] = useState('');
  const [uploadLoading, setUploadLoading] = useState(false);
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadName, setUploadName] = useState('');
  const [uploadFormat, setUploadFormat] = useState('custom');
  const [sampleDatasets, setSampleDatasets] = useState([]);
  // ── GEOIP ────────────────────────────────────────────────────────────────
  const [geoData, setGeoData] = useState(null);
  const [geoLoading, setGeoLoading] = useState(false);
  const [geoIP, setGeoIP] = useState('');
  // ── XAI ──────────────────────────────────────────────────────────────────
  const [xaiIP, setXaiIP] = useState('');
  const [xaiCtx, setXaiCtx] = useState('');
  const [xaiData, setXaiData] = useState(null);
  const [xaiLoading, setXaiLoading] = useState(false);
  // ── LSTM ─────────────────────────────────────────────────────────────────
  const [lstmData, setLstmData] = useState(null);
  const [lstmLoading, setLstmLoading] = useState(false);
  const [lstmHours, setLstmHours] = useState(6);
  // ── BEHAVIOR ─────────────────────────────────────────────────────────────
  const [behaviorData, setBehaviorData] = useState(null);
  const [behaviorLoading, setBehaviorLoading] = useState(false);

  const accent = themeAccent('cyan', '#00e5ff');

  useEffect(() => {
    if (tab === 'performance' && !perfData) loadPerf();
    if (tab === 'clustering' && !clusterData) loadCluster();
    if (tab === 'dataset') {
      api.getDatasets().then(setDatasets).catch(() => {});
      if (!sampleDatasets.length) api.getSampleDatasets().then(d => setSampleDatasets(d.samples || [])).catch(() => {});
    }
    if (tab === 'lstm' && !lstmData) loadLstm();
    if (tab === 'behavior' && !behaviorData) loadBehavior();
    if (tab === 'geoip' && !geoData) loadBulkGeoip();
  }, [tab]);

  const loadPerf = async () => {
    setPerfLoading(true);
    try { setPerfData(await api.getModelPerformance()); } catch { }
    setPerfLoading(false);
  };

  const loadCluster = async () => {
    setClusterLoading(true);
    try { setClusterData(await api.getCluster()); } catch { }
    setClusterLoading(false);
  };

  const loadAttr = async () => {
    setAttrLoading(true);
    try {
      const d = await api.getFeatureAttribution({ ip_address: attrIP, threat_type: attrThreat, context: attrCtx });
      setAttrData(d);
    } catch (e) { setAttrData({ error: e.message }); }
    setAttrLoading(false);
  };

  const loadAe = async () => {
    setAeLoading(true);
    try {
      const d = await api.getAutoencoderScore({ ip_address: aeIP, context: '' });
      setAeData(d);
    } catch (e) { setAeData({ error: e.message }); }
    setAeLoading(false);
  };

  const loadXai = async () => {
    if (!xaiIP.trim()) return;
    setXaiLoading(true);
    try {
      const d = await api.getXaiExplanation({ ip_address: xaiIP.trim(), context: xaiCtx });
      setXaiData(d);
    } catch (e) { setXaiData({ error: e.message }); }
    setXaiLoading(false);
  };

  const loadLstm = async () => {
    setLstmLoading(true);
    try { setLstmData(await api.getLstmTrend(lstmHours)); } catch { }
    setLstmLoading(false);
  };

  const loadBehavior = async () => {
    setBehaviorLoading(true);
    try { setBehaviorData(await api.getUserBehavior()); } catch { }
    setBehaviorLoading(false);
  };

  const loadBulkGeoip = async () => {
    setGeoLoading(true);
    try { setGeoData(await api.getBulkGeoip([])); } catch { }
    setGeoLoading(false);
  };

  const lookupGeoip = async () => {
    if (!geoIP.trim()) return;
    setGeoLoading(true);
    try {
      const d = await api.getGeoip(geoIP.trim());
      setGeoData({ single: d });
    } catch { }
    setGeoLoading(false);
  };

  const handleUpload = async () => {
    if (!uploadFile) { setUploadMsg('Fayl tanlanmagan'); return; }
    setUploadLoading(true);
    setUploadMsg('');
    try {
      const fd = new FormData();
      fd.append('file', uploadFile);
      fd.append('name', uploadName || uploadFile.name);
      fd.append('format_type', uploadFormat);
      const res = await api.uploadDataset(fd);
      if (res.trained) {
        const dist = res.retrain?.distribution || {};
        const distStr = Object.entries(dist).map(([k,v]) => `${k}:${v}`).join(', ');
        setUploadMsg(`✓ ${res.message}\nTaqsimot: ${distStr}`);
      } else {
        setUploadMsg((res.message || 'Yuklandi') + (res.retrain?.error ? `\n⚠ Model o'qitmadi: ${res.retrain.error}` : ''));
      }
      api.getDatasets().then(setDatasets).catch(() => {});
    } catch (e) { setUploadMsg('Xato: ' + e.message); }
    setUploadLoading(false);
  };

  const tabs = [
    { id: 'performance', label: 'Model Samaradorligi' },
    { id: 'shap', label: 'Feature Attribution' },
    { id: 'autoencoder', label: 'Autoencoder / Zero-Day' },
    { id: 'clustering', label: 'Klasterlash' },
    { id: 'xai', label: 'XAI Tushuntirish' },
    { id: 'lstm', label: 'LSTM Trend' },
    { id: 'geoip', label: 'GeoIP Xaritasi' },
    { id: 'behavior', label: 'Xatti-harakat' },
    { id: 'dataset', label: 'Dataset Yuklash' },
  ];

  const algoColors = { 'Random Forest': '#39ff14', 'XGBoost': '#00e5ff', 'Naive Bayes': '#ffab00', 'SVM': '#a855f7' };
  const severityColors = { ddos: '#ff1744', sqli: '#ff4500', brute_force: '#ff8c00', phishing: '#ffd700', ransomware: '#ff1744', mitm: '#00bcd4', zero_day: '#e040fb', apt: '#ff1744', port_scan: '#64b5f6' };
  const bar = (val, max = 100, color = accent) => (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 10, background: 'rgba(255,255,255,.07)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${Math.min(val / max * 100, 100)}%`, background: color, transition: 'width .5s' }}/>
      </div>
      <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color, minWidth: 40 }}>{val}%</span>
    </div>
  );

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <div className="filter-bar" style={{ marginBottom: 16 }}>
        {tabs.map(t => (
          <button key={t.id} className={`filter-btn${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── 1. MODEL SAMARADORLIGI ── */}
      {tab === 'performance' && (
        <div>
          {perfLoading && <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><div className="spinner"/></div>}
          {perfData && !perfData.error && (
            <>
              <div style={{ marginBottom: 10, padding: '8px 12px', background: perfData.data_source === 'real' ? 'rgba(57,255,20,.08)' : 'rgba(255,171,0,.08)', border: `1px solid ${perfData.data_source === 'real' ? '#39ff1444' : '#ffab0044'}`, fontFamily: 'Share Tech Mono', fontSize: 11, color: perfData.data_source === 'real' ? '#39ff14' : '#ffab00' }}>
                {perfData.data_source === 'real'
                  ? `✓ REAL DATA: ${perfData.real_samples} ta haqiqiy IP tahlil natijasi asosida baholandi`
                  : `⚠ SINTETIK DATA: Hali haqiqiy tahlil yo'q — IP Tahlil sahifasida kamida 10 ta IP tahlil qiling`}
              </div>
              <Panel title="ALGORITMLAR — ANIQLIK METRIKALAR" color={accent}>
                <div className="panel-body" style={{ overflowX: 'auto' }}>
                  <table className="alerts-table">
                    <thead>
                      <tr><th>ALGORITM</th><th>ACCURACY</th><th>PRECISION</th><th>RECALL</th><th>F1-SCORE</th><th>VIZUAL</th></tr>
                    </thead>
                    <tbody>
                      {Object.entries(perfData.algorithms || {}).map(([name, m]) => (
                        <tr key={name}>
                          <td style={{ color: algoColors[name] || accent, fontWeight: 700 }}>{name}</td>
                          <td className="td-mono">{m.accuracy}%</td>
                          <td className="td-mono">{m.precision}%</td>
                          <td className="td-mono">{m.recall}%</td>
                          <td className="td-mono" style={{ color: m.f1 >= 90 ? '#39ff14' : m.f1 >= 70 ? '#ffab00' : '#ff1744', fontWeight: 700 }}>{m.f1}%</td>
                          <td style={{ minWidth: 160 }}>{bar(m.f1, 100, algoColors[name] || accent)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14 }}>
                <Panel title="CONFUSION MATRIX (Random Forest)" color="#a855f7">
                  <div className="panel-body" style={{ overflowX: 'auto', paddingTop: 8, paddingBottom: 8 }}>
                    <table style={{ borderCollapse: 'collapse', fontSize: 10, fontFamily: 'Share Tech Mono' }}>
                      <thead>
                        <tr>
                          <th style={{ padding: '4px 6px', color: '#4a6a84' }}>↓pred / actual→</th>
                          {(perfData.confusion_matrix?.labels || []).map(l => (
                            <th key={l} style={{ padding: '4px 6px', color: '#a855f7', writingMode: 'vertical-lr', transform: 'rotate(180deg)', height: 70 }}>{l.toUpperCase()}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {(perfData.confusion_matrix?.matrix || []).map((row, ri) => {
                          const rowMax = Math.max(...row, 1);
                          return (
                            <tr key={ri}>
                              <td style={{ padding: '3px 6px', color: '#a855f7', fontSize: 9 }}>
                                {(perfData.confusion_matrix?.labels?.[ri] || '').toUpperCase()}
                              </td>
                              {row.map((val, ci) => (
                                <td key={ci} style={{
                                  padding: '3px 5px', textAlign: 'center', fontSize: 10,
                                  background: ri === ci
                                    ? `rgba(57,255,20,${val / rowMax * 0.6 + 0.1})`
                                    : val > 0 ? `rgba(255,23,68,${val / rowMax * 0.5 + 0.1})` : 'transparent',
                                  color: ri === ci ? '#39ff14' : val > 0 ? '#ff1744' : '#4a6a84',
                                  border: '1px solid rgba(74,106,132,.2)',
                                }}>{val}</td>
                              ))}
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </Panel>

                <Panel title="TAHDID TURLARINI ANIQLASH (F1-Score %)" color="#39ff14">
                  <div className="panel-body" style={{ paddingTop: 8, paddingBottom: 8, display: 'grid', gap: 10 }}>
                    {Object.entries(perfData.per_class_f1 || {}).slice(0, 9).map(([threat, algos]) => (
                      <div key={threat}>
                        <div style={{ fontSize: 10, color: severityColors[threat] || '#4a6a84', marginBottom: 4, fontFamily: 'Share Tech Mono', letterSpacing: 1 }}>
                          {threat.toUpperCase()}
                        </div>
                        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                          {Object.entries(algos).map(([algo, f1]) => (
                            <div key={algo} style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: algoColors[algo] || '#4a6a84' }}>
                              {algo.split(' ')[0]}: <span style={{ color: f1 >= 90 ? '#39ff14' : f1 >= 70 ? '#ffab00' : '#ff4444' }}>{f1}%</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              </div>
            </>
          )}
          {(!perfData || perfData.error) && !perfLoading && (
            <div style={{ textAlign: 'center', padding: 40, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>
              {perfData?.error || 'Model performance yuklanmadi'}
              <button className="filter-btn active" style={{ marginTop: 16, display: 'block', margin: '16px auto' }} onClick={loadPerf}>QAYTA YUKLASH</button>
            </div>
          )}
        </div>
      )}

      {/* ── 2. FEATURE ATTRIBUTION (SHAP-like) ── */}
      {tab === 'shap' && (
        <div>
          <Panel title="FEATURE ATTRIBUTION — QAYSI XUSUSIYAT TAHDIDNI ANIQLADI?" color={accent}>
            <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, paddingTop: 12, paddingBottom: 12 }}>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>IP MANZIL</div>
                <input className="form-input" value={attrIP} onChange={e => setAttrIP(e.target.value)} placeholder="192.168.1.1"/>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>TAHDID TURI</div>
                <select className="form-input" value={attrThreat} onChange={e => setAttrThreat(e.target.value)}>
                  {THREATS_LIST.map(t => <option key={t.v} value={t.v}>{t.l}</option>)}
                </select>
              </div>
              <div>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>KONTEKST</div>
                <input className="form-input" value={attrCtx} onChange={e => setAttrCtx(e.target.value)} placeholder="ssh brute force urinish..."/>
              </div>
            </div>
            <button className="action-btn" style={{ padding: '8px 20px', fontSize: 12 }} onClick={loadAttr} disabled={attrLoading}>
              {attrLoading ? 'HISOBLANMOQDA...' : 'ATTRIBUTION HISOBLASH'}
            </button>
          </Panel>

          {attrData && !attrData.error && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14 }}>
              <Panel title="FEATURE CONTRIBUTIONS (PER-PREDICTION)" color={accent}>
                <div className="panel-body" style={{ paddingTop: 10, paddingBottom: 10 }}>
                  <div style={{ fontSize: 11, color: '#4a6a84', marginBottom: 10, fontFamily: 'Share Tech Mono' }}>
                    Asosiy ehtimollik: <span style={{ color: accent }}>{attrData.baseline_probability}</span>
                    {' '}({attrData.threat_type?.toUpperCase()})
                  </div>
                  {(attrData.feature_contributions || []).slice(0, 10).map(({ feature, value }) => {
                    const isPos = value >= 0;
                    const pct = Math.min(Math.abs(value) * 500, 100);
                    return (
                      <div key={feature} style={{ marginBottom: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                          <span style={{ fontSize: 11, fontFamily: 'Share Tech Mono', color: '#94b4c8' }}>{feature}</span>
                          <span style={{ fontSize: 11, fontFamily: 'Share Tech Mono', color: isPos ? '#39ff14' : '#ff4444' }}>
                            {isPos ? '+' : ''}{value}
                          </span>
                        </div>
                        <div style={{ height: 8, background: 'rgba(255,255,255,.07)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: isPos ? '#39ff14' : '#ff4444', opacity: 0.8 }}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Panel>

              <Panel title="GLOBAL FEATURE IMPORTANCE (Random Forest)" color="#a855f7">
                <div className="panel-body" style={{ paddingTop: 10, paddingBottom: 10 }}>
                  {(attrData.global_importance || []).slice(0, 10).map(({ feature, value }) => {
                    const pct = Math.min(value * 500, 100);
                    return (
                      <div key={feature} style={{ marginBottom: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                          <span style={{ fontSize: 11, fontFamily: 'Share Tech Mono', color: '#94b4c8' }}>{feature}</span>
                          <span style={{ fontSize: 11, fontFamily: 'Share Tech Mono', color: '#a855f7' }}>{(value * 100).toFixed(2)}%</span>
                        </div>
                        <div style={{ height: 8, background: 'rgba(255,255,255,.07)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: '#a855f7', opacity: 0.8 }}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            </div>
          )}
          {attrData?.error && <div style={{ color: '#ff4444', padding: 20, fontFamily: 'Share Tech Mono' }}>Xato: {attrData.error}</div>}
        </div>
      )}

      {/* ── 3. AUTOENCODER / ZERO-DAY ── */}
      {tab === 'autoencoder' && (
        <div>
          <Panel title="AUTOENCODER ANOMALY DETECTOR — ZERO-DAY ANIQLASH" color="#e040fb">
            <div className="panel-body" style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.8 }}>
                Autoencoder normal trafik patternlarini o'rganadi. Agar input reconstruction error yuqori bo'lsa — noma'lum (zero-day) xatti-harakat aniqlandi.
                <br/>Arxitektura: MLPRegressor (20 → 14 → 6 → 14 → 20) — bottleneck.
              </div>
            </div>
            <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>IP MANZIL TAHLIL QILING</div>
                <input className="form-input" value={aeIP} onChange={e => setAeIP(e.target.value)} placeholder="192.168.1.201"/>
              </div>
              <button className="action-btn" style={{ padding: '8px 20px', fontSize: 12 }} onClick={loadAe} disabled={aeLoading}>
                {aeLoading ? 'HISOBLANMOQDA...' : 'AUTOENCODER TAHLIL'}
              </button>
            </div>
          </Panel>

          {aeData && !aeData.error && (
            <div style={{ marginTop: 14 }}>
              <div style={{ marginBottom: 10, padding: '7px 12px', fontFamily: 'Share Tech Mono', fontSize: 11, background: aeData.real_samples_trained > 0 ? 'rgba(57,255,20,.07)' : 'rgba(255,171,0,.07)', border: `1px solid ${aeData.real_samples_trained > 0 ? '#39ff1444' : '#ffab0044'}`, color: aeData.real_samples_trained > 0 ? '#39ff14' : '#ffab00' }}>
                {aeData.real_samples_trained > 0 ? `✓ Real data: ${aeData.real_samples_trained} ta haqiqiy namuna bilan o'qitilgan | Threshold: ${aeData.threshold}` : `⚠ Sintetik data bilan o'qitilgan | Threshold: ${aeData.threshold}`}
              </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <Panel title="RECONSTRUCTION ERROR & ANOMALY SCORE" color="#e040fb">
                <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                    {[
                      ['Reconstruction Error', aeData.reconstruction_error, '#ffab00'],
                      ['Anomaly Score', aeData.anomaly_pct, aeData.is_anomaly ? '#ff1744' : '#39ff14'],
                    ].map(([lbl, val, col]) => (
                      <div key={lbl} style={{ padding: 14, border: `1px solid ${col}44`, background: `${col}11` }}>
                        <div style={{ fontSize: 10, color: '#4a6a84', letterSpacing: 1, marginBottom: 6 }}>{lbl}</div>
                        <div style={{ fontSize: 22, color: col, fontFamily: 'Orbitron,monospace' }}>{val}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{
                    padding: 16, border: `1px solid ${aeData.is_anomaly ? '#ff174444' : '#39ff1444'}`,
                    background: aeData.is_anomaly ? 'rgba(255,23,68,.08)' : 'rgba(57,255,20,.06)',
                    color: aeData.is_anomaly ? '#ff1744' : '#39ff14',
                    fontFamily: 'Share Tech Mono', fontSize: 13, lineHeight: 1.6,
                  }}>
                    {aeData.is_anomaly ? '⚠ ' : '✓ '}{aeData.label}
                  </div>
                </div>
              </Panel>

              <Panel title="TOP RECONSTRUCTION ERRORS (Feature bo'yicha)" color="#ffab00">
                <div className="panel-body" style={{ paddingTop: 10, paddingBottom: 10 }}>
                  {(aeData.top_error_features || []).map(({ feature, error }) => {
                    const pct = Math.min(error * 2000, 100);
                    return (
                      <div key={feature} style={{ marginBottom: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                          <span style={{ fontSize: 11, fontFamily: 'Share Tech Mono', color: '#94b4c8' }}>{feature}</span>
                          <span style={{ fontSize: 11, fontFamily: 'Share Tech Mono', color: '#ffab00' }}>{error}</span>
                        </div>
                        <div style={{ height: 8, background: 'rgba(255,255,255,.07)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ height: '100%', width: `${pct}%`, background: '#ffab00', opacity: 0.8 }}/>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            </div>
            </div>
          )}
          {aeData?.error && <div style={{ color: '#ff4444', padding: 20, fontFamily: 'Share Tech Mono' }}>Xato: {aeData.error}</div>}
        </div>
      )}

      {/* ── 4. KLASTERLASH ── */}
      {tab === 'clustering' && (
        <div>
          {clusterLoading && <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><div className="spinner"/></div>}
          {clusterData && clusterData.error && (
            <div style={{ padding: 30, textAlign: 'center', border: '1px solid #ffab0044', background: 'rgba(255,171,0,.06)', borderRadius: 4 }}>
              <div style={{ color: '#ffab00', fontFamily: 'Share Tech Mono', fontSize: 14, marginBottom: 10 }}>⚠ {clusterData.error}</div>
              <div style={{ color: '#4a6a84', fontSize: 12 }}>{clusterData.detail}</div>
              <button className="filter-btn active" style={{ marginTop: 16 }} onClick={loadCluster}>QAYTA YUKLASH</button>
            </div>
          )}
          {clusterData && !clusterData.error && (
            <>
              {clusterData.sources && (
                <div style={{ marginBottom: 12, padding: '7px 12px', background: 'rgba(57,255,20,.06)', border: '1px solid #39ff1433', fontFamily: 'Share Tech Mono', fontSize: 11, color: '#39ff14', display: 'flex', gap: 20 }}>
                  {clusterData.sources.threat_log && <span>✓ ThreatLog: {clusterData.sources.threat_log} ta</span>}
                  {clusterData.sources.scan_record && <span>✓ Tarmoq skan: {clusterData.sources.scan_record} ta</span>}
                </div>
              )}
              <div className="stat-grid" style={{ marginBottom: 14 }}>
                {[
                  ['NAMUNALAR', clusterData.n_samples, 'cyan'],
                  ['K-MEANS KLASTER', clusterData.n_kmeans_clusters, 'green'],
                  ['DBSCAN KLASTER', clusterData.n_dbscan_clusters, 'amber'],
                  ['ANOMALIYALAR', clusterData.dbscan_noise_count, 'red'],
                ].map(([lbl, val, col]) => (
                  <StatCard key={lbl} label={lbl} value={val} color={col}/>
                ))}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                <Panel title="K-MEANS KLASTERLAR" color={accent}>
                  <div className="panel-body" style={{ paddingTop: 8, paddingBottom: 8, display: 'grid', gap: 10 }}>
                    {(clusterData.clusters || []).map((c, i) => (
                      <div key={i} style={{ padding: 12, border: '1px solid var(--border2)', background: 'rgba(13,27,46,.4)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                          <span style={{ color: accent, fontFamily: 'Share Tech Mono', fontWeight: 700 }}>Klaster {c.id}</span>
                          <span style={{ color: '#4a6a84', fontFamily: 'Share Tech Mono', fontSize: 11 }}>{c.members} ta</span>
                        </div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          {Object.entries(c.threat_types || {}).slice(0, 5).map(([t, cnt]) => (
                            <span key={t} style={{
                              fontSize: 10, padding: '2px 8px', border: '1px solid', fontFamily: 'Share Tech Mono',
                              borderColor: (severityColors[t] || '#4a6a84') + '66',
                              color: severityColors[t] || '#4a6a84',
                              background: (severityColors[t] || '#4a6a84') + '11',
                            }}>{t}: {cnt}</span>
                          ))}
                        </div>
                        {c.anomaly_count > 0 && (
                          <div style={{ marginTop: 6, fontSize: 10, color: '#ff4444', fontFamily: 'Share Tech Mono' }}>
                            DBSCAN anomaliya: {c.anomaly_count} ta
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </Panel>

                <Panel title="KLASTER NUQTALAR (Scatter — 100 ta namuna)" color="#a855f7">
                  <div className="panel-body" style={{ paddingTop: 8, paddingBottom: 8 }}>
                    <svg viewBox="0 0 300 220" style={{ width: '100%', background: 'rgba(8,17,30,.6)', borderRadius: 4 }}>
                      {(clusterData.points || []).slice(0, 80).map((p, i) => {
                        const cx = 20 + p.x * 260;
                        const cy = 200 - p.y * 180;
                        const clusterColors = ['#39ff14', '#00e5ff', '#ff1744', '#ffab00', '#a855f7', '#f97316', '#06b6d4', '#84cc16', '#ec4899'];
                        const col = p.dbscan === -1 ? '#ff1744' : clusterColors[p.kmeans % clusterColors.length];
                        return <circle key={i} cx={cx} cy={cy} r={p.dbscan === -1 ? 5 : 3} fill={col} opacity={0.7}/>;
                      })}
                    </svg>
                    <div style={{ marginTop: 8, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                      {['#39ff14', '#00e5ff', '#ffab00', '#a855f7'].map((col, i) => (
                        <span key={i} style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: '#4a6a84' }}>
                          <span style={{ color: col }}>●</span> Klaster {i}
                        </span>
                      ))}
                      <span style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: '#ff4444' }}>● DBSCAN Noise</span>
                    </div>
                  </div>
                </Panel>
              </div>
            </>
          )}
          {!clusterData && !clusterLoading && (
            <div style={{ textAlign: 'center', padding: 40, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>
              <button className="filter-btn active" onClick={loadCluster}>KLASTERLASHNI BOSHLASH</button>
            </div>
          )}
        </div>
      )}

      {/* ── 5. DATASET YUKLASH ── */}
      {tab === 'dataset' && (
        <div>
          {/* Namuna datasetlar */}
          {sampleDatasets.length > 0 && (
            <Panel title="NAMUNA DATASETLAR — YUKLAB OLIB TEST QILING" color="#ffab00" style={{ marginBottom: 14 }}>
              <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
                <div style={{ fontSize: 11, color: '#4a6a84', marginBottom: 14, fontFamily: 'Share Tech Mono' }}>
                  O'z datasetingiz bo'lmasa — quyidagilardan birini yuklab oling, keyin yuqoridagi formaga yuklang.
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                  {sampleDatasets.map(s => {
                    const apiKey = localStorage.getItem('cg_api_key') || 'cyberguard-demo-key';
                    return (
                      <div key={s.id} style={{ padding: 16, border: `1px solid ${s.color}44`, background: `${s.color}08` }}>
                        <div style={{ color: s.color, fontFamily: 'Share Tech Mono', fontWeight: 700, fontSize: 13, marginBottom: 6 }}>{s.name}</div>
                        <div style={{ fontSize: 11, color: '#94b4c8', marginBottom: 8, lineHeight: 1.6 }}>{s.desc}</div>
                        <div style={{ display: 'flex', gap: 12, fontSize: 10, fontFamily: 'Share Tech Mono', color: '#4a6a84', marginBottom: 12 }}>
                          <span>{s.rows} qator</span>
                          <span>{s.features} feature</span>
                        </div>
                        <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 10, lineHeight: 1.5 }}>
                          <span style={{ color: s.color }}>Labels: </span>{s.labels}
                        </div>
                        <button
                          className="action-btn"
                          style={{ padding: '6px 14px', fontSize: 11, width: '100%' }}
                          onClick={() => {
                            fetch(api.getSampleDownloadUrl(s.id), { headers: { 'X-API-Key': apiKey } })
                              .then(r => r.ok ? r.blob() : Promise.reject())
                              .then(blob => {
                                const a = document.createElement('a');
                                a.href = URL.createObjectURL(blob);
                                a.download = `sample_${s.id}.csv`;
                                a.click();
                                URL.revokeObjectURL(a.href);
                              })
                              .catch(() => {});
                          }}
                        >YUKLAB OLISH</button>
                      </div>
                    );
                  })}
                </div>
              </div>
            </Panel>
          )}
        <div>
          <Panel title="HAQIQIY DATASET YUKLASH (NSL-KDD / CICIDS2017 / Custom CSV)" color="#ffab00">
            <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
              <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.8, marginBottom: 16 }}>
                CSV formatdagi dataset yuklang. Faylda <code style={{ color: '#ffab00' }}>label</code> yoki <code style={{ color: '#ffab00' }}>class</code> ustuni bo'lishi kerak.
                NSL-KDD: 41 feature | CICIDS2017: 80+ feature | UNSW-NB15: 49 feature
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 14 }}>
                <div>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>DATASET NOMI</div>
                  <input className="form-input" value={uploadName} onChange={e => setUploadName(e.target.value)} placeholder="NSL-KDD 2024"/>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>FORMAT</div>
                  <select className="form-input" value={uploadFormat} onChange={e => setUploadFormat(e.target.value)}>
                    <option value="nsl_kdd">NSL-KDD</option>
                    <option value="cicids2017">CICIDS2017</option>
                    <option value="unsw_nb15">UNSW-NB15</option>
                    <option value="custom">Custom CSV</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>CSV FAYL</div>
                  <input type="file" accept=".csv" className="form-input" style={{ padding: '4px 8px' }}
                    onChange={e => setUploadFile(e.target.files?.[0] || null)}/>
                </div>
              </div>
              <button className="action-btn" style={{ padding: '8px 20px', fontSize: 12 }} onClick={handleUpload} disabled={uploadLoading}>
                {uploadLoading ? 'YUKLANMOQDA...' : 'DATASET YUKLASH'}
              </button>
              {uploadMsg && (
                <div style={{ marginTop: 12, padding: 12, background: uploadMsg.startsWith('Xato') ? 'rgba(255,23,68,.1)' : 'rgba(57,255,20,.1)', color: uploadMsg.startsWith('Xato') ? '#ff4444' : '#39ff14', fontFamily: 'Share Tech Mono', fontSize: 12, lineHeight: 1.7 }}>
                  {uploadMsg}
                </div>
              )}
            </div>
          </Panel>

          {datasets.length > 0 && (
            <Panel title="YUKLANGAN DATASETLAR" color="#ffab00" style={{ marginTop: 14 }}>
              <div className="panel-body" style={{ overflowX: 'auto' }}>
                <table className="alerts-table">
                  <thead>
                    <tr><th>NOMI</th><th>FORMAT</th><th>YOZUVLAR</th><th>XUSUSIYATLAR</th><th>HOLAT</th><th>SANA</th></tr>
                  </thead>
                  <tbody>
                    {datasets.map(d => (
                      <tr key={d.id}>
                        <td style={{ fontWeight: 600, color: '#ffab00' }}>{d.name}</td>
                        <td className="td-mono">{d.format_type}</td>
                        <td className="td-mono">{d.row_count.toLocaleString()}</td>
                        <td className="td-mono">{d.feature_count}</td>
                        <td className="td-mono" style={{ color: d.is_trained ? '#39ff14' : '#4a6a84' }}>{d.is_trained ? "✓ O'QITILDI" : 'FAQAT YUKLANDI'}</td>
                        <td className="td-mono" style={{ fontSize: 10, color: '#4a6a84' }}>{new Date(d.created_at).toLocaleDateString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}
        </div>
        </div>
      )}

      {/* ── 6. XAI TUSHUNTIRISH ── */}
      {tab === 'xai' && (
        <div>
          <Panel title="XAI — EXPLAINABLE AI: MODEL NIMA UCHUN BU QARORNI QABUL QILDI?" color="#a855f7">
            <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
              <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.8, marginBottom: 14 }}>
                IP manzilni kiriting — model u haqida qanday qaror qabul qilishini va <b style={{ color: '#a855f7' }}>NIMA UCHUN</b> aynan shunday deb o'ylashini tushuntiradi.
                Feature importance va contribution asosida ishlaydi.
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr auto', gap: 10, marginBottom: 14, alignItems: 'flex-end' }}>
                <div>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>IP MANZIL</div>
                  <input className="form-input" value={xaiIP} onChange={e => setXaiIP(e.target.value)} placeholder="192.168.1.100"/>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>KONTEKST (ixtiyoriy)</div>
                  <input className="form-input" value={xaiCtx} onChange={e => setXaiCtx(e.target.value)} placeholder="ssh brute force urinish..."/>
                </div>
                <button className="action-btn" style={{ padding: '8px 20px', fontSize: 12 }} onClick={loadXai} disabled={xaiLoading || !xaiIP.trim()}>
                  {xaiLoading ? 'TAHLIL...' : 'TUSHUNTIR'}
                </button>
              </div>

              {xaiData && !xaiData.error && (
                <div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 16 }}>
                    <div style={{ padding: 14, background: '#a855f711', border: '1px solid #a855f744' }}>
                      <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>BASHORAT QILINGAN TAHDID</div>
                      <div style={{ fontSize: 16, color: '#a855f7', fontFamily: 'Share Tech Mono', fontWeight: 700 }}>{xaiData.predicted_threat_label}</div>
                      <div style={{ fontSize: 10, color: '#4a6a84', marginTop: 2, fontFamily: 'Share Tech Mono' }}>{xaiData.predicted_threat}</div>
                    </div>
                    <div style={{ padding: 14, background: '#39ff1411', border: '1px solid #39ff1444' }}>
                      <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>ISHONCH DARAJASI</div>
                      <div style={{ fontSize: 24, color: '#39ff14', fontFamily: 'Share Tech Mono', fontWeight: 700 }}>{(xaiData.confidence * 100).toFixed(1)}%</div>
                    </div>
                    <div style={{ padding: 14, background: '#00e5ff11', border: '1px solid #00e5ff44' }}>
                      <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>TUSHUNTIRISH</div>
                      <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.6 }}>{xaiData.explanation}</div>
                    </div>
                  </div>

                  <Panel title="FEATURE HISSALARI (Feature Contributions)" color="#a855f7">
                    <div className="panel-body" style={{ paddingTop: 8 }}>
                      {(xaiData.top_features || []).map((f, i) => (
                        <div key={f.feature} style={{ marginBottom: 10 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: f.direction === 'up' ? '#ff6b6b' : '#39ff14' }}>
                              {f.direction === 'up' ? '▲' : '▼'} {f.feature}
                            </span>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: '#4a6a84' }}>
                              val={f.value.toFixed(3)}  imp={f.importance.toFixed(3)}  contrib={f.contribution.toFixed(4)}
                            </span>
                          </div>
                          <div style={{ height: 8, background: 'rgba(255,255,255,.05)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${Math.min(Math.abs(f.contribution) * 500, 100)}%`, background: f.direction === 'up' ? '#ff6b6b' : '#39ff14', transition: 'width .5s' }}/>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Panel>

                  {xaiData.signature && Object.keys(xaiData.signature).length > 0 && (
                    <Panel title={`TAHDID IMZOSI — ${xaiData.predicted_threat_label}`} color="#ff6b6b" style={{ marginTop: 14 }}>
                      <div className="panel-body" style={{ paddingTop: 10 }}>
                        <div style={{ marginBottom: 10 }}>
                          <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 6 }}>INDIKATORLAR</div>
                          {(xaiData.signature.indicators || []).map((ind, i) => (
                            <div key={i} style={{ fontSize: 11, color: '#94b4c8', marginBottom: 4 }}>• {ind}</div>
                          ))}
                        </div>
                        <div>
                          <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 6 }}>HIMOYA CHORALARI</div>
                          {(xaiData.signature.mitigation || []).map((m, i) => (
                            <div key={i} style={{ fontSize: 11, color: '#39ff14', marginBottom: 4 }}>✓ {m}</div>
                          ))}
                        </div>
                      </div>
                    </Panel>
                  )}

                  <Panel title="BARCHA TAHDIDLAR EHTIMOLI" color="#4a6a84" style={{ marginTop: 14 }}>
                    <div className="panel-body" style={{ paddingTop: 8 }}>
                      {Object.entries(xaiData.probabilities || {}).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                          <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#94b4c8', minWidth: 100 }}>{k}</span>
                          <div style={{ flex: 1, height: 8, background: 'rgba(255,255,255,.05)', borderRadius: 2, overflow: 'hidden' }}>
                            <div style={{ height: '100%', width: `${v * 100}%`, background: k === xaiData.predicted_threat ? '#a855f7' : '#4a6a84', transition: 'width .5s' }}/>
                          </div>
                          <span style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: k === xaiData.predicted_threat ? '#a855f7' : '#4a6a84', minWidth: 45 }}>{(v * 100).toFixed(1)}%</span>
                        </div>
                      ))}
                    </div>
                  </Panel>
                </div>
              )}
              {xaiData?.error && <div style={{ color: '#ff4444', fontFamily: 'Share Tech Mono', fontSize: 12 }}>Xato: {xaiData.error}</div>}
              {!xaiData && !xaiLoading && (
                <div style={{ color: '#4a6a84', fontFamily: 'Share Tech Mono', textAlign: 'center', padding: 30 }}>
                  IP manzil kiriting va TUSHUNTIR tugmasini bosing
                </div>
              )}
            </div>
          </Panel>
        </div>
      )}

      {/* ── 7. LSTM TREND PREDICTION ── */}
      {tab === 'lstm' && (
        <div>
          <Panel title="LSTM / MLP TIME-SERIES — TAHDID TRENDI BASHORATI" color="#00e5ff">
            <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
              <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.8, marginBottom: 14 }}>
                So'nggi 48 soatlik tahdid tarixi asosida MLP vaqt qatori modeli kelajakdagi tahdid sonini bashorat qiladi.
                Real ma'lumotlar bo'lmasa, demo rejimida ishlaydi.
              </div>
              <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end', marginBottom: 14 }}>
                <div>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>OLDINDAN KO'RA (soat)</div>
                  <select className="form-input" style={{ width: 120 }} value={lstmHours} onChange={e => setLstmHours(+e.target.value)}>
                    {[3, 6, 12, 24].map(h => <option key={h} value={h}>{h} soat</option>)}
                  </select>
                </div>
                <button className="action-btn" style={{ padding: '8px 20px', fontSize: 12 }} onClick={loadLstm} disabled={lstmLoading}>
                  {lstmLoading ? 'HISOBLANMOQDA...' : 'YANGILASH'}
                </button>
                {lstmData && (
                  <div style={{ padding: '6px 14px', background: lstmData.is_real ? '#39ff1411' : '#ffab0011', border: `1px solid ${lstmData.is_real ? '#39ff1444' : '#ffab0044'}`, fontFamily: 'Share Tech Mono', fontSize: 10, color: lstmData.is_real ? '#39ff14' : '#ffab00' }}>
                    {lstmData.is_real ? '✓ REAL DATA' : '⚠ DEMO DATA'}
                  </div>
                )}
              </div>

              {lstmLoading && <div style={{ display: 'flex', justifyContent: 'center', padding: 30 }}><div className="spinner"/></div>}

              {lstmData && !lstmLoading && (
                <div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
                    {[
                      { label: 'TREND', value: lstmData.trend_label, color: lstmData.trend === 'rising' ? '#ff4444' : lstmData.trend === 'falling' ? '#39ff14' : '#ffab00' },
                      { label: 'JORIY O\'RTA', value: lstmData.recent_avg?.toFixed(1) + '/soat', color: '#00e5ff' },
                      { label: 'BASHORAT O\'RTA', value: lstmData.predicted_avg?.toFixed(1) + '/soat', color: '#a855f7' },
                      { label: 'MODEL', value: lstmData.model, color: '#39ff14' },
                    ].map(({ label, value, color }) => (
                      <div key={label} style={{ padding: 12, background: `${color}11`, border: `1px solid ${color}44`, textAlign: 'center' }}>
                        <div style={{ fontSize: 9, color: '#4a6a84', marginBottom: 4 }}>{label}</div>
                        <div style={{ fontFamily: 'Share Tech Mono', fontSize: 13, color, fontWeight: 700 }}>{value}</div>
                      </div>
                    ))}
                  </div>

                  <Panel title="TARIX (so'nggi 48 soat) + BASHORAT" color="#00e5ff">
                    <div className="panel-body" style={{ paddingTop: 12, overflowX: 'auto' }}>
                      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 140, minWidth: 600 }}>
                        {(lstmData.history || []).slice(-24).map((h, i) => {
                          const maxH = Math.max(...(lstmData.history || []).map(x => x.count), ...(lstmData.predictions || []).map(x => x.count), 1);
                          return (
                            <div key={i} title={`${h.hour}h: ${h.count}`} style={{ flex: 1, height: `${(h.count / maxH) * 100}%`, background: '#00e5ff88', minHeight: 2, position: 'relative' }}/>
                          );
                        })}
                        <div style={{ width: 2, background: '#ffab00', alignSelf: 'stretch' }}/>
                        {(lstmData.predictions || []).map((p, i) => {
                          const maxH = Math.max(...(lstmData.history || []).map(x => x.count), ...(lstmData.predictions || []).map(x => x.count), 1);
                          return (
                            <div key={i} title={`+${p.hour}h: ${p.count}`} style={{ flex: 1, height: `${(p.count / maxH) * 100}%`, background: '#a855f7aa', minHeight: 2, border: '1px dashed #a855f7' }}/>
                          );
                        })}
                      </div>
                      <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 10, fontFamily: 'Share Tech Mono', color: '#4a6a84' }}>
                        <span style={{ color: '#00e5ff' }}>■ Tarix (24 soat)</span>
                        <span style={{ color: '#ffab00' }}>| Hozir</span>
                        <span style={{ color: '#a855f7' }}>■ Bashorat ({lstmHours} soat)</span>
                      </div>
                    </div>
                  </Panel>

                  {lstmData.type_counts_24h && (
                    <Panel title="TAHDID TURLARI — SO'NGI 24 SOAT" color="#a855f7" style={{ marginTop: 14 }}>
                      <div className="panel-body" style={{ paddingTop: 8 }}>
                        {Object.entries(lstmData.type_counts_24h).map(([k, v]) => (
                          <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#94b4c8', minWidth: 100 }}>{k}</span>
                            <div style={{ flex: 1, height: 8, background: 'rgba(255,255,255,.05)', borderRadius: 2, overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: `${Math.min(v * 10, 100)}%`, background: '#a855f7', transition: 'width .5s' }}/>
                            </div>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#a855f7', minWidth: 30 }}>{v}</span>
                          </div>
                        ))}
                      </div>
                    </Panel>
                  )}
                </div>
              )}
            </div>
          </Panel>
        </div>
      )}

      {/* ── 8. GEOIP XARITASI ── */}
      {tab === 'geoip' && (
        <div>
          <Panel title="GEOIP — IP MANZILLAR GEOGRAFIYASI" color="#39ff14">
            <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
              <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.8, marginBottom: 14 }}>
                Tahdid loglaridagi IP manzillar qayerdan kelganini ko'ring. ip-api.com orqali aniqlanadi (bepul, API kalit talab qilmaydi).
              </div>
              <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'flex-end' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 10, color: '#4a6a84', marginBottom: 4 }}>BITTA IP QIDIRISH</div>
                  <input className="form-input" value={geoIP} onChange={e => setGeoIP(e.target.value)} placeholder="8.8.8.8" onKeyDown={e => e.key === 'Enter' && lookupGeoip()}/>
                </div>
                <button className="action-btn" style={{ padding: '8px 16px', fontSize: 12 }} onClick={lookupGeoip} disabled={geoLoading || !geoIP.trim()}>QIDIRISH</button>
                <button className="filter-btn" onClick={loadBulkGeoip} disabled={geoLoading}>BARCHA TAHDIDLAR</button>
              </div>

              {geoLoading && <div style={{ display: 'flex', justifyContent: 'center', padding: 30 }}><div className="spinner"/></div>}

              {geoData && !geoLoading && (() => {
                const items = geoData.single ? [geoData.single] : (geoData.results || []);
                const riskColor = r => r === 'high' ? '#ff1744' : r === 'medium' ? '#ffab00' : '#39ff14';
                return (
                  <div>
                    {geoData.single && (
                      <div>
                        <div style={{ marginBottom: 14, padding: 16, background: '#39ff1411', border: '1px solid #39ff1444' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
                            {[
                              ['IP', geoData.single.ip],
                              ['MAMLAKAT', `${geoData.single.country_code} — ${geoData.single.country}`],
                              ['SHAHAR', `${geoData.single.city || '-'}, ${geoData.single.region || '-'}`],
                              ['ISP', geoData.single.isp || '-'],
                              ['KOORDINATLAR', geoData.single.lat ? `${geoData.single.lat?.toFixed(2)}, ${geoData.single.lon?.toFixed(2)}` : '-'],
                              ['XAVF', geoData.single.risk?.toUpperCase() || '-'],
                            ].map(([k, v]) => (
                              <div key={k}>
                                <div style={{ fontSize: 9, color: '#4a6a84', marginBottom: 2 }}>{k}</div>
                                <div style={{ fontFamily: 'Share Tech Mono', fontSize: 12, color: k === 'XAVF' ? riskColor(geoData.single.risk) : '#94b4c8' }}>{v}</div>
                              </div>
                            ))}
                          </div>
                          {geoData.single.is_proxy && <div style={{ marginTop: 8, color: '#ff1744', fontFamily: 'Share Tech Mono', fontSize: 11 }}>⚠ PROXY / VPN ANIQLANDI</div>}
                          {geoData.single.is_hosting && <div style={{ marginTop: 4, color: '#ffab00', fontFamily: 'Share Tech Mono', fontSize: 11 }}>⚠ HOSTING / DATACENTER IP</div>}
                          {geoData.single.error && <div style={{ color: '#ff4444', fontSize: 11 }}>{geoData.single.error}</div>}
                        </div>
                        {geoData.single.lat != null && (
                          <GlobeCanvas
                            countryCode={geoData.single.country_code}
                            lat={geoData.single.lat}
                            lon={geoData.single.lon}
                          />
                        )}
                      </div>
                    )}

                    {items.length > 0 && (
                      <table className="alerts-table">
                        <thead>
                          <tr><th>#</th><th>IP</th><th>MAMLAKAT</th><th>SHAHAR</th><th>ISP</th><th>PROXY</th><th>XAVF</th></tr>
                        </thead>
                        <tbody>
                          {items.map((g, i) => (
                            <tr key={g.ip || i}>
                              <td className="td-mono" style={{ color: '#4a6a84' }}>{i + 1}</td>
                              <td className="td-mono">{g.ip}</td>
                              <td className="td-mono">{g.country_code} — {g.country}</td>
                              <td className="td-mono" style={{ fontSize: 10, color: '#4a6a84' }}>{g.city || '-'}</td>
                              <td className="td-mono" style={{ fontSize: 10, color: '#4a6a84' }}>{g.isp || '-'}</td>
                              <td className="td-mono" style={{ color: g.is_proxy ? '#ff1744' : '#39ff14' }}>{g.is_proxy ? 'HA' : 'YOQ'}</td>
                              <td><span style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: riskColor(g.risk) }}>{(g.risk || 'low').toUpperCase()}</span></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                );
              })()}
              {!geoData && !geoLoading && (
                <div style={{ color: '#4a6a84', fontFamily: 'Share Tech Mono', textAlign: 'center', padding: 30 }}>
                  IP kiriting yoki "BARCHA TAHDIDLAR" tugmasini bosing
                </div>
              )}
            </div>
          </Panel>

          <Panel title="GLOBAL SUBMARINE CABLE MAP — DUNYO KABEL TARMOG'I" color="#ff1744">
            <div className="panel-body" style={{ paddingTop: 10, paddingBottom: 10 }}>
              <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.7, marginBottom: 10 }}>
                Dunyo bo'ylab suv osti fiber-optik kabellari. Qizil chiziqlar — asosiy magistral yo'nalishlar. Nuqtalar — quruqlikka chiqish joylari (landing stations).
              </div>
              <WorldCableMap />
            </div>
          </Panel>
        </div>
      )}

      {/* ── 9. XATTI-HARAKAT TAHLILI ── */}
      {tab === 'behavior' && (
        <div>
          <Panel title="XATTI-HARAKAT TAHLILI — IP VA TARMOQ SKAN STATISTIKASI" color="#ffab00">
            <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
              <div style={{ display: 'flex', gap: 12, marginBottom: 14 }}>
                <button className="action-btn" style={{ padding: '8px 20px', fontSize: 12 }} onClick={loadBehavior} disabled={behaviorLoading}>
                  {behaviorLoading ? 'YUKLANMOQDA...' : 'YANGILASH'}
                </button>
              </div>

              {behaviorLoading && <div style={{ display: 'flex', justifyContent: 'center', padding: 30 }}><div className="spinner"/></div>}

              {behaviorData && !behaviorLoading && (
                <div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 16 }}>
                    {[
                      { label: "7 KUNLIK TAHDIDLAR", value: behaviorData.total_threats_7d, color: '#ff4444' },
                      { label: 'BLOKLANGAN (7 kun)', value: behaviorData.blocked_count_7d, color: '#ffab00' },
                      { label: 'SKANLAR (24 soat)', value: behaviorData.scan_count_24h, color: '#00e5ff' },
                      { label: 'SKANLAR (7 kun)', value: behaviorData.scan_count_7d, color: '#39ff14' },
                    ].map(({ label, value, color }) => (
                      <div key={label} style={{ padding: 12, background: `${color}11`, border: `1px solid ${color}44`, textAlign: 'center' }}>
                        <div style={{ fontSize: 9, color: '#4a6a84', marginBottom: 4 }}>{label}</div>
                        <div style={{ fontFamily: 'Share Tech Mono', fontSize: 20, color, fontWeight: 700 }}>{value ?? 0}</div>
                      </div>
                    ))}
                  </div>

                  {(behaviorData.anomalies || []).length > 0 && (
                    <div style={{ marginBottom: 14, padding: 12, background: '#ff444411', border: '1px solid #ff444444' }}>
                      <div style={{ fontSize: 11, color: '#ff4444', fontFamily: 'Share Tech Mono', fontWeight: 700, marginBottom: 8 }}>ANOMALIYALAR ANIQLANDI</div>
                      {behaviorData.anomalies.map((a, i) => (
                        <div key={i} style={{ fontSize: 11, color: '#ffab00', marginBottom: 4 }}>⚠ {a.message}</div>
                      ))}
                    </div>
                  )}

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                    <Panel title="ENG KO'P TAHLIL QILINGAN IP LAR (7 kun)" color="#ffab00">
                      <div className="panel-body" style={{ paddingTop: 8 }}>
                        {(behaviorData.top_ips || []).map((item, i) => (
                          <div key={item.ip_address} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: '#4a6a84', minWidth: 20 }}>#{i+1}</span>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#94b4c8', flex: 1 }}>{item.ip_address}</span>
                            <div style={{ width: 80, height: 6, background: 'rgba(255,255,255,.05)', borderRadius: 2, overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: `${Math.min(item.count / ((behaviorData.top_ips[0]?.count || 1)) * 100, 100)}%`, background: '#ffab00' }}/>
                            </div>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#ffab00', minWidth: 30 }}>{item.count}</span>
                          </div>
                        ))}
                        {(behaviorData.top_ips || []).length === 0 && (
                          <div style={{ color: '#4a6a84', fontFamily: 'Share Tech Mono', fontSize: 11 }}>Hali ma'lumot yo'q</div>
                        )}
                      </div>
                    </Panel>

                    <Panel title="KO'P BLOKLANGAN IP LAR (7 kun)" color="#ff4444">
                      <div className="panel-body" style={{ paddingTop: 8 }}>
                        {(behaviorData.blocked_ips || []).map((item, i) => (
                          <div key={item.ip_address} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 10, color: '#4a6a84', minWidth: 20 }}>#{i+1}</span>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#94b4c8', flex: 1 }}>{item.ip_address}</span>
                            <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#ff4444', minWidth: 30 }}>{item.count}x</span>
                          </div>
                        ))}
                        {(behaviorData.blocked_ips || []).length === 0 && (
                          <div style={{ color: '#4a6a84', fontFamily: 'Share Tech Mono', fontSize: 11 }}>Bloklangan IP yo'q</div>
                        )}
                      </div>
                    </Panel>
                  </div>

                  {(behaviorData.critical_events || []).length > 0 && (
                    <Panel title="KRITIK HODISALAR — SO'NGI 24 SOAT" color="#ff1744" style={{ marginTop: 14 }}>
                      <div className="panel-body" style={{ overflowX: 'auto', paddingTop: 8 }}>
                        <table className="alerts-table">
                          <thead>
                            <tr><th>IP</th><th>TAHDID TURI</th><th>VAQT</th></tr>
                          </thead>
                          <tbody>
                            {(behaviorData.critical_events || []).map((ev, i) => (
                              <tr key={i}>
                                <td style={{ color: '#ff6b6b', fontFamily: 'Share Tech Mono' }}>{ev.ip_address}</td>
                                <td className="td-mono">{ev.threat_type}</td>
                                <td className="td-mono" style={{ fontSize: 10, color: '#4a6a84' }}>{new Date(ev.created_at).toLocaleString()}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </Panel>
                  )}
                </div>
              )}
              {!behaviorData && !behaviorLoading && (
                <div style={{ color: '#4a6a84', fontFamily: 'Share Tech Mono', textAlign: 'center', padding: 30 }}>
                  YANGILASH tugmasini bosib statistikani ko'ring
                </div>
              )}
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}

// ── VISUALIZATION PAGE ─────────────────────────────────────────────────────
function VisualizationPage() {
  const [tab, setTab] = useState('timeline');
  const [timelineData, setTimelineData] = useState(null);
  const [heatmapData, setHeatmapData] = useState(null);
  const [days, setDays] = useState(7);
  const [loading, setLoading] = useState(false);
  const accent = themeAccent('cyan', '#00e5ff');

  useEffect(() => {
    if (tab === 'timeline') loadTimeline();
    if (tab === 'heatmap' && !heatmapData) loadHeatmap();
  }, [tab, days]);

  const loadTimeline = async () => {
    setLoading(true);
    try { setTimelineData(await api.getThreatTimeline(days)); } catch { }
    setLoading(false);
  };

  const loadHeatmap = async () => {
    setLoading(true);
    try { setHeatmapData(await api.getHeatmap()); } catch { }
    setLoading(false);
  };

  const threatColors = {
    ddos: '#ff1744', sqli: '#ff4500', brute_force: '#ff8c00', phishing: '#ffd700',
    ransomware: '#e040fb', mitm: '#00bcd4', zero_day: '#f97316', apt: '#a855f7', port_scan: '#64b5f6',
  };

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      <div className="filter-bar" style={{ marginBottom: 16 }}>
        <button className={`filter-btn${tab === 'timeline' ? ' active' : ''}`} onClick={() => setTab('timeline')}>Hujum Vaqt Chizig'i</button>
        <button className={`filter-btn${tab === 'heatmap' ? ' active' : ''}`} onClick={() => setTab('heatmap')}>Tahdid Issiqlik Xaritasi</button>
      </div>

      {/* ── TIMELINE ── */}
      {tab === 'timeline' && (
        <div>
          <div style={{ display: 'flex', gap: 10, marginBottom: 14, alignItems: 'center' }}>
            {[3, 7, 14, 30].map(d => (
              <button key={d} className={`filter-btn${days === d ? ' active' : ''}`} onClick={() => setDays(d)}>{d} kun</button>
            ))}
            {loading && <div className="spinner" style={{ width: 18, height: 18 }}/>}
          </div>

          {timelineData && (
            <>
              <Panel title={`HUJUM VAQT CHIZIG'I — ${days} KUNLIK TREND`} color={accent}>
                <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
                  {/* Simple SVG line chart */}
                  {(() => {
                    const data = timelineData.timeline || [];
                    if (!data.length) return <div style={{ color: '#4a6a84', textAlign: 'center', padding: 20 }}>Ma'lumot yo'q</div>;
                    const W = 800, H = 180, PAD = 40;
                    const maxVal = Math.max(1, ...data.map(d => d.total));
                    const xStep = (W - PAD * 2) / Math.max(data.length - 1, 1);
                    const yScale = (val) => H - PAD - (val / maxVal) * (H - PAD * 2);

                    const makePath = (key) => {
                      const pts = data.map((d, i) => `${PAD + i * xStep},${yScale(d[key] || 0)}`);
                      return `M ${pts.join(' L ')}`;
                    };

                    const threats = ['ddos', 'sqli', 'brute_force', 'phishing', 'ransomware', 'mitm', 'zero_day', 'apt', 'port_scan'];
                    return (
                      <div style={{ overflowX: 'auto' }}>
                        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', minWidth: 500 }}>
                          {[0, 0.25, 0.5, 0.75, 1].map(pct => (
                            <g key={pct}>
                              <line x1={PAD} y1={yScale(maxVal * pct)} x2={W - PAD} y2={yScale(maxVal * pct)}
                                stroke="rgba(74,106,132,.2)" strokeWidth="1"/>
                              <text x={PAD - 4} y={yScale(maxVal * pct) + 4} textAnchor="end"
                                fontSize="9" fill="#4a6a84" fontFamily="Share Tech Mono">{Math.round(maxVal * pct)}</text>
                            </g>
                          ))}
                          <path d={makePath('total')} fill="none" stroke={accent} strokeWidth="2" opacity="0.4"/>
                          {threats.map(t => (
                            <path key={t} d={makePath(t)} fill="none" stroke={threatColors[t]} strokeWidth="1.5" opacity="0.75"/>
                          ))}
                          {data.filter((_, i) => i % Math.max(1, Math.floor(data.length / 8)) === 0).map((d, i, arr) => {
                            const origIdx = data.indexOf(d);
                            return (
                              <text key={i} x={PAD + origIdx * xStep} y={H - 4} textAnchor="middle"
                                fontSize="8" fill="#4a6a84" fontFamily="Share Tech Mono">{d.label}</text>
                            );
                          })}
                        </svg>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 10 }}>
                          {threats.map(t => (
                            <span key={t} style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: threatColors[t] }}>
                              ─ {t.toUpperCase()}
                            </span>
                          ))}
                          <span style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: accent, opacity: 0.6 }}>── TOTAL</span>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              </Panel>

              <Panel title="TAHDID TURLARINING UMUMIY TAQSIMOTI" color="#a855f7" style={{ marginTop: 14 }}>
                <div className="panel-body" style={{ display: 'flex', flexWrap: 'wrap', gap: 10, paddingTop: 10, paddingBottom: 10 }}>
                  {Object.entries(timelineData.threat_totals || {}).map(([threat, count]) => (
                    <div key={threat} style={{
                      padding: '10px 16px', border: `1px solid ${(threatColors[threat] || '#4a6a84')}44`,
                      background: `${(threatColors[threat] || '#4a6a84')}11`, borderRadius: 4,
                    }}>
                      <div style={{ fontSize: 10, color: '#4a6a84', letterSpacing: 1 }}>{threat.toUpperCase()}</div>
                      <div style={{ fontSize: 22, fontFamily: 'Orbitron,monospace', color: threatColors[threat] || '#4a6a84', marginTop: 4 }}>{count}</div>
                    </div>
                  ))}
                </div>
              </Panel>
            </>
          )}
        </div>
      )}

      {/* ── HEATMAP ── */}
      {tab === 'heatmap' && (
        <div>
          {loading && <div style={{ display: 'flex', justifyContent: 'center', padding: 40 }}><div className="spinner"/></div>}
          {heatmapData && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <Panel title="PORT BO'YICHA HUJUM TAQSIMOTI" color={accent}>
                <div className="panel-body" style={{ paddingTop: 8, paddingBottom: 8 }}>
                  {Object.entries(heatmapData.all_ports || {})
                    .filter(([, v]) => v.count > 0 || v.label)
                    .sort(([, a], [, b]) => b.count - a.count)
                    .slice(0, 15)
                    .map(([port, info]) => {
                      const maxCount = Math.max(1, ...Object.values(heatmapData.all_ports || {}).map(v => v.count));
                      const pct = (info.count / maxCount) * 100;
                      const htPct = info.count > 0 ? (info.high_threat / info.count) * 100 : 0;
                      return (
                        <div key={port} style={{ marginBottom: 8 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                            <span style={{ fontSize: 11, fontFamily: 'Share Tech Mono', color: '#94b4c8' }}>
                              :{port} <span style={{ color: '#4a6a84' }}>{info.label}</span>
                            </span>
                            <span style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: htPct > 50 ? '#ff4444' : accent }}>
                              {info.count} scan | {Math.round(htPct)}% yuksak xavf
                            </span>
                          </div>
                          <div style={{ height: 10, background: 'rgba(255,255,255,.07)', borderRadius: 2, overflow: 'hidden', display: 'flex' }}>
                            <div style={{ height: '100%', width: `${pct * (1 - htPct / 100)}%`, background: accent, opacity: 0.5 }}/>
                            <div style={{ height: '100%', width: `${pct * htPct / 100}%`, background: '#ff1744', opacity: 0.8 }}/>
                          </div>
                        </div>
                      );
                    })}
                </div>
              </Panel>

              <Panel title="SUBNET BO'YICHA TAHDID ZICHLIGI" color="#ff1744">
                {Object.keys(heatmapData.subnets || {}).length === 0 ? (
                  <div style={{ color: '#4a6a84', padding: 20, fontFamily: 'Share Tech Mono', textAlign: 'center' }}>
                    Tahdid loglari yo'q — IP tahlil sahifasidan ba'zi tahlillar qiling
                  </div>
                ) : (
                  <div className="panel-body" style={{ overflowX: 'auto', paddingTop: 8, paddingBottom: 8 }}>
                    <table className="alerts-table">
                      <thead>
                        <tr><th>SUBNET</th><th>JAMI</th><th>KRITIK</th><th>YUQORI</th><th>O'RTA</th></tr>
                      </thead>
                      <tbody>
                        {Object.entries(heatmapData.subnets || {}).sort(([, a], [, b]) => b.count - a.count).map(([subnet, info]) => (
                          <tr key={subnet}>
                            <td className="td-mono" style={{ color: '#00e5ff' }}>{subnet}</td>
                            <td className="td-mono">{info.count}</td>
                            <td className="td-mono" style={{ color: '#ff1744' }}>{info.critical}</td>
                            <td className="td-mono" style={{ color: '#ff8c00' }}>{info.high}</td>
                            <td className="td-mono" style={{ color: '#ffab00' }}>{info.medium}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>
            </div>
          )}
          {!heatmapData && !loading && (
            <div style={{ textAlign: 'center', padding: 40, color: '#4a6a84', fontFamily: 'Share Tech Mono' }}>
              <button className="filter-btn active" onClick={loadHeatmap}>HEATMAP YUKLASH</button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── MITRE ATT&CK PAGE ─────────────────────────────────────────────────────
function MitrePage() {
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const accent = themeAccent('cyan', '#00e5ff');

  useEffect(() => {
    api.getMitreList().then(d => { setData(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  const tacticColors = {
    'Initial Access': '#ff8c00', 'Execution': '#e040fb', 'Credential Access': '#ff1744',
    'Discovery': '#64b5f6', 'Lateral Movement': '#a855f7', 'Collection': '#00bcd4',
    'Impact': '#ff1744', 'Exfiltration': '#f97316',
  };

  const killChainColors = ['#4a6a84', '#ffab00', '#ff8f00', '#e65100', '#c62828', '#b71c1c', '#ff1744'];

  if (loading) return <div style={{ display: 'flex', justifyContent: 'center', padding: 60 }}><div className="spinner"/></div>;

  const mappings = data?.mappings || [];
  const phases = data?.kill_chain_phases || [];

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      {/* Kill Chain visualization */}
      <Panel title="LOCKHEED MARTIN CYBER KILL CHAIN" color={accent} style={{ marginBottom: 14 }}>
        <div className="panel-body" style={{ paddingTop: 14, paddingBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'stretch', gap: 0, overflowX: 'auto' }}>
            {phases.map((phase, i) => {
              const activeThreats = mappings.filter(m => m.kill_chain_index === i);
              return (
                <div key={phase.name} style={{ flex: 1, minWidth: 110, position: 'relative' }}>
                  <div style={{
                    padding: '14px 10px', textAlign: 'center',
                    background: `${killChainColors[i]}22`,
                    border: `1px solid ${killChainColors[i]}44`,
                    borderRight: i < phases.length - 1 ? 'none' : `1px solid ${killChainColors[i]}44`,
                    minHeight: 80,
                  }}>
                    <div style={{ fontSize: 9, color: '#4a6a84', letterSpacing: 1, marginBottom: 4 }}>{i + 1}</div>
                    <div style={{ fontSize: 11, color: killChainColors[i], fontFamily: 'Share Tech Mono', fontWeight: 700, marginBottom: 6 }}>
                      {phase.label}
                    </div>
                    <div style={{ fontSize: 9, color: '#4a6a84' }}>{phase.name}</div>
                    {activeThreats.length > 0 && (
                      <div style={{ marginTop: 8, display: 'flex', flexWrap: 'wrap', gap: 3, justifyContent: 'center' }}>
                        {activeThreats.map(t => (
                          <span key={t.threat_type} onClick={() => setSelected(t)} style={{
                            fontSize: 8, padding: '2px 5px', borderRadius: 2,
                            background: `${killChainColors[i]}33`, color: killChainColors[i],
                            border: `1px solid ${killChainColors[i]}66`, cursor: 'pointer',
                            fontFamily: 'Share Tech Mono',
                          }}>{t.threat_type.toUpperCase()}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  {i < phases.length - 1 && (
                    <div style={{
                      position: 'absolute', right: -8, top: '50%', transform: 'translateY(-50%)',
                      width: 0, height: 0, zIndex: 1,
                      borderTop: '6px solid transparent', borderBottom: '6px solid transparent',
                      borderLeft: `8px solid ${killChainColors[i]}66`,
                    }}/>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </Panel>

      {/* MITRE Table */}
      <Panel title="MITRE ATT&CK TEXNIKALAR JADVALI" color="#a855f7">
        <div className="panel-body" style={{ overflowX: 'auto' }}>
          <table className="alerts-table">
            <thead>
              <tr><th>TAHDID</th><th>TEXNIKA ID</th><th>TEXNIKA</th><th>TAKTIKA</th><th>KILL CHAIN</th><th>AHAMIYAT</th></tr>
            </thead>
            <tbody>
              {mappings.map(m => (
                <tr key={m.threat_type} onClick={() => setSelected(selected?.threat_type === m.threat_type ? null : m)}
                  style={{ cursor: 'pointer', background: selected?.threat_type === m.threat_type ? 'rgba(0,229,255,.06)' : undefined }}>
                  <td style={{ fontWeight: 700, color: accent }}>{m.threat_name}</td>
                  <td className="td-mono" style={{ color: '#a855f7' }}>{m.technique_id}</td>
                  <td style={{ fontSize: 12, color: '#94b4c8' }}>{m.technique}</td>
                  <td>
                    <span style={{
                      fontSize: 10, padding: '2px 8px', border: '1px solid',
                      borderColor: `${tacticColors[m.tactic] || '#4a6a84'}66`,
                      color: tacticColors[m.tactic] || '#4a6a84',
                      background: `${tacticColors[m.tactic] || '#4a6a84'}11`,
                      fontFamily: 'Share Tech Mono',
                    }}>{m.tactic}</span>
                  </td>
                  <td style={{ color: killChainColors[m.kill_chain_index] || '#4a6a84', fontSize: 11, fontFamily: 'Share Tech Mono' }}>
                    {phases[m.kill_chain_index]?.label || m.kill_chain_phase}
                  </td>
                  <td><Badge sev={m.severity}/></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      {selected && (
        <Panel title={`TEXNIKA TAFSILOTI — ${selected.technique_id}`} color={accent} style={{ marginTop: 14 }}>
          <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, paddingTop: 12, paddingBottom: 12 }}>
            {[
              ['Tahdid turi', selected.threat_name, accent],
              ['Texnika ID', selected.technique_id, '#a855f7'],
              ['Taktika', selected.tactic, tacticColors[selected.tactic] || '#4a6a84'],
              ['Kill Chain bosqichi', phases[selected.kill_chain_index]?.label || selected.kill_chain_phase, killChainColors[selected.kill_chain_index]],
            ].map(([lbl, val, col]) => (
              <div key={lbl} style={{ padding: 14, border: `1px solid ${col}44` }}>
                <div style={{ fontSize: 10, color: '#4a6a84', letterSpacing: 1, marginBottom: 4 }}>{lbl}</div>
                <div style={{ color: col, fontFamily: 'Share Tech Mono', fontSize: 14 }}>{val}</div>
              </div>
            ))}
          </div>
          <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12, color: '#94b4c8', fontSize: 13, lineHeight: 1.8 }}>
            {selected.description}
          </div>
        </Panel>
      )}
    </div>
  );
}

// ── REPORTS PAGE ───────────────────────────────────────────────────────────
function ReportsPage() {
  const [incidents, setIncidents] = useState([]);
  const [incLoading, setIncLoading] = useState(false);
  const [correlating, setCorrelating] = useState(false);
  const [corrMsg, setCorrMsg] = useState('');
  const [migrateMsg, setMigrateMsg] = useState('');
  const [migrateLoading, setMigrateLoading] = useState(false);
  const accent = themeAccent('cyan', '#00e5ff');

  const runMigrate = async () => {
    setMigrateLoading(true); setMigrateMsg('');
    try {
      const res = await api.runMigration();
      setMigrateMsg(res.success ? `✓ ${res.output?.trim() || "Barcha migrationlar qo'llandi"}` : `⚠ ${res.error}`);
      if (res.success) loadIncidents();
    } catch (e) { setMigrateMsg('Xato: ' + e.message); }
    setMigrateLoading(false);
  };

  useEffect(() => { loadIncidents(); }, []);

  const loadIncidents = async () => {
    setIncLoading(true);
    try {
      const d = await api.getIncidents();
      setIncidents(d.incidents || []);
    } catch { }
    setIncLoading(false);
  };

  const runCorr = async () => {
    setCorrelating(true);
    setCorrMsg('');
    try {
      const d = await api.runCorrelation();
      const n = (d.new_incidents || []).length;
      setCorrMsg(n > 0 ? `${n} ta yangi intsident aniqlandi!` : "Yangi intsidentlar topilmadi (yetarli tahdid log yo'q)");
      setIncidents(d.all_incidents || []);
    } catch (e) { setCorrMsg('Xato: ' + e.message); }
    setCorrelating(false);
  };

  const sev = s => ({ critical: '#ff1744', high: '#ff8c00', medium: '#ffab00', low: '#39ff14' }[s] || '#4a6a84');

  return (
    <div style={{ animation: 'fadeUp .3s ease' }}>
      {/* ── DATABASE MIGRATION TRIGGER ── */}
      <div style={{ marginBottom: 14, padding: '10px 16px', background: 'rgba(255,171,0,.06)', border: '1px solid rgba(255,171,0,.3)', display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: '#ffab00' }}>⚠ JADVAL XATOSI BO'LSA:</span>
        <button
          className="action-btn"
          style={{ padding: '6px 16px', fontSize: 11, borderColor: '#ffab0066', color: '#ffab00' }}
          onClick={runMigrate}
          disabled={migrateLoading}
        >
          {migrateLoading ? 'QABUL QILINMOQDA...' : 'DB MIGRATIONLARNI QABUL QILISH'}
        </button>
        {migrateMsg && (
          <span style={{ fontFamily: 'Share Tech Mono', fontSize: 11, color: migrateMsg.startsWith('✓') ? '#39ff14' : '#ff4444', flex: 1 }}>
            {migrateMsg}
          </span>
        )}
      </div>

      {/* Export cards */}
      <Panel title="MA'LUMOTLARNI EKSPORT QILISH" color={accent} style={{ marginBottom: 14 }}>
        <div className="panel-body" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14, paddingTop: 14, paddingBottom: 14 }}>
          {[
            { title: 'CSV EKSPORT', desc: 'Excel va data analysis uchun', color: '#39ff14', url: api.getExportCsvUrl(), fileName: 'cyberguard_threats.csv' },
            { title: 'JSON EKSPORT', desc: 'API va dasturlash uchun', color: '#00e5ff', url: api.getExportJsonUrl(), fileName: 'cyberguard_threats.json' },
            { title: 'PDF HISOBOT', desc: 'Professional taqdimot uchun', color: '#ff4444', url: api.getExportPdfUrl(), fileName: 'cyberguard_report.pdf' },
          ].map(({ title, desc, color, url, fileName }) => (
            <div key={title} style={{
              padding: 20, border: `1px solid ${color}44`, background: `${color}08`,
              display: 'flex', flexDirection: 'column', gap: 10,
            }}>
              <div style={{ fontSize: 14, color, fontFamily: 'Share Tech Mono', fontWeight: 700 }}>{title}</div>
              <div style={{ fontSize: 12, color: '#4a6a84', flex: 1 }}>{desc}</div>
              <a
                href={url}
                download={fileName}
                style={{
                  display: 'inline-block', padding: '8px 16px', background: `${color}22`,
                  border: `1px solid ${color}66`, color, fontFamily: 'Share Tech Mono',
                  fontSize: 12, textDecoration: 'none', textAlign: 'center', cursor: 'pointer',
                }}
                onClick={e => {
                  e.preventDefault();
                  const apiKey = localStorage.getItem('cg_api_key') || 'cyberguard-demo-key';
                  fetch(url, { headers: { 'X-API-Key': apiKey } })
                    .then(r => r.ok ? r.blob() : Promise.reject(r.status))
                    .then(blob => {
                      const a = document.createElement('a');
                      a.href = URL.createObjectURL(blob);
                      a.download = fileName;
                      a.click();
                      URL.revokeObjectURL(a.href);
                    })
                    .catch(() => {});
                }}
              >YUKLAB OLISH</a>
            </div>
          ))}
        </div>
      </Panel>

      {/* Incidents / Correlation */}
      <Panel title="TAHDID KORRELYATSIYASI — INTSIDENTLAR" color="#ff4444">
        <div className="panel-body" style={{ paddingTop: 12, paddingBottom: 12 }}>
          <div style={{ fontSize: 11, color: '#94b4c8', lineHeight: 1.8, marginBottom: 14 }}>
            Korrelyatsiya dvigatel mavjud tahdid loglarini tahlil qilib, bir nechta hodisani birlashtirib "Intsident" sifatida qayd etadi.
            Masalan: Brute Force + Port Scan → APT hujumi ehtimoli.
          </div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 14 }}>
            <button className="action-btn" style={{ padding: '8px 20px', fontSize: 12 }} onClick={runCorr} disabled={correlating}>
              {correlating ? 'TAHLIL QILINMOQDA...' : 'KORRELYATSIYA DVIGATELNI ISHLATISH'}
            </button>
            <button className="filter-btn" onClick={loadIncidents}>YANGILASH</button>
            {corrMsg && (
              <span style={{
                fontFamily: 'Share Tech Mono', fontSize: 12,
                color: corrMsg.includes('yangi') && !corrMsg.includes("yo'q") ? '#39ff14' : '#ffab00',
              }}>{corrMsg}</span>
            )}
          </div>

          {incLoading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 30 }}><div className="spinner"/></div>
          ) : incidents.length === 0 ? (
            <div style={{ color: '#4a6a84', fontFamily: 'Share Tech Mono', textAlign: 'center', padding: 20 }}>
              Hozircha intsident yo'q. Korrelyatsiya dvigatelni ishlatib ko'ring.
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 10 }}>
              {incidents.map(inc => (
                <div key={inc.id} style={{
                  padding: 16, border: `1px solid ${sev(inc.severity)}44`,
                  background: `${sev(inc.severity)}08`,
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                    <div>
                      <span style={{ color: sev(inc.severity), fontFamily: 'Share Tech Mono', fontWeight: 700, fontSize: 14 }}>{inc.title}</span>
                      <span style={{ marginLeft: 10, fontSize: 10, color: '#4a6a84' }}>#{inc.id}</span>
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <Badge sev={inc.severity}/>
                      <span style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: '#4a6a84' }}>
                        {new Date(inc.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>
                  <div style={{ fontSize: 12, color: '#94b4c8', marginBottom: 8 }}>{inc.description}</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: '#4a6a84' }}>
                      Aloqador IP lar:
                    </span>
                    {(inc.involved_ips || []).slice(0, 6).map(ip => (
                      <span key={ip} style={{ fontSize: 10, fontFamily: 'Share Tech Mono', color: '#00e5ff', padding: '1px 6px', border: '1px solid #00e5ff33', background: '#00e5ff11' }}>{ip}</span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}


// ── ROOT APP ───────────────────────────────────────────────────────────────
export default function App() {
  const [loggedIn, setLoggedIn] = useState(() => safeStorageGet('cg_auth', '') === '1');
  const [page, setPage]         = useState(() => {
    const stored = safeStorageGet('cg_page', 'dashboard');
    return stored === 'insights' ? 'threat_library' : stored;
  });
  const [analyzeIP, setAnalyzeIP] = useState('');
  const [analyzeContext, setAnalyzeContext] = useState('');
  const [analyzeThreat, setAnalyzeThreat] = useState('');
  const [alertCount, setAlertCount] = useState(0);
  const [themeMode, setThemeMode] = useState(() => safeStorageGet('cg_theme', 'classic'));
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const time = useClock();
  const isMobile = useViewport(900);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', themeMode);
    document.body.setAttribute('data-theme', themeMode);
    safeStorageSet('cg_theme', themeMode);
  }, [themeMode]);

  useEffect(() => {
    if (!isMobile) {
      setMobileNavOpen(false);
    }
  }, [isMobile]);

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

  const navTo = p => { setPage(p); safeStorageSet('cg_page', p); };
  const handleLogin = () => { safeStorageSet('cg_auth', '1'); setLoggedIn(true); };
  const toggleTheme = () => setThemeMode(mode => mode === 'hacker' ? 'classic' : 'hacker');

  const handleNetworkAnalyze = (ip, options = {}) => {
    setAnalyzeIP(ip);
    setAnalyzeContext(options.context || '');
    setAnalyzeThreat(options.threat || '');
    navTo('analyze');
  };

  if (!loggedIn) return <LoginPage onLogin={handleLogin}/>;

  return (
    <div className={`app ${themeMode === 'hacker' ? 'theme-hacker' : 'theme-classic'}`}>
      {isMobile && mobileNavOpen && <div className="mobile-sidebar-backdrop" onClick={() => setMobileNavOpen(false)}/>}
      <Sidebar
        page={page}
        setPage={navTo}
        alertCount={alertCount}
        mobileOpen={!isMobile || mobileNavOpen}
        onClose={() => setMobileNavOpen(false)}
        themeMode={themeMode}
        onToggleTheme={toggleTheme}
      />
      <div className="main">
        <TopBar page={page} time={time} onMenuToggle={() => setMobileNavOpen(open => !open)} themeMode={themeMode} onToggleTheme={toggleTheme}/>
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
          {page === 'ai_lab'    && <AILabPage/>}
          {page === 'visualization' && <VisualizationPage/>}
          {page === 'mitre'     && <MitrePage/>}
          {page === 'reports'   && <ReportsPage/>}
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



