import { useState, useEffect } from 'react';
import { api } from '../services/api';

const RISK_COLOR = {
  critical: { bg: '#FCEBEB', text: '#A32D2D', label: 'Kritik' },
  high:     { bg: '#FAEEDA', text: '#854F0B', label: 'Yuqori' },
  medium:   { bg: '#E6F1FB', text: '#185FA5', label: "O'rta" },
  low:      { bg: '#EAF3DE', text: '#3B6D11', label: 'Past' },
  unknown:  { bg: '#F1EFE8', text: '#5F5E5A', label: 'Noma\'lum' },
};

export default function NetworkScan({ onAnalyze }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(null);
  const [reputation, setReputation] = useState(null);

  const scan = async () => {
    setLoading(true);
    try {
      const data = await api.scanNetwork();
      setDevices(data.devices || []);
    } catch {
      setDevices(getDemoDevices());
    }
    setLoading(false);
  };

  const checkReputation = async (ip) => {
    setReputation(null);
    setSelected(ip);
    const data = await api.getReputation(ip);
    setReputation(data);
  };

  useEffect(() => { scan(); }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 13, color: 'var(--muted)' }}>
          {devices.length} qurilma topildi
        </span>
        <button className="btn-primary" onClick={scan} disabled={loading}>
          {loading ? 'Skanerlayapti...' : 'Qayta skanerlash'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        {devices.map(dev => {
          const rc = RISK_COLOR[dev.risk] || RISK_COLOR.unknown;
          const isSelected = selected === dev.ip;
          return (
            <div
              key={dev.ip}
              onClick={() => checkReputation(dev.ip)}
              style={{
                border: isSelected ? '1.5px solid #185FA5' : '0.5px solid var(--border)',
                borderRadius: 8, padding: '10px 12px', cursor: 'pointer',
                background: isSelected ? '#E6F1FB' : 'var(--card-bg)',
                transition: '.15s',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: 12, fontWeight: 500 }}>{dev.name}</span>
                <span style={{
                  fontSize: 10, padding: '2px 7px', borderRadius: 8,
                  background: rc.bg, color: rc.text, fontWeight: 500,
                }}>{rc.label}</span>
              </div>
              <div style={{ fontSize: 11, color: 'var(--muted)', fontFamily: 'monospace' }}>{dev.ip}</div>
              <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 2 }}>
                {dev.network_type} · {dev.status === 'online'
                  ? <span style={{ color: '#3B6D11' }}>Online</span>
                  : <span style={{ color: '#888' }}>Offline</span>}
              </div>
              {dev.open_ports?.length > 0 && (
                <div style={{ fontSize: 10, color: 'var(--muted)', marginTop: 3 }}>
                  Portlar: {dev.open_ports.join(', ')}
                </div>
              )}
              <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                <button
                  className="btn-sm"
                  onClick={e => { e.stopPropagation(); onAnalyze(dev.ip); }}
                >
                  Tahlil qilish ↗
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {reputation && (
        <div style={{
          background: 'var(--surface)', borderRadius: 8,
          padding: 12, fontSize: 12, lineHeight: 1.7,
          border: '0.5px solid var(--border)',
        }}>
          <div style={{ fontWeight: 500, marginBottom: 6 }}>
            IP Ma'lumot: {reputation.ip}
          </div>
          {reputation.is_local ? (
            <>
              <div style={{ color: 'var(--muted)', marginBottom: 4 }}>{reputation.message}</div>
              <div>Qurilma: {reputation.local_info?.device_name}</div>
              <div>Tarmoq: {reputation.local_info?.network_type}</div>
            </>
          ) : (
            <>
              <div>AbuseIPDB ball: <strong style={{ color: reputation.demo_abuse_score > 50 ? '#E24B4A' : '#639922' }}>
                {reputation.demo_abuse_score ?? reputation.abuse_score ?? 0}/100
              </strong></div>
              {reputation.country && <div>Mamlakat: {reputation.country}</div>}
              {reputation.isp && <div>ISP: {reputation.isp}</div>}
              {reputation.message && <div style={{ color: 'var(--muted)' }}>{reputation.message}</div>}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function getDemoDevices() {
  return [
    { ip: '192.168.1.1',   name: 'Router/Gateway',    risk: 'low',      network_type: 'LAN',    status: 'online',  open_ports: [22, 80, 443] },
    { ip: '192.168.1.100', name: 'Admin PC',           risk: 'low',      network_type: 'LAN',    status: 'online',  open_ports: [22, 3389] },
    { ip: '192.168.1.200', name: "Shubhali qurilma",   risk: 'high',     network_type: 'LAN',    status: 'online',  open_ports: [22, 80, 8080, 3389, 445] },
    { ip: '192.168.1.201', name: "Noma'lum qurilma",   risk: 'critical', network_type: 'LAN',    status: 'online',  open_ports: [21, 23, 3306, 1433] },
    { ip: '10.0.0.10',     name: 'Web Server',         risk: 'medium',   network_type: 'LAN',    status: 'online',  open_ports: [80, 443, 8080] },
    { ip: '10.0.0.20',     name: 'Database Server',    risk: 'medium',   network_type: 'LAN',    status: 'online',  open_ports: [3306, 5432] },
    { ip: '172.16.0.1',    name: 'VPN Gateway',        risk: 'low',      network_type: 'VPN',    status: 'online',  open_ports: [1194, 443] },
    { ip: '172.16.0.50',   name: 'Test Server',        risk: 'medium',   network_type: 'VPN',    status: 'offline', open_ports: [22, 80] },
  ];
}
