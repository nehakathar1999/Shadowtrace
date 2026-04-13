import { useState, useEffect } from "react";
const DEFAULT_API_HOST = `${window.location.protocol}//${window.location.hostname}:8000`;
const API_BASE = (import.meta.env.VITE_API_URL || DEFAULT_API_HOST).replace(/\/+$/, "");

// ── Icons ─────────────────────────────────────────────────────────────────────
const GlobeIcon = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <circle cx="12" cy="12" r="10" /><ellipse cx="12" cy="12" rx="4" ry="10" />
    <line x1="2" y1="12" x2="22" y2="12" />
    <line x1="4.9" y1="6" x2="19.1" y2="6" /><line x1="4.9" y1="18" x2="19.1" y2="18" />
  </svg>
);
const ShieldIcon = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
const MapIcon = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6" />
    <line x1="8" y1="2" x2="8" y2="18" /><line x1="16" y1="6" x2="16" y2="22" />
  </svg>
);
const StatsIcon = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" />
  </svg>
);
const LoginIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
    <polyline points="10 17 15 12 10 7" /><line x1="15" y1="12" x2="3" y2="12" />
  </svg>
);
const LogoIcon = () => (
  <svg width="28" height="28" viewBox="0 0 40 40" fill="none">
    <circle cx="20" cy="20" r="18" stroke="#00e5ff" strokeWidth="2" />
    <ellipse cx="20" cy="20" rx="7" ry="18" stroke="#00e5ff" strokeWidth="2" />
    <line x1="2" y1="20" x2="38" y2="20" stroke="#00e5ff" strokeWidth="2" />
  </svg>
);
const TerminalIcon = ({ size = 14, color = "#00e5ff" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
    <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
  </svg>
);
const TrendUpIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2">
    <polyline points="23 6 13.5 15.5 8.5 10.5 1 18" /><polyline points="17 6 23 6 23 12" />
  </svg>
);
const AlertTriangle = ({ color = "#f59e0b", size = 13 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);
const CircleAlert = ({ color = "#ef4444", size = 13 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
);
const ClockIcon = ({ size = 13 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
  </svg>
);
const ServerIcon = ({ size = 13 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" />
    <line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" />
  </svg>
);

const INITIAL_STATS = {
  scan_history: [],
  totals: {
    scans: 0,
    hosts_scanned: 0,
    total_vulns: 0,
    critical: 0,
    exposed: 0,
    ips: 0,
    ranges: 0,
    domains: 0,
    avg_risk_score: 0
  },
  common_ports: [],
  vuln_breakdown: [],
  os_stats: [],
  risk_distribution: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  }
};

// ── Risk color helper ─────────────────────────────────────────────────────────
function riskColor(score) {
  if (score >= 70) return "text-red-400";
  if (score >= 40) return "text-amber-400";
  if (score >= 20) return "text-yellow-400";
  return "text-emerald-400";
}
function riskLabel(score) {
  if (score >= 70) return { text: "CRITICAL", cls: "bg-red-500/10 border-red-500/40 text-red-400" };
  if (score >= 40) return { text: "HIGH",     cls: "bg-amber-500/10 border-amber-500/40 text-amber-400" };
  if (score >= 20) return { text: "MEDIUM",   cls: "bg-yellow-500/10 border-yellow-500/40 text-yellow-400" };
  return                  { text: "LOW",      cls: "bg-emerald-500/10 border-emerald-500/40 text-emerald-400" };
}
function typeColor(type) {
  if (type === "Domain") return "text-cyan-400 bg-cyan-400/8 border-cyan-400/20";
  if (type === "Range")  return "text-violet-400 bg-violet-400/8 border-violet-400/20";
  return "text-cyan-400 bg-cyan-500/[0.05] border-cyan-500/15";
}

export default function Stats({ theme, onHistorySelect }) {
  const [statsData, setStatsData] = useState(INITIAL_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("All");

  useEffect(() => {
    let shouldCancel = false;

    const fetchStats = async () => {
      try {
        const response = await fetch(`${API_BASE}/stats`);
        if (!response.ok) {
          throw new Error('Failed to fetch stats');
        }
        const data = await response.json();
        if (!shouldCancel) {
          setStatsData(data);
          setError(null);
        }
      } catch (err) {
        if (!shouldCancel) {
          setError(`Failed to fetch stats: ${err.message}`);
          console.error('Error fetching stats:', err);
        }
      } finally {
        if (!shouldCancel) {
          setLoading(false);
        }
      }
    };

    // Initial read
    fetchStats();

    // Poll every 5 seconds to keep stats live
    const intervalId = setInterval(fetchStats, 5000);

    return () => {
      shouldCancel = true;
      clearInterval(intervalId);
    };
  }, []);

  const filtered = filter === "All" ? statsData.scan_history
    : statsData.scan_history.filter(s => s.type === filter);

  const isDark = theme === 'dark';

  if (loading) {
    return (
      <div className={`min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'bg-gray-50 text-gray-900'} flex items-center justify-center`}>
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4"></div>
          <p>Loading statistics...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'bg-gray-50 text-gray-900'} flex items-center justify-center`}>
        <div className="text-center">
          <p className="text-red-400 mb-2">Error loading statistics</p>
          <p className="text-sm">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'bg-gray-50 text-gray-900'}`} style={{ fontFamily: "'Segoe UI',system-ui,sans-serif" }}>
      <style>{`
        html,body,#root{background:${theme === 'dark' ? '#0a0d14' : '#f8fafc'};min-height:100vh;}
        ::-webkit-scrollbar{width:4px;}
        ::-webkit-scrollbar-track{background:transparent;}
        ::-webkit-scrollbar-thumb{background:${theme === 'dark' ? '#1e293b' : '#cbd5e1'};border-radius:4px;}
        .scan-history-scroll::-webkit-scrollbar { width: 6px; }
        .scan-history-scroll::-webkit-scrollbar-track { background: ${theme === 'dark' ? '#0a0f1a' : '#f1f5f9'}; }
        .scan-history-scroll::-webkit-scrollbar-thumb { background: ${theme === 'dark' ? '#22d3ee' : '#94a3b8'}; border-radius: 999px; }
        .scan-history-scroll { max-height: calc(10*42px + 52px); min-height: calc(10*42px + 52px); height: calc(10*42px + 52px); margin-top: 8px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: ${theme === 'dark' ? '#22d3ee #0a0f1a' : '#94a3b8 #f1f5f9'}; margin-bottom: 0; padding-bottom: 0; }
        .scan-history-scroll table { margin-bottom: 0; }
        .scan-history-table thead th { position: sticky; top: 0; z-index: 20; }
        .stat-card {
          background: ${theme === 'dark' ? '#0a0f1a' : '#ffffff'};
          border: 1.5px solid ${theme === 'dark' ? 'rgba(34,211,238,0.26)' : 'rgba(96,165,250,0.42)'};
          border-radius: 12px;
          box-shadow: none;
          min-height: 520px;
          display: flex;
          flex-direction: column;
        }
        .stat-card-inner-border {
          border-bottom: 1px solid ${theme === 'dark' ? 'rgba(0,229,255,0.08)' : 'rgba(148,163,184,0.2)'};
        }
        .inner-box {
          background: ${theme === 'dark' ? 'rgba(0,229,255,0.02)' : 'rgba(148,163,184,0.05)'};
          border: 1px solid ${theme === 'dark' ? 'rgba(0,229,255,0.08)' : 'rgba(148,163,184,0.2)'};
          border-radius: 8px;
        }
        .table-row-border {
          border-bottom: 1px solid ${theme === 'dark' ? 'rgba(0,229,255,0.08)' : 'rgba(148,163,184,0.2)'};
        }
      `}</style>

      <main className="w-full max-w-[1400px] mx-auto px-8 py-5">
        {/* ── Page header ── */}
        <div className="flex items-start justify-between mb-5">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-cyan-400 font-mono text-xs">
              <TerminalIcon size={13} color="#00e5ff" /> GLOBAL STATISTICS
            </div>
            {/*
            <h1
              className={`text-3xl font-black tracking-tight ${isDark ? 'text-slate-100' : 'text-slate-900'}`}
              style={{ margin: 0, lineHeight: 1 }}
            >
              Scanner Intelligence Overview
            </h1>
            <p
              className={`text-sm ${isDark ? 'text-slate-300' : 'text-gray-600'}`}
              style={{ margin: "18px 0 0", lineHeight: 1.2 }}
            >
              Aggregated data from all scans performed in this session
            </p>
            */}
          </div>
        </div>

        {/* ── Top summary cards ── */}
        <div className="grid grid-cols-4 gap-4 mb-7 mt-7">
          {[
            { label: "TOTAL SCANS",       val: statsData.totals.scans,      sub: "All targets",         icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>, valCls: "text-cyan-400", border: "border-cyan-500/20" },
            { label: "IPs SCANNED",       val: statsData.totals.ips + statsData.totals.ranges * 8, sub: `${statsData.totals.ips} direct · ${statsData.totals.ranges} ranges`, icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>, valCls: "text-violet-400", border: "border-cyan-500/20" },
            { label: "VULNERABILITIES",   val: statsData.totals.total_vulns, sub: `${statsData.totals.critical} critical risk`, icon: <AlertTriangle color="#f59e0b" size={16} />, valCls: "text-amber-400", border: "border-amber-500/15" },
            { label: "EXPOSED TARGETS",   val: statsData.totals.exposed,    sub: "Critical risk found",  icon: <CircleAlert color="#ef4444" size={16} />, valCls: "text-red-400", border: "border-red-500/15" },
          ].map(card => (
            <div
              key={card.label}
              className={`rounded-xl px-6 py-4 border ${theme === 'dark' ? 'bg-[#111111]' : 'bg-white'}`}
              style={{
                borderColor:
                  card.label === "TOTAL SCANS" ? (isDark ? "rgba(34,211,238,0.38)" : "rgba(96,165,250,0.65)") :
                  card.label === "IPs SCANNED" ? (isDark ? "rgba(167,139,250,0.34)" : "rgba(167,139,250,0.58)") :
                  card.label === "VULNERABILITIES" ? (isDark ? "rgba(251,191,36,0.34)" : "rgba(245,158,11,0.6)") :
                  (isDark ? "rgba(248,113,113,0.34)" : "rgba(248,113,113,0.58)")
              }}
            >
              <div className="flex items-center justify-between mb-2">
                <span className={`text-[11px] font-bold tracking-widest ${theme === 'dark' ? 'text-white' : 'text-gray-700'}`}>{card.label}</span>
                <span className="flex">{card.icon}</span>
              </div>
              <div className={`text-[30px] font-black font-mono mb-1 ${card.valCls}`}>{card.val}</div>
              <div className={`text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'} font-mono`}>{card.sub}</div>
            </div>
          ))}
        </div>

        {/* ── Middle row: scan history + port chart ── */}
        <div className="grid grid-cols-3 gap-5 mb-5">

          {/* Scan history table — 2/3 width */}
          <div className="col-span-2 stat-card overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-cyan-400/30">
              <div className={`flex items-center gap-2 text-xs font-bold tracking-widest ${isDark ? 'text-cyan-400' : 'text-blue-500'}`}>
                <TerminalIcon size={13} color={isDark ? '#00e5ff' : '#0284c7'} /> SCAN HISTORY
              </div>
              <div className="flex gap-1.5">
                {["All","IP","Domain","Range"].map(f => (
                  <button key={f} onClick={() => setFilter(f)}
                    className={`px-3 py-1 rounded-md text-xs font-semibold cursor-pointer transition-all border
                      ${filter === f
                        ? `${isDark ? 'bg-cyan-400/10 border-cyan-400/30 text-cyan-400' : 'bg-blue-100 border-blue-300 text-blue-700'}`
                        : `${isDark ? 'bg-transparent border-cyan-500/10 text-slate-300 hover:text-slate-100' : 'bg-transparent border-blue-100 text-gray-600 hover:text-blue-800'}`}`}>
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto scan-history-scroll flex-1" style={{ overflowY: 'auto' }}>
              <table className="w-full border-collapse text-sm scan-history-table">
                <thead>
                  <tr>
                    {["TARGET","TYPE","DATE","HOSTS","PORTS","VULNS","RISK SCORE","STATUS"].map(h => (
                      <th key={h} className={`text-left py-2.5 px-4 text-[10px] font-bold tracking-widest whitespace-nowrap ${isDark ? 'text-slate-400 border-b border-cyan-400/40 bg-cyan-500/[0.04]' : 'text-gray-500 border-b border-gray-200 bg-gray-100'}`}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((s, i) => {
                    const risk = riskLabel(s.riskScore);
                    return (
                      <tr
                        key={s.id}
                        onClick={() => onHistorySelect?.(s)}
                        style={{ cursor: onHistorySelect ? 'pointer' : 'default' }}
                        className={` ${isDark ? 'hover:bg-cyan-500/[0.05]' : 'hover:bg-gray-50'} transition-colors`}>
                        <td className={`py-3 px-4 font-mono text-xs font-semibold whitespace-nowrap ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>{s.target}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${typeColor(s.type)}`}>{s.type}</span>
                        </td>
                        <td className={`py-3 px-4 text-xs font-mono whitespace-nowrap ${isDark ? 'text-cyan-200/70' : 'text-gray-500'}`}>{s.date}</td>
                        <td className={`py-3 px-4 font-mono text-xs font-semibold ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>{s.hostsUp}</td>
                        <td className={`py-3 px-4 text-xs font-mono ${isDark ? 'text-slate-100' : 'text-gray-700'}`}>{s.openPorts}</td>
                        <td className="py-3 px-4">
                          <span className={`text-xs font-mono font-semibold ${s.vulns > 0 ? (isDark ? 'text-amber-400' : 'text-orange-500') : (isDark ? 'text-slate-200' : 'text-gray-600')}`}>{s.vulns}</span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className={`w-16 h-1.5 rounded-full overflow-hidden ${isDark ? 'bg-cyan-500/[0.05]' : 'bg-gray-200'}`}>
                              <div className="h-full rounded-full" style={{ width: `${s.riskScore}%`, background: s.riskScore >= 70 ? "#ef4444" : s.riskScore >= 40 ? "#f59e0b" : "#10b981" }} />
                            </div>
                            <span className={`text-xs font-bold font-mono ${riskColor(s.riskScore)}`}>{s.riskScore}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${risk.cls}`}>{risk.text}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Most common open ports — 1/3 width */}
          <div
            className={`overflow-hidden rounded-xl border ${isDark ? 'bg-[#0a0f1a] text-slate-200' : 'bg-white text-gray-800'}`}
            style={{
              borderColor: isDark ? 'rgba(34,211,238,0.28)' : 'rgba(96,165,250,0.42)'
            }}
          >
            <div className={`px-6 py-4 border-b ${isDark ? 'border-cyan-400/30' : 'border-gray-200'}`}>
              <div className={`flex items-center gap-2 ${isDark ? 'text-cyan-400' : 'text-blue-600'} text-xs font-bold tracking-widest`}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={isDark ? '#00e5ff' : '#0ea5e9'} strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                MOST COMMON OPEN PORTS
              </div>
              <p className={`${isDark ? 'text-slate-200' : 'text-gray-600'} text-xs mt-1`}>Across all scanned targets</p>
            </div>
            <div className="right-panel-scroll px-6 py-4 flex flex-col gap-3.5">
              {statsData.common_ports.map((p, i) => (
                <div key={p.port}>
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-black font-mono w-10 ${isDark ? 'text-cyan-400' : 'text-cyan-400'}`}>{p.port}</span>
                      <span className={`text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-gray-700'}`}>{p.service}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-mono ${isDark ? 'text-slate-400' : 'text-slate-400'}`}>{p.count} hosts</span>
                      <span className={`text-xs font-bold font-mono ${isDark ? 'text-slate-200' : 'text-gray-700'}`} style={{ color: p.color }}>{p.pct}%</span>
                    </div>
                  </div>
                  <div className="h-1 rounded-full bg-cyan-500/[0.05] overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${p.pct}%`, background: p.color, opacity: 0.7 }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <style>{`
          .right-panel-scroll { max-height: calc(10*42px + 52px); min-height: calc(10*42px + 52px); height: calc(10*42px + 52px); overflow-y: auto; }
          .right-panel-scroll::-webkit-scrollbar { width: 7px; }
          .right-panel-scroll::-webkit-scrollbar-track { background: ${isDark ? '#0a0f1a' : '#f1f5f9'}; }
          .right-panel-scroll::-webkit-scrollbar-thumb { background: ${isDark ? '#22d3ee' : '#94a3b8'}; border-radius: 999px; }
          .right-panel-scroll { scrollbar-width: thin; scrollbar-color: ${isDark ? '#22d3ee #0a0f1a' : '#94a3b8 #f1f5f9'}; }
        `}</style>

        {/* ── Bottom row: Vuln breakdown + OS stats + Risk distribution ── */}
        <div className="grid grid-cols-3 gap-5">

          {/* Vulnerability breakdown */}
          <div className={`overflow-hidden rounded-xl border ${isDark ? 'bg-[#0a0f1a]' : 'bg-white'} `} style={isDark ? { borderColor:'rgba(251,191,36,0.28)' } : { borderColor:'rgba(245,158,11,0.42)' }}>
            <div className={`px-6 py-4 border-b ${isDark ? 'border-amber-400/15' : 'border-amber-200'}`}>
              <div className={`flex items-center gap-2 ${isDark ? 'text-amber-400' : 'text-amber-600'} text-xs font-bold tracking-widest`}>
                <AlertTriangle color={isDark ? '#f59e0b' : '#d97706'} size={13} /> VULNERABILITY BREAKDOWN
              </div>
              <p className={`${isDark ? 'text-white' : 'text-gray-500'} text-xs mt-1`}>By vulnerability category</p>
            </div>
            <div className="px-6 py-5 flex flex-col gap-4">
              {statsData.vuln_breakdown.map(v => (
                <div key={v.name}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className={`text-xs ${isDark ? 'text-slate-200' : 'text-gray-500'}`}>{v.name}</span>
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-mono ${isDark ? 'text-slate-300' : 'text-gray-600'}`}>{v.count} found</span>
                      <span className="text-xs font-bold font-mono" style={{ color: v.color }}>{v.pct}%</span>
                    </div>
                  </div>
                  <div className="h-1.5 rounded-full bg-amber-400/[0.07] overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${v.pct}%`, background: v.color, opacity: 0.75 }} />
                  </div>
                </div>
              ))}
              <div className={`mt-2 pt-4 border-t ${isDark ? 'border-amber-400/15' : 'border-amber-200/40'}`}>
                <div className="flex items-center justify-between">
                  <span className={`text-xs ${isDark ? 'text-slate-200' : 'text-gray-500'}`}>Total vulnerabilities found</span>
                  <span className="text-lg font-black font-mono text-amber-400">{statsData.totals.total_vulns}</span>
                </div>
              </div>
            </div>
          </div>

          {/* OS Detection stats */}
          <div className={`overflow-hidden rounded-xl border ${isDark ? 'bg-[#0a0f1a] text-slate-200' : 'bg-white text-gray-700'}`} style={isDark ? { borderColor:'rgba(167,139,250,0.28)' } : { borderColor:'rgba(167,139,250,0.42)' }}>
            <div className={`px-6 py-4 border-b ${isDark ? 'border-violet-400/15' : 'border-violet-200/50'}`}>
              <div className={`flex items-center gap-2 text-xs font-bold tracking-widest ${isDark ? 'text-violet-400' : 'text-violet-600'}`}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={isDark ? '#a78bfa' : '#7c3aed'} strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                OS DETECTION SUMMARY
              </div>
              <p className={`${isDark ? 'text-white' : 'text-gray-500'} text-xs mt-1`}>Detected operating systems</p>
            </div>
            <div className="px-6 py-5">
              <div className="flex items-center justify-center mb-6">
                <div className="relative w-32 h-32">
                  <svg viewBox="0 0 36 36" className="w-full h-full -rotate-90">
                    <circle cx="18" cy="18" r="15.9" fill="none" stroke="rgba(167,139,250,0.12)" strokeWidth="3.5" />
                    {statsData.os_stats.map((os, idx) => {
                      const colors = isDark ? ['#22d3ee', '#f97316', '#22c55e', '#6b7280'] : ['#3b82f6', '#f97316', '#22c55e', '#6b7280'];
                      const color = colors[idx % colors.length];
                      const startPct = statsData.os_stats.slice(0, idx).reduce((sum, item) => sum + item.pct, 0);
                      const thisPct = os?.pct || 0;
                      return (
                        <circle
                          key={`${os?.name || 'os'}-${idx}`}
                          cx="18"
                          cy="18"
                          r="15.9"
                          fill="none"
                          stroke={color}
                          strokeWidth="3.5"
                          strokeDasharray={`${thisPct * 2.64} 264`}
                          strokeDashoffset={`-${startPct * 2.64}`}
                          strokeLinecap="round"
                        />
                      );
                    })}
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-2xl font-black font-mono ${isDark ? 'text-slate-100' : 'text-gray-900'}`}>{statsData.os_stats[0]?.pct || 0}%</span>
                    <span className={`text-[10px] ${isDark ? 'text-slate-400' : 'text-gray-500'}`}>{statsData.os_stats[0]?.name || 'Unknown'}</span>
                  </div>
                </div>
              </div>
              <div className="flex flex-col gap-3">
                {statsData.os_stats.map((os, index) => {
                  const colors = isDark ? ['#22d3ee', '#f97316', '#22c55e', '#6b7280'] : ['#3b82f6', '#f97316', '#22c55e', '#6b7280'];
                  const osColor = colors[index % colors.length];

                  return (
                    <div key={os.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: osColor }} />
                        <span className={`text-sm ${isDark ? 'text-slate-300' : 'text-gray-700'}`}>{os.name}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <div className={`w-20 h-1.5 rounded-full ${isDark ? 'bg-violet-400/[0.08]' : 'bg-violet-200/50'} overflow-hidden`}>
                          <div className="h-full rounded-full" style={{ width: `${os.pct}%`, background: osColor }} />
                        </div>
                        <span className="text-sm font-bold font-mono w-8 text-right" style={{ color: osColor }}>{os.pct}%</span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Risk distribution */}
          <div className={`overflow-hidden rounded-xl border ${isDark ? 'bg-[#0a0f1a] text-slate-200' : 'bg-white text-gray-800'}`} style={isDark ? { borderColor:'rgba(248,113,113,0.28)' } : { borderColor:'rgba(248,113,113,0.42)' }}>
            <div className={`px-6 py-4 border-b ${isDark ? 'border-red-400/15' : 'border-red-200/50'}`}>
              <div className={`flex items-center gap-2 ${isDark ? 'text-red-400' : 'text-red-600'} text-xs font-bold tracking-widest`}>
                <CircleAlert color="#ef4444" size={13} /> RISK DISTRIBUTION
              </div>
              <p className={`${isDark ? 'text-white' : 'text-gray-500'} text-xs mt-1`}>Scan results by risk level</p>
            </div>
            <div className="px-6 py-5 flex flex-col gap-4">
              {[
                { label: "Critical",  count: statsData.risk_distribution.critical, color: "#ef4444", bg: "bg-red-500/8",    border: "border-red-500/20" },
                { label: "High",      count: statsData.risk_distribution.high, color: "#f59e0b", bg: "bg-amber-500/8", border: "border-amber-500/20" },
                { label: "Medium",    count: statsData.risk_distribution.medium, color: "#eab308", bg: "bg-yellow-500/8", border: "border-yellow-500/20" },
                { label: "Low",       count: statsData.risk_distribution.low,  color: "#10b981", bg: "bg-emerald-500/8", border: "border-emerald-500/20" },
              ].map(r => (
                <div key={r.label} className={`flex items-center justify-between px-4 py-3 rounded-lg ${r.bg} border ${r.border}`}>
                  <div className="flex items-center gap-3">
                    <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: r.color }} />
                    <span className={`text-sm font-semibold ${isDark ? 'text-slate-300' : 'text-gray-700'}`}>{r.label} Risk</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className={`w-16 h-1.5 rounded-full ${isDark ? 'bg-red-400/[0.08]' : 'bg-red-100'} overflow-hidden`}>
                      <div className="h-full rounded-full" style={{ width: `${(r.count / statsData.totals.scans) * 100}%`, background: r.color }} />
                    </div>
                    <span className="text-lg font-black font-mono w-5 text-right" style={{ color: r.color }}>{r.count}</span>
                  </div>
                </div>
              ))}
              <div className="mt-2 pt-4 border-t border-red-400/15 grid grid-cols-3 gap-3 text-center">
                <div>
                  <div className="text-xl font-black font-mono text-cyan-400">{statsData.totals.ips}</div>
                  <div className={`text-[10px] tracking-wider mt-0.5 ${isDark ? 'text-slate-400' : 'text-gray-500'}`}>IPs</div>
                </div>
                <div>
                  <div className="text-xl font-black font-mono text-violet-400">{statsData.totals.domains}</div>
                  <div className={`text-[10px] tracking-wider mt-0.5 ${isDark ? 'text-slate-400' : 'text-gray-500'}`}>DOMAINS</div>
                </div>
                <div>
                  <div className={`text-xl font-black font-mono ${isDark ? 'text-slate-300' : 'text-gray-800'}`}>{statsData.totals.ranges}</div>
                  <div className={`text-[10px] tracking-wider mt-0.5 ${isDark ? 'text-slate-400' : 'text-gray-500'}`}>RANGES</div>
                </div>
              </div>
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}



