import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../lib/api";

const LIGHT_MAROON_PAGE_BG = "#fcf8f3";

function BlobBg() {
  const ref = useRef(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    let W = canvas.width = window.innerWidth;
    let H = canvas.height = window.innerHeight;
    const resize = () => {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    };
    window.addEventListener("resize", resize);

    const blobs = [
      { x: W * 0.15, y: H * 0.3, r: 380, color: "#1a1a2e", vx: 0.08, vy: 0.06 },
      { x: W * 0.8, y: H * 0.65, r: 320, color: "#6b1f3a", vx: -0.07, vy: 0.09 },
      { x: W * 0.5, y: H * 0.1, r: 220, color: "#e8d5c4", vx: 0.06, vy: -0.05 },
      { x: W * 0.9, y: H * 0.1, r: 200, color: "#6b1f3a", vx: -0.05, vy: 0.08 },
    ];

    let raf;
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = "#f5f0e8";
      ctx.fillRect(0, 0, W, H);
      blobs.forEach((b) => {
        b.x += b.vx;
        b.y += b.vy;
        if (b.x < -b.r) b.x = W + b.r;
        if (b.x > W + b.r) b.x = -b.r;
        if (b.y < -b.r) b.y = H + b.r;
        if (b.y > H + b.r) b.y = -b.r;
        const g = ctx.createRadialGradient(b.x, b.y, 0, b.x, b.y, b.r);
        g.addColorStop(0, b.color + "40");
        g.addColorStop(1, b.color + "00");
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2);
        ctx.fill();
      });
      ctx.strokeStyle = "rgba(26,26,46,0.04)";
      ctx.lineWidth = 0.7;
      const size = 42;
      const rows = Math.ceil(H / (size * 1.73)) + 2;
      const cols = Math.ceil(W / (size * 2)) + 2;
      for (let r = -1; r < rows; r += 1) {
        for (let c = -1; c < cols; c += 1) {
          const cx = c * size * 2 + (r % 2) * size + size;
          const cy = r * size * 1.73 + size;
          ctx.beginPath();
          for (let a = 0; a < 6; a += 1) {
            const angle = (Math.PI / 3) * a - Math.PI / 6;
            const px = cx + size * 0.88 * Math.cos(angle);
            const py = cy + size * 0.88 * Math.sin(angle);
            if (a === 0) ctx.moveTo(px, py);
            else ctx.lineTo(px, py);
          }
          ctx.closePath();
          ctx.stroke();
        }
      }
      raf = requestAnimationFrame(draw);
    };

    draw();
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return <canvas ref={ref} className="scan-blob-canvas" />;
}

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
const TrashIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h18" />
    <path d="M8 6V4h8v2" />
    <path d="M19 6l-1 14H6L5 6" />
    <path d="M10 11v6" />
    <path d="M14 11v6" />
  </svg>
);
const RescanIcon = ({ size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M21 12a9 9 0 1 1-2.64-6.36" />
    <path d="M21 3v6h-6" />
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
  if (score >= 40) return "text-orange-400";
  if (score >= 20) return "text-yellow-400";
  return "text-emerald-400";
}
function riskLabel(score) {
  if (score >= 70) return { text: "CRITICAL", cls: "bg-red-500/10 border-red-500/40 text-red-400" };
  if (score >= 40) return { text: "HIGH",     cls: "bg-orange-500/10 border-orange-500/40 text-orange-400" };
  if (score >= 20) return { text: "MEDIUM",   cls: "bg-yellow-500/10 border-yellow-500/40 text-yellow-400" };
  return                  { text: "LOW",      cls: "bg-emerald-500/10 border-emerald-500/40 text-emerald-400" };
}
function typeColor(type) {
  if (type === "Domain") return "text-[var(--accent)] bg-[rgba(107,31,58,0.08)] border-[rgba(107,31,58,0.2)]";
  if (type === "Range")  return "text-violet-400 bg-violet-400/8 border-violet-400/20";
  return "text-[var(--accent)] bg-[rgba(107,31,58,0.05)] border-[rgba(107,31,58,0.15)]";
}

function StackedColumn3DGraph({ items, total, isDark, emptyLabel = "No data" }) {
  const safeItems = items.filter((item) => (Number(item?.count) || 0) > 0);
  const [hovered, setHovered] = useState(null);

  const shadeColor = (hex, amount = 0) => {
    const normalized = String(hex || "").replace("#", "");
    if (normalized.length !== 6) return hex;
    const num = Number.parseInt(normalized, 16);
    const adjust = (channel) => Math.max(0, Math.min(255, channel + amount));
    const r = adjust((num >> 16) & 255);
    const g = adjust((num >> 8) & 255);
    const b = adjust(num & 255);
    return `rgb(${r}, ${g}, ${b})`;
  };

  const blendWithWhite = (hex, weight = 0.2) => {
    const normalized = String(hex || "").replace("#", "");
    if (normalized.length !== 6) return hex;
    const num = Number.parseInt(normalized, 16);
    const mix = (channel) => Math.round(channel + (255 - channel) * weight);
    const r = mix((num >> 16) & 255);
    const g = mix((num >> 8) & 255);
    const b = mix(num & 255);
    return `rgb(${r}, ${g}, ${b})`;
  };

  return (
    <div className={`rounded-xl p-3 ${isDark ? 'bg-white/[0.02] border border-white/5' : 'bg-gray-50 border border-gray-200'}`}>
      {total <= 0 || safeItems.length === 0 ? (
        <div className={`h-44 flex items-center justify-center text-sm ${isDark ? 'text-slate-500' : 'text-gray-500'}`}>
          {emptyLabel}
        </div>
      ) : (
        <div className="relative h-44 flex items-end justify-center gap-0.5 px-1 pb-2 pt-2 overflow-visible">
          {safeItems.map((item) => {
            const ratio = total > 0 ? item.count / total : 0;
            const height = Math.max(42, Math.min(128, ratio * 250));
            return (
              <div
                key={item.label}
                className="relative flex flex-col items-center justify-end gap-2 min-w-0 h-full"
                onMouseEnter={() => setHovered(item.label)}
                onMouseLeave={() => setHovered(null)}
              >
                {hovered === item.label ? (
                  <div
                    className={`absolute left-1/2 z-10 -translate-x-1/2 rounded-lg px-3 py-2 text-xs border pointer-events-none whitespace-nowrap ${isDark ? 'bg-[#09111d] border-cyan-400/20 text-slate-200' : 'bg-white border-gray-200 text-gray-800'}`}
                    style={{ bottom: height + 42 }}
                  >
                    <div className="font-semibold">{item.label}</div>
                    <div className="font-mono mt-1" style={{ color: item.color }}>{item.count} findings</div>
                    <div className={`${isDark ? 'text-slate-400' : 'text-gray-500'}`}>{item.pct}% share</div>
                  </div>
                ) : null}
                <div className="relative cursor-pointer" style={{ width: 54, height }}>
                  <svg
                    viewBox={`0 0 60 ${height + 18}`}
                    width="54"
                    height={height + 18}
                    className="overflow-visible"
                  >
                    <defs>
                      <linearGradient id={`stack-front-${item.label}`} x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stopColor={shadeColor(item.color, 28)} />
                        <stop offset="100%" stopColor={item.color} />
                      </linearGradient>
                      <linearGradient id={`stack-side-${item.label}`} x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor={shadeColor(item.color, -10)} />
                        <stop offset="100%" stopColor={shadeColor(item.color, -40)} />
                      </linearGradient>
                    </defs>
                    <polygon
                      points={`16,8 38,8 46,13 24,13`}
                      fill={shadeColor(item.color, 54)}
                    />
                    <rect
                      x="16"
                      y="8"
                      width="22"
                      height={height - 8}
                      rx="0.4"
                      fill={`url(#stack-front-${item.label})`}
                    />
                    <polygon
                      points={`38,8 46,13 46,${height + 5} 38,${height}`}
                      fill={`url(#stack-side-${item.label})`}
                    />
                    <polygon
                      points={`16,${height} 38,${height} 46,${height + 5} 24,${height + 5}`}
                      fill={shadeColor(item.color, -18)}
                      opacity="0.12"
                    />
                    <line x1="16" y1="8" x2="38" y2="8" stroke={shadeColor(item.color, 70)} strokeWidth="1.1" opacity="0.72" />
                    <line x1="38" y1="8" x2="46" y2="13" stroke={shadeColor(item.color, 20)} strokeWidth="1" opacity="0.42" />
                    <line x1="24" y1="13" x2="46" y2="13" stroke={shadeColor(item.color, 10)} strokeWidth="0.8" opacity="0.24" />
                    <line x1="38" y1="8" x2="38" y2={height} stroke={shadeColor(item.color, -14)} strokeWidth="1" opacity="0.36" />
                    <line x1="46" y1="13" x2="46" y2={height + 5} stroke={shadeColor(item.color, -46)} strokeWidth="1" opacity="0.28" />
                  </svg>
                </div>
                <div className="text-center min-w-0">
                  <div className={`text-[11px] truncate max-w-[72px] ${isDark ? 'text-slate-300' : 'text-gray-700'}`}>{item.label}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function MultiLineTrendGraph({ items, total, isDark }) {
  const activeItems = items.filter((item) => (Number(item?.count) || 0) > 0);
  const chartItems = activeItems.length > 0 ? activeItems : items;
  const [hovered, setHovered] = useState(null);
  const width = 260;
  const height = 144;
  const leftPad = 12;
  const rightPad = 12;
  const topPad = 10;
  const bottomPad = 18;
  const innerWidth = width - leftPad - rightPad;
  const innerHeight = height - topPad - bottomPad;
  const denominator = Math.max(total, ...chartItems.map((item) => Number(item?.count) || 0), 1);

  const buildPath = (item, index) => {
    const pct = (Number(item?.count) || 0) / denominator;
    const amp = Math.max(12, innerHeight * (0.18 + pct * 0.38));
    const baseY = topPad + innerHeight * (0.22 + index * 0.18);
    const startX = leftPad;
    const endX = leftPad + innerWidth;
    const cp1x = leftPad + innerWidth * 0.25;
    const cp2x = leftPad + innerWidth * 0.68;
    const cp3x = leftPad + innerWidth * 0.82;
    const y1 = Math.max(topPad + 6, baseY + amp * (index % 2 === 0 ? -1 : 1));
    const y2 = Math.min(topPad + innerHeight - 6, baseY + amp * (index % 2 === 0 ? 0.9 : -0.9));
    const y3 = Math.max(topPad + 6, baseY + amp * (index % 2 === 0 ? 0.22 : -0.22));
    return `M ${startX} ${baseY} C ${cp1x} ${y1}, ${cp2x} ${y2}, ${endX} ${y3}`;
  };

  const getTooltipPosition = (index) => {
    const baseY = topPad + innerHeight * (0.22 + index * 0.18);
    const amp = Math.max(
      12,
      innerHeight * (0.18 + (((Number(chartItems[index]?.count) || 0) / denominator) * 0.38))
    );
    const y3 = Math.max(
      topPad + 6,
      baseY + amp * (index % 2 === 0 ? 0.22 : -0.22)
    );
    return {
      left: Math.max(56, Math.min(width - 56, leftPad + innerWidth * 0.78)),
      top: Math.max(8, y3 - 44),
    };
  };

  return (
    <div className={`rounded-xl border p-3 ${isDark ? 'bg-white/[0.02] border-white/5' : 'bg-gray-50 border-gray-200'}`}>
      <div className="relative h-44">
        {hovered ? (
          <div
            className={`absolute z-10 rounded-lg px-3 py-2 text-xs border pointer-events-none -translate-x-1/2 ${isDark ? 'bg-[#09111d] border-cyan-400/20 text-slate-200' : 'bg-white border-gray-200 text-gray-800'}`}
            style={getTooltipPosition(chartItems.findIndex((item) => item.label === hovered.label))}
          >
            <div className="font-semibold">{hovered.label}</div>
            <div className="font-mono mt-1" style={{ color: hovered.color }}>{hovered.count} findings</div>
            <div className={`${isDark ? 'text-slate-400' : 'text-gray-500'}`}>{Math.round((hovered.count / Math.max(total, 1)) * 100)}% share</div>
          </div>
        ) : null}
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full">
          {[0.18, 0.36, 0.54, 0.72, 0.9].map((step) => (
            <line
              key={step}
              x1={leftPad}
              x2={width - rightPad}
              y1={topPad + innerHeight * step}
              y2={topPad + innerHeight * step}
              stroke={isDark ? "rgba(148,163,184,0.16)" : "rgba(148,163,184,0.22)"}
              strokeWidth="1"
            />
          ))}
          {chartItems.map((item, index) => (
            <g
              key={item.label}
              onMouseEnter={() => setHovered(item)}
              onMouseLeave={() => setHovered(null)}
            >
              <path
                d={buildPath(item, index)}
                fill="none"
                stroke={item.color}
                strokeWidth="2.2"
                strokeLinecap="round"
              />
              <path
                d={buildPath(item, index)}
                fill="none"
                stroke="transparent"
                strokeWidth="14"
                strokeLinecap="round"
              />
            </g>
          ))}
        </svg>
      </div>
      <div className="grid grid-cols-2 gap-2 mt-2">
        {chartItems.map((item) => (
          <div key={item.label} className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="w-2.5 h-0.5 flex-shrink-0 rounded-full" style={{ background: item.color }} />
              <span className={`text-[11px] truncate ${isDark ? 'text-slate-300' : 'text-gray-700'}`}>{item.label}</span>
            </div>
            <span className="text-[10px] font-mono" style={{ color: item.color }}>{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function formatFoundLabel(count) {
  return `${count} found`;
}

function DistributionCard({ title, subtitle, icon, iconColor, borderColor, headerBorderColor, children, theme = "light" }) {
  const isDark = theme === "dark";
  return (
    <div
      className={`overflow-hidden rounded-[28px] border ${isDark ? 'bg-[#0a0f1a] text-slate-200' : 'bg-white text-gray-800'}`}
      style={{ borderColor }}
    >
      <div className="px-5 py-4" style={{ borderBottom: `1px solid ${headerBorderColor}` }}>
        <div className="flex items-center gap-2 text-xs font-bold tracking-[0.18em]" style={{ color: iconColor }}>
          {icon}
          {title}
        </div>
        <p className={`mt-1 text-xs ${isDark ? 'text-slate-300' : 'text-gray-500'}`}>{subtitle}</p>
      </div>
      <div className="px-5 py-4">
        {children}
      </div>
    </div>
  );
}

function RiskDistributionList({ items, totals, theme = "light" }) {
  const isDark = theme === "dark";
  const maxCount = Math.max(...items.map((item) => Number(item.count) || 0), 1);
  const rowTints = isDark
    ? ["rgba(239,68,68,0.08)", "rgba(249,115,22,0.08)", "rgba(234,179,8,0.08)", "rgba(16,185,129,0.08)"]
    : ["rgba(239,68,68,0.07)", "rgba(245,158,11,0.07)", "rgba(234,179,8,0.08)", "rgba(16,185,129,0.08)"];
  const rowBorders = isDark
    ? ["rgba(248,113,113,0.22)", "rgba(251,146,60,0.22)", "rgba(250,204,21,0.22)", "rgba(52,211,153,0.22)"]
    : ["rgba(248,113,113,0.28)", "rgba(251,146,60,0.28)", "rgba(250,204,21,0.28)", "rgba(52,211,153,0.28)"];

  return (
    <div className="flex flex-col gap-3.5">
      {items.map((item, index) => {
        const widthPct = `${Math.max(8, Math.round(((Number(item.count) || 0) / maxCount) * 100))}%`;
        return (
          <div
            key={item.label}
            className="rounded-[14px] border px-4 py-3"
            style={{ background: rowTints[index], borderColor: rowBorders[index] }}
          >
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <span className="h-3 w-3 rounded-full" style={{ background: item.color }} />
                <span className={`text-[14px] font-semibold ${isDark ? 'text-slate-100' : 'text-[#24395d]'}`}>{item.label}</span>
              </div>
              <div className="flex min-w-[98px] items-center justify-end gap-3">
                <div className={`h-1.5 w-16 overflow-hidden rounded-full ${isDark ? 'bg-white/10' : 'bg-[#fde2e4]'}`}>
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: item.count > 0 ? widthPct : "0%",
                      background: item.color,
                      transition: "width 800ms ease",
                    }}
                  />
                </div>
                <span className="w-5 text-right font-mono text-[14px] font-bold" style={{ color: item.color }}>
                  {item.count}
                </span>
              </div>
            </div>
          </div>
        );
      })}

      <div className="mt-1 grid grid-cols-3 gap-2 border-t pt-3 text-center" style={{ borderColor: isDark ? "rgba(248,113,113,0.18)" : "rgba(248,113,113,0.16)" }}>
        {[
          { label: "IPs", value: totals.ips, color: "#06b6d4" },
          { label: "DOMAINS", value: totals.domains, color: "#8b5cf6" },
          { label: "RANGES", value: totals.ranges, color: isDark ? "#cbd5e1" : "#1f3a5f" },
        ].map((item) => (
          <div key={item.label}>
            <div className="font-mono text-[19px] font-black" style={{ color: item.color }}>{item.value}</div>
            <div className={`mt-1 text-[10px] tracking-[0.16em] ${isDark ? 'text-slate-400' : 'text-gray-500'}`}>{item.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function VulnerabilityBreakdownList({ items, total, theme = "light" }) {
  const isDark = theme === "dark";

  if (total <= 0 || items.length === 0) {
    return (
      <div className={`rounded-[18px] border px-5 py-12 text-center text-sm ${isDark ? 'border-white/10 bg-white/[0.02] text-slate-400' : 'border-amber-100 bg-amber-50/40 text-gray-500'}`}>
        No vulnerabilities found
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3.5">
      {items.map((item) => {
        const pct = total > 0 ? Math.round((item.count / total) * 100) : 0;
        return (
          <div key={item.label}>
            <div className="mb-1.5 flex items-center justify-between gap-4">
              <span className={`text-[14px] ${isDark ? 'text-slate-100' : 'text-[#3b4f74]'}`}>{item.label}</span>
              <div className="flex items-center gap-2 font-mono text-[13px]">
                <span className={isDark ? 'text-slate-300' : 'text-[#24395d]'}>{formatFoundLabel(item.count)}</span>
                <span className="font-bold" style={{ color: item.color }}>{pct}%</span>
              </div>
            </div>
            <div className={`h-1.5 overflow-hidden rounded-full ${isDark ? 'bg-white/10' : 'bg-[#faf7ef]'}`}>
              <div
                className="h-full rounded-full"
                style={{
                  width: item.count > 0 ? `${Math.max(pct, 8)}%` : "0%",
                  background: item.color,
                  transition: "width 800ms ease",
                }}
              />
            </div>
          </div>
        );
      })}

      <div className="mt-2 flex items-center justify-between border-t pt-3" style={{ borderColor: isDark ? "rgba(245,158,11,0.18)" : "rgba(245,158,11,0.16)" }}>
        <span className={`text-[13px] ${isDark ? 'text-slate-300' : 'text-[#3b4f74]'}`}>Total vulnerabilities found</span>
        <span className="font-mono text-[28px] font-black leading-none" style={{ color: "#eab308" }}>{total}</span>
      </div>
    </div>
  );
}

function SplitAreaGraph({ items, total, isDark }) {
  if (total <= 0 || items.every((item) => !item.count)) {
    return (
      <div className={`rounded-xl border h-44 flex items-center justify-center ${isDark ? 'bg-white/[0.02] border-white/5 text-slate-500' : 'bg-gray-50 border-gray-200 text-gray-500'}`}>
        No risk data
      </div>
    );
  }

  return (
    <div className={`rounded-xl border overflow-hidden h-44 ${isDark ? 'bg-white/[0.02] border-white/5' : 'bg-gray-50 border-gray-200'}`}>
      <div className="flex h-full">
        {items.map((item) => (
          <div
            key={item.label}
            className="relative flex flex-col justify-end p-3 min-w-0"
            style={{
              flex: Math.max(item.count, 0.8),
              background: `linear-gradient(180deg, ${item.color}12 0%, ${item.color}28 100%)`,
              borderRight: '1px solid rgba(148,163,184,0.12)',
            }}
          >
            <div
              className="absolute inset-x-0 bottom-0"
              style={{
                height: `${Math.max(14, (item.count / total) * 100)}%`,
                background: `linear-gradient(180deg, ${item.color}55, ${item.color}99)`,
              }}
            />
            <div className="relative z-10">
              <div className={`text-[10px] uppercase tracking-wider truncate ${isDark ? 'text-slate-200' : 'text-gray-700'}`}>{item.label}</div>
              <div className="text-xl font-black font-mono mt-1" style={{ color: item.color }}>{item.count}</div>
              <div className={`text-[10px] font-mono ${isDark ? 'text-slate-300' : 'text-gray-600'}`}>{Math.round((item.count / total) * 100)}%</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ThreeDPiePorts({ items, isDark }) {
  const safeItems = items.filter((item) => (Number(item?.count) || 0) > 0).slice(0, 5);
  const total = safeItems.reduce((sum, item) => sum + (Number(item?.count) || 0), 0);
  const [hovered, setHovered] = useState(null);

  const shadeColor = (hex, amount = 0) => {
    const normalized = String(hex || "").replace("#", "");
    if (normalized.length !== 6) return hex;
    const num = Number.parseInt(normalized, 16);
    const adjust = (channel) => Math.max(0, Math.min(255, channel + amount));
    const r = adjust((num >> 16) & 255);
    const g = adjust((num >> 8) & 255);
    const b = adjust(num & 255);
    return `rgb(${r}, ${g}, ${b})`;
  };

  const blendWithWhite = (hex, weight = 0.2) => {
    const normalized = String(hex || "").replace("#", "");
    if (normalized.length !== 6) return hex;
    const num = Number.parseInt(normalized, 16);
    const mix = (channel) => Math.round(channel + (255 - channel) * weight);
    const r = mix((num >> 16) & 255);
    const g = mix((num >> 8) & 255);
    const b = mix(num & 255);
    return `rgb(${r}, ${g}, ${b})`;
  };

  const cx = 110;
  const cy = 72;
  const rx = 74;
  const ry = 42;
  const depth = 16;

  const pointOnEllipse = (angle, yOffset = 0) => ({
    x: cx + rx * Math.cos(angle),
    y: cy + ry * Math.sin(angle) + yOffset,
  });

  const slicePath = (start, end) => {
    const startPt = pointOnEllipse(start);
    const endPt = pointOnEllipse(end);
    const largeArc = end - start > Math.PI ? 1 : 0;
    return `M ${cx} ${cy} L ${startPt.x} ${startPt.y} A ${rx} ${ry} 0 ${largeArc} 1 ${endPt.x} ${endPt.y} Z`;
  };

  const sidePath = (start, end) => {
    const topStart = pointOnEllipse(start);
    const topEnd = pointOnEllipse(end);
    const bottomStart = pointOnEllipse(start, depth);
    const bottomEnd = pointOnEllipse(end, depth);
    const largeArc = end - start > Math.PI ? 1 : 0;
    return `M ${topStart.x} ${topStart.y} A ${rx} ${ry} 0 ${largeArc} 1 ${topEnd.x} ${topEnd.y} L ${bottomEnd.x} ${bottomEnd.y} A ${rx} ${ry} 0 ${largeArc} 0 ${bottomStart.x} ${bottomStart.y} Z`;
  };

  const radialWallPath = (angle) => {
    const topArc = pointOnEllipse(angle);
    const bottomArc = pointOnEllipse(angle, depth);
    return `M ${cx} ${cy} L ${topArc.x} ${topArc.y} L ${bottomArc.x} ${bottomArc.y} L ${cx} ${cy + depth} Z`;
  };

  const clampInterval = (start, end, min, max) => {
    const s = Math.max(start, min);
    const e = Math.min(end, max);
    return e > s ? [s, e] : null;
  };

  let angle = -Math.PI / 2;
  const slices = safeItems.map((item) => {
    const sweep = total > 0 ? ((Number(item.count) || 0) / total) * Math.PI * 2 : 0;
    const start = angle;
    const end = angle + sweep;
    angle = end;
    return {
      ...item,
      start,
      end,
      offsetX: 0,
      offsetY: 0,
    };
  });

  const smallestPort = [...slices]
    .sort((a, b) => (Number(a.count) || 0) - (Number(b.count) || 0))[0]?.port;
  const greenSlicePort = slices[0]?.port;
  const slicesWithOffset = slices.map((slice) => {
    if (slice.port !== smallestPort && slice.port !== greenSlicePort) {
      return slice;
    }
    const mid = slice.start + (slice.end - slice.start) / 2;
    const offset = 5;
    return {
      ...slice,
      offsetX: Math.cos(mid) * offset,
      offsetY: Math.sin(mid) * offset,
    };
  });

  const visibleSides = slicesWithOffset.flatMap((slice) => {
    const normalizedIntervals = [
      clampInterval(slice.start, slice.end, 0, Math.PI),
      clampInterval(slice.start, slice.end, Math.PI * 2, Math.PI * 3),
    ].filter(Boolean);

    return normalizedIntervals.map(([start, end]) => ({
      key: `${slice.label}-${start}`,
      color: slice.color,
      label: slice.label,
      path: sidePath(start % (Math.PI * 2), end % (Math.PI * 2) || Math.PI * 2),
      offsetX: slice.offsetX,
      offsetY: slice.offsetY,
    }));
  });

  const explodedWalls = slicesWithOffset
    .filter((slice) => slice.offsetX || slice.offsetY)
    .flatMap((slice) => ([
      {
        key: `${slice.label}-start-wall`,
        path: radialWallPath(slice.start),
        fill: blendWithWhite(shadeColor(slice.color, -22), 0.08),
        offsetX: slice.offsetX,
        offsetY: slice.offsetY,
      },
      {
        key: `${slice.label}-end-wall`,
        path: radialWallPath(slice.end),
        fill: blendWithWhite(shadeColor(slice.color, -30), 0.04),
        offsetX: slice.offsetX,
        offsetY: slice.offsetY,
      },
    ]));

  if (safeItems.length === 0) {
    return (
      <div className={`h-44 flex items-center justify-center text-sm ${isDark ? 'text-slate-500' : 'text-gray-500'}`}>
        No port data
      </div>
    );
  }

  return (
    <div className="relative">
      {hovered ? (
        <div className={`absolute right-2 top-2 z-10 rounded-lg px-3 py-2 text-xs border pointer-events-none ${isDark ? 'bg-[#09111d] border-cyan-400/20 text-slate-200' : 'bg-white border-gray-200 text-gray-800'}`}>
          <div className="font-semibold">Port {hovered.port} · {hovered.service}</div>
          <div className="font-mono mt-1" style={{ color: hovered.color }}>{hovered.count} hosts</div>
          <div className={`${isDark ? 'text-slate-400' : 'text-gray-500'}`}>{hovered.pct}% share</div>
        </div>
      ) : null}
      <div className="flex items-center justify-center">
        <svg viewBox="0 0 220 156" className="h-44 w-full max-w-[260px] overflow-visible">
          <ellipse
            cx={cx}
            cy={cy + depth + 6}
            rx={rx + 6}
            ry={ry - 8}
            fill={isDark ? "rgba(15,23,42,0.45)" : "rgba(148,163,184,0.18)"}
          />
          {visibleSides.map((slice) => (
            <path
              key={slice.key}
              d={slice.path}
              fill={blendWithWhite(shadeColor(slice.color, -16), 0.1)}
              transform={`translate(${slice.offsetX} ${slice.offsetY})`}
            />
          ))}
          {explodedWalls.map((wall) => (
            <path
              key={wall.key}
              d={wall.path}
              fill={wall.fill}
              transform={`translate(${wall.offsetX} ${wall.offsetY})`}
            />
          ))}
          {slicesWithOffset.map((slice) => (
            <path
              key={slice.label}
              d={slicePath(slice.start, slice.end)}
              fill={`url(#pie-grad-${slice.port})`}
              stroke="none"
              onMouseEnter={() => setHovered(slice)}
              onMouseLeave={() => setHovered(null)}
              transform={`translate(${slice.offsetX} ${slice.offsetY})`}
              style={{ cursor: "pointer" }}
            />
          ))}
          <defs>
            {slicesWithOffset.map((slice) => (
              <linearGradient key={slice.port} id={`pie-grad-${slice.port}`} x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor={blendWithWhite(slice.color, 0.35)} />
                <stop offset="100%" stopColor={blendWithWhite(slice.color, 0.12)} />
              </linearGradient>
            ))}
          </defs>
        </svg>
      </div>
      <div className="grid grid-cols-1 gap-2 mt-2">
        {safeItems.map((item) => (
          <div
            key={item.port}
            className={`flex items-center justify-between gap-3 rounded-lg px-3 py-2 border ${isDark ? 'border-white/5 bg-white/[0.02]' : 'border-gray-200 bg-white'}`}
            onMouseEnter={() => setHovered(item)}
            onMouseLeave={() => setHovered(null)}
          >
            <div className="flex items-center gap-2 min-w-0">
              <span className="h-2.5 w-2.5 rounded-full flex-shrink-0" style={{ background: item.color }} />
              <span className={`text-xs font-black font-mono ${isDark ? 'text-cyan-400' : 'text-cyan-500'}`}>{item.port}</span>
              <span className={`text-xs truncate ${isDark ? 'text-slate-200' : 'text-gray-700'}`}>{item.service}</span>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <span className={`text-xs font-mono ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{item.count}</span>
              <span className="text-xs font-bold font-mono" style={{ color: item.color }}>{item.pct}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Stats({ theme, onHistorySelect, onHistoryDelete, onHistoryRescan }) {
  const [statsData, setStatsData] = useState(INITIAL_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("All");
  const [busyActionId, setBusyActionId] = useState(null);

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

    fetchStats();
    const intervalId = setInterval(fetchStats, 5000);

    return () => {
      shouldCancel = true;
      clearInterval(intervalId);
    };
  }, []);

  const removeHistoryEntry = (entryId) => {
    setStatsData((prev) => ({
      ...prev,
      scan_history: prev.scan_history.filter((item) => item.id !== entryId),
      totals: {
        ...prev.totals,
        scans: Math.max(0, prev.totals.scans - 1),
      },
    }));
  };

  const handleDelete = async (event, entry) => {
    event.stopPropagation();
    if (!entry || !onHistoryDelete) return;

    setBusyActionId(`delete-${entry.id}`);
    const deleted = await onHistoryDelete(entry);
    if (deleted) {
      removeHistoryEntry(entry.id);
    }
    setBusyActionId(null);
  };

  const handleRescan = (event, entry) => {
    event.stopPropagation();
    onHistoryRescan?.(entry);
  };

  const filtered = filter === "All" ? statsData.scan_history
    : statsData.scan_history.filter(s => s.type === filter);

  const isDark = theme === 'dark';
  const vulnDonutItems = statsData.vuln_breakdown.map((item) => ({
    label: item.name,
    count: item.count,
    color: item.color,
    pct: item.pct,
  }));
  const topCommonPorts = statsData.common_ports.slice(0, 5);
  const riskItems = [
    { label: "Critical Risk", count: statsData.risk_distribution.critical, color: "#ef4444" },
    { label: "High Risk", count: statsData.risk_distribution.high, color: "#f59e0b" },
    { label: "Medium Risk", count: statsData.risk_distribution.medium, color: "#eab308" },
    { label: "Low Risk", count: statsData.risk_distribution.low, color: "#10b981" },
  ];
  const totalRiskFindings = riskItems.reduce((sum, item) => sum + item.count, 0);

  if (loading) {
    return (
      <div className={`relative z-0 min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'text-[var(--text)]'} flex items-center justify-center`} style={theme === 'dark' ? undefined : { backgroundColor: LIGHT_MAROON_PAGE_BG }}>
        <BlobBg />
        <div className="relative z-10 text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4"></div>
          <p>Loading statistics...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`relative z-0 min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'text-[var(--text)]'} flex items-center justify-center`} style={theme === 'dark' ? undefined : { backgroundColor: LIGHT_MAROON_PAGE_BG }}>
        <BlobBg />
        <div className="relative z-10 text-center">
          <p className="text-red-400 mb-2">Error loading statistics</p>
          <p className="text-sm">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`relative z-0 min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'text-[var(--text)]'}`} style={theme === 'dark' ? { fontFamily: "'Segoe UI',system-ui,sans-serif" } : { fontFamily: "'Segoe UI',system-ui,sans-serif", backgroundColor: LIGHT_MAROON_PAGE_BG }}>
      <style>{`
        html,body,#root{background:${theme === 'dark' ? '#0a0d14' : LIGHT_MAROON_PAGE_BG};min-height:100vh;}
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
      <BlobBg />

      <main className="relative z-10 w-full max-w-[1400px] mx-auto px-8 py-5">
        {/* ── Page header ── */}
        <div className="flex items-start justify-between mb-5">
          <div className="space-y-3">
            <div className="flex items-center gap-2 text-[var(--accent)] font-mono text-xs">
              <TerminalIcon size={13} color="#6b1f3a" /> GLOBAL STATISTICS
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
            { label: "TOTAL SCANS",       val: statsData.totals.scans,      sub: "All targets",         icon: <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6b1f3a" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>, valCls: "text-[var(--accent)]", border: "border-cyan-500/20" },
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
                <span className="flex">
                  {card.label === "IPs SCANNED" ? (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6b1f3a" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                  ) : (
                    card.icon
                  )}
                </span>
              </div>
              <div className={`text-[30px] font-black font-mono mb-1 ${(card.label === "TOTAL SCANS" || card.label === "IPs SCANNED") ? 'text-[var(--accent)]' : card.valCls}`}>{card.val}</div>
              <div className={`text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'} font-mono`}>{card.sub}</div>
            </div>
          ))}
        </div>

        {/* ── Middle row: scan history + port chart ── */}
        <div className="grid grid-cols-3 gap-5 mb-5">

          {/* Scan history table — 2/3 width */}
          <div className="col-span-2 stat-card overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-[rgba(107,31,58,0.2)]">
              <div className={`flex items-center gap-2 text-xs font-bold tracking-widest ${isDark ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>
                <TerminalIcon size={13} color={isDark ? '#00e5ff' : '#6b1f3a'} /> SCAN HISTORY
              </div>
              <div className="flex gap-1.5">
                {["All","IP","Domain","Range"].map(f => (
                  <button key={f} onClick={() => setFilter(f)}
                    className={`px-3 py-1 rounded-md text-xs font-semibold cursor-pointer transition-all border
                      ${filter === f
                        ? `${isDark ? 'bg-cyan-400/10 border-cyan-400/30 text-cyan-400' : 'bg-[rgba(107,31,58,0.08)] border-[rgba(107,31,58,0.2)] text-[var(--accent)]'}`
                        : `${isDark ? 'bg-transparent border-cyan-500/10 text-slate-300 hover:text-slate-100' : 'bg-transparent border-[rgba(107,31,58,0.12)] text-gray-600 hover:text-[var(--accent)]'}`}`}>
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto scan-history-scroll flex-1" style={{ overflowY: 'auto' }}>
              <table className="w-full border-collapse text-sm scan-history-table">
                <thead>
                  <tr>
                    {["TARGET","TYPE","DATE","HOSTS","PORTS","VULNS","RISK SCORE","STATUS","ACTIONS"].map(h => (
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
                              <div className="h-full rounded-full" style={{ width: `${s.riskScore}%`, background: s.riskScore >= 70 ? "#ef4444" : s.riskScore >= 40 ? "#f97316" : s.riskScore >= 20 ? "#facc15" : "#10b981" }} />
                            </div>
                            <span className={`text-xs font-bold font-mono ${riskColor(s.riskScore)}`}>{s.riskScore}</span>
                          </div>
                        </td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${risk.cls}`}>{risk.text}</span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <span
                              role="button"
                              aria-label={`Rescan ${s.target}`}
                              title={`Rescan ${s.target}`}
                              onClick={(event) => handleRescan(event, s)}
                              className={`inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors ${
                                isDark
                                  ? 'border-cyan-500/25 text-cyan-300 hover:bg-cyan-500/10'
                                  : 'border-blue-200 text-blue-600 hover:bg-blue-50'
                              }`}
                            >
                              <RescanIcon />
                            </span>
                            <span
                              role="button"
                              aria-label={`Delete ${s.target}`}
                              title={`Delete ${s.target}`}
                              onClick={(event) => handleDelete(event, s)}
                              className={`inline-flex h-8 w-8 items-center justify-center rounded-lg border transition-colors ${
                                busyActionId === `delete-${s.id}`
                                  ? isDark
                                    ? 'border-red-500/35 text-red-300 bg-red-500/10 opacity-70'
                                    : 'border-red-200 text-red-500 bg-red-50 opacity-70'
                                  : isDark
                                    ? 'border-red-500/25 text-red-300 hover:bg-red-500/10'
                                    : 'border-red-200 text-red-500 hover:bg-red-50'
                              }`}
                            >
                              <TrashIcon />
                            </span>
                          </div>
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
              <p className={`${isDark ? 'text-slate-200' : 'text-gray-600'} text-xs mt-1`}>3D pie of top 5 ports across all scanned targets</p>
            </div>
            <div className="px-6 py-4">
              <ThreeDPiePorts items={topCommonPorts} isDark={isDark} />
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
          <DistributionCard
            title="VULNERABILITY BREAKDOWN"
            subtitle="By vulnerability category"
            icon={<AlertTriangle color={isDark ? '#f59e0b' : '#f59e0b'} size={13} />}
            iconColor={isDark ? '#fbbf24' : '#f59e0b'}
            borderColor={isDark ? 'rgba(251,191,36,0.28)' : 'rgba(245,158,11,0.42)'}
            headerBorderColor={isDark ? 'rgba(251,191,36,0.16)' : 'rgba(245,158,11,0.16)'}
            theme={theme}
          >
            <VulnerabilityBreakdownList
              items={vulnDonutItems}
              total={statsData.totals.total_vulns}
              theme={theme}
            />
          </DistributionCard>

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
          <DistributionCard
            title="RISK DISTRIBUTION"
            subtitle="Scan results by risk level"
            icon={<CircleAlert color="#ef4444" size={13} />}
            iconColor="#ef4444"
            borderColor={isDark ? 'rgba(248,113,113,0.28)' : 'rgba(248,113,113,0.42)'}
            headerBorderColor={isDark ? 'rgba(248,113,113,0.16)' : 'rgba(248,113,113,0.16)'}
            theme={theme}
          >
            <RiskDistributionList items={riskItems} totals={statsData.totals} theme={theme} />
          </DistributionCard>

        </div>
      </main>
    </div>
  );
}
