import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../lib/api";
const SCAN_REQUEST_TIMEOUT_MS = 120000;
const EXAMPLES = [
  "192.168.1.1",
  "192.168.1.0/24",
  "10.0.0.1-10.0.0.255",
  "example.com",
  "192.168.1.1,192.168.1.2"
];

const STAGES = [
  { label: "Host Discovery", icon: "wifi" },
  { label: "Port Scanning (1-65535)", icon: "Scan" },
  { label: "Service Detection", icon: "terminal" },
  { label: "Vulnerability Assessment", icon: "shield" },
  { label: "Security Analysis", icon: "triangle" },
];

const LAST_SCAN_STORAGE_KEY = "vapt_last_scan_result";
const ACTIVE_SCAN_STORAGE_KEY = "vapt_active_scan_target";
const ACTIVE_SCAN_META_STORAGE_KEY = "vapt_active_scan_meta";

function getEstimatedScanDurationMs(target) {
  const value = String(target || "").trim();
  const parts = value.split(",").map((part) => part.trim()).filter(Boolean);
  const itemCount = Math.max(parts.length, 1);
  const hasRange = /\/\d{1,2}$/.test(value) || value.includes("-");
  const hasDomain = /[a-zA-Z]/.test(value) && value.includes(".");

  if (hasRange) return 24000 + (itemCount - 1) * 2500;
  if (itemCount > 1) return 18000 + (itemCount - 1) * 2200;
  if (hasDomain) return 16000;
  return 13000;
}

function getScanRequestTimeoutMs(target) {
  const value = String(target || "").trim();
  const parts = value.split(",").map((part) => part.trim()).filter(Boolean);
  const itemCount = Math.max(parts.length, 1);
  const hasRange = /\/\d{1,2}$/.test(value) || value.includes("-");
  const hasDomain = /[a-zA-Z]/.test(value) && value.includes(".");

  if (hasRange) return 10 * 60 * 1000;
  if (itemCount > 1) return 6 * 60 * 1000;
  if (hasDomain) return 3 * 60 * 1000;
  return SCAN_REQUEST_TIMEOUT_MS;
}

function getApiErrorMessage(data, status) {
  if (data?.error) return data.error;
  if (data?.detail) return data.detail;
  return `HTTP ${status}`;
}

function BlobBg() {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    let W = canvas.width = window.innerWidth;
    let H = canvas.height = window.innerHeight;
    const resize = () => { W = canvas.width = window.innerWidth; H = canvas.height = window.innerHeight; };
    window.addEventListener("resize", resize);

    const blobs = [
      { x: W * 0.15, y: H * 0.3, r: 380, color: "#1a1a2e", vx: 0.08, vy: 0.06 },
      { x: W * 0.80, y: H * 0.65, r: 320, color: "#6b1f3a", vx: -0.07, vy: 0.09 },
      { x: W * 0.50, y: H * 0.10, r: 220, color: "#e8d5c4", vx: 0.06, vy: -0.05 },
      { x: W * 0.90, y: H * 0.10, r: 200, color: "#6b1f3a", vx: -0.05, vy: 0.08 },
    ];

    let raf;
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = "#f5f0e8";
      ctx.fillRect(0, 0, W, H);
      blobs.forEach((b) => {
        b.x += b.vx; b.y += b.vy;
        if (b.x < -b.r) b.x = W + b.r;
        if (b.x > W + b.r) b.x = -b.r;
        if (b.y < -b.r) b.y = H + b.r;
        if (b.y > H + b.r) b.y = -b.r;
        const g = ctx.createRadialGradient(b.x, b.y, 0, b.x, b.y, b.r);
        g.addColorStop(0, b.color + "40");
        g.addColorStop(1, b.color + "00");
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2); ctx.fill();
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
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
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
const ShieldSvg = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
const MapSvg = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6" />
    <line x1="8" y1="2" x2="8" y2="18" /><line x1="16" y1="6" x2="16" y2="22" />
  </svg>
);
const StatsSvg = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <line x1="18" y1="20" x2="18" y2="10" /><line x1="12" y1="20" x2="12" y2="4" /><line x1="6" y1="20" x2="6" y2="14" />
  </svg>
);
const ScanSvg = ({ size = 20 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);
const FilterSvg = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
  </svg>
);
const BulbSvg = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <line x1="9" y1="18" x2="15" y2="18" /><line x1="10" y1="22" x2="14" y2="22" />
    <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14" />
  </svg>
);
const LoginSvg = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
    <polyline points="10 17 15 12 10 7" /><line x1="15" y1="12" x2="3" y2="12" />
  </svg>
);
const TerminalSvg = ({ size = 16, color = "currentColor" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
    <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
  </svg>
);
const TriangleSvg = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="8.5" x2="12" y2="13.5" />
    <circle cx="12" cy="16.5" r="1" fill="currentColor" />
  </svg>
);
const PauseSvg = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="9" y1="5" x2="9" y2="19" />
    <line x1="15" y1="5" x2="15" y2="19" />
  </svg>
);
const PlaySvg = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polygon points="7 5 19 12 7 19 7 5" />
  </svg>
);
const CloseSvg = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
    <line x1="18" y1="6" x2="6" y2="18" />
    <line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);
const WifiSvg = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3.5 10.5c6-5 13-5 17 0" />
    <path d="M6 13c4-3.5 8-3.5 12 0" />
    <path d="M8.5 15.5c2.5-2 5.5-2 8 0" />
    <circle cx="12" cy="18.5" r="1.15" fill="currentColor" />
  </svg>
);
const CheckSvg = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
  </svg>
);
const ChevronSvg = ({ open }) => (
  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.25s" }}>
    <polyline points="6 9 12 15 18 9" />
  </svg>
);
const LogoSvg = () => (
  <svg width="28" height="28" viewBox="0 0 40 40" fill="none">
    <circle cx="20" cy="20" r="18" stroke="#3b82f6" strokeWidth="2" />
    <ellipse cx="20" cy="20" rx="7" ry="18" stroke="#3b82f6" strokeWidth="2" />
    <line x1="2" y1="20" x2="38" y2="20" stroke="#3b82f6" strokeWidth="2" />
  </svg>
);
function StageIcon({ type, size = 19 }) {
  if (type === "check") return <CheckSvg size={size} />;
  if (type === "wifi") return <WifiSvg size={size} />;
  if (type === "Scan") return <ScanSvg size={size} />;
  if (type === "terminal") return <TerminalSvg size={size} />;
  if (type === "shield") return <ShieldSvg size={size} />;
  if (type === "triangle") return <TriangleSvg size={size} />;
  return null;
}

// ── Home Page ─────────────────────────────────────────────────────────────────
function HomePage({ onScan, theme, previewMode = false, onRequireLogin }) {
  const [query, setQuery] = useState("");
  const [showExamples, setShowExamples] = useState(false);
  const [error, setError] = useState("");

  const isValidTarget = (target) => {
    if (!target || target.trim().length === 0) return false;
    const parts = target.split(",").map((p) => p.trim());

    for (const part of parts) {
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(part)) {
        const octets = part.split(".").map(Number);
        if (octets.every((o) => o >= 0 && o <= 255)) continue;
      }

      const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
      if (cidrPattern.test(part)) {
        const [ip, mask] = part.split("/");
        const octets = ip.split(".").map(Number);
        const maskNum = Number(mask);
        if (octets.every((o) => o >= 0 && o <= 255) && maskNum >= 0 && maskNum <= 32) continue;
      }

      const rangePattern = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;
      if (rangePattern.test(part)) {
        const [start, end] = part.split("-");
        const startOctets = start.split(".").map(Number);
        const endOctets = end.split(".").map(Number);
        if (startOctets.every((o) => o >= 0 && o <= 255) && endOctets.every((o) => o >= 0 && o <= 255)) continue;
      }

      const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
      if (domainPattern.test(part)) continue;

      const localHostPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
      if (localHostPattern.test(part)) continue;

      return false;
    }

    return true;
  };

  const go = () => {
    const trimmed = query.trim();
    if (!isValidTarget(trimmed)) {
      setError("Invalid target format. Please enter: IP address, CIDR subnet (10.0.0.0/24), IP range (10.0.0.1-10.0.0.10), or domain name");
      setTimeout(() => setError(""), 4000);
      return;
    }
    if (previewMode) {
      setError("Preview mode is for display only. Please log in or sign up to run real IP or domain scans.");
      return;
    }
    setError("");
    onScan(trimmed);
  };

  return (
    <main
      className="relative z-10 h-[calc(100vh-88px)] h-[calc(100dvh-88px)] flex items-start justify-center px-6 pt-7 sm:pt-8 overflow-hidden"
      style={{
        backgroundColor: 'transparent',
      }}
    >
      <style>{`
        @keyframes scanSpin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes scanPulse {
          0%, 100% { transform: scale(0.92); opacity: 0.45; }
          50% { transform: scale(1); opacity: 0.95; }
        }
      `}</style>
      <div className="flex flex-col items-center w-full max-w-6xl">
        <div
          className="mb-5 flex items-center justify-center rounded-full p-5"
          style={{
            position: "relative",
            width: "96px",
            height: "96px",
            border: "1.5px solid rgba(107,31,58,0.20)",
            background: "radial-gradient(circle at 30% 30%, rgba(255,255,255,0.9), rgba(245,240,232,0.72))",
            boxShadow: "0 18px 42px rgba(107,31,58,0.12)",
            backdropFilter: "blur(12px)",
          }}
        >
          <span
            style={{
              position: "absolute",
              inset: "10px",
              borderRadius: "999px",
              border: "1px solid rgba(107,31,58,0.16)",
              animation: "scanPulse 2.2s ease-in-out infinite",
            }}
          />
          <span
            style={{
              position: "absolute",
              inset: "4px",
              borderRadius: "999px",
              borderTop: "2px solid rgba(107,31,58,0.85)",
              borderRight: "2px solid transparent",
              borderBottom: "2px solid rgba(107,31,58,0.18)",
              borderLeft: "2px solid transparent",
              animation: "scanSpin 3.4s linear infinite",
            }}
          />
          <span style={{ color: "#6b1f3a", position: "relative", zIndex: 1 }}>
            <GlobeIcon size={42} />
          </span>
        </div>

        <h1
          className="text-4xl sm:text-5xl lg:text-6xl font-semibold tracking-tight text-center m-0"
          style={{ margin: 0, lineHeight: 1.05, color: 'rgba(26,26,46,0.96)' }}
        >
          VULN SCAN
        </h1>
        <p
          className="text-sm sm:text-lg text-center max-w-3xl"
          style={{ marginTop: 10, marginBottom: 22, color: 'var(--text-dim)' }}
        >
          Vulnerability Assessment &amp; Penetration Testing Platform
        </p>

        <div className="flex flex-col items-center gap-3 w-full">
          <div
            className="relative w-full max-w-[980px]"
            style={{
              borderRadius: '34px',
              border: 'none',
              background: 'transparent',
              boxShadow: 'none',
              padding: '12px',
            }}
          >
            <input
              type="text"
              placeholder="192.168.1.1 or 10.0.0.0/24 or example.com"
              value={query}
              onChange={(e) => { setQuery(e.target.value); setError(""); }}
              onKeyDown={(e) => e.key === "Enter" && go()}
              className="w-full text-xl outline-none transition-colors"
              style={{
                width: '100%',
                padding: '16px 54px 16px 24px',
                borderRadius: '24px',
                border: '1px solid transparent',
                background: '#ffffff',
                color: 'var(--text)',
                boxShadow: 'inset 0 1px 2px rgba(26,26,46,0.06)',
              }}
            />
            <span className="absolute right-6 top-1/2 -translate-y-1/2 flex scale-110" style={{ color: '#6b1f3a' }}>
              <ScanSvg />
            </span>
          </div>

          {error && (
            <div
              className="w-full px-4 py-3 rounded-lg text-sm"
              style={{
                border: '1px solid rgba(191,90,75,0.35)',
                background: 'rgba(191,90,75,0.08)',
                color: 'rgba(107,31,58,0.95)',
              }}
            >
              {error}
            </div>
          )}

          {previewMode && (
            <div
              className="w-full rounded-2xl px-5 py-4 text-sm"
              style={{
                background: 'rgba(212,168,83,0.12)',
                border: '1px solid rgba(212,168,83,0.18)',
                color: 'var(--text)',
              }}
            >
              Preview mode is active. You can explore the scanner UI here, but real scans only run after login or signup.
              {onRequireLogin && (
                <button
                  onClick={onRequireLogin}
                  className="ml-3 rounded-xl px-4 py-2 text-sm font-semibold transition"
                  style={{
                    background: 'var(--accent)',
                    color: 'var(--bg)',
                    border: '1px solid rgba(212,168,83,0.2)',
                  }}
                >
                  Login to enable scanning
                </button>
              )}
            </div>
          )}

          <div className="flex gap-4 flex-wrap justify-center">
            <button
              onClick={go}
              className="min-w-40 px-8 py-3 rounded-2xl text-lg font-semibold cursor-pointer hover:opacity-90 transition-opacity border-none"
              style={{
                background: 'var(--accent)',
                color: 'var(--bg)',
                boxShadow: '0 18px 30px rgba(107,31,58,0.18)',
              }}
            >
              {previewMode ? "Preview Only" : "Scan"}
            </button>
            <button
              onClick={() => setShowExamples((v) => !v)}
              className="flex items-center gap-2 px-6 py-3 rounded-2xl text-base font-medium cursor-pointer transition-all"
              style={{
                border: '1px solid var(--border-hi)',
                background: 'var(--accent-bg)',
                color: 'var(--accent)',
              }}
            >
              <BulbSvg /> Examples
            </button>
          </div>

          {showExamples && (
            <div
              className="w-full max-w-[980px] rounded-2xl p-5"
              style={{
                background: 'transparent',
                border: '1px solid rgba(107,31,58,0.15)',
              }}
            >
              <div className="mt-2 grid w-full grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
                {EXAMPLES.map((ex) => (
                  <button
                    key={ex}
                    onClick={() => {
                      setQuery(ex);
                      setShowExamples(false);
                    }}
                    className="w-full px-4 py-1.5 rounded-lg text-center text-xs font-medium cursor-pointer transition-all"
                    style={{
                      border: '1px solid var(--border)',
                      background: 'rgba(26,26,46,0.04)',
                      color: 'var(--text)',
                    }}
                  >
                    {ex}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}

// ── Scan Page ─────────────────────────────────────────────────────────────────
function ScanPage({ target, onScanComplete, onCancel, theme }) {
  const [progress, setProgress] = useState(0);
  const [displayProgress, setDisplayProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState(0);
  const [logs, setLogs] = useState([]);
  const [scanResponse, setScanResponse] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [scanDone, setScanDone] = useState(false);
  const [isPaused, setIsPaused] = useState(false);
  const [isCancelled, setIsCancelled] = useState(false);
  const [jobId, setJobId] = useState(null);
  const [animateStageChange, setAnimateStageChange] = useState(false);
  const [isPageVisible, setIsPageVisible] = useState(() =>
    typeof document === "undefined" ? true : !document.hidden
  );
  const [isSessionReady, setIsSessionReady] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const logRef = useRef(null);
  const shouldStickToBottomRef = useRef(true);
  const isCancelledRef = useRef(false);
  const onScanCompleteRef = useRef(onScanComplete);
  const onCancelRef = useRef(onCancel);
  const stageLogRef = useRef(new Set());
  const finalLogsRef = useRef([]);
  const finalLogsFlushedRef = useRef(false);
  const lastProgressTickRef = useRef(Date.now());
  const estimatedScanDurationMs = getEstimatedScanDurationMs(target);
  const previousStageRef = useRef(0);

  useEffect(() => {
    onScanCompleteRef.current = onScanComplete;
  }, [onScanComplete]);

  useEffect(() => {
    onCancelRef.current = onCancel;
  }, [onCancel]);

  useEffect(() => {
    const onVisibilityChange = () => {
      const visible = !document.hidden;
      setIsPageVisible(visible);
      if (visible) {
        lastProgressTickRef.current = Date.now();
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, []);

  useEffect(() => {
    setIsSessionReady(false);
    let restored = false;
    try {
      const raw = localStorage.getItem(ACTIVE_SCAN_META_STORAGE_KEY);
      if (raw) {
        const meta = JSON.parse(raw);
        if (meta?.target === target) {
          const resumedProgress = Number(meta.progress);
          const resumedDisplayProgress = Number(meta.displayProgress);
          const safeDisplayProgress = Number.isFinite(resumedDisplayProgress)
            ? Math.min(95, Math.max(0, resumedDisplayProgress))
            : 0;
          const baseProgress = Number.isFinite(resumedProgress)
            ? Math.min(95, Math.max(0, resumedProgress))
            : 0;
          const monotonicProgress = Math.max(baseProgress, safeDisplayProgress);
          const resumedStage = Number(meta.currentStage);
          const baseStage = Number.isFinite(resumedStage)
            ? Math.min(4, Math.max(0, resumedStage))
            : Math.min(4, Math.floor(monotonicProgress / 22));

          setProgress(monotonicProgress);
          setDisplayProgress(monotonicProgress);
          setCurrentStage(baseStage);
          if (Array.isArray(meta.logs)) setLogs(meta.logs);
          setIsPaused(Boolean(meta.isPaused));
          setIsCancelled(Boolean(meta.isCancelled));
          if (meta.jobId) setJobId(meta.jobId);
          if (meta.scanDone) setScanDone(true);
          if (meta.scanError) setScanError(meta.scanError);
          if (meta.scanResponse) setScanResponse(meta.scanResponse);
          restored = true;
        }
      }
    } catch {}

    if (!restored) {
      setProgress(0);
      setDisplayProgress(0);
      setCurrentStage(0);
      setLogs([]);
      setScanResponse(null);
      setScanError(null);
      setScanDone(false);
      setIsPaused(false);
      setIsCancelled(false);
      setJobId(null);
    }
    stageLogRef.current = new Set();
    finalLogsRef.current = [];
    finalLogsFlushedRef.current = false;
    isCancelledRef.current = false;
    lastProgressTickRef.current = Date.now();
    setIsSessionReady(true);
  }, [target, estimatedScanDurationMs]);

  useEffect(() => {
    const intervalId = setInterval(() => {
      setDisplayProgress((prev) => {
        if (isPaused || isCancelled) return prev;
        const targetProgress = Math.max(prev, progress);
        if (targetProgress <= prev) return prev;
        const step = Math.max(0.18, Math.min(0.9, (targetProgress - prev) * 0.08));
        if (targetProgress - prev < step) return targetProgress;
        return prev + step;
      });
    }, 90);

    return () => clearInterval(intervalId);
  }, [progress, isPaused, isCancelled]);

  const ts = () => {
    const d = new Date(), h = d.getHours(), m = d.getMinutes(), sc = d.getSeconds();
    const ampm = h >= 12 ? "pm" : "am", hh = h % 12 || 12;
    return `[${String(hh).padStart(2,"0")}:${String(m).padStart(2,"0")}:${String(sc).padStart(2,"0")} ${ampm}]`;
  };
  const pushLog = (msg) => setLogs(prev => [...prev, { time: ts(), msg }]);

  useEffect(() => {
    return;
    if (!isSessionReady || logs.length > 0) return;
    const t = [
      setTimeout(() => pushLog(`Starting VAPT scan for target: ${target}`), 300),
      setTimeout(() => pushLog("Initializing scan modules..."), 800),
      setTimeout(() => pushLog(`Scan started at ${new Date().toLocaleTimeString("en-US",{hour12:false})}`), 1300),
      setTimeout(() => pushLog("Host discovery completed — 1 host found"), 2400),
      setTimeout(() => pushLog("Starting port scan (1-65535)..."), 3000),
    ];
    return () => t.forEach(clearTimeout);
  }, [target, isSessionReady, logs.length]);

  useEffect(() => {
    if (!isSessionReady || jobId || scanDone || isCancelled || scanResponse || scanError) return undefined;
    let active = true;

    const run = async () => {
      try {
        setIsLoading(true);
        const res = await fetch(`${API_BASE}/scan/start?target=${encodeURIComponent(target)}`, {
          mode: "cors",
          headers: { Accept: "application/json" },
        });
        const data = await res.json();
        if (!active) return;
        if (!res.ok || data.error) throw new Error(getApiErrorMessage(data, res.status));
        setJobId(data.job_id);
        if (Array.isArray(data.logs)) setLogs(data.logs);
      } catch (err) {
        if (!active) return;
        const message = err?.message || "Failed to start scan job.";
        setScanError(message);
        setScanDone(true);
      } finally {
        if (active) setIsLoading(false);
      }
    };

    run();
    return () => {
      active = false;
    };
  }, [target, isSessionReady, jobId, scanDone, isCancelled, scanResponse, scanError]);

  useEffect(() => {
    if (!isSessionReady || !jobId || isCancelled) return undefined;

    const poll = async () => {
      try {
        const res = await fetch(`${API_BASE}/scan/status?job_id=${encodeURIComponent(jobId)}`, {
          mode: "cors",
          headers: { Accept: "application/json" },
        });
        const data = await res.json();
        if (!res.ok || data.error) {
          if (res.status === 404) {
            // Recover from stale localStorage job IDs after refresh/backend restart.
            setJobId(null);
            setProgress(0);
            setCurrentStage(0);
            setScanDone(false);
            setScanError(null);
            setIsPaused(false);
            setIsLoading(false);
            try {
              localStorage.removeItem(ACTIVE_SCAN_META_STORAGE_KEY);
            } catch {}
            pushLog("Previous scan session expired. Restarting scan...");
            return;
          }
          throw new Error(getApiErrorMessage(data, res.status));
        }

        if (Array.isArray(data.logs)) setLogs(data.logs);
        if (typeof data.progress === "number") {
          const nextProgress = Math.max(0, Math.min(100, data.progress));
          // Keep progress monotonic even if the page is restored from local
          // state or backend updates arrive slightly out of order.
          setProgress((prev) => Math.max(prev, nextProgress));
        }
        if (typeof data.stage_index === "number") {
          const nextStage = Math.max(0, Math.min(4, data.stage_index));
          setCurrentStage((prev) => Math.max(prev, nextStage));
        }
        setIsPaused(data.status === "paused");
        setIsLoading(data.status === "running" || data.status === "queued");

        if (data.status === "completed") {
          setScanResponse(data.result || null);
          setScanError(null);
          setProgress(100);
          setScanDone(true);
          setIsPaused(false);
          setIsLoading(false);
        } else if (data.status === "error") {
          setScanError(data.error || "Scan failed.");
          setScanDone(true);
          setIsPaused(false);
          setIsLoading(false);
        } else if (data.status === "cancelled") {
          setScanError(data.error || "Scan cancelled.");
          setScanDone(true);
          setIsPaused(false);
          setIsLoading(false);
        }
      } catch (err) {
        setScanError(err?.message || "Failed to poll scan status.");
        setScanDone(true);
        setIsLoading(false);
      }
    };

    poll();
    const intervalId = setInterval(poll, 1000);
    return () => clearInterval(intervalId);
  }, [jobId, isSessionReady, isCancelled]);

  useEffect(() => {
    if (!isSessionReady) return undefined;
    lastProgressTickRef.current = Date.now();
    return undefined;
  }, [scanDone, isPaused, isCancelled, isSessionReady, isPageVisible]);

  useEffect(() => {
    lastProgressTickRef.current = Date.now();
  }, [isPaused, isCancelled, scanDone, isSessionReady, target]);

  useEffect(() => {
    return;
    if (isPaused || isCancelled) return;

    const visibleMilestones = [
      { threshold: 22, key: "port", log: "Port scanning in progress..." },
      { threshold: 45, key: "service", log: "Port scan complete. Starting service detection..." },
      { threshold: 65, key: "vuln", log: "Services detected. Running vulnerability assessment..." },
      { threshold: 82, key: "analysis", log: "Vulnerability scan done. Running security analysis..." },
      { threshold: 95, key: "wait", log: "Scan stages complete, waiting for backend to return final results..." },
    ];

    visibleMilestones.forEach((milestone) => {
      if (displayProgress >= milestone.threshold && !stageLogRef.current.has(milestone.key)) {
        stageLogRef.current.add(milestone.key);
        pushLog(milestone.log);
      }
    });
  }, [displayProgress, isPaused, isCancelled]);

  useEffect(() => {
    if (previousStageRef.current === currentStage) return;
    previousStageRef.current = currentStage;
    setAnimateStageChange(true);
    const timer = setTimeout(() => setAnimateStageChange(false), 320);
    return () => clearTimeout(timer);
  }, [currentStage]);

  useEffect(() => {
    if (isCancelled || isPaused) return undefined;
    if (scanDone && displayProgress >= 99.5) {
      if (!finalLogsFlushedRef.current) {
        finalLogsFlushedRef.current = true;
        finalLogsRef.current.forEach((message) => pushLog(message));
      }
      const result = scanError ? { error: scanError } : scanResponse;
      try {
        localStorage.removeItem(ACTIVE_SCAN_META_STORAGE_KEY);
      } catch {}
      const timer = setTimeout(() => onScanCompleteRef.current?.(result), 450);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [scanDone, displayProgress, scanResponse, scanError, isPaused, isCancelled]);

  const handleLogScroll = () => {
    const node = logRef.current;
    if (!node) return;
    const distanceFromBottom = node.scrollHeight - node.scrollTop - node.clientHeight;
    shouldStickToBottomRef.current = distanceFromBottom < 32;
  };

  useEffect(() => {
    const node = logRef.current;
    if (!node || !shouldStickToBottomRef.current) return;
    node.scrollTop = node.scrollHeight;
  }, [logs]);
  useEffect(() => {
    if (!isSessionReady || !target) return;
    const payload = {
      target,
      jobId,
      progress,
      displayProgress,
      currentStage,
      logs,
      isPaused,
      isCancelled,
      scanDone,
      scanError,
      scanResponse,
    };
    try {
      localStorage.setItem(ACTIVE_SCAN_META_STORAGE_KEY, JSON.stringify(payload));
    } catch {}
  }, [target, jobId, progress, displayProgress, currentStage, logs, isPaused, isCancelled, scanDone, scanError, scanResponse, isSessionReady]);
  const controlsLocked = isCancelled || (scanDone && displayProgress >= 99.5);

  const togglePause = async () => {
    if (controlsLocked) return;
    if (!jobId) return;
    const nextPaused = !isPaused;
    setIsPaused(nextPaused);
    try {
      const endpoint = nextPaused ? "pause" : "resume";
      const res = await fetch(`${API_BASE}/scan/${endpoint}?job_id=${encodeURIComponent(jobId)}`, {
        mode: "cors",
        headers: { Accept: "application/json" },
      });
      const data = await res.json();
      if (!res.ok || data.error) throw new Error(getApiErrorMessage(data, res.status));
      if (Array.isArray(data.logs)) setLogs(data.logs);
    } catch (err) {
      setIsPaused(!nextPaused);
      pushLog(err?.message || "Failed to update pause state.");
    }
  };

  const cancelScan = async () => {
    if (controlsLocked) return;
    isCancelledRef.current = true;
    if (jobId) {
      try {
        await fetch(`${API_BASE}/scan/cancel?job_id=${encodeURIComponent(jobId)}`, {
          mode: "cors",
          headers: { Accept: "application/json" },
        });
      } catch {}
    }
    setIsCancelled(true);
    setIsPaused(false);
    setScanError(null);
    setIsLoading(false);
    setScanDone(false);
    try {
      localStorage.removeItem(ACTIVE_SCAN_META_STORAGE_KEY);
    } catch {}
    onCancelRef.current?.();
  };

  return (
    <main className="relative z-10 w-full min-h-[calc(100vh-88px)] px-6 pt-0 pb-6 -mt-2">
      <style>{`
        @keyframes scan-bar-sheen {
          0% { transform: translateX(-140%); opacity: 0; }
          8% { opacity: 0.9; }
          50% { opacity: 1; }
          92% { opacity: 0.9; }
          100% { transform: translateX(620%); opacity: 0; }
        }
        @keyframes stage-fade-slide {
          0% { opacity: 0; transform: translateY(10px) scale(0.985); }
          100% { opacity: 1; transform: translateY(0) scale(1); }
        }
        .stage-change-once {
          animation: stage-fade-slide 280ms ease-out;
        }
        .scan-log-scroll {
          scrollbar-width: thin;
          scrollbar-color: ${theme === 'dark' ? '#22d3ee #0f172a' : '#94a3b8 #e5e7eb'};
        }
        .scan-log-scroll::-webkit-scrollbar {
          width: 8px;
        }
        .scan-log-scroll::-webkit-scrollbar-track {
          background: ${theme === 'dark' ? '#0f172a' : '#e5e7eb'};
          border-radius: 999px;
        }
        .scan-log-scroll::-webkit-scrollbar-thumb {
          background: ${theme === 'dark' ? '#22d3ee' : '#94a3b8'};
          border-radius: 999px;
        }
      `}</style>
      <div className="mx-auto max-w-7xl mt-6">
      <div className="text-center mb-4">
        <h4 className="text-[19px] font-bold mb-1"
          style={{ color: theme === 'dark' ? '#e2e8f0' : 'var(--maroon)' }}>
          {isCancelled ? "Scan Cancelled" : scanDone && displayProgress >= 99.5 ? "Scan Complete" : "Scanning in Progress"}
        </h4>
        <p className={`text-[16px] ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} m-0`}>
          Target: <span className={`${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'} font-semibold`}>{target}</span>
        </p>
      </div>

      {/* Stage Card */}
      <div className={`mx-auto max-w-[1060px] ${theme === 'dark' ? 'bg-[#0b1020]/98 border-cyan-500/18' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)]'} rounded-[16px] border px-6 py-4 mb-5`}>
        <div className="flex items-start justify-between mb-4">
          <div className={`flex items-start gap-3 ${animateStageChange ? "stage-change-once" : ""}`}>
            <span className={`flex pt-0.5 ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}><StageIcon type={STAGES[currentStage].icon} size={42} /></span>
            <div className="flex flex-col gap-3 -ml-1">
              <div>
              <div className={`text-[26px] font-bold leading-none ${theme === 'dark' ? 'text-slate-100' : 'text-gray-900'}`}>{STAGES[currentStage].label}</div>
              <div className={`text-[15px] ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'} mt-3`}>Stage {currentStage + 1} of 5</div>
              </div>
              <div className="flex items-center gap-2.5 -ml-10">
                <div className="relative group">
                  <button
                    onClick={togglePause}
                    disabled={controlsLocked}
                    aria-label={isPaused ? "Resume scan" : "Pause scan"}
                    className={`w-9 h-9 rounded-md inline-flex items-center justify-center border transition-all ${
                      controlsLocked
                        ? theme === "dark"
                          ? "opacity-50 cursor-not-allowed border-slate-700 bg-transparent text-slate-500"
                          : "opacity-50 cursor-not-allowed border-gray-200 bg-transparent text-gray-400"
                        : theme === "dark"
                          ? "border-cyan-400/35 bg-transparent text-cyan-400 hover:bg-cyan-400/10"
                          : "border-[rgba(107,31,58,0.2)] bg-transparent text-[var(--accent)] hover:bg-[rgba(107,31,58,0.12)]"
                    }`}
                    style={theme === "dark" && !controlsLocked
                      ? {
                          background: "transparent",
                          borderColor: "rgba(34,211,238,0.45)"
                        }
                      : undefined}
                  >
                    {isPaused ? <PlaySvg /> : <PauseSvg />}
                  </button>
                  {!controlsLocked && (
                    <span className={`pointer-events-none absolute left-1/2 top-full z-20 mt-2 -translate-x-1/2 whitespace-nowrap rounded-lg px-2.5 py-1.5 text-xs font-medium opacity-0 shadow-sm transition-all duration-150 group-hover:translate-y-0 group-hover:opacity-100 ${
                      theme === "dark"
                        ? "border border-slate-700 bg-slate-800 text-slate-200"
                        : "border border-gray-200 bg-gray-100 text-gray-700"
                    }`}>
                      {isPaused ? "Resume scan" : "Pause scan"}
                    </span>
                  )}
                </div>
                <div className="relative group">
                  <button
                    onClick={cancelScan}
                    disabled={controlsLocked}
                    aria-label={isCancelled ? "Scan cancelled" : "Cancel scan"}
                    className={`w-9 h-9 rounded-md inline-flex items-center justify-center border transition-all ${
                      controlsLocked
                        ? theme === "dark"
                          ? "opacity-50 cursor-not-allowed border-slate-700 bg-transparent text-slate-500"
                          : "opacity-50 cursor-not-allowed border-gray-200 bg-transparent text-gray-400"
                        : theme === "dark"
                          ? "border-cyan-400/35 bg-transparent text-cyan-400 hover:bg-cyan-400/10"
                          : "border-[rgba(107,31,58,0.2)] bg-transparent text-[var(--accent)] hover:bg-[rgba(107,31,58,0.12)]"
                    }`}
                    style={theme === "dark" && !controlsLocked
                      ? {
                          background: "transparent",
                          borderColor: "rgba(34,211,238,0.45)"
                        }
                      : undefined}
                  >
                    <CloseSvg />
                  </button>
                  {!controlsLocked && (
                    <span className={`pointer-events-none absolute left-1/2 top-full z-20 mt-2 -translate-x-1/2 whitespace-nowrap rounded-lg px-2.5 py-1.5 text-xs font-medium opacity-0 shadow-sm transition-all duration-150 group-hover:translate-y-0 group-hover:opacity-100 ${
                      theme === "dark"
                        ? "border border-slate-700 bg-slate-800 text-slate-200"
                        : "border border-gray-200 bg-gray-100 text-gray-700"
                    }`}>
                      Cancel scan
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
          <div className={`text-[42px] font-black font-mono leading-none ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{Math.round(displayProgress)}%</div>
        </div>

        {/* Progress bar */}
        <div className={`relative h-[10px] rounded-full ${theme === 'dark' ? 'bg-slate-700/60' : 'bg-gray-200'} overflow-hidden mb-4 transition-all duration-500`}>
          {displayProgress < 99.5 && !isPaused && !isCancelled && (
            <span
              className="absolute inset-y-0 left-0 z-10 w-[22%] pointer-events-none"
              style={{
                animation: "scan-bar-sheen 1.6s linear infinite",
                background: theme === 'dark'
                  ? "linear-gradient(90deg, rgba(255,255,255,0) 0%, rgba(255,255,255,0.10) 18%, rgba(255,255,255,0.34) 50%, rgba(255,255,255,0.10) 82%, rgba(255,255,255,0) 100%)"
                  : "linear-gradient(90deg, rgba(0,0,0,0) 0%, rgba(0,0,0,0.08) 18%, rgba(0,0,0,0.30) 50%, rgba(0,0,0,0.08) 82%, rgba(0,0,0,0) 100%)",
              }}
            />
          )}
        </div>

        {/* Stage pills */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3.5">
          {STAGES.map((stage, i) => {
            const done = i < currentStage, active = i === currentStage;
            const iconType = done ? "check" : stage.icon;
            return (
              <div key={i} className={`flex flex-col items-center justify-center py-2.5 px-3 rounded-[12px] min-h-[60px] border transition-all
                ${done ? "border-emerald-400/70 bg-emerald-500/10"
                  : active ? (theme === 'dark' ? "border-cyan-400/65 bg-cyan-400/[0.05]" : "border-[rgba(107,31,58,0.2)] bg-[rgba(107,31,58,0.08)]")
                  : theme === 'dark' ? "border-slate-800 bg-[#0a0f1b]" : "border-[rgba(26,26,46,0.12)] bg-[rgba(245,240,232,0.95)]"}`}>
                <span className={`flex ${done ? "text-emerald-400" : active ? (theme === 'dark' ? "text-cyan-400" : "text-[var(--accent)]") : theme === 'dark' ? "text-slate-500" : "text-gray-500"}`}>
                  <StageIcon type={iconType} size={22} />
                </span>
                <span className={`text-[13px] mt-1.5 text-center leading-tight font-medium
                  ${done ? "text-emerald-300" : active ? (theme === 'dark' ? "text-slate-100" : "text-gray-800") : theme === 'dark' ? 'text-slate-600' : 'text-gray-600'}`}>
                  {stage.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Terminal */}
      {scanError && (
        <div className="mx-auto max-w-5xl mb-5 p-4 rounded-xl border border-red-500 bg-red-500/10 text-red-200">
          <div className="font-semibold">Scan failed</div>
          <div className="text-sm mt-1">{scanError}</div>
          <button onClick={() => window.location.reload()} className="mt-3 inline-flex items-center gap-2 px-3 py-1.5 border border-red-400 rounded-lg text-xs font-semibold hover:bg-red-500/10">
            Retry (reload app)
          </button>
        </div>
      )}
      <div className={`mx-auto max-w-[1060px] ${theme === 'dark' ? 'bg-[#0a0e16]/95 border-cyan-500/[0.10]' : 'bg-white/95 border-gray-300'} rounded-[16px] border overflow-hidden`}>
        <div className={`flex items-center justify-between px-8 py-5 border-b ${theme === 'dark' ? 'border-cyan-500/[0.08]' : 'border-gray-300'}`}>
          <span className={`flex items-center gap-2 ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>
            <TerminalSvg size={16} color={theme === 'dark' ? "#22d3ee" : "#6b1f3a"} />
            <span className="font-mono text-[15px]">scan.log</span>
          </span>
        </div>
        <div
          ref={logRef}
          onScroll={handleLogScroll}
          className="scan-log-scroll px-8 py-6 h-[320px] overflow-y-auto overscroll-contain leading-loose"
        >
          {logs.map((log, i) => (
            <div key={i} className="flex gap-3 mb-0.5">
              <span className={`${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'} font-mono text-xs flex-shrink-0`}>{log.time}</span>
              <span className={`text-slate-400 font-mono text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{log.msg}</span>
            </div>
          ))}
          {progress < 100 && !isCancelled && <span className={`${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'} font-mono animate-pulse`}>▋</span>}
        </div>
      </div>
      </div>
    </main>
  );
}

// ── Vulns / Results Page ──────────────────────────────────────────────────────
const MOCK_HOSTS = [
  {
    id: 1, hostname: "kristellar.com", country: "US",
    provider: "Amazon AWS • United States", status: "SAFE", hostState: "UP",
    openPorts: 4, services: 4, osDetection: "Linux (90%)", vulnerabilities: 0,
    ports: [
      { port: 22,   protocol: "tcp", service: "ssh",   product: "OpenSSH",     version: "9.0" },
      { port: 80,   protocol: "tcp", service: "http",  product: "Apache httpd", version: "2.4.59" },
      { port: 443,  protocol: "tcp", service: "https", product: "OpenSSL",      version: "1.1.1w" },
      { port: 8080, protocol: "tcp", service: "http",  product: "Tomcat",       version: "10.1.5" },
    ],
    insecureProtocols: [
      { port: 80,   msg: "HTTP - Unencrypted protocol detected" },
      { port: 8080, msg: "HTTP - Unencrypted protocol detected" },
    ],
    tlsIssues: [{ port: 443, msg: "Weak TLS version detected (1.1.1w)" }],
  },
  {
    id: 2, hostname: "api.kristellar.com", country: "US",
    provider: "Amazon AWS • United States", status: "WARNING", hostState: "UP",
    openPorts: 3, services: 3, osDetection: "Linux (85%)", vulnerabilities: 2,
    ports: [
      { port: 22,   protocol: "tcp", service: "ssh",   product: "OpenSSH", version: "8.4" },
      { port: 443,  protocol: "tcp", service: "https", product: "nginx",   version: "1.24.0" },
      { port: 3000, protocol: "tcp", service: "http",  product: "Node.js", version: "18.12.0" },
    ],
    insecureProtocols: [{ port: 3000, msg: "HTTP - Unencrypted protocol detected" }],
    tlsIssues: [],
  },
  {
    id: 3, hostname: "mail.kristellar.com", country: "US",
    provider: "Amazon AWS • United States", status: "CRITICAL", hostState: "UP",
    openPorts: 5, services: 5, osDetection: "Linux (75%)", vulnerabilities: 1,
    ports: [
      { port: 25,  protocol: "tcp", service: "smtp",  product: "Postfix", version: "3.7.3", },
      { port: 110, protocol: "tcp", service: "pop3",  product: "Dovecot", version: "2.3.20" },
      { port: 143, protocol: "tcp", service: "imap",  product: "Dovecot", version: "2.3.20" },
      { port: 465, protocol: "tcp", service: "smtps", product: "Postfix", version: "3.7.3" },
      { port: 993, protocol: "tcp", service: "imaps", product: "Dovecot", version: "2.3.20" },
    ],
    insecureProtocols: [
      { port: 25,  msg: "SMTP - Unencrypted mail transfer detected" },
      { port: 110, msg: "POP3 - Unencrypted mail retrieval detected" },
    ],
    tlsIssues: [{ port: 465, msg: "Weak TLS version detected (1.0)" }],
  },
];

function StatusBadge({ label }) {
  const map = {
    SAFE: "bg-emerald-500/8 border-emerald-500/45 text-emerald-300",
    WARNING: "bg-amber-500/8 border-amber-500/45 text-amber-300",
    CRITICAL: "bg-red-500/8 border-red-500/45 text-red-300",
    HIGH: "bg-red-500/8 border-red-500/45 text-red-300",
    MEDIUM: "bg-amber-500/8 border-amber-500/45 text-amber-300",
    LOW: "bg-emerald-500/8 border-emerald-500/45 text-emerald-300",
    UP: "bg-emerald-500/8 border-emerald-500/45 text-emerald-300",
    "HOST IS UP": "bg-emerald-500/8 border-emerald-500/45 text-emerald-300",
  };
  return (
    <span className={`px-3 py-1 rounded-lg text-[11px] font-bold tracking-[0.18em] border uppercase ${map[label] || map.UP}`}>
      {label}
    </span>
  );
}

function getRiskLabel(vulnerabilities) {
  const items = Array.isArray(vulnerabilities) ? vulnerabilities : [];
  const severities = items.map((v) => String(v?.severity || "").toUpperCase());

  if (severities.includes("CRITICAL") || severities.includes("HIGH")) return "HIGH";
  if (severities.includes("MEDIUM")) return "MEDIUM";
  if (items.length > 0 || typeof vulnerabilities === "number" && vulnerabilities > 0) return "LOW";
  return "SAFE";
}

function getCountryBadge(host) {
  const value = String(host.country || "").trim().toUpperCase();
  if (value.length === 2) return value;
  if (value.length > 2) return value.slice(0, 2);
  return "NA";
}

function SectionTitle({ color = "bg-cyan-400", textColor = "text-cyan-400", children }) {
  return (
    <div className={`flex items-center gap-2.5 text-xs font-bold tracking-widest mb-3.5 ${textColor}`}>
      <span className={`w-1 h-4 rounded flex-shrink-0 ${color}`} />
      {children}
    </div>
  );
}

function stripPortPrefix(message, port) {
  if (!message) return "";
  const portLabel = String(port).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return message.replace(new RegExp(`^Port\\s*${portLabel}:\\s*`, "i"), "");
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

function truncateText(value, max = 120) {
  const text = String(value || "").trim();
  if (!text) return "N/A";
  return text.length > max ? `${text.slice(0, max).trimEnd()}...` : text;
}

function formatLabel(value) {
  return String(value || "")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

const DOMAIN_INTEL_SECTION_SCHEMAS = [
  {
    title: "Background",
    keys: ["site_title", "date_first_seen", "site_rank", "primary_language", "description"],
  },
  {
    title: "Network",
    keys: [
      "site",
      "domain",
      "netblock_owner",
      "nameserver",
      "hosting_company",
      "domain_registrar",
      "hosting_country",
      "nameserver_organisation",
      "ipv4_address",
      "organisation",
      "ipv4_autonomous_systems",
      "dns_admin",
      "ipv6_address",
      "top_level_domain",
      "ipv6_autonomous_systems",
      "dns_security_extensions",
      "reverse_dns",
    ],
  },
  {
    title: "Security",
    keys: ["ssl_tls", "sender_policy_framework", "dmarc"],
  },
  {
    title: "DNS Records",
    keys: [
      "robtex_dnssec_status",
      "robtex_a_records",
      "robtex_aaaa_records",
      "robtex_cname_records",
      "robtex_mx_records",
      "robtex_ns_records",
      "robtex_txt_records",
      "robtex_soa_records",
      "robtex_passive_dns",
      "robtex_passive_dns_count",
      "robtex_source",
      "robtex_records_table",
      "robtex_dns_history_table",
      "robtex_resolution_tree",
    ],
  },
  {
    title: "Technology",
    keys: ["web_trackers", "site_technology"],
  },
];

function buildDomainIntelSections(details, displayItems) {
  const hasVisibleValue = (value, kind = null) => {
    if (kind) {
      if (Array.isArray(value)) return value.length > 0;
      return value != null;
    }
    if (Array.isArray(value)) return value.length > 0;
    if (value && typeof value === "object") return Object.keys(value).length > 0;
    if (typeof value === "string") return value.trim() !== "";
    return value != null;
  };

  const detailMap = {};
  Object.entries(details || {}).forEach(([key, value]) => {
    if (!hasVisibleValue(value)) return;
    detailMap[key] = {
      key,
      label: formatLabel(key),
      value,
    };
  });

  toArray(displayItems).forEach((item) => {
    if (!item?.key) return;
    if (!hasVisibleValue(item.value, item.kind || null)) return;
    detailMap[item.key] = {
      key: item.key,
      label: item.label || formatLabel(item.key),
      value: item.value,
      kind: item.kind || null,
    };
  });

  const usedKeys = new Set();
  const sections = DOMAIN_INTEL_SECTION_SCHEMAS.map((schema) => {
    const items = schema.keys
      .map((key) => {
        usedKeys.add(key);
        return detailMap[key] || null;
      })
      .filter(Boolean);
    return { title: schema.title, items };
  });

  const extras = Object.values(detailMap).filter((item) => !usedKeys.has(item.key));
  if (extras.length > 0) {
    sections.push({ title: "Other", items: extras });
  }

  return sections.filter((section) => section.items.length > 0);
}

function chunkPairs(items) {
  const pairs = [];
  for (let index = 0; index < items.length; index += 2) {
    pairs.push(items.slice(index, index + 2));
  }
  return pairs;
}

function renderRobtexRecordsTable(rows, theme) {
  const items = toArray(rows);
  if (items.length === 0) return null;
  return (
    <div className={`overflow-hidden rounded-xl border ${theme === 'dark' ? 'border-slate-700 bg-[#0b1220]/70' : 'border-slate-200 bg-slate-50/80'}`}>
      <div className={`grid grid-cols-[90px_90px_minmax(0,1fr)] px-4 py-2 text-[11px] font-bold uppercase tracking-widest ${theme === 'dark' ? 'bg-slate-900/80 text-slate-400' : 'bg-slate-100 text-slate-500'}`}>
        <div>Type</div>
        <div>Count</div>
        <div>Sample Data</div>
      </div>
      {items.map((row, index) => (
        <div
          key={`${row.type}-${index}`}
          className={`grid grid-cols-[90px_90px_minmax(0,1fr)] gap-3 px-4 py-3 text-sm ${theme === 'dark' ? 'border-t border-slate-800 text-slate-200' : 'border-t border-slate-200 text-slate-800'}`}
        >
          <div className="font-semibold">{row.type}</div>
          <div className={`${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>{row.count}</div>
          <div className="break-words font-mono text-xs leading-6">{row.sample}</div>
        </div>
      ))}
    </div>
  );
}

function renderRobtexHistoryTable(rows, theme) {
  const items = toArray(rows);
  if (items.length === 0) return null;
  return (
    <div className="space-y-2">
      {items.map((row, index) => (
        <div
          key={`${row.type}-${row.value}-${index}`}
          className={`rounded-xl border px-4 py-3 ${theme === 'dark' ? 'border-slate-700 bg-[#0b1220]/70' : 'border-slate-200 bg-slate-50/80'}`}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded-md px-2 py-1 text-xs font-bold ${theme === 'dark' ? 'bg-emerald-500/10 text-emerald-300' : 'bg-emerald-50 text-emerald-700'}`}>{row.type}</span>
            <span className="font-mono text-sm break-all">{row.value}</span>
          </div>
          <div className={`mt-2 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>
            {row.first_seen} to {row.last_seen} | {row.observations} obs | {row.active_host_count} host{row.active_host_count === 1 ? "" : "s"}
          </div>
          {toArray(row.hosts).length > 0 ? (
            <div className={`mt-1 break-all text-[11px] font-mono ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>
              {row.hosts.join(", ")}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function renderRobtexResolutionTree(rows, theme) {
  const items = toArray(rows);
  if (items.length === 0) return null;
  return (
    <div className={`overflow-hidden rounded-xl border ${theme === 'dark' ? 'border-slate-700 bg-[#0b1220]/70' : 'border-slate-200 bg-slate-50/80'}`}>
      {items.map((row, index) => (
        <div key={`${row.type}-${row.value}-${index}`} className={`${index > 0 ? theme === 'dark' ? 'border-t border-slate-800' : 'border-t border-slate-200' : ''}`}>
          <div className="grid grid-cols-[72px_minmax(0,1fr)] gap-3 px-4 py-3">
            <div className={`text-sm font-bold ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{row.type}</div>
            <div>
              <div className="break-all font-mono text-sm">{row.value}</div>
              {row.annotation ? (
                <div className={`mt-1 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{row.annotation}</div>
              ) : null}
            </div>
          </div>
          {toArray(row.children).length > 0 ? (
            <div className={`px-4 pb-3 pl-10 ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>
              {row.children.map((child, childIndex) => (
                <div key={`${child.type}-${child.value}-${childIndex}`} className="grid grid-cols-[56px_minmax(0,1fr)] gap-3 py-1.5">
                  <div className={`text-xs font-semibold ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>{child.type}</div>
                  <div>
                    <div className="break-all font-mono text-xs">{child.value}</div>
                    {child.annotation ? (
                      <div className={`mt-0.5 text-[11px] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>{child.annotation}</div>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function renderDomainIntelComplexItem(item, theme) {
  if (item.kind === "records_table") return renderRobtexRecordsTable(item.value, theme);
  if (item.kind === "history_table") return renderRobtexHistoryTable(item.value, theme);
  if (item.kind === "resolution_tree") return renderRobtexResolutionTree(item.value, theme);
  return null;
}

const PORT_PROTOCOL_LABELS = {
  21: "FTP",
  22: "SSH",
  23: "TELNET",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  123: "NTP",
  143: "IMAP",
  161: "SNMP",
  389: "LDAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  587: "SMTP",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1521: "ORACLE",
  3306: "MYSQL",
  3389: "RDP",
  5432: "POSTGRESQL",
  6379: "REDIS",
  8080: "HTTP",
  8443: "HTTPS",
};

function getDisplayProtocol(portInfo) {
  const mapped = PORT_PROTOCOL_LABELS[Number(portInfo?.port)];
  if (mapped) return mapped;

  const service = String(portInfo?.service || "").trim().toLowerCase();
  if (service && service !== "unknown") {
    if (service.includes("https") || service.includes("ssl") || service.includes("tls")) return "HTTPS";
    if (service === "http" || service === "http-alt" || service === "http-proxy" || service.includes("http")) return "HTTP";
    if (service.includes("ssh")) return "SSH";
    if (service.includes("smtp")) return "SMTP";
    if (service.includes("imap")) return "IMAP";
    if (service.includes("pop3")) return "POP3";
    if (service.includes("dns") || service === "domain") return "DNS";
    if (service.includes("mysql")) return "MYSQL";
    if (service.includes("postgres")) return "POSTGRESQL";
    if (service.includes("rdp") || service.includes("ms-wbt-server")) return "RDP";
    if (service.includes("smb") || service.includes("microsoft-ds")) return "SMB";
    if (service.includes("netbios")) return "NETBIOS";
    return service.toUpperCase();
  }

  const protocol = String(portInfo?.protocol || "").trim();
  return protocol ? protocol.toUpperCase() : "UNKNOWN";
}

function HostCard({ host, theme }) {
  const [open, setOpen] = useState(Boolean(host.defaultOpen));
  const hostStateLabel = host.hostState || "Host is up";
  const riskLabel = getRiskLabel(host.vulnerabilityItems ?? host.vulnerabilities);
  const countryBadge = getCountryBadge(host);
  const portEntries = toArray(host.ports);
  const insecureProtocols = toArray(host.insecureProtocols);
  const tlsIssues = toArray(host.tlsIssues);
  const credentialFindings = toArray(host.credentialScan?.findings);
  const relatedSubdomains = toArray(host.relatedSubdomains);
  const riskSummary = host.riskSummary || {};
  const serviceIntel = portEntries.filter((item) => item?.banner || toArray(item?.scripts).length > 0);
  const domainIntelligence = host.domainIntelligence || {};
  const domainIntelSections = buildDomainIntelSections(
    domainIntelligence.details || {},
    toArray(domainIntelligence.display_details),
  );

  return (
    <div className={`rounded-xl p-6 border transition-colors duration-200 ${open
      ? theme === 'dark'
        ? 'bg-[#0d1220]/95 border-sky-400/70 text-slate-200'
        : 'bg-white border-[rgba(107,31,58,0.3)] text-gray-900'
      : theme === 'dark'
        ? 'bg-[#0d1220]/95 border-cyan-500/10 text-slate-200 hover:border-sky-400/70'
        : 'bg-[rgba(245,240,232,0.95)] border-[rgba(107,31,58,0.18)] text-[var(--text)] hover:border-[rgba(107,31,58,0.4)]'
    }`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-5">
        <div className="flex items-start gap-3.5">
          <div className={`w-9 h-9 rounded-lg ${theme === 'dark' ? 'bg-cyan-400/8 border-cyan-400/20 text-slate-400' : 'bg-[rgba(107,31,58,0.05)] border-[rgba(107,31,58,0.2)] text-[var(--accent)]'} flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5`}>
            {countryBadge}
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap mb-1">
              <span className={`text-lg font-bold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{host.hostname}</span>
              <StatusBadge label={riskLabel} />
              <StatusBadge label={hostStateLabel.toUpperCase()} />
            </div>
            <div className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{host.vendor || host.provider || "Unknown vendor"}</div>
            <div className={`text-xs ${theme === 'dark' ? 'text-slate-600' : 'text-gray-500'} font-mono mt-0.5`}>
              Hostname: {host.hostname}
              {host.ip ? `  |  IP: ${host.ip}` : ""}
              {host.domain && host.domain !== host.hostname ? `  |  Domain: ${host.domain}` : ""}
            </div>
          </div>
        </div>
        <button onClick={() => setOpen(v => !v)}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-semibold cursor-pointer transition-all flex-shrink-0 ${
            theme === 'dark'
              ? 'border-cyan-400/35 bg-transparent text-cyan-400 hover:bg-cyan-400/10'
              : 'border-[rgba(107,31,58,0.2)] bg-transparent text-[var(--accent)] hover:bg-[rgba(107,31,58,0.12)]'
          }`}>
          {open ? "Collapse" : "Expand"} <ChevronSvg open={open} />
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "OPEN PORTS",      val: `${host.openPorts} detected`,   cls: theme === 'dark' ? "text-cyan-400" : "text-[var(--accent)]" },
          { label: "SERVICES",         val: `${host.services} identified`,  cls: theme === 'dark' ? "text-cyan-400" : "text-[var(--accent)]" },
          { label: "OS DETECTION",     val: host.osDetection,               cls: "text-violet-400" },
          { label: "VULNERABILITIES",  val: `${host.vulnerabilities} found`,cls: "text-amber-400" },
        ].map(item => (
          <div key={item.label} className="flex flex-col gap-1">
            <span className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{item.label}</span>
            <span className={`text-sm font-semibold font-mono ${item.cls}`}>{item.val}</span>
          </div>
        ))}
      </div>

      {/* Expanded */}
      {open && (
        <div className="mt-5">
          <div className={`h-px mb-6 ${theme === 'dark' ? 'bg-cyan-500/8' : 'bg-[rgba(107,31,58,0.1)]'}`} />

          {/* Port Scan Table */}
          <div className="mb-6">
            <SectionTitle>PORT SCAN RESULTS</SectionTitle>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>
                    {["PORT","PROTOCOL","SERVICE","PRODUCT","VERSION"].map(h => (
                      <th key={h} className={`text-left py-2.5 px-4 text-[11px] font-bold tracking-wider ${theme === 'dark' ? 'text-slate-400 border-b border-white/5 bg-white/[0.02]' : 'text-gray-500 border-b border-[rgba(107,31,58,0.12)] bg-[rgba(245,240,232,0.95)]'}`}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {portEntries.map((p, i) => (
                    <tr key={i} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                      <td className={`py-3 px-4 font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{p.port}</td>
                      <td className={`py-3 px-4 ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{getDisplayProtocol(p)}</td>
                      <td className={`py-3 px-4 ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{p.service && p.service !== "unknown" ? p.service : "Unidentified service"}</td>
                      <td className={`py-3 px-4 font-mono ${theme === 'dark' ? 'text-slate-300' : 'text-gray-800'}`}>{p.product || "Fingerprint unavailable"}</td>
                      <td className={`py-3 px-4 ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{p.version || "Not detected"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

      <div className="space-y-6 mb-6">
            <div>
              <SectionTitle color="bg-sky-400" textColor="text-sky-400">ASSET INTELLIGENCE</SectionTitle>
              <div className={`rounded-2xl border p-5 ${theme === 'dark' ? 'border-sky-500/20 bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.12),transparent_32%),#0b1220]' : 'border-sky-200 bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.08),transparent_30%),white]'}`}>
                <div className={`flex flex-wrap items-center gap-x-6 gap-y-2 border-b pb-4 mb-4 ${theme === 'dark' ? 'border-slate-800 text-slate-300' : 'border-slate-200 text-slate-700'}`}>
                  <div><span className={`mr-2 text-[11px] font-bold uppercase tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>Status</span>{domainIntelligence.enabled ? "Collected" : "Unavailable"}</div>
                  <div><span className={`mr-2 text-[11px] font-bold uppercase tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>DNSSEC</span>{domainIntelligence.details?.robtex_dnssec_status || "Unknown"}</div>
                  <div><span className={`mr-2 text-[11px] font-bold uppercase tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>Subdomains</span>{relatedSubdomains.length}</div>
                  <div><span className={`mr-2 text-[11px] font-bold uppercase tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-slate-500'}`}>DNS History</span>{domainIntelligence.details?.robtex_passive_dns_count || 0}</div>
                </div>
                {domainIntelligence.note ? (
                  <div className={`mb-4 text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{domainIntelligence.note}</div>
                ) : null}
                {domainIntelSections.length === 0 ? (
                  <div className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No domain intelligence recorded for this asset.</div>
                ) : (
                  <div className="space-y-5">
                    {domainIntelSections.map((section) => (
                      <div key={section.title} className={`border-l-2 pl-4 ${theme === 'dark' ? 'border-sky-500/30' : 'border-sky-300'}`}>
                        <div className="mb-3">
                          <div className={`text-base font-semibold ${theme === 'dark' ? 'text-slate-100' : 'text-slate-900'}`}>{section.title}</div>
                        </div>
                        <div>
                          {chunkPairs(section.items.filter((item) => !item.kind)).map((pair, rowIndex) => (
                            <div key={`${section.title}-${rowIndex}`} className={`border-t first:border-t-0 ${theme === 'dark' ? 'border-slate-800' : 'border-slate-200'}`}>
                              {pair.map((item) => (
                                  <div key={item.key} className="grid grid-cols-[180px_minmax(0,1fr)] items-start gap-4 py-2">
                                    <div className={`text-sm font-semibold ${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'}`}>{item.label}</div>
                                  <div className={`text-sm leading-6 break-words ${theme === 'dark' ? 'text-slate-100' : 'text-slate-900'}`}>{String(item.value)}</div>
                                  </div>
                              ))}
                            </div>
                          ))}
                          {section.items.filter((item) => item.kind).map((item) => (
                            <div key={item.key} className="pt-2">
                              <div className={`mb-2 text-sm font-semibold ${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'}`}>{item.label}</div>
                              {renderDomainIntelComplexItem(item, theme)}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div>
              <SectionTitle color="bg-rose-400" textColor="text-rose-400">PRIORITIZED RISK</SectionTitle>
              <div className={`rounded-lg p-4 border ${theme === 'dark' ? 'bg-[#111827]/60 border-slate-700' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)]'}`}>
                <div className="grid grid-cols-3 gap-3 mb-3">
                  <div>
                    <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>ASSET IMPORTANCE</div>
                    <div className={`mt-1 text-sm font-semibold ${theme === 'dark' ? 'text-rose-300' : 'text-rose-600'}`}>{riskSummary.asset_importance ? formatLabel(riskSummary.asset_importance) : "N/A"}</div>
                  </div>
                  <div>
                    <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>IMPORTANCE SCORE</div>
                    <div className={`mt-1 text-sm font-semibold font-mono ${theme === 'dark' ? 'text-slate-200' : 'text-gray-900'}`}>{riskSummary.asset_importance_score ?? "N/A"}</div>
                  </div>
                  <div>
                    <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>HIGHEST RISK</div>
                    <div className={`mt-1 text-sm font-semibold font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-600'}`}>{riskSummary.highest_risk_score ?? 0}</div>
                  </div>
                </div>
                {host.vulnerabilityItems?.length ? (
                  <div className="space-y-2">
                    {host.vulnerabilityItems.slice(0, 3).map((item, index) => (
                      <div key={`${item?.title || item?.cve || "risk"}-${index}`} className={`rounded-md px-3 py-2 border ${theme === 'dark' ? 'border-white/5 bg-white/[0.02]' : 'border-gray-200 bg-white'}`}>
                        <div className="flex items-center justify-between gap-3">
                          <span className={`text-sm font-semibold ${theme === 'dark' ? 'text-slate-100' : 'text-gray-900'}`}>{item.title || item.cve || "Risk finding"}</span>
                          <span className={`text-xs font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>Risk {item.risk_score ?? 0}</span>
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2">
                          <span className={`rounded-md px-2 py-1 text-[11px] font-mono ${theme === 'dark' ? 'bg-cyan-500/[0.08] text-cyan-300 border border-cyan-500/20' : 'bg-[rgba(107,31,58,0.05)] text-[var(--accent)] border-[rgba(107,31,58,0.2)]'}`}>
                            CVE: {item.cve || item.cve_id || "UNKNOWN"}
                          </span>
                          {Array.isArray(item.cwe_ids) && item.cwe_ids.length > 0 && (
                            <span className={`rounded-md px-2 py-1 text-[11px] font-mono ${theme === 'dark' ? 'bg-amber-500/[0.08] text-amber-300 border border-amber-500/20' : 'bg-amber-50 text-amber-700 border border-amber-200'}`}>
                              CWE: {item.cwe_ids.join(", ")}
                            </span>
                          )}
                        </div>
                        {item.weakness_summary && (
                          <div className={`mt-2 text-xs ${theme === 'dark' ? 'text-amber-200' : 'text-amber-800'}`}>
                            {item.weakness_summary}
                          </div>
                        )}
                        <div className={`mt-1 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>
                          {item.risk_formula || truncateText(item.description, 90)}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No prioritized host risks were generated.</span>
                )}
              </div>
            </div>

            <div>
              <SectionTitle color="bg-emerald-400" textColor="text-emerald-400">SERVICE INTELLIGENCE</SectionTitle>
              <div className={`rounded-lg p-4 border flex flex-col gap-3 ${theme === 'dark' ? 'bg-[#111827]/60 border-slate-700' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)]'}`}>
                {serviceIntel.length === 0 ? (
                  <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No banners or NSE script output captured for this host.</span>
                ) : (
                  serviceIntel.slice(0, 6).map((item, index) => (
                    <div key={`${item?.port || "svc"}-${index}`} className={`rounded-md px-3 py-3 border ${theme === 'dark' ? 'border-white/5 bg-white/[0.02]' : 'border-gray-200 bg-white'}`}>
                      <div className="flex items-center justify-between gap-3">
                        <span className={`text-sm font-semibold font-mono ${theme === 'dark' ? 'text-emerald-300' : 'text-emerald-700'}`}>Port {item.port} - {item.service || "unknown"}</span>
                        <span className={`text-[11px] ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>{String(item.banner_source || "socket").toUpperCase()}</span>
                      </div>
                      <div className={`mt-1 text-xs ${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>
                        Banner: {truncateText(item.banner || "No banner captured.", 110)}
                      </div>
                      {toArray(item.scripts).length > 0 && (
                        <div className={`mt-2 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>
                          {toArray(item.scripts).slice(0, 2).map((script, scriptIndex) => (
                            <div key={`${script?.id || "script"}-${scriptIndex}`}>
                              <span className={`font-mono ${theme === 'dark' ? 'text-cyan-300' : 'text-[var(--accent)]'}`}>{script.id || "nse-script"}:</span> {truncateText(script.output, 90)}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
            </div>
          </div>

          {/* Insecure Protocols */}
          <div className="mb-6">
            <SectionTitle color="bg-amber-400" textColor="text-amber-400">INSECURE PROTOCOL DETECTION</SectionTitle>
            <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#111827]/60 border border-slate-700' : 'bg-[rgba(245,240,232,0.95)] border border-[rgba(26,26,46,0.12)]'}`}>
              {insecureProtocols.length === 0
                ? <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No insecure protocols detected.</span>
                : insecureProtocols.map((item, i) => (
                  <div key={i} className="flex items-center gap-2.5">
                    <span className="text-amber-400 flex"><TriangleSvg size={14} /></span>
                    <span className={`${theme === 'dark' ? 'text-slate-200' : 'text-gray-700'} font-mono text-sm`}>
                      <span className="text-amber-400">Port {item.port}:</span> {stripPortPrefix(item.message || item.msg || "Insecure protocol detected.", item.port)}
                    </span>
                  </div>
                ))
              }
            </div>
          </div>

          {/* TLS Issues */}
          <div className="mb-6">
            <SectionTitle color="bg-violet-400" textColor="text-violet-400">TLS / WEAK ENCRYPTION OBSERVATIONS</SectionTitle>
            <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#111827]/60 border border-slate-700' : 'bg-[rgba(245,240,232,0.95)] border border-[rgba(26,26,46,0.12)]'}`}>
              {tlsIssues.length === 0
                ? <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No TLS issues detected.</span>
                : tlsIssues.map((item, i) => (
                  <div key={i} className="flex items-center gap-2.5">
                    <span className="text-violet-400 flex"><ShieldSvg size={14} /></span>
                    <span className={`${theme === 'dark' ? 'text-slate-200' : 'text-gray-700'} font-mono text-sm`}>
                      <span className="text-violet-400">Port {item.port}:</span> {stripPortPrefix(item.message || item.msg || "TLS observation detected.", item.port)}
                    </span>
                  </div>
                ))
              }
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 mb-6">
            <div>
              <SectionTitle color="bg-cyan-400" textColor="text-cyan-400">SUBDOMAIN LINKS</SectionTitle>
              <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#111827]/60 border border-slate-700' : 'bg-[rgba(245,240,232,0.95)] border border-[rgba(26,26,46,0.12)]'}`}>
                {relatedSubdomains.length === 0 ? (
                  <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No related subdomains mapped to this host.</span>
                ) : (
                  relatedSubdomains.map((item, index) => (
                    <div key={`${item?.subdomain || "subdomain"}-${index}`} className="flex items-center justify-between gap-3">
                      <span className={`text-sm font-mono ${theme === 'dark' ? 'text-cyan-300' : 'text-[var(--accent)]'}`}>{item.subdomain}</span>
                      <span className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>{item.source || "inventory"}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div>
              <SectionTitle color="bg-red-400" textColor="text-red-400">SSH CREDENTIAL CHECKS</SectionTitle>
              <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#111827]/60 border border-slate-700' : 'bg-[rgba(245,240,232,0.95)] border border-[rgba(26,26,46,0.12)]'}`}>
                {!host.credentialScan?.enabled ? (
                  <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>Credential validation was not enabled for this scan.</span>
                ) : credentialFindings.length === 0 ? (
                  <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No supplied SSH credentials succeeded.</span>
                ) : (
                  credentialFindings.map((item, index) => (
                    <div key={`${item?.username || "credential"}-${index}`} className={`rounded-md px-3 py-3 border ${theme === 'dark' ? 'border-red-500/20 bg-red-500/[0.05]' : 'border-red-200 bg-red-50'}`}>
                      <div className={`text-sm font-semibold ${theme === 'dark' ? 'text-red-300' : 'text-red-700'}`}>{item.title || "SSH credential finding"}</div>
                      <div className={`mt-1 text-xs font-mono ${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>
                        Username: {item.username || "unknown"} | Port: {item.port || 22} | Status: {item.status || "success"}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* View Profile Button */}
          <div className="flex items-center justify-center gap-2 p-3.5 rounded-lg border border-cyan-500/15 bg-cyan-500/[0.03] cursor-pointer hover:bg-cyan-500/8 transition-all">
            <TerminalSvg size={14} color="#00e5ff" />
            <span className="text-cyan-400 text-sm font-mono">&gt;_ View Complete Device Profile</span>
          </div>
        </div>
      )}
    </div>
  );
}

function VulnsPage({ scanData, theme }) {
  const isLive = Boolean(scanData);
  const hosts = scanData?.assets ?? [];
  const scanState = isLive ? "LIVE" : "NO DATA";
  const hostsUp = scanData?.active_hosts ?? 0;
  const openPorts = hosts.reduce((sum, h) => sum + (Array.isArray(h.open_ports) ? h.open_ports.length : 0), 0);
  const vulnerabilities = scanData?.vulnerability_summary?.total_vulnerabilities ?? 0;
  const critical = scanData?.vulnerability_summary?.critical_risk ?? 0;
  const inventory = scanData?.asset_inventory || {};
  const trafficAnalysis = scanData?.traffic_analysis || {};
  const ticketExport = scanData?.ticket_export || {};
  const inventorySubdomains = toArray(inventory.subdomains);
  const inventoryServices = toArray(inventory.services);
  const domainIntelligence = inventory.domain_intelligence || {};
  const networkMap = inventory.network_map || {};
  const protocolUsage = toArray(trafficAnalysis.protocol_usage);
  const suspiciousTraffic = toArray(trafficAnalysis.suspicious_traffic);
  const malwarePatterns = toArray(trafficAnalysis.malware_patterns);
  const exportedTickets = toArray(ticketExport.tickets);
  const scanProfile = scanData?.scan_profile || {};

  if (scanData?.error) {
    return (
      <main className="w-full px-6 py-8 text-slate-300">
        <div className="bg-[#0f1523]/90 border border-red-500/40 rounded-xl p-6 mb-6">
          <h2 className="text-xl font-bold text-red-300 mb-2">Scan error</h2>
          <p className="text-sm text-slate-400">{scanData.error}</p>
          <p className="text-xs text-slate-500 mt-2">Please verify target and try again.</p>
        </div>
      </main>
    );
  }

  if (!isLive) {
    return (
      <main className="w-full px-6 py-8 text-slate-300">
        <div className="bg-[#0f1523]/90 border border-amber-500/40 rounded-xl p-6 mb-6">
          <h2 className="text-xl font-bold text-amber-300 mb-2">Backend scan data not yet available.</h2>
          <p className="text-sm text-slate-400">Please confirm the API backend is running and the scan has completed. If you just triggered a scan, return to the scan page and wait for completion.</p>
        </div>
      </main>
    );
  }

  return (
    <main className="relative z-10 w-full px-6 py-8 honeycomb-bg">
      {/* Query bar */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3.5">
          <span className="text-[var(--accent)] font-mono text-sm flex items-center gap-2">
            <TerminalSvg size={14} color="var(--accent)" /> SCAN QUERY:
          </span>
          <span className="px-3.5 py-1.5 rounded-lg border border-[rgba(107,31,58,0.2)] bg-[rgba(107,31,58,0.05)] text-[var(--accent)] font-mono text-sm font-semibold tracking-wide">
            Scanned Targets ({scanState})
          </span>
        </div>
        {/* <button className="flex items-center gap-2 px-4 py-2 rounded-lg border border-violet-600/45 bg-transparent text-violet-400 text-sm font-medium cursor-pointer hover:bg-violet-600/10 transition-all">
          <FilterSvg /> Advanced Filters
        </button> */}
      </div>

      <h1 className="text-3xl font-bold text-[var(--accent)] font-mono tracking-wide mb-6">{hostsUp} host{hostsUp === 1 ? "" : "s"} discovered</h1>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-3.5 mb-7">
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-500/10 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#00e5ff' : '#6b1f3a'} strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
            HOSTS UP
          </div>
          <div className={`${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'} text-4xl font-black font-mono`}>{hostsUp}</div>
        </div>
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-500/10 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#00e5ff' : '#6b1f3a'} strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            OPEN PORTS
          </div>
          <div className={`${theme === 'dark' ? 'text-cyan-400' : 'text-green-600'} text-4xl font-black font-mono`}>{openPorts}</div>
        </div>
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-amber-500/15 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#f59e0b' : '#f59e0b'} strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
            VULNERABILITIES
          </div>
          <div className={`${theme === 'dark' ? 'text-amber-400' : 'text-orange-600'} text-4xl font-black font-mono`}>{vulnerabilities}</div>
        </div>
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-red-500/15 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#ef4444' : '#ef4444'} strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
            CRITICAL RISK
          </div>
          <div className={`${theme === 'dark' ? 'text-red-400' : 'text-rose-600'} text-4xl font-black font-mono`}>{critical}</div>
        </div>
      </div>

      {/* Host Cards */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-7">
        <div className={`rounded-xl p-5 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-500/10 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
          <SectionTitle>ASSET INVENTORY</SectionTitle>
          <div className="grid grid-cols-2 gap-3 mb-4">
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>ASSETS</div>
              <div className={`mt-1 text-2xl font-black font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{inventory.asset_count ?? hosts.length}</div>
            </div>
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>SUBDOMAINS</div>
              <div className={`mt-1 text-2xl font-black font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{inventorySubdomains.length}</div>
            </div>
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>MAP NODES</div>
              <div className={`mt-1 text-lg font-bold font-mono ${theme === 'dark' ? 'text-slate-200' : 'text-gray-900'}`}>{toArray(networkMap.nodes).length}</div>
            </div>
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>MAP EDGES</div>
              <div className={`mt-1 text-lg font-bold font-mono ${theme === 'dark' ? 'text-slate-200' : 'text-gray-900'}`}>{toArray(networkMap.edges).length}</div>
            </div>
          </div>
          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>DISCOVERED SERVICES</div>
          <div className="flex flex-wrap gap-2 mb-4">
            {inventoryServices.length === 0 ? (
              <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No inventory services recorded.</span>
            ) : (
              inventoryServices.slice(0, 10).map((service) => (
                <span key={service} className={`px-2.5 py-1 rounded-full text-xs font-mono border ${theme === 'dark' ? 'border-cyan-500/20 bg-cyan-500/[0.05] text-cyan-300' : 'border-[rgba(107,31,58,0.2)] bg-[rgba(107,31,58,0.05)] text-[var(--accent)]'}`}>
                  {String(service).toUpperCase()}
                </span>
              ))
            )}
          </div>
          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>SUBDOMAIN ENUMERATION</div>
          <div className="space-y-2 max-h-44 overflow-auto pr-1">
            {inventorySubdomains.length === 0 ? (
                  <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No subdomains discovered. This usually means the target was an IP, DNS brute-force found nothing, or DNS resolution was blocked.</span>
            ) : (
              inventorySubdomains.slice(0, 8).map((item, index) => (
                <div key={`${item?.subdomain || "subdomain"}-${index}`} className="flex items-center justify-between gap-3">
                  <span className={`text-sm font-mono ${theme === 'dark' ? 'text-cyan-300' : 'text-[var(--accent)]'}`}>{item.subdomain}</span>
                  <span className={`text-xs ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>{item.resolved_ip || "unresolved"}</span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className={`rounded-xl p-5 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-violet-500/10 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
          <SectionTitle color="bg-violet-400" textColor="text-violet-400">TRAFFIC ANALYSIS</SectionTitle>
          <div className="grid grid-cols-2 gap-3 mb-4">
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>STATUS</div>
              <div className={`mt-1 text-sm font-semibold ${trafficAnalysis.enabled ? 'text-emerald-400' : theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>
                {trafficAnalysis.enabled ? "Enabled" : "Unavailable"}
              </div>
            </div>
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>DURATION</div>
              <div className={`mt-1 text-sm font-semibold font-mono ${theme === 'dark' ? 'text-slate-200' : 'text-gray-900'}`}>{trafficAnalysis.duration_seconds ?? 0}s</div>
            </div>
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>SUSPICIOUS</div>
              <div className={`mt-1 text-lg font-bold font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-600'}`}>{suspiciousTraffic.length}</div>
            </div>
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>MALWARE HITS</div>
              <div className={`mt-1 text-lg font-bold font-mono ${theme === 'dark' ? 'text-red-300' : 'text-red-600'}`}>{malwarePatterns.length}</div>
            </div>
          </div>
          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>PROTOCOL USAGE</div>
          <div className="space-y-2 mb-4">
            {protocolUsage.length === 0 ? (
              <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>{trafficAnalysis.note || "No traffic telemetry captured. Scapy sniffing may be unavailable or no matching packets were seen during capture."}</span>
            ) : (
              protocolUsage.map((item, index) => (
                <div key={`${item?.protocol || "protocol"}-${index}`} className="flex items-center justify-between gap-3">
                  <span className={`text-sm font-mono ${theme === 'dark' ? 'text-violet-300' : 'text-violet-700'}`}>{item.protocol}</span>
                  <span className={`text-xs font-mono ${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>{item.count}</span>
                </div>
              ))
            )}
          </div>
          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>SUSPICIOUS EVENTS</div>
          <div className="space-y-2 max-h-44 overflow-auto pr-1">
            {suspiciousTraffic.length === 0 ? (
              <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No suspicious traffic events recorded.</span>
            ) : (
              suspiciousTraffic.slice(0, 6).map((item, index) => (
                <div key={`${item?.src || "traffic"}-${index}`} className={`rounded-md px-3 py-2 border ${theme === 'dark' ? 'border-white/5 bg-white/[0.02]' : 'border-[rgba(26,26,46,0.12)] bg-[rgba(245,240,232,0.95)]'}`}>
                  <div className={`text-sm ${theme === 'dark' ? 'text-slate-200' : 'text-[var(--text)]'}`}>{truncateText(item.detail, 70)}</div>
                  <div className={`mt-1 text-xs font-mono ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>{item.src || "unknown"} {" -> "} {item.dst || "unknown"} {item.port ? `:${item.port}` : ""}</div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className={`rounded-xl p-5 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-amber-500/10 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
          <SectionTitle color="bg-amber-400" textColor="text-amber-400">EXPORT AND PROFILE</SectionTitle>
          <div className="grid grid-cols-2 gap-3 mb-4">
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>TICKETS</div>
              <div className={`mt-1 text-2xl font-black font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-600'}`}>{ticketExport.count ?? exportedTickets.length}</div>
            </div>
            <div>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>CREDENTIAL CHECK</div>
              <div className={`mt-1 text-sm font-semibold ${scanProfile.include_credential_scan ? 'text-emerald-400' : theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>
                {scanProfile.include_credential_scan ? "Enabled" : "Disabled"}
              </div>
            </div>
          </div>
          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>TICKET PREVIEW</div>
          <div className="space-y-2 mb-4 max-h-44 overflow-auto pr-1">
            {exportedTickets.length === 0 ? (
              <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No ticket export payload was generated.</span>
            ) : (
              exportedTickets.slice(0, 6).map((ticket, index) => (
                <div key={`${ticket?.title || "ticket"}-${index}`} className={`rounded-md px-3 py-2 border ${theme === 'dark' ? 'border-white/5 bg-white/[0.02]' : 'border-[rgba(26,26,46,0.12)] bg-[rgba(245,240,232,0.95)]'}`}>
                  <div className={`text-sm font-semibold ${theme === 'dark' ? 'text-slate-100' : 'text-[var(--text)]'}`}>{ticket.title || "Untitled finding"}</div>
                  <div className={`mt-1 text-xs font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>{ticket.asset || "asset"} | {ticket.severity || "UNKNOWN"} | Score {ticket.priority_score ?? 0}</div>
                </div>
              ))
            )}
          </div>
          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>SCAN PROFILE</div>
          <div className="flex flex-wrap gap-2">
            {Object.entries(scanProfile).map(([key, value]) => (
              <span key={key} className={`px-2.5 py-1 rounded-full text-xs border ${theme === 'dark' ? 'border-slate-700 bg-slate-900/70 text-slate-300' : 'border-[rgba(26,26,46,0.12)] bg-[rgba(245,240,232,0.95)] text-[var(--text)]'}`}>
                {formatLabel(key)}: {typeof value === "boolean" ? (value ? "On" : "Off") : String(value)}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className={`rounded-xl px-5 py-4 border mb-7 ${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-500/10 text-slate-200' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)] text-[var(--text)]'}`}>
        <SectionTitle>ADDITIONAL SCAN MODULES</SectionTitle>
        <div className="flex flex-wrap gap-3">
          {[
            { label: "Subdomains", value: inventorySubdomains.length > 0 ? `${inventorySubdomains.length} discovered` : "No results" },
            { label: "Traffic", value: trafficAnalysis.enabled ? `${protocolUsage.length} protocol groups` : "Unavailable" },
            { label: "Tickets", value: (ticketExport.count ?? exportedTickets.length) > 0 ? `${ticketExport.count ?? exportedTickets.length} generated` : "No tickets" },
            { label: "Credential checks", value: scanProfile.include_credential_scan ? "Enabled" : "Disabled" },
          ].map((item) => (
            <div key={item.label} className={`rounded-lg px-4 py-3 border min-w-[170px] ${theme === 'dark' ? 'bg-white/[0.02] border-white/5' : 'bg-[rgba(245,240,232,0.95)] border-[rgba(26,26,46,0.12)]'}`}>
              <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>{item.label.toUpperCase()}</div>
              <div className={`mt-1 text-sm font-semibold ${theme === 'dark' ? 'text-cyan-300' : 'text-[var(--accent)]'}`}>{item.value}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-4">
        {hosts.map((host, idx) => {
          const hostIp = host.resolved_ip || host.ip;
          const relatedSubdomains = inventorySubdomains.filter((item) => item?.resolved_ip && item.resolved_ip === hostIp);
          return (
          <HostCard
            key={host.ip || host.hostname || idx}
            theme={theme}
            host={{
              id: idx + 1,
              hostname: host.hostname || host.ip || "Unknown",
              ip: host.resolved_ip || host.ip || "",
              domain: host.domain || "",
              country: host.country || "NA",
              provider: host.vendor || "Unknown",
              vendor: host.vendor || "Unknown",
              deviceType: host.device_type || "Unknown Device",
              status: "UP",
              hostState: "Host is up",
              openPorts: Array.isArray(host.open_ports) ? host.open_ports.length : 0,
              services: Array.isArray(host.open_ports) ? host.open_ports.length : 0,
              osDetection: host.os_name || host.os || "Unknown",
              vulnerabilities: Array.isArray(host.vulnerabilities) ? host.vulnerabilities.length : 0,
              vulnerabilityItems: Array.isArray(host.vulnerabilities) ? host.vulnerabilities : [],
              ports: Array.isArray(host.open_ports)
                ? host.open_ports.map(p => ({ ...p, protocol: p.protocol || "tcp" }))
                : (Array.isArray(host.ports) ? host.ports : []),
              insecureProtocols: host.insecure_protocols || host.insecureProtocols || [],
              tlsIssues: host.tls_issues || host.tlsIssues || [],
              credentialScan: host.credential_scan || host.credentialScan || null,
              riskSummary: host.risk_summary || host.riskSummary || null,
              relatedSubdomains,
              domainIntelligence,
              defaultOpen: idx === 0,
            }}
          />
          );
        })}
      </div>
    </main>
  );
}

// ── App Root ──────────────────────────────────────────────────────────────────
export default function VaptScanner({
  onScanComplete,
  theme,
  previewMode = false,
  onRequireLogin,
  requestedScanTarget = null,
  scanRequestNonce = 0,
  onRequestedScanConsumed,
}) {
  const [scanTarget, setScanTarget] = useState(() => {
    if (previewMode) return null;
    try {
      return localStorage.getItem(ACTIVE_SCAN_STORAGE_KEY);
    } catch {
      return null;
    }
  });
  const [page, setPage] = useState(() => (scanTarget ? "scan" : "home"));
  const [scanResult, setScanResult] = useState(() => {
    try {
      const stored = localStorage.getItem(LAST_SCAN_STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    if (page === "scan" && !scanTarget) {
      setPage("home");
    }
  }, [page, scanTarget]);

  useEffect(() => {
    if (previewMode) return;

    const target = String(requestedScanTarget || "").trim();
    if (!target) return;

    setScanResult(null);
    setScanTarget(target);
    try {
      localStorage.setItem(ACTIVE_SCAN_STORAGE_KEY, target);
      localStorage.removeItem(ACTIVE_SCAN_META_STORAGE_KEY);
    } catch {}
    setPage("scan");
    onRequestedScanConsumed?.();
  }, [requestedScanTarget, scanRequestNonce, previewMode, onRequestedScanConsumed]);

  const handleScan = (t) => {
    if (previewMode) return;
    setScanTarget(t);
    try {
      localStorage.setItem(ACTIVE_SCAN_STORAGE_KEY, t);
    } catch {}
    setPage("scan");
  };
  const handleScanComplete = (result) => {
    setScanResult(result);
    setScanTarget(null);
    try {
      localStorage.setItem(LAST_SCAN_STORAGE_KEY, JSON.stringify(result));
      localStorage.removeItem(ACTIVE_SCAN_STORAGE_KEY);
      localStorage.removeItem(ACTIVE_SCAN_META_STORAGE_KEY);
    } catch {}
    setPage("vulns");
    if (onScanComplete) onScanComplete(result);
  };
  const handleScanCancel = () => {
    setScanTarget(null);
    try {
      localStorage.removeItem(ACTIVE_SCAN_STORAGE_KEY);
      localStorage.removeItem(ACTIVE_SCAN_META_STORAGE_KEY);
    } catch {}
    setPage("home");
  };

  const visiblePage = previewMode ? "home" : page;
  const visibleScanTarget = previewMode ? null : scanTarget;

  return (
    <div className={`relative z-0 w-full ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'bg-[var(--bg)] text-[var(--text)]'}`} style={{ fontFamily: "'Segoe UI',system-ui,sans-serif" }}>
      <style>{`html,body,#root{background:${theme === 'dark' ? '#0a0d14' : 'var(--bg)'};min-height:100vh;}`}</style>
      <BlobBg />
      {visiblePage === "home"  && <HomePage onScan={handleScan} theme={theme} previewMode={previewMode} onRequireLogin={onRequireLogin} />}
      {visibleScanTarget && (
        <div className={visiblePage === "scan" ? "relative z-10" : "hidden"}>
          <ScanPage target={visibleScanTarget} onScanComplete={handleScanComplete} onCancel={handleScanCancel} theme={theme} />
        </div>
      )}
      {visiblePage === "vulns" && <VulnsPage scanData={scanResult} theme={theme} />}
    </div>
  );
}

