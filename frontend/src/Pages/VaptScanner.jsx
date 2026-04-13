import { useState, useEffect, useRef } from "react";

const DEFAULT_API_HOST = `${window.location.protocol}//${window.location.hostname}:8000`;
const API_BASE = (import.meta.env.VITE_API_URL || DEFAULT_API_HOST).replace(/\/+$/, "");
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
const BigLogoSvg = ({ theme }) => {
  const globeStroke = theme === "dark" ? "#2563eb" : "#3b82f6";

  return (
  <svg width="76" height="76" viewBox="0 0 80 80" fill="none">
    <circle cx="40" cy="40" r="34" stroke="#7c3aed" strokeWidth="2.5" />
    <circle cx="40" cy="40" r="26" stroke={globeStroke} strokeWidth="2" />
    <ellipse cx="40" cy="40" rx="12" ry="34" stroke={globeStroke} strokeWidth="2" />
    <line x1="6" y1="40" x2="74" y2="40" stroke={globeStroke} strokeWidth="2" />
    <line x1="12" y1="24" x2="68" y2="24" stroke={globeStroke} strokeWidth="1.5" strokeDasharray="3 2" />
    <line x1="12" y1="56" x2="68" y2="56" stroke={globeStroke} strokeWidth="1.5" strokeDasharray="3 2" />
  </svg>
  );
};
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

  // Validation function for target input
  const isValidTarget = (target) => {
    if (!target || target.trim().length === 0) return false;

    const parts = target.split(",").map(p => p.trim());

    for (const part of parts) {
      // Check for IP address pattern (e.g., 192.168.1.1)
      const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipPattern.test(part)) {
        const octets = part.split(".").map(Number);
        if (octets.every(o => o >= 0 && o <= 255)) continue;
      }

      // Check for CIDR notation (e.g., 10.0.0.0/24)
      const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
      if (cidrPattern.test(part)) {
        const [ip, mask] = part.split("/");
        const octets = ip.split(".").map(Number);
        const maskNum = Number(mask);
        if (octets.every(o => o >= 0 && o <= 255) && maskNum >= 0 && maskNum <= 32) continue;
      }

      // Check for IP range (e.g., 192.168.1.1-192.168.1.10)
      const rangePattern = /^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$/;
      if (rangePattern.test(part)) {
        const [start, end] = part.split("-");
        const startOctets = start.split(".").map(Number);
        const endOctets = end.split(".").map(Number);
        if (
          startOctets.every(o => o >= 0 && o <= 255) &&
          endOctets.every(o => o >= 0 && o <= 255)
        ) continue;
      }

      // Check for domain pattern (e.g., example.com, subdomain.example.com)
      const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
      if (domainPattern.test(part)) continue;

      // Allow single-label hostnames (local network hosts like 'm')
      const localHostPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
      if (localHostPattern.test(part)) continue;

      // If none match, it's invalid
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
    <>
      <main className="h-[calc(100vh-88px)] h-[calc(100dvh-88px)] flex items-start justify-center px-6 pt-7 sm:pt-8 overflow-hidden">
      <div className="flex flex-col items-center w-full max-w-6xl">
        <div
          className="mb-4 flex items-center justify-center rounded-full border border-violet-500/25 bg-violet-500/5 p-3"
          style={{
            boxShadow: theme === 'dark'
              ? "0 0 0 1px rgba(124,58,237,0.16), 0 0 32px rgba(124,58,237,0.12)"
              : "0 0 0 1px rgba(124,58,237,0.12), 0 0 32px rgba(59,130,246,0.10)"
          }}
        >
          <div
            style={{
              filter: theme === 'dark'
                ? "drop-shadow(0 0 16px rgba(124,58,237,0.18))"
                : "drop-shadow(0 0 16px rgba(59,130,246,0.20))",
              transform: "scale(0.96)"
            }}
          >
            <BigLogoSvg theme={theme} />
          </div>
        </div>

        <h1
          className={`text-4xl sm:text-5xl lg:text-6xl font-semibold tracking-tight text-center m-0 bg-gradient-to-r ${theme === 'dark' ? 'from-cyan-300 via-cyan-400 to-sky-400' : 'from-indigo-400 via-blue-400 to-blue-300'} bg-clip-text text-transparent`}
          style={{ margin: 0, lineHeight: 1.05 }}
        >
          VAPT SCANNER PRO
        </h1>
        <p
          className="text-sm sm:text-lg text-slate-400 text-center max-w-3xl"
          style={{ marginTop: 10, marginBottom: 22 }}
        >
          Vulnerability Assessment &amp; Penetration Testing Platform
        </p>

        <div className="flex flex-col items-center gap-3 w-full">
          <div className="relative w-full max-w-[980px]">
            <input
              className={`w-full py-5 pl-7 pr-16 rounded-2xl border ${theme === 'dark' ? 'bg-[#0b1020]/92 text-slate-100 placeholder-slate-500 caret-cyan-400 shadow-[0_0_0_1px_rgba(34,211,238,0.12)]' : 'bg-white text-gray-900 placeholder-gray-500 caret-blue-400 shadow-[0_0_0_1px_rgba(59,130,246,0.12)]'} text-xl outline-none transition-colors ${
                error ? "border-red-500/60 focus:border-red-500" : theme === 'dark' ? "border-cyan-400/60 focus:border-cyan-400" : "border-blue-400/60 focus:border-blue-400"
              }`}
              type="text" placeholder="192.168.1.1 or 10.0.0.0/24 or example.com"
              value={query} onChange={(e) => { setQuery(e.target.value); setError(""); }}
              onKeyDown={(e) => e.key === "Enter" && go()}
            />
            <span className={`absolute right-6 top-1/2 -translate-y-1/2 flex scale-110 ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-500'}`}><ScanSvg /></span>
          </div>

          {error && (
            <div className="w-full px-4 py-3 rounded-lg bg-red-500/10 border border-red-500/40 text-red-400 text-sm">
              {error}
            </div>
          )}

          {previewMode && (
            <div className={`w-full rounded-2xl border px-5 py-4 text-sm ${theme === 'dark' ? 'border-violet-400/30 bg-violet-400/8 text-violet-200' : 'border-sky-200 bg-sky-50 text-sky-700'}`}>
              Preview mode is active. You can explore the scanner UI here, but real scans only run after login or signup.
              {onRequireLogin && (
                <button
                  onClick={onRequireLogin}
                  className={`ml-3 rounded-xl px-4 py-2 text-sm font-semibold transition ${theme === 'dark' ? 'bg-violet-500/20 text-violet-200 hover:bg-violet-500/30' : 'bg-white text-sky-700 hover:bg-sky-100'}`}
                >
                  Login to enable scanning
                </button>
              )}
            </div>
          )}

          <div className="flex gap-4 flex-wrap justify-center">
            <button onClick={go}
              className="min-w-40 px-8 py-3 rounded-2xl text-[#0a0d14] text-lg font-semibold cursor-pointer hover:opacity-90 transition-opacity border-none"
              style={{ background: theme === 'dark' ? "linear-gradient(135deg,#67e8f9,#06b6d4)" : "linear-gradient(135deg,#60a5fa,#2563eb)" }}>
              {previewMode ? "Preview Only" : "Scan"}
            </button>
            {/* <button className="flex items-center gap-1.5 px-5 py-3 rounded-xl border border-violet-600/45 bg-transparent text-violet-400 text-sm font-medium cursor-pointer hover:bg-violet-600/10 transition-all">
              <FilterSvg /> Advanced Filters
            </button> */}
            <button onClick={() => setShowExamples(v => !v)}
              className="flex items-center gap-2 px-6 py-3 rounded-2xl border border-violet-500/45 bg-violet-500/[0.03] text-base font-medium cursor-pointer hover:bg-violet-500/10 transition-all">
              <BulbSvg /> Examples
            </button>
          </div>

          {showExamples && (
            <div className={`w-full max-w-[980px] ${theme === 'dark' ? 'bg-[#0f141e]/85 border-cyan-500/10' : 'bg-white/85 border-gray-300'} rounded-2xl p-5`}>
              <div className="mt-2 grid w-full grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
                {EXAMPLES.map(ex => (
                  <button key={ex} onClick={() => { setQuery(ex); setShowExamples(false); }}
                    className={`w-full px-4 py-1.5 rounded-lg bg-transparent text-center text-xs font-medium cursor-pointer transition-all ${theme === 'dark' ? 'border border-cyan-400/35 text-cyan-400 hover:bg-cyan-400/10' : 'border border-blue-400/35 text-blue-600 hover:bg-blue-400/10'}`}>
                    {ex}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
      </main>
    </>
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

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [logs]);
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
    <main className="w-full min-h-[calc(100vh-88px)] px-6 pt-0 pb-6 -mt-2">
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
      `}</style>
      <div className="mx-auto max-w-7xl">
      <div className="text-center mb-4">
        <h1 className="text-[32px] font-bold mb-1 bg-clip-text text-transparent"
          style={{ backgroundImage: theme === 'dark' ? "linear-gradient(90deg,#67e8f9,#06b6d4)" : "linear-gradient(90deg,#60a5fa,#6366f1)" }}>
          {isCancelled ? "Scan Cancelled" : scanDone && displayProgress >= 99.5 ? "Scan Complete" : "Scanning in Progress"}
        </h1>
        <p className={`text-[17px] ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} m-0`}>
          Target: <span className={`${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'} font-semibold`}>{target}</span>
        </p>
      </div>

      {/* Stage Card */}
      <div className={`mx-auto max-w-[1060px] ${theme === 'dark' ? 'bg-[#0b1020]/98 border-cyan-500/18' : 'bg-white/95 border-gray-300'} rounded-[16px] border px-6 py-4 mb-5`}>
        <div className="flex items-start justify-between mb-4">
          <div className={`flex items-start gap-3 ${animateStageChange ? "stage-change-once" : ""}`}>
            <span className={`flex pt-0.5 ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}><StageIcon type={STAGES[currentStage].icon} size={42} /></span>
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
                          : "border-blue-200 bg-transparent text-blue-600 hover:bg-blue-50/40"
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
                          : "border-blue-200 bg-transparent text-blue-600 hover:bg-blue-50/40"
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
          <div className={`text-[42px] font-black font-mono leading-none ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>{Math.round(displayProgress)}%</div>
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
                  : active ? (theme === 'dark' ? "border-cyan-400/65 bg-cyan-400/[0.05]" : "border-blue-400/65 bg-blue-400/[0.05]")
                  : theme === 'dark' ? "border-slate-800 bg-[#0a0f1b]" : "border-gray-200 bg-gray-50"}`}>
                <span className={`flex ${done ? "text-emerald-400" : active ? (theme === 'dark' ? "text-cyan-400" : "text-blue-600") : theme === 'dark' ? "text-slate-500" : "text-gray-500"}`}>
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
          <span className={`flex items-center gap-2 ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>
            <TerminalSvg size={16} color={theme === 'dark' ? "#22d3ee" : "#3b82f6"} />
            <span className="font-mono text-[15px]">scan.log</span>
          </span>
        </div>
        <div ref={logRef} className="px-8 py-6 max-h-72 overflow-y-auto leading-loose">
          {logs.map((log, i) => (
            <div key={i} className="flex gap-3 mb-0.5">
              <span className={`${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'} font-mono text-xs flex-shrink-0`}>{log.time}</span>
              <span className={`text-slate-400 font-mono text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{log.msg}</span>
            </div>
          ))}
          {progress < 100 && !isCancelled && <span className={`${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'} font-mono animate-pulse`}>▋</span>}
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
  const [open, setOpen] = useState(false);
  const hostStateLabel = host.hostState || "Host is up";
  const riskLabel = getRiskLabel(host.vulnerabilityItems ?? host.vulnerabilities);
  const countryBadge = getCountryBadge(host);
  return (
    <div className={`rounded-xl p-6 border transition-colors duration-200 ${open
      ? theme === 'dark'
        ? 'bg-[#0d1220]/95 border-sky-400/70 text-slate-200'
        : 'bg-white border-sky-400 text-gray-900'
      : theme === 'dark'
        ? 'bg-[#0d1220]/95 border-cyan-500/10 text-slate-200 hover:border-sky-400/70'
        : 'bg-white border-gray-200 text-gray-900 hover:border-sky-400'
    }`}>
      {/* Header */}
      <div className="flex items-start justify-between mb-5">
        <div className="flex items-start gap-3.5">
          <div className={`w-9 h-9 rounded-lg ${theme === 'dark' ? 'bg-cyan-400/8 border-cyan-400/20 text-slate-400' : 'bg-blue-50 border-blue-100 text-blue-600'} flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5`}>
            {countryBadge}
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap mb-1">
              <span className={`text-lg font-bold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>{host.hostname}</span>
              <StatusBadge label={riskLabel} />
              <StatusBadge label={hostStateLabel.toUpperCase()} />
            </div>
            <div className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{host.vendor || host.provider || "Unknown vendor"}</div>
            <div className={`text-xs ${theme === 'dark' ? 'text-slate-600' : 'text-gray-500'} font-mono mt-0.5`}>Hostname: {host.hostname}</div>
          </div>
        </div>
        <button onClick={() => setOpen(v => !v)}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-semibold cursor-pointer transition-all flex-shrink-0 ${
            theme === 'dark'
              ? 'border-cyan-400/35 bg-transparent text-cyan-400 hover:bg-cyan-400/10'
              : 'border-blue-400/35 bg-transparent text-blue-600 hover:bg-blue-400/10'
          }`}>
          {open ? "Collapse" : "Expand"} <ChevronSvg open={open} />
        </button>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "OPEN PORTS",      val: `${host.openPorts} detected`,   cls: theme === 'dark' ? "text-cyan-400" : "text-blue-600" },
          { label: "SERVICES",         val: `${host.services} identified`,  cls: theme === 'dark' ? "text-cyan-400" : "text-blue-600" },
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
          <div className={`h-px mb-6 ${theme === 'dark' ? 'bg-cyan-500/8' : 'bg-blue-200'}`} />

          {/* Port Scan Table */}
          <div className="mb-6">
            <SectionTitle>PORT SCAN RESULTS</SectionTitle>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr>
                    {["PORT","PROTOCOL","SERVICE","PRODUCT","VERSION"].map(h => (
                      <th key={h} className={`text-left py-2.5 px-4 text-[11px] font-bold tracking-wider ${theme === 'dark' ? 'text-slate-400 border-b border-white/5 bg-white/[0.02]' : 'text-gray-500 border-b border-gray-200 bg-gray-50'}`}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {host.ports.map((p, i) => (
                    <tr key={i} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                      <td className={`py-3 px-4 font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>{p.port}</td>
                      <td className="py-3 px-4 text-slate-400">{getDisplayProtocol(p)}</td>
                      <td className="py-3 px-4 text-slate-400">{p.service}</td>
                      <td className="py-3 px-4 text-slate-300 font-mono">{p.product}</td>
                      <td className="py-3 px-4 text-slate-400">{p.version}</td>
                      
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Insecure Protocols */}
          <div className="mb-6">
            <SectionTitle color="bg-amber-400" textColor="text-amber-400">INSECURE PROTOCOL DETECTION</SectionTitle>
            <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#111827]/60 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
              {host.insecureProtocols.length === 0
                ? <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No insecure protocols detected.</span>
                : host.insecureProtocols.map((item, i) => (
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
            <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#111827]/60 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
              {host.tlsIssues.length === 0
                ? <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No TLS issues detected.</span>
                : host.tlsIssues.map((item, i) => (
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
    <main className="w-full px-6 py-8">
      {/* Query bar */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3.5">
          <span className="text-cyan-400 font-mono text-sm flex items-center gap-2">
            <TerminalSvg size={14} color="#00e5ff" /> SCAN QUERY:
          </span>
          <span className="px-3.5 py-1.5 rounded-lg border border-cyan-400/35 text-cyan-400 font-mono text-sm font-semibold tracking-wide">
            Scanned Targets ({scanState})
          </span>
        </div>
        {/* <button className="flex items-center gap-2 px-4 py-2 rounded-lg border border-violet-600/45 bg-transparent text-violet-400 text-sm font-medium cursor-pointer hover:bg-violet-600/10 transition-all">
          <FilterSvg /> Advanced Filters
        </button> */}
      </div>

      <h1 className="text-3xl font-bold text-cyan-400 font-mono tracking-wide mb-6">{hostsUp} host{hostsUp === 1 ? "" : "s"} discovered</h1>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-3.5 mb-7">
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-500/10 text-slate-200' : 'bg-white border-gray-200 text-gray-900'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#00e5ff' : '#0ea5e9'} strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
            HOSTS UP
          </div>
          <div className={`${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'} text-4xl font-black font-mono`}>{hostsUp}</div>
        </div>
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-500/10 text-slate-200' : 'bg-white border-gray-200 text-gray-900'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#00e5ff' : '#0ea5e9'} strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            OPEN PORTS
          </div>
          <div className={`${theme === 'dark' ? 'text-cyan-400' : 'text-green-600'} text-4xl font-black font-mono`}>{openPorts}</div>
        </div>
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-amber-500/15 text-slate-200' : 'bg-white border-gray-200 text-gray-900'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#f59e0b' : '#f59e0b'} strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
            VULNERABILITIES
          </div>
          <div className={`${theme === 'dark' ? 'text-amber-400' : 'text-orange-600'} text-4xl font-black font-mono`}>{vulnerabilities}</div>
        </div>
        <div className={`rounded-xl px-5 py-4 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-red-500/15 text-slate-200' : 'bg-white border-gray-200 text-gray-900'}`}>
          <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest mb-3 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#ef4444' : '#ef4444'} strokeWidth="2"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
            CRITICAL RISK
          </div>
          <div className={`${theme === 'dark' ? 'text-red-400' : 'text-rose-600'} text-4xl font-black font-mono`}>{critical}</div>
        </div>
      </div>

      {/* Host Cards */}
      <div className="flex flex-col gap-4">
        {hosts.map((host, idx) => (
          <HostCard
            key={host.ip || host.hostname || idx}
            theme={theme}
            host={{
              id: idx + 1,
              hostname: host.hostname || host.ip || "Unknown",
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
              ports: Array.isArray(host.open_ports),
              ports: Array.isArray(host.open_ports)
                ? host.open_ports.map(p => ({ ...p, protocol: p.protocol || "tcp" }))
                : (Array.isArray(host.ports) ? host.ports : []),
              insecureProtocols: host.insecure_protocols || host.insecureProtocols || [],
              tlsIssues: host.tls_issues || host.tlsIssues || [],
            }}
          />
        ))}
      </div>
    </main>
  );
}

// ── App Root ──────────────────────────────────────────────────────────────────
export default function VaptScanner({ onScanComplete, theme, previewMode = false, onRequireLogin }) {
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
    <div className={`w-full ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'bg-gray-50 text-gray-900'}`} style={{ fontFamily: "'Segoe UI',system-ui,sans-serif" }}>
      <style>{`html,body,#root{background:${theme === 'dark' ? '#0a0d14' : '#f9fafb'};min-height:100vh;}`}</style>
      {visiblePage === "home"  && <HomePage onScan={handleScan} theme={theme} previewMode={previewMode} onRequireLogin={onRequireLogin} />}
      {visibleScanTarget && (
        <div className={visiblePage === "scan" ? "" : "hidden"}>
          <ScanPage target={visibleScanTarget} onScanComplete={handleScanComplete} onCancel={handleScanCancel} theme={theme} />
        </div>
      )}
      {visiblePage === "vulns" && <VulnsPage scanData={scanResult} theme={theme} />}
    </div>
  );
}
