import { useState, useEffect } from "react";

const DEFAULT_API_HOST = `${window.location.protocol}//${window.location.hostname}:8000`;
const API_BASE = (import.meta.env.VITE_API_URL || DEFAULT_API_HOST).replace(/\/+$/, "");
const LAST_SCAN_STORAGE_KEY = "vapt_last_scan_result";

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
const FilterIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
  </svg>
);
const PulseIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00e5ff" strokeWidth="2">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
);
const TriangleIcon = ({ color = "#f59e0b", size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
    <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
  </svg>
);
const AlertIcon = ({ color = "#ef4444", size = 14 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
  </svg>
);
const ChevronIcon = ({ open }) => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
    style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.25s" }}>
    <polyline points="6 9 12 15 18 9" />
  </svg>
);
const TerminalIcon = ({ size = 14, color = "#00e5ff" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2">
    <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
  </svg>
);

// ── Mock Data ─────────────────────────────────────────────────────────────────
const MOCK_HOSTS = [];

const SUMMARY = { hostsUp: 0, openPorts: 0, vulnerabilities: 0, criticalRisk: 0 };

// ── Status Badge ──────────────────────────────────────────────────────────────
function Badge({ label, type, theme = "dark" }) {
  const map = theme === "dark"
    ? {
        green: "bg-emerald-500/8 border border-emerald-500/45 text-emerald-300",
        cyan: "bg-cyan-400/8 border border-cyan-400/40 text-cyan-300",
        orange: "bg-amber-500/8 border border-amber-500/45 text-amber-300",
        red: "bg-red-500/8 border border-red-500/45 text-red-300",
      }
    : {
        green: "bg-white border border-emerald-200 text-emerald-600",
        cyan: "bg-white border border-blue-200 text-blue-600",
        orange: "bg-white border border-amber-200 text-amber-600",
        red: "bg-white border border-rose-200 text-rose-600",
      };
  return (
    <span className={`px-3 py-1 rounded-lg text-[11px] font-bold tracking-[0.18em] uppercase ${map[type] || map.cyan}`}>
      {label}
    </span>
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

function getRiskLabel(vulnerabilities, relatedCount = 0) {
  const items = toArray(vulnerabilities);
  const severities = items.map((v) => String(v?.severity || "").toUpperCase());

  if (severities.includes("CRITICAL") || severities.includes("HIGH")) return "HIGH";
  if (severities.includes("MEDIUM")) return "MEDIUM";
  if (items.length > 0 || relatedCount > 0 || typeof vulnerabilities === "number" && vulnerabilities > 0) return "LOW";
  return "SAFE";
}

function getCountryBadge(host) {
  const value = String(host.country || "").trim().toUpperCase();
  if (value.length === 2) return value;
  if (value.length > 2) return value.slice(0, 2);
  return "NA";
}

function toArray(value, fallback = []) {
  return Array.isArray(value) ? value : fallback;
}

function normalizeTarget(value) {
  return String(value || "").trim().toLowerCase();
}

function isIp(value) {
  return /^\d+\.\d+\.\d+\.\d+$/.test(value);
}

function isCidr(value) {
  return /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(value);
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function cidrContains(cidr, ip) {
  const [base, maskStr] = cidr.split('/');
  if (!isIp(base) || !isIp(ip)) return false;
  const mask = Number(maskStr);
  if (Number.isNaN(mask) || mask < 0 || mask > 32) return false;
  const baseInt = ipToInt(base);
  const ipInt = ipToInt(ip);
  const netmask = mask === 0 ? 0 : 0xFFFFFFFF << (32 - mask) >>> 0;
  return (baseInt & netmask) === (ipInt & netmask);
}

function hostMatchesTarget(host, target) {
  const t = normalizeTarget(target);
  if (!t) return false;

  const hostIp = normalizeTarget(host?.ip || host?.ipAddress || host?.resolved_ip || host?.dns || "");
  const hostName = normalizeTarget(host?.hostname || host?.domain || host?.displayHostname || "");

  if (!hostIp && !hostName) return false;

  if (t === hostIp || t === hostName) return true;

  if (isCidr(t) && isIp(hostIp) && cidrContains(t, hostIp)) return true;

  if (isIp(t) && isCidr(hostName)) {
    // Sometimes hostName contains CIDR-like content, left fallback
    return false;
  }

  // If target is CIDR but hostName is not ip, still match on pattern
  if (isCidr(t) && hostName.includes(t.split('/')[0])) return true;

  if (hostName.includes(t)) return true;

  if (isIp(t) && isIp(hostIp)) {
    // Exact ip already handled, also treat same /24 and /16 as match if relevant
    const city = hostIp.split('.');
    const q = t.split('.');
    if (city[0] === q[0] && city[1] === q[1] && city[2] === q[2]) return true; // same /24
    if (city[0] === q[0] && city[1] === q[1]) return true; // same /16
  }

  if (hostIp.startsWith(t)) return true;

  return false;
}

function formatCvssScore(score) {
  const numeric = Number(score);
  return Number.isFinite(numeric) ? numeric.toFixed(1) : "N/A";
}

function getRemediationText(vulnerability) {
  if (vulnerability?.remediation) return vulnerability.remediation;

  const product = vulnerability?.product || toArray(vulnerability?.affected_products)[0]?.product || vulnerability?.service || "the affected service";
  const version = vulnerability?.version || toArray(vulnerability?.affected_products)[0]?.version || "";

  if (version) {
    return `Upgrade ${product} from version ${version} to a vendor-supported fixed release, restrict unnecessary exposure, and verify the fix with a rescan.`;
  }

  return `Validate the exact version of ${product}, apply the latest vendor patch, restrict access to trusted networks, and verify the fix with a rescan.`;
}

function normalizeCveResponse(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.data)) return data.data;
  return [];
}

function normalizeScanVulnerability(vulnerability, host) {
  const cveId = vulnerability?.cve || vulnerability?.cve_id || null;
  return {
    cve_id: cveId || `${host?.hostname || host?.ip || "HOST"}-${vulnerability?.port || "PORT"}`,
    description: vulnerability?.description || "Detected during scanner-side vulnerability assessment.",
    severity: vulnerability?.severity || "UNKNOWN",
    cvss_score: vulnerability?.cvss_score ?? null,
    affected_products: [
      {
        product: vulnerability?.product || vulnerability?.service || host?.device_type || "Detected service",
        version: vulnerability?.version || "",
      },
    ],
    remediation: vulnerability?.remediation || "",
    _source: "scan_result",
  };
}

function collectScanCves(hosts) {
  const seen = new Set();
  return toArray(hosts).flatMap((host) =>
    toArray(host?.vulnerabilities).map((vulnerability) => {
      const normalized = normalizeScanVulnerability(vulnerability, host);
      const key = `${normalized.cve_id}-${normalized.affected_products?.[0]?.product || ""}`;
      if (seen.has(key)) return null;
      seen.add(key);
      return normalized;
    })
  ).filter(Boolean);
}

function normalizeOwaspResults(owasp) {
  const results = Array.isArray(owasp?.results) ? owasp.results : [];
  const summary = owasp?.summary || {};
  return {
    enabled: Boolean(owasp?.enabled),
    normalizedUrl: owasp?.normalized_url || owasp?.target || null,
    totalCategories: summary.total_categories ?? results.length,
    categoriesWithFindings: summary.categories_with_findings ?? results.filter((item) => (item?.findings_count ?? 0) > 0).length,
    totalFindings: summary.total_findings ?? results.reduce((sum, item) => sum + (item?.findings_count ?? 0), 0),
    requestsMade: summary.requests_made ?? 0,
    parametersTested: summary.parameters_tested ?? 0,
    authFindings: summary.auth_findings ?? 0,
    businessLogicFindings: summary.business_logic_findings ?? 0,
    advancedAnalysis: owasp?.advanced_analysis || {},
    results,
  };
}

function getValidationBadge(validationStatus) {
  const value = String(validationStatus || "").toLowerCase();
  if (value === "confirmed") return { label: "Confirmed", type: "red" };
  if (value === "needs_manual_review") return { label: "Needs Review", type: "orange" };
  return { label: "Heuristic", type: "cyan" };
}

function renderSteps(steps) {
  return toArray(steps).filter(Boolean);
}

function normalizeToken(value) {
  return String(value || "").trim().toLowerCase();
}

function buildHostSearchTerms(host, ports) {
  const baseTerms = [
    host.osName,
    host.os,
    host.osFamily,
    host.hostname,
    host.provider,
  ];

  const portTerms = ports.flatMap((port) => [
    port?.service,
    port?.product,
    port?.version,
  ]);

  return [...baseTerms, ...portTerms]
    .map(normalizeToken)
    .flatMap((term) => term.split(/[^a-z0-9.+-]+/))
    .filter((term) => term.length >= 3 && term !== "unknown");
}

function buildCveSearchText(cve) {
  const affectedProducts = toArray(cve?.affected_products)
    .flatMap((item) => [item?.product, item?.version]);

  return [
    cve?.cve_id,
    cve?.description,
    cve?.severity,
    ...affectedProducts,
  ]
    .map(normalizeToken)
    .join(" ");
}

function inferRelatedCves(host, ports, cves) {
  const terms = buildHostSearchTerms(host, ports);
  if (terms.length === 0) return [];

  return toArray(cves)
    .filter((cve) => {
      const haystack = buildCveSearchText(cve);
      return terms.some((term) => haystack.includes(term));
    })
    .sort((a, b) => (b?.cvss_score ?? 0) - (a?.cvss_score ?? 0));
}

// ── Host Card ─────────────────────────────────────────────────────────────────
function HostCard({ host, theme, cves, isHighlighted = false }) {
  const [expanded, setExpanded] = useState(false);

  const vulnerabilities = toArray(host.vulnerabilities);
  const safeCves = toArray(cves);
  const hostCveIds = vulnerabilities.flatMap(v => [v?.cve, v?.cve_id].filter(Boolean));
  const insecureProtocols = toArray(host.insecureProtocols || host.insecure_protocols);
  const tlsIssues = toArray(host.tlsIssues || host.tls_issues);
  const ports = toArray(host.ports || host.open_ports || host.openPorts);
  const directRelatedCves = safeCves.filter(c => hostCveIds.includes(c.cve_id));
  const inferredFeedCves = inferRelatedCves(host, ports, safeCves)
    .filter((cve) => !hostCveIds.includes(cve.cve_id));
  const relatedCves = [...directRelatedCves, ...inferredFeedCves];
  const displayVulnerabilities = vulnerabilities.length > 0
    ? vulnerabilities
    : relatedCves.slice(0, 3).map((cve) => ({
        cve: cve.cve_id,
        severity: cve.severity || "UNKNOWN",
        title: cve.cve_id,
        description: cve.description || "Matched from integrated CVE catalog.",
        cvss_score: cve.cvss_score ?? null,
        product: toArray(cve.affected_products)[0]?.product || "Catalog match",
        version: toArray(cve.affected_products)[0]?.version || "",
        remediation: cve.remediation || "",
      }));
  const vulnerabilityCount = displayVulnerabilities.length || (typeof host.vulnerabilities === "number" ? host.vulnerabilities : 0);
  const riskLabel = getRiskLabel(vulnerabilities, relatedCves.length);
  const countryBadge = getCountryBadge(host);

  return (
    <div className={`rounded-xl px-5 py-4 overflow-hidden border shadow-sm transition-colors duration-200 ${expanded
      ? theme === 'dark'
        ? 'bg-[#0d121e]/95 border-sky-400/70 text-slate-200'
        : 'bg-white border-sky-400 text-gray-900'
      : theme === 'dark'
        ? 'bg-[#0d121e]/95 border-cyan-500/10 text-slate-200 hover:border-sky-400/70'
        : 'bg-white border-gray-200 text-gray-900 hover:border-sky-400'
    } ${isHighlighted ? 'ring ring-cyan-400/50 ring-2' : ''}`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div className="flex items-start gap-3.5">
          {/* Country badge */}
          <div className={`w-9 h-9 rounded-lg ${theme === 'dark' ? 'bg-cyan-400/8 border-cyan-400/20 text-slate-400' : 'bg-blue-50 border-blue-200 text-blue-500'} flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5`}>
            {countryBadge}
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap mb-1">
              <span className={`text-base sm:text-lg font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>{host.displayHostname || host.hostname}</span>
              <Badge label={riskLabel} type={riskLabel === "HIGH" ? "red" : riskLabel === "MEDIUM" ? "orange" : "green"} theme={theme} />
              <Badge label="UP" type="green" theme={theme} />
            </div>
            <div className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>{host.vendor || host.provider || "Unknown vendor"}</div>
            <div className={`text-xs font-mono mt-1 ${theme === 'dark' ? 'text-slate-600' : 'text-gray-500'}`}>Hostname: {host.hostname || host.displayHostname}</div>
            <div className={`text-xs font-mono ${theme === 'dark' ? 'text-slate-600' : 'text-gray-500'}`}>IP: {host.ipAddress || host.ip || host.resolved_ip || "Unknown"}</div>
          </div>
        </div>
        <button
          onClick={() => setExpanded(v => !v)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all flex-shrink-0 ${
            theme === 'dark'
              ? 'border-cyan-400/35 bg-transparent text-cyan-400 hover:bg-cyan-400/10'
              : 'border-blue-400/35 bg-transparent text-blue-600 hover:bg-blue-400/10'
          }`}
        >
          {expanded ? "Collapse" : "Expand"} <ChevronIcon open={expanded} />
        </button>
      </div>

      {/* Expanded section */}
      {expanded && (
        <div className="mt-5">
          <div className={`h-px mb-5 ${theme === 'dark' ? 'bg-cyan-500/8' : 'bg-blue-500/8'}`} />
          <div className={`max-h-[420px] overflow-y-auto pr-1 ${theme === 'dark' ? 'bg-transparent' : 'bg-transparent'}`}>
            {/* Summary row */}
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 pt-1 mb-6">
              <div className="flex flex-col gap-1">
                <span className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>OPEN PORTS</span>
                <span className={`text-sm font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>{host.openPorts} detected</span>
              </div>
              <div className="flex flex-col gap-1">
                <span className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>SERVICES</span>
                <span className={`text-sm font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>{host.services} identified</span>
              </div>
              <div className="flex flex-col gap-1">
                <span className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>OS DETECTION</span>
                <span className="text-sm font-semibold text-violet-400 font-mono">{host.osDetection}</span>
              </div>
              <div className="flex flex-col gap-1">
                <span className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>VULNERABILITIES</span>
                <span className="text-sm font-semibold text-amber-400 font-mono">{vulnerabilityCount} found</span>
              </div>
            </div>

            {/* Port Scan Results */}
            <div className="mb-6">
              <div className={`flex items-center gap-2.5 text-xs font-bold tracking-widest mb-3.5 ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>
                <span className={`w-0.5 h-4 rounded flex-shrink-0 ${theme === 'dark' ? 'bg-cyan-400' : 'bg-blue-500'}`} />
                PORT SCAN RESULTS
              </div>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <thead>
                    <tr>
                      {["PORT","PROTOCOL","SERVICE","PRODUCT","VERSION"].map(h => (
                        <th key={h} className={`text-left py-2.5 px-4 text-[11px] font-bold tracking-wider ${theme === 'dark' ? 'text-slate-600 border-b border-white/5 bg-white/[0.02]' : 'text-gray-600 border-b border-gray-200 bg-gray-100'}`}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((p, i) => (
                      <tr key={i} className={`border-b ${theme==='dark'?'border-white/[0.04] hover:bg-white/[0.02]':'border-gray-200 hover:bg-gray-50'} transition-colors`}>
                        <td className={`py-3 px-4 font-semibold font-mono ${theme==='dark'?'text-cyan-400':'text-blue-600'}`}>{p.port}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-400':'text-gray-600'}`}>{getDisplayProtocol(p)}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-400':'text-gray-600'}`}>{p.service}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-300':'text-gray-700'} font-mono`}>{p.product}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-400':'text-gray-600'}`}>{p.version}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Insecure Protocol Detection */}
            <div className="mb-6">
              <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-amber-400 mb-3.5">
                <span className="w-0.5 h-4 rounded bg-amber-400 flex-shrink-0" />
                INSECURE PROTOCOL DETECTION
              </div>
              <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#0f172a]/80 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
                {insecureProtocols.length === 0
                  ? <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No insecure protocols detected.</span>
                  : insecureProtocols.map((item, i) => (
                    <div key={i} className="flex items-center gap-2.5">
                      <TriangleIcon color="#f59e0b" size={15} />
                      <span className={`${theme === 'dark' ? 'text-slate-200' : 'text-gray-700'} font-mono text-sm`}>
                        <span className="text-amber-400">Port {item.port}:</span> {stripPortPrefix(item.message || item.msg || "Insecure protocol detected.", item.port)}
                      </span>
                    </div>
                  ))
                }
              </div>
            </div>

            {/* TLS / Weak Encryption */}
            <div className="mb-6">
              <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-violet-400 mb-3.5">
                <span className="w-0.5 h-4 rounded bg-violet-400 flex-shrink-0" />
                TLS / WEAK ENCRYPTION OBSERVATIONS
              </div>
              <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#0f172a]/80 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
                {tlsIssues.length === 0
                  ? <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No TLS issues detected.</span>
                  : tlsIssues.map((item, i) => (
                    <div key={i} className="flex items-center gap-2.5">
                      <ShieldIcon size={14} />
                      <span className={`${theme === 'dark' ? 'text-slate-200' : 'text-gray-700'} font-mono text-sm`}>
                        <span className="text-violet-400">Port {item.port}:</span> {stripPortPrefix(item.message || item.msg || "TLS observation detected.", item.port)}
                      </span>
                    </div>
                  ))
                }
              </div>
            </div>

            {/* Vulnerability Assessment */}
            <div className="mb-6">
              <div className={`sticky top-0 z-20 px-4 pt-4 pb-3 border-b rounded-t-xl ${theme === 'dark' ? 'bg-[#0f172a]/95 border-slate-700' : 'bg-gray-50/95 border-gray-200'} backdrop-blur-sm`}>
                <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-red-400">
                  <span className="w-0.5 h-4 rounded bg-red-400 flex-shrink-0" />
                  VULNERABILITY ASSESSMENT
                </div>
              </div>
              <div className={`rounded-b-xl p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#0f172a]/80 border border-t-0 border-slate-700' : 'bg-gray-50 border border-t-0 border-gray-200'}`}>
                {displayVulnerabilities.length === 0
                  ? <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No vulnerabilities detected for this host.</span>
                  : displayVulnerabilities.map((v, i) => (
                    <div key={i} className={`p-4 rounded-xl border ${theme === 'dark' ? 'border-red-500/20 bg-gradient-to-r from-red-500/8 to-transparent' : 'border-gray-200 bg-white'}`}>
                      {(() => {
                        const validationBadge = getValidationBadge(v.validation_status);
                        return (
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div className="space-y-1 text-left">
                          <span className={`${theme === 'dark' ? 'text-cyan-300' : 'text-blue-600'} font-semibold text-xs tracking-wide`}>{v.cve || "CVE-UNKNOWN"}</span>
                          <div className={`${theme === 'dark' ? 'text-white' : 'text-gray-900'} text-base font-semibold leading-snug`}>
                            {v.title || "Vulnerability"}
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <Badge label={validationBadge.label} type={validationBadge.type} theme={theme} />
                          <Badge label={(v.severity || "UNKNOWN").toUpperCase()} type={v.severity === "CRITICAL" ? "red" : v.severity === "HIGH" ? "orange" : "cyan"} theme={theme} />
                        </div>
                      </div>
                        );
                      })()}
                      <div className="mt-3 flex flex-wrap gap-2">
                        <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-cyan-400/8 text-cyan-300 border border-cyan-400/20' : 'bg-white text-blue-700 border border-blue-200'}`}>
                          CVE: {v.cve || "UNKNOWN"}
                        </span>
                        <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-violet-400/8 text-violet-300 border border-violet-400/20' : 'bg-white text-violet-700 border border-violet-200'}`}>
                          CVSS: {formatCvssScore(v.cvss_score)}
                        </span>
                        {v.confidence && (
                          <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-slate-700/50 text-slate-200 border border-slate-600' : 'bg-slate-50 text-slate-700 border border-slate-200'}`}>
                            Confidence: {String(v.confidence).toUpperCase()}
                          </span>
                        )}
                      </div>
                      <div className={`${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'} text-sm leading-6 mt-2 text-left max-w-4xl`}>
                        {v.description || "No description available."}
                      </div>
                      <div className="grid gap-3 mt-4 md:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
                        <div className={`rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-white/[0.03] border border-white/[0.06]' : 'bg-white border border-gray-200'}`}>
                          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>AFFECTED SERVICE</div>
                          <div className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-xs uppercase tracking-wide text-left`}>
                            {v.product || "Unknown product"} {v.version ? `version ${v.version}` : ""}
                          </div>
                        </div>
                        <div className={`rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-emerald-500/6 border border-emerald-500/20' : 'bg-white border border-gray-200'}`}>
                          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-emerald-300/80' : 'text-emerald-600'}`}>REMEDIATION</div>
                          <div className={`${theme === 'dark' ? 'text-slate-200' : 'text-gray-700'} text-sm leading-6 text-left`}>
                            {getRemediationText(v)}
                          </div>
                        </div>
                      </div>

                      {(toArray(v.evidence).length > 0 || v.evidence) && (
                        <div className={`mt-4 rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-slate-900/60 border border-slate-700' : 'bg-slate-50 border border-slate-200'}`}>
                          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>VALIDATION EVIDENCE</div>
                          <div className={`${theme === 'dark' ? 'text-slate-200' : 'text-slate-700'} text-sm leading-6`}>
                            {toArray(v.evidence).length > 0 ? (
                              toArray(v.evidence).map((item, index) => (
                                <div key={index}>- {item}</div>
                              ))
                            ) : (
                              <div>{v.evidence}</div>
                            )}
                          </div>
                        </div>
                      )}

                      {toArray(v.automated_checks).length > 0 && (
                        <div className={`mt-4 rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-cyan-500/6 border border-cyan-500/20' : 'bg-cyan-50 border border-cyan-100'}`}>
                          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-cyan-300' : 'text-cyan-700'}`}>SCANNER EXECUTED CHECKS</div>
                          <div className="flex flex-col gap-3">
                            {toArray(v.automated_checks).map((check, index) => (
                              <div key={index} className={`rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-slate-950/70 border border-slate-800' : 'bg-white border border-cyan-100'}`}>
                                <div className="flex flex-wrap items-center justify-between gap-2">
                                  <div className={`${theme === 'dark' ? 'text-white' : 'text-slate-900'} text-sm font-semibold`}>{check.name}</div>
                                  <Badge
                                    label={String(check.status || "unknown").toUpperCase()}
                                    type={String(check.status || "").toLowerCase() === "completed" ? "green" : String(check.status || "").toLowerCase() === "failed" ? "orange" : "cyan"}
                                    theme={theme}
                                  />
                                </div>
                                <div className={`${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'} mt-2 text-sm leading-6`}>
                                  {check.details || "No check details recorded."}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {renderSteps(v.steps_to_reproduce).length > 0 && (
                        <div className={`mt-4 rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-amber-500/6 border border-amber-500/20' : 'bg-amber-50 border border-amber-100'}`}>
                          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>MANUAL FOLLOW-UP</div>
                          <div className={`${theme === 'dark' ? 'text-slate-200' : 'text-slate-700'} text-sm leading-6`}>
                            {renderSteps(v.steps_to_reproduce).map((step, index) => (
                              <div key={index}>{index + 1}. {step}</div>
                            ))}
                          </div>
                          {v.reproduction && (
                            <pre className={`mt-3 overflow-x-auto rounded-lg px-3 py-3 text-xs ${theme === 'dark' ? 'bg-slate-950 text-cyan-300' : 'bg-white text-blue-700 border border-blue-100'}`}>{v.reproduction}</pre>
                          )}
                        </div>
                      )}
                    </div>
                  ))
                }

                {displayVulnerabilities.length === 0 && (
                  <div className="mt-3 p-3 rounded-lg border border-slate-300/40 bg-slate-200/10">
                    <p className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-xs`}>No direct CVE match for this host in global feed.</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/*
          <div className="flex items-center justify-center gap-2 p-3.5 rounded-lg border border-cyan-500/15 bg-cyan-500/[0.03] cursor-pointer hover:bg-cyan-500/8 transition-all mt-2">
            <TerminalIcon size={14} color="#00e5ff" />
            <span className="text-cyan-400 text-sm font-mono">View Complete Device Profile</span>
          </div>
          */}
        </div>
      )}
    </div>
  );
}

function OwaspCategoryCard({ category, theme }) {
  const [expanded, setExpanded] = useState(false);
  const findings = toArray(category?.findings);
  const findingsCount = category?.findings_count ?? findings.length;
  const hasFindings = findingsCount > 0;
  const severityType = category?.severity === "HIGH" ? "red" : category?.severity === "MEDIUM" ? "orange" : "cyan";

  return (
    <div className={`relative pl-7 ${expanded ? 'pb-6' : 'pb-4'} ${theme === 'dark' ? 'text-slate-200' : 'text-slate-900'}`}>
      <div className={`absolute left-[11px] top-0 bottom-0 w-px ${theme === 'dark' ? 'bg-violet-400/15' : 'bg-slate-200'}`} />
      <div className={`absolute left-0 top-1.5 h-[22px] w-[22px] rounded-full border-2 ${theme === 'dark' ? 'border-violet-400 bg-[#0f1523]' : 'border-violet-500 bg-white'}`} />

      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-sm font-mono font-semibold ${theme === 'dark' ? 'text-violet-300' : 'text-violet-700'}`}>{category?.id || category?.short || "OWASP"}</span>
            {hasFindings && (
              <Badge label={category?.severity || "INFO"} type={severityType} theme={theme} />
            )}
            <span className={`text-[11px] font-semibold uppercase tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>
              {findingsCount} findings
            </span>
          </div>
          <div className={`text-xl font-semibold leading-tight ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>{category?.title || "OWASP Category"}</div>
          <div className={`${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} text-sm max-w-2xl`}>
            {!hasFindings
              ? "Baseline review completed for this category with no direct findings recorded."
              : "Review the linked findings and evidence for this OWASP category below."}
          </div>
        </div>
        {hasFindings && (
          <button
            onClick={() => setExpanded((value) => !value)}
            className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-all ${
              theme === 'dark'
                ? 'border-violet-400/35 text-violet-300 hover:bg-violet-400/10'
                : 'border-violet-300 bg-white text-violet-700 hover:bg-violet-50'
            }`}
          >
            {expanded ? "Collapse" : "Expand"} <ChevronIcon open={expanded} />
          </button>
        )}
      </div>

      {expanded && (
        <div className="mt-5 ml-1 h-[190px] overflow-y-auto pr-1">
          {!hasFindings ? (
            <div className={`ml-3 border-l-2 pl-5 text-sm ${theme === 'dark' ? 'border-slate-700 text-slate-400' : 'border-slate-200 text-slate-600'}`}>
              No obvious OWASP findings were detected for this category in the current scan.
            </div>
          ) : (
            <div className="space-y-5">
              {findings.map((finding, index) => (
                <div key={`${category?.id || 'owasp'}-${index}`} className="relative ml-3 pl-5">
                  <div className={`absolute left-0 top-1 h-3 w-3 rounded-full ${theme === 'dark' ? 'bg-violet-400/80' : 'bg-violet-500'}`} />
                  <div className={`absolute left-[5px] top-5 bottom-[-20px] w-px ${index === findings.length - 1 ? 'hidden' : theme === 'dark' ? 'bg-violet-400/10' : 'bg-slate-200'}`} />
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="space-y-1.5">
                      <div className={`${theme === 'dark' ? 'text-violet-200' : 'text-violet-700'} text-sm font-semibold`}>{finding?.title || "Finding"}</div>
                      <div className={`${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'} text-sm leading-6`}>{finding?.description || finding?.evidence || "No details provided."}</div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {finding?.validation_status && (
                        <Badge label={getValidationBadge(finding.validation_status).label} type={getValidationBadge(finding.validation_status).type} theme={theme} />
                      )}
                      {finding?.confidence && (
                        <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-slate-900 text-slate-200' : 'bg-slate-100 text-slate-700'}`}>
                          {String(finding.confidence).toUpperCase()}
                        </span>
                      )}
                    </div>
                  </div>
                  {finding?.url && (
                    <div className={`mt-3 inline-flex max-w-full rounded-full px-3 py-1.5 text-xs font-mono ${
                      theme === 'dark'
                        ? 'bg-slate-900 text-cyan-300'
                        : 'bg-slate-100 text-blue-700'
                    }`}>
                      {finding.url}
                    </div>
                  )}
                  {finding?.payload && (
                    <div className={`mt-3 rounded-lg px-3 py-2 text-xs font-mono ${theme === 'dark' ? 'bg-slate-900 text-amber-300' : 'bg-amber-50 text-amber-700 border border-amber-100'}`}>
                      Payload: {finding.payload}
                    </div>
                  )}
                  {finding?.request && (
                    <pre className={`mt-3 overflow-x-auto rounded-lg px-3 py-3 text-xs ${theme === 'dark' ? 'bg-slate-950 text-cyan-300' : 'bg-slate-50 text-blue-700 border border-slate-200'}`}>{finding.request}</pre>
                  )}
                  {finding?.response_snippet && (
                    <pre className={`mt-3 overflow-x-auto rounded-lg px-3 py-3 text-xs ${theme === 'dark' ? 'bg-slate-950 text-slate-300 border border-slate-800' : 'bg-white text-slate-700 border border-slate-200'}`}>{finding.response_snippet}</pre>
                  )}
                  {renderSteps(finding?.steps_to_reproduce).length > 0 && (
                    <div className={`mt-3 rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-white/[0.03] border border-white/[0.06]' : 'bg-slate-50 border border-slate-200'}`}>
                      <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>STEPS TO REPRODUCE</div>
                      {renderSteps(finding.steps_to_reproduce).map((step, stepIndex) => (
                        <div key={stepIndex} className={`${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'} text-sm leading-6`}>
                          {stepIndex + 1}. {step}
                        </div>
                      ))}
                      {finding?.reproduction && (
                        <pre className={`mt-3 overflow-x-auto rounded-lg px-3 py-3 text-xs ${theme === 'dark' ? 'bg-slate-950 text-cyan-300' : 'bg-white text-blue-700 border border-blue-100'}`}>{finding.reproduction}</pre>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function Vulns({ scanData, theme, selectedTarget }) {
  const [persistedScanData, setPersistedScanData] = useState(() => {
    try {
      const stored = localStorage.getItem(LAST_SCAN_STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    if (scanData) {
      setPersistedScanData(scanData);
      try {
        localStorage.setItem(LAST_SCAN_STORAGE_KEY, JSON.stringify(scanData));
      } catch {
        // Ignore storage failures so the live scan view still renders.
      }
    }
  }, [scanData]);

  const effectiveScanData = scanData || persistedScanData;
  const hosts = Array.isArray(effectiveScanData?.assets) ? effectiveScanData.assets : [];

  const normalizedTarget = normalizeTarget(selectedTarget);
  const targetMatchedHosts = normalizedTarget ? hosts.filter(host => hostMatchesTarget(host, normalizedTarget)) : [];
  const displayedHosts = normalizedTarget && targetMatchedHosts.length > 0 ? targetMatchedHosts : hosts;

  const scanCves = collectScanCves(hosts);
  const hostsUp = effectiveScanData?.active_hosts ?? hosts.length;
  const openPorts = hosts.reduce((acc, host) => acc + (host.open_ports?.length ?? host.ports?.length ?? 0), 0);
  const vulnerabilitySummary = effectiveScanData?.vulnerability_summary || {};
  const vulnerabilities = vulnerabilitySummary.total_vulnerabilities ?? 0;
  const criticalRisk = vulnerabilitySummary.critical_risk ?? 0;
  const confirmedFindings = vulnerabilitySummary.confirmed_findings ?? 0;
  const needsReview = vulnerabilitySummary.needs_review ?? 0;
  const owasp = normalizeOwaspResults(effectiveScanData?.owasp_top_10);
  const scanStatus = effectiveScanData ? "LIVE" : "NO DATA";
  const scanError = effectiveScanData?.error || null;
  const [downloadingFormat, setDownloadingFormat] = useState(null);

  const resolveReportPath = async () => {
    const directPath = effectiveScanData?.report_files?.json || effectiveScanData?.report_files?.txt;
    if (directPath) return directPath;

    try {
      const res = await fetch(`${API_BASE}/stats`, { cache: "no-store" });
      if (!res.ok) return null;
      const data = await res.json();
      const history = Array.isArray(data?.scan_history) ? data.scan_history : [];
      if (history.length === 0) return null;

      const input = String(effectiveScanData?.input || "").trim().toLowerCase();
      const inputDash = input.replaceAll("/", "-");
      const match = history.find((item) => {
        const t = String(item?.target || "").trim().toLowerCase();
        return t === input || t === inputDash || t.replaceAll("-", "/") === input;
      });

      return match?.reportPath || history[0]?.reportPath || null;
    } catch {
      return null;
    }
  };

  const downloadReport = async (format) => {
    if (downloadingFormat) return;
    const reportPath = await resolveReportPath();
    if (!reportPath) {
      alert("No report available for download yet. Please run a scan first.");
      return;
    }

    const encodedPath = encodeURIComponent(reportPath);
    const url = `${API_BASE}/download_report?path=${encodedPath}&format=${format}&_ts=${Date.now()}`;

    try {
      setDownloadingFormat(format);
      const resp = await fetch(url, { cache: "no-store" });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        alert(`Report download failed: ${err.detail || `HTTP ${resp.status}`}`);
        return;
      }

      const blob = await resp.blob();
      const link = document.createElement("a");
      const fileName = resp.headers.get("content-disposition")?.match(/filename="?([^"]+)"?/)?.[1] || `scan_report.${format}`;
      const objectUrl = URL.createObjectURL(blob);
      link.href = objectUrl;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      // Delay cleanup so browser has time to start the download reliably.
      setTimeout(() => {
        URL.revokeObjectURL(objectUrl);
        document.body.removeChild(link);
      }, 1500);
    } catch (error) {
      console.error(error);
      alert(`Report download failed: ${error.message}`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  const [cves, setCves] = useState([]);

  useEffect(() => {
    const loadCves = async () => {
      const endpoints = [
        `${API_BASE}/api/threat-intel/cves`,
        `${API_BASE}/api/threat/cves`,
      ];

      for (const endpoint of endpoints) {
        try {
          const res = await fetch(endpoint);
          if (!res.ok) continue;
          const data = await res.json();
          setCves(normalizeCveResponse(data));
          return;
        } catch (err) {
          console.error('CVE API error', err);
        }
      }

      setCves([]);
    };

    loadCves();
  }, []);

  const effectiveCves = cves.length > 0 ? cves : scanCves;

  if (!effectiveScanData) {
    return (
      <div className={`min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'bg-gray-50 text-gray-900'}`} style={{ fontFamily: "'Segoe UI',system-ui,sans-serif" }}>
        <style>{`html,body,#root{background:${theme === 'dark' ? '#0a0d14' : '#f8fafc'};min-height:100vh;}`}</style>
        <main className="w-full max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-7 text-left">
          <div className={`mb-6 p-4 rounded-xl border ${theme === 'dark' ? 'border-amber-500/40 bg-[#0f1523]/90 text-amber-300' : 'border-amber-300 bg-white text-amber-700'}`}>
            <strong>No scan data yet.</strong> Run a scan first, then this page will show only that scanned target and keep it after refresh.
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className={`min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'bg-gray-50 text-gray-900'}`} style={{ fontFamily: "'Segoe UI',system-ui,sans-serif" }}>
      <style>{`html,body,#root{background:${theme === 'dark' ? '#0a0d14' : '#f8fafc'};min-height:100vh;}`}</style>

      <main className="w-full max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-4 text-left">

        {/* Query bar */}
        <div className={`sticky top-0 z-30 backdrop-blur-md ${theme === 'dark' ? 'bg-transparent' : 'bg-transparent'} pb-2 pt-2 mb-8`}>
          <div className="mx-auto max-w-[1400px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`font-mono text-2xl font-normal tracking-wide ${theme === 'dark' ? 'text-cyan-300' : 'text-blue-700'}`}>
                {effectiveScanData?.input ? `Target scan: ${effectiveScanData.input}` : `Scanned Targets (${scanStatus})`}
              </span>
            </div>
          </div>
        </div>

        {scanError && (
          <div className="mt-4 mb-6 p-4 rounded-xl border border-red-500 bg-red-500/10 text-red-300">
            <strong>Scan Error:</strong> {scanError}
          </div>
        )}

        {/* Hosts discovered (disabled) */}
        { /* <h1 className={`text-lg sm:text-xl font-mono font-semibold tracking-wide mb-0 ${theme === 'dark' ? 'text-blue-300' : 'text-blue-700'}`}>
          {hostsUp} hosts discovered
        </h1> */ }

        {/* Stat cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mb-6">
          {/* Hosts Up */}
          <div className={`${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-400/45 text-slate-200 shadow-[0_0_0_1px_rgba(34,211,238,0.12)]' : 'bg-white border-blue-400 text-gray-900'} rounded-xl px-4 py-3.5 border shadow-sm`}>
            <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'} mb-3`}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#22d3ee' : '#0ea5e9'} strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
              </svg>
              HOSTS UP
            </div>
            <div className={`text-2xl font-bold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-blue-600'}`}>{hostsUp}</div>
          </div>
          {/* Open Ports */}
          <div className={`${theme === 'dark' ? 'bg-[#0f1523]/90 border-emerald-400/45 text-slate-200 shadow-[0_0_0_1px_rgba(52,211,153,0.12)]' : 'bg-white border-emerald-400 text-gray-900'} rounded-xl px-4 py-3.5 border shadow-sm`}>
            <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'} mb-3`}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#34d399' : '#16a34a'} strokeWidth="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              OPEN PORTS
            </div>
            <div className={`${theme === 'dark' ? 'text-emerald-400' : 'text-emerald-600'} text-2xl font-bold font-mono`}>{openPorts}</div>
          </div>
          {/* Vulnerabilities */}
          <div className={`${theme === 'dark' ? 'bg-[#0f1523]/90 border-amber-400/45 text-slate-200 shadow-[0_0_0_1px_rgba(251,191,36,0.12)]' : 'bg-white border-amber-400 text-gray-900'} rounded-xl px-4 py-3.5 border shadow-sm`}>
            <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'} mb-3`}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#f59e0b' : '#eab308'} strokeWidth="2">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>
              VULNERABILITIES
            </div>
            <div className={`${theme === 'dark' ? 'text-amber-400' : 'text-orange-500'} text-2xl font-bold font-mono`}>{vulnerabilities}</div>
            <div className={`mt-2 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>Confirmed: {confirmedFindings} | Review: {needsReview}</div>
          </div>
          {/* Critical Risk */}
          <div className={`${theme === 'dark' ? 'bg-[#0f1523]/90 border-red-400/45 text-slate-200 shadow-[0_0_0_1px_rgba(248,113,113,0.12)]' : 'bg-white border-red-400 text-gray-900'} rounded-xl px-4 py-3.5 border shadow-sm`}>
            <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'} mb-3`}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#ef4444' : '#ef4444'} strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              CRITICAL RISK
            </div>
            <div className={`${theme === 'dark' ? 'text-red-400' : 'text-rose-600'} text-2xl font-bold font-mono`}>{criticalRisk}</div>
          </div>
        </div>

        {/* Report download buttons */}
        <div className="mb-6 flex flex-wrap gap-2">
          <button
            onClick={() => downloadReport('json')}
            disabled={Boolean(downloadingFormat)}
            className={`rounded-lg px-3 py-2 bg-sky-600 text-white text-xs font-medium hover:bg-sky-700 ${downloadingFormat ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
          >
            {downloadingFormat === "json" ? "Downloading..." : "Download JSON"}
          </button>
          <button
            onClick={() => downloadReport('txt')}
            disabled={Boolean(downloadingFormat)}
            className={`rounded-lg px-3 py-2 bg-slate-600 text-white text-xs font-medium hover:bg-slate-700 ${downloadingFormat ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
          >
            {downloadingFormat === "txt" ? "Downloading..." : "Download TXT"}
          </button>
          <button
            onClick={() => downloadReport('pdf')}
            disabled={Boolean(downloadingFormat)}
            className={`rounded-lg px-3 py-2 bg-emerald-600 text-white text-xs font-medium hover:bg-emerald-700 ${downloadingFormat ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
          >
            {downloadingFormat === "pdf" ? "Downloading..." : "Download PDF"}
          </button>
          {/* <button onClick={() => downloadReport('docx')} className="rounded-lg px-3 py-2 bg-violet-600 text-white text-xs font-medium hover:bg-violet-700">Download Word</button> */}
        </div>

        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="text-sm font-semibold text-slate-400">
            {normalizedTarget
              ? targetMatchedHosts.length > 0
                ? `Showing host(s) related to "${selectedTarget}"` 
                : `No matching hosts found for "${selectedTarget}". Showing all hosts.`
              : "Showing all hosts"}
          </div>
        </div>
        <div className="flex flex-col gap-4">
          {displayedHosts.map((host, index) => {
            const foundPorts = host.open_ports?.length ?? host.ports?.length ?? 0;
            const computedStatus = host.status || (foundPorts > 0 ? "UP" : "DOWN");
            const isSelected = normalizedTarget && hostMatchesTarget(host, normalizedTarget);

            return (
              <HostCard
                key={host.ip || host.hostname || index}
                theme={theme}
                cves={effectiveCves}
                isHighlighted={isSelected}
                host={{
                ...host,
                id: index + 1,
                hostState: host.hostState || computedStatus,
                status: computedStatus,
                openPorts: foundPorts,
                services: foundPorts,
                osDetection: host.os_name || host.os || host.osName || "Unknown",
                ports: host.open_ports || host.ports || [],
                provider: host.vendor || host.provider || "Unknown",
                vendor: host.vendor || host.provider || "Unknown",
                country: host.country || "NA",
                hostname: host.domain || host.hostname || host.resolved_ip || "Unknown",
                ipAddress: host.ip || host.resolved_ip || "Unknown",
                displayHostname: host.domain || host.hostname || host.resolved_ip || host.ip || host.input || "Unknown",
                deviceType: host.device_type || "Unknown Device",
                insecureProtocols: host.insecure_protocols || host.insecureProtocols || [],
                tlsIssues: host.tls_issues || host.tlsIssues || [],
                vulnerabilities: host.vulnerabilities || [],
                }} />
            );
          })}
        </div>
        <div className={`mt-6 overflow-hidden rounded-[28px] border px-4 py-4 sm:px-6 ${theme === 'dark' ? 'border-violet-400/20 bg-[#0f1523]/90' : 'border-violet-100 bg-gradient-to-br from-white via-[#fcfcff] to-[#f7f8ff]'}`}>
          <div className={`sticky top-0 z-10 pb-5 ${theme === 'dark' ? 'bg-[#0f1523]/95' : 'bg-[linear-gradient(180deg,rgba(255,255,255,0.96),rgba(255,255,255,0.88))]'} backdrop-blur-sm`}>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className={`text-[11px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-violet-300' : 'text-violet-700'}`}>OWASP TOP 10</div>
                <h2 className={`mt-2 text-xl font-semibold ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>Backend web checks integrated into this scan report</h2>
                <p className={`mt-2 text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>
                  {owasp.enabled
                    ? `Scanned target URL: ${owasp.normalizedUrl || 'N/A'}`
                    : "OWASP application checks run only for domain or URL based targets."}
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-end gap-3">
                <div className={`min-w-[132px] rounded-xl px-5 py-3 ${theme === 'dark' ? 'bg-violet-400/6 text-violet-200 ring-1 ring-violet-400/15' : 'bg-white/80 text-violet-700 ring-1 ring-violet-100 shadow-sm'}`}>
                  <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>CATEGORIES</div>
                  <div className="mt-1 text-2xl font-mono font-bold">{owasp.totalCategories}</div>
                </div>
                <div className={`min-w-[132px] rounded-xl px-5 py-3 ${theme === 'dark' ? 'bg-amber-400/6 text-amber-200 ring-1 ring-amber-400/15' : 'bg-white/80 text-amber-700 ring-1 ring-amber-100 shadow-sm'}`}>
                  <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>WITH FINDINGS</div>
                  <div className="mt-1 text-2xl font-mono font-bold">{owasp.categoriesWithFindings}</div>
                </div>
                <div className={`min-w-[132px] rounded-xl px-5 py-3 ${theme === 'dark' ? 'bg-rose-400/6 text-rose-200 ring-1 ring-rose-400/15' : 'bg-white/80 text-rose-700 ring-1 ring-rose-100 shadow-sm'}`}>
                  <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>TOTAL FINDINGS</div>
                  <div className="mt-1 text-2xl font-mono font-bold">{owasp.totalFindings}</div>
                </div>
              </div>
            </div>
          </div>

          {owasp.enabled && owasp.results.length > 0 && (
            <div className={`mt-3 h-[322px] overflow-y-auto pr-3 ${theme === 'dark' ? '' : 'pl-1'}`}>
              {owasp.results.map((category) => (
                <OwaspCategoryCard
                  key={category?.id || category?.title}
                  category={category}
                  theme={theme}
                />
              ))}
            </div>
          )}
        </div>

        {owasp.enabled && (
          <div className={`mt-6 rounded-[28px] border px-4 py-4 sm:px-6 ${theme === 'dark' ? 'border-cyan-400/20 bg-[#0f1523]/90' : 'border-cyan-100 bg-white'}`}>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className={`text-[11px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-cyan-300' : 'text-cyan-700'}`}>ADVANCED ANALYSIS</div>
                <h2 className={`mt-2 text-xl font-semibold ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>Parameter fuzzing, auth checks, and workflow review</h2>
              </div>
              <div className="flex flex-wrap gap-3">
                <div className={`min-w-[132px] rounded-xl px-4 py-3 ${theme === 'dark' ? 'bg-cyan-400/6 text-cyan-200 ring-1 ring-cyan-400/15' : 'bg-cyan-50 text-cyan-700 ring-1 ring-cyan-100'}`}>
                  <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>REQUESTS</div>
                  <div className="mt-1 text-2xl font-mono font-bold">{owasp.requestsMade}</div>
                </div>
                <div className={`min-w-[132px] rounded-xl px-4 py-3 ${theme === 'dark' ? 'bg-violet-400/6 text-violet-200 ring-1 ring-violet-400/15' : 'bg-violet-50 text-violet-700 ring-1 ring-violet-100'}`}>
                  <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>PARAMETERS</div>
                  <div className="mt-1 text-2xl font-mono font-bold">{owasp.parametersTested}</div>
                </div>
                <div className={`min-w-[132px] rounded-xl px-4 py-3 ${theme === 'dark' ? 'bg-amber-400/6 text-amber-200 ring-1 ring-amber-400/15' : 'bg-amber-50 text-amber-700 ring-1 ring-amber-100'}`}>
                  <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>AUTH FINDINGS</div>
                  <div className="mt-1 text-2xl font-mono font-bold">{owasp.authFindings}</div>
                </div>
                <div className={`min-w-[132px] rounded-xl px-4 py-3 ${theme === 'dark' ? 'bg-rose-400/6 text-rose-200 ring-1 ring-rose-400/15' : 'bg-rose-50 text-rose-700 ring-1 ring-rose-100'}`}>
                  <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>WORKFLOW REVIEW</div>
                  <div className="mt-1 text-2xl font-mono font-bold">{owasp.businessLogicFindings}</div>
                </div>
              </div>
            </div>

            <div className="mt-5 grid gap-4 lg:grid-cols-2">
              <div className={`rounded-2xl border px-4 py-4 ${theme === 'dark' ? 'border-slate-700 bg-slate-900/40' : 'border-slate-200 bg-slate-50'}`}>
                <div className={`text-[11px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-cyan-300' : 'text-cyan-700'}`}>DISCOVERED PARAMETERS</div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {toArray(owasp.advancedAnalysis?.parameter_discovery?.discovered_parameters).length > 0 ? (
                    toArray(owasp.advancedAnalysis?.parameter_discovery?.discovered_parameters).map((item) => (
                      <span key={item} className={`rounded-full px-3 py-1 text-xs font-mono ${theme === 'dark' ? 'bg-slate-800 text-slate-200' : 'bg-white text-slate-700 border border-slate-200'}`}>{item}</span>
                    ))
                  ) : (
                    <span className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>No parameters discovered.</span>
                  )}
                </div>
              </div>
              <div className={`rounded-2xl border px-4 py-4 ${theme === 'dark' ? 'border-slate-700 bg-slate-900/40' : 'border-slate-200 bg-slate-50'}`}>
                <div className={`text-[11px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>WORKFLOW PATHS</div>
                <div className="mt-3 flex flex-col gap-2">
                  {toArray(owasp.advancedAnalysis?.business_logic?.review_paths).length > 0 ? (
                    toArray(owasp.advancedAnalysis?.business_logic?.review_paths).map((item) => (
                      <span key={item} className={`text-sm font-mono ${theme === 'dark' ? 'text-slate-200' : 'text-slate-700'}`}>{item}</span>
                    ))
                  ) : (
                    <span className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>No workflow-style paths discovered.</span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
