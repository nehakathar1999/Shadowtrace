import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../lib/api";
const LAST_SCAN_STORAGE_KEY = "vapt_last_scan_result";
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
        cyan: "bg-white border border-[rgba(107,31,58,0.2)] text-[var(--accent)]",
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

function toArray(value, fallback = []) {
  return Array.isArray(value) ? value : fallback;
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
    const items = schema.keys.map((key) => {
      usedKeys.add(key);
      return detailMap[key] || null;
    }).filter(Boolean);
    return { title: schema.title, items };
  });

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
  const cweIds = Array.isArray(vulnerability?.cwe_ids)
    ? vulnerability.cwe_ids.filter(Boolean)
    : [];
  const weaknessSummary = vulnerability?.weakness_summary || vulnerability?.weakness || "";
  return {
    cve_id: cveId || `${host?.hostname || host?.ip || "HOST"}-${vulnerability?.port || "PORT"}`,
    cve: cveId,
    description: vulnerability?.description || "Detected during scanner-side vulnerability assessment.",
    severity: vulnerability?.severity || "UNKNOWN",
    cvss_score: vulnerability?.cvss_score ?? null,
    cwe_ids: cweIds,
    weakness_summary: weaknessSummary,
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
  const [expanded, setExpanded] = useState(Boolean(host.defaultExpanded));

  const vulnerabilities = toArray(host.vulnerabilities);
  const safeCves = toArray(cves);
  const hostCveIds = vulnerabilities.flatMap(v => [v?.cve, v?.cve_id].filter(Boolean));
  const insecureProtocols = toArray(host.insecureProtocols || host.insecure_protocols);
  const tlsIssues = toArray(host.tlsIssues || host.tls_issues);
  const ports = toArray(host.ports || host.open_ports || host.openPorts);
  const credentialFindings = toArray(host.credentialScan?.findings);
  const relatedSubdomains = toArray(host.relatedSubdomains);
  const riskSummary = host.riskSummary || {};
  const serviceIntel = ports.filter((item) => item?.banner || toArray(item?.scripts).length > 0);
  const directRelatedCves = safeCves.filter(c => hostCveIds.includes(c.cve_id));
  const inferredFeedCves = inferRelatedCves(host, ports, safeCves)
    .filter((cve) => !hostCveIds.includes(cve.cve_id));
  const relatedCves = [...directRelatedCves, ...inferredFeedCves];
  const domainIntelligence = host.domainIntelligence || {};
  const domainIntelSections = buildDomainIntelSections(
    domainIntelligence.details || {},
    toArray(domainIntelligence.display_details),
  );
  const displayVulnerabilities = vulnerabilities.length > 0
    ? vulnerabilities
    : relatedCves.slice(0, 3).map((cve) => ({
        cve: cve.cve_id,
        severity: cve.severity || "UNKNOWN",
        title: cve.cve_id,
        description: cve.description || "Matched from integrated CVE catalog.",
        cvss_score: cve.cvss_score ?? null,
        cwe_ids: toArray(cve.cwe_ids),
        weakness_summary: cve.weakness_summary || "",
        product: toArray(cve.affected_products)[0]?.product || "Catalog match",
        version: toArray(cve.affected_products)[0]?.version || "",
        remediation: cve.remediation || "",
      }));
  const vulnerabilityCount = displayVulnerabilities.length || (typeof host.vulnerabilities === "number" ? host.vulnerabilities : 0);
  const riskLabel = getRiskLabel(vulnerabilities, relatedCves.length);
  const primaryTitle = host.displayHostname || host.hostname || host.ipAddress || host.ip || host.resolved_ip || "Target";
  const hostnameValue = host.hostname || host.displayHostname || primaryTitle;
  const ipValue = host.ipAddress || host.ip || host.resolved_ip || "";

  return (
    <div className={`rounded-xl px-5 py-4 overflow-hidden border shadow-sm transition-colors duration-200 ${expanded
      ? theme === 'dark'
        ? 'bg-[#0d121e]/95 border-sky-400/70 text-slate-200'
        : 'bg-white border-[rgba(107,31,58,0.35)] text-gray-900'
      : theme === 'dark'
        ? 'bg-[#0d121e]/95 border-cyan-500/10 text-slate-200 hover:border-sky-400/70'
        : 'bg-white border-gray-200 text-gray-900 hover:border-[rgba(107,31,58,0.35)]'
    } ${isHighlighted ? 'ring ring-[rgba(107,31,58,0.32)] ring-2' : ''}`}>
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-4">
        <div>
          <div className="flex items-center gap-2.5 flex-wrap mb-1">
            <span className={`text-base sm:text-lg font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{primaryTitle}</span>
            <Badge label={riskLabel} type={riskLabel === "HIGH" ? "red" : riskLabel === "MEDIUM" ? "orange" : "green"} theme={theme} />
            <Badge label="UP" type="green" theme={theme} />
          </div>
          <div className={`text-xs font-mono mt-1 ${theme === 'dark' ? 'text-slate-600' : 'text-gray-500'}`}>Hostname: {hostnameValue}</div>
          {ipValue ? (
            <div className={`text-xs font-mono ${theme === 'dark' ? 'text-slate-600' : 'text-gray-500'}`}>IP: {ipValue}</div>
          ) : null}
        </div>
        <button
          onClick={() => setExpanded(v => !v)}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-all flex-shrink-0 ${
            theme === 'dark'
              ? 'border-cyan-400/35 bg-transparent text-cyan-400 hover:bg-cyan-400/10'
              : 'border-[rgba(107,31,58,0.25)] bg-transparent text-[var(--accent)] hover:bg-[rgba(107,31,58,0.08)]'
          }`}
        >
          {expanded ? "Collapse" : "Expand"} <ChevronIcon open={expanded} />
        </button>
      </div>

      {/* Expanded section */}
      {expanded && (
        <div className="mt-5">
          <div className={`h-px mb-5 ${theme === 'dark' ? 'bg-cyan-500/8' : 'bg-[rgba(107,31,58,0.12)]'}`} />
          <div className={`max-h-[420px] overflow-y-auto pr-1 ${theme === 'dark' ? 'bg-transparent' : 'bg-transparent'}`}>
            {/* Summary row */}
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 pt-1 mb-6">
              <div className="flex flex-col gap-1">
                <span className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>OPEN PORTS</span>
                <span className={`text-sm font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{host.openPorts} detected</span>
              </div>
              <div className="flex flex-col gap-1">
                <span className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>SERVICES</span>
                <span className={`text-sm font-semibold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{host.services} identified</span>
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
              <div className={`flex items-center gap-2.5 text-xs font-bold tracking-widest mb-3.5 ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>
                <span className={`w-0.5 h-4 rounded flex-shrink-0 ${theme === 'dark' ? 'bg-cyan-400' : 'bg-[var(--accent)]'}`} />
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
                        <td className={`py-3 px-4 font-semibold font-mono ${theme==='dark'?'text-cyan-400':'text-[var(--accent)]'}`}>{p.port}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-400':'text-gray-600'}`}>{getDisplayProtocol(p)}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-400':'text-gray-600'}`}>{p.service && p.service !== "unknown" ? p.service : "Unidentified service"}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-300':'text-gray-700'} font-mono`}>{p.product || "Fingerprint unavailable"}</td>
                        <td className={`py-3 px-4 ${theme==='dark'?'text-slate-400':'text-gray-600'}`}>{p.version || "Not detected"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="space-y-6 mb-6">
              <div>
                <div className={`flex items-center gap-2.5 text-xs font-bold tracking-widest mb-3.5 ${theme === 'dark' ? 'text-sky-400' : 'text-[var(--accent)]'}`}>
                  <span className={`w-0.5 h-4 rounded flex-shrink-0 ${theme === 'dark' ? 'bg-sky-400' : 'bg-[var(--accent)]'}`} />
                  ASSET INTELLIGENCE
                </div>
                <div className={`rounded-2xl border p-5 ${theme === 'dark' ? 'border-sky-500/20 bg-[radial-gradient(circle_at_top_left,rgba(14,165,233,0.12),transparent_32%),#0b1220]' : 'border-[rgba(107,31,58,0.16)] bg-[radial-gradient(circle_at_top_left,rgba(107,31,58,0.08),transparent_30%),white]'}`}>
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
                        <div key={section.title} className={`border-l-2 pl-4 ${theme === 'dark' ? 'border-sky-500/30' : 'border-[rgba(107,31,58,0.28)]'}`}>
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
                <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-rose-400 mb-3.5">
                  <span className="w-0.5 h-4 rounded bg-rose-400 flex-shrink-0" />
                  PRIORITIZED RISK
                </div>
                <div className={`rounded-lg p-4 ${theme === 'dark' ? 'bg-[#0f172a]/80 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
                  <div className="grid grid-cols-3 gap-3 mb-3">
                    <div>
                      <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>ASSET IMPORTANCE</div>
                      <div className={`mt-1 text-sm font-semibold ${theme === 'dark' ? 'text-rose-300' : 'text-[var(--accent)]'}`}>{riskSummary.asset_importance ? formatLabel(riskSummary.asset_importance) : "N/A"}</div>
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
                  {displayVulnerabilities.length === 0 ? (
                    <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No prioritized host risks were generated.</span>
                  ) : (
                    <div className="space-y-2">
                      {displayVulnerabilities.slice(0, 3).map((item, index) => (
                        <div key={`${item?.title || item?.cve || "risk"}-${index}`} className={`rounded-md px-3 py-2 border ${theme === 'dark' ? 'border-white/5 bg-white/[0.02]' : 'border-gray-200 bg-white'}`}>
                          <div className="flex items-center justify-between gap-3">
                            <span className={`text-sm font-semibold ${theme === 'dark' ? 'text-slate-100' : 'text-gray-900'}`}>{item.title || item.cve || "Risk finding"}</span>
                            <span className={`text-xs font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>Risk {item.risk_score ?? 0}</span>
                          </div>
                          <div className={`mt-1 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>
                            {truncateText(item.description, 90)}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div>
                <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-emerald-400 mb-3.5">
                  <span className="w-0.5 h-4 rounded bg-emerald-400 flex-shrink-0" />
                  SERVICE INTELLIGENCE
                </div>
                <div className={`rounded-lg p-4 flex flex-col gap-3 ${theme === 'dark' ? 'bg-[#0f172a]/80 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
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

            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 mb-6">
              <div>
                <div className={`flex items-center gap-2.5 text-xs font-bold tracking-widest mb-3.5 ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>
                  <span className={`w-0.5 h-4 rounded flex-shrink-0 ${theme === 'dark' ? 'bg-cyan-400' : 'bg-[var(--accent)]'}`} />
                  SUBDOMAIN LINKS
                </div>
                <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#0f172a]/80 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
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
                <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-red-400 mb-3.5">
                  <span className="w-0.5 h-4 rounded bg-red-400 flex-shrink-0" />
                  SSH CREDENTIAL CHECKS
                </div>
                <div className={`rounded-lg p-4 flex flex-col gap-2.5 ${theme === 'dark' ? 'bg-[#0f172a]/80 border border-slate-700' : 'bg-gray-50 border border-gray-200'}`}>
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
                        const cveLabel = v.cve || v.cve_id;
                        return (
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div className="space-y-1 text-left">
                          <span className={`${theme === 'dark' ? 'text-cyan-300' : 'text-[var(--accent)]'} font-semibold text-xs tracking-wide`}>
                            {cveLabel || "CVE-UNKNOWN"}
                          </span>
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
                        <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-cyan-400/8 text-cyan-300 border border-cyan-400/20' : 'bg-white text-[var(--accent)] border border-[rgba(107,31,58,0.2)]'}`}>
                          CVE: {v.cve || v.cve_id || "UNKNOWN"}
                        </span>
                        <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-violet-400/8 text-violet-300 border border-violet-400/20' : 'bg-white text-[var(--accent)] border border-[rgba(107,31,58,0.2)]'}`}>
                          CVSS: {formatCvssScore(v.cvss_score)}
                        </span>
                        {v.confidence && (
                          <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-slate-700/50 text-slate-200 border border-slate-600' : 'bg-slate-50 text-slate-700 border border-slate-200'}`}>
                            Confidence: {String(v.confidence).toUpperCase()}
                          </span>
                        )}
                        {toArray(v.cwe_ids).length > 0 && (
                          <span className={`rounded-lg px-3 py-1 text-[11px] font-mono font-semibold ${theme === 'dark' ? 'bg-amber-400/8 text-amber-300 border border-amber-400/20' : 'bg-white text-amber-700 border border-amber-200'}`}>
                            CWE: {toArray(v.cwe_ids).join(", ")}
                          </span>
                        )}
                      </div>
                      <div className={`${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'} text-sm leading-6 mt-2 text-left max-w-4xl`}>
                        {v.description || "No description available."}
                      </div>
                      {(v.weakness_summary || toArray(v.cwe_ids).length > 0) && (
                        <div className={`mt-3 rounded-lg px-3 py-3 text-left ${theme === 'dark' ? 'bg-amber-500/6 border border-amber-500/20' : 'bg-amber-50 border border-amber-200'}`}>
                          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-amber-300/80' : 'text-amber-700'}`}>
                            WEAKNESS
                          </div>
                          <div className={`${theme === 'dark' ? 'text-slate-200' : 'text-gray-700'} text-sm leading-6`}>
                            {v.weakness_summary || `Mapped weakness identifiers: ${toArray(v.cwe_ids).join(", ")}`}
                          </div>
                        </div>
                      )}
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
                        <div className={`mt-4 rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-cyan-500/6 border border-cyan-500/20' : 'bg-[rgba(107,31,58,0.04)] border border-[rgba(107,31,58,0.12)]'}`}>
                          <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-cyan-300' : 'text-[var(--accent)]'}`}>SCANNER EXECUTED CHECKS</div>
                          <div className="flex flex-col gap-3">
                            {toArray(v.automated_checks).map((check, index) => (
                              <div key={index} className={`rounded-lg px-3 py-3 ${theme === 'dark' ? 'bg-slate-950/70 border border-slate-800' : 'bg-white border border-[rgba(107,31,58,0.12)]'}`}>
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
                            <pre className={`mt-3 overflow-x-auto rounded-lg px-3 py-3 text-xs ${theme === 'dark' ? 'bg-slate-950 text-cyan-300' : 'bg-white text-[var(--accent)] border border-[rgba(107,31,58,0.12)]'}`}>{v.reproduction}</pre>
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
          <div className={`flex items-center justify-center gap-2 p-3.5 rounded-lg border cursor-pointer transition-all mt-2 ${theme === 'dark' ? 'border-cyan-500/15 bg-cyan-500/[0.03] hover:bg-cyan-500/8' : 'border-[rgba(107,31,58,0.12)] bg-[rgba(107,31,58,0.04)] hover:bg-[rgba(107,31,58,0.08)]'}`}>
            <TerminalIcon size={14} color="#00e5ff" />
            <span className={`${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'} text-sm font-mono`}>View Complete Device Profile</span>
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
            <span className={`text-sm font-mono font-semibold ${theme === 'dark' ? 'text-violet-300' : 'text-[var(--accent)]'}`}>{category?.id || category?.short || "OWASP"}</span>
            {hasFindings && (
              <Badge label={category?.severity || "INFO"} type={severityType} theme={theme} />
            )}
            <span className={`text-[11px] font-semibold uppercase tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>
              {findingsCount} findings
            </span>
          </div>
          <div className={`text-lg font-semibold leading-tight ${theme === 'dark' ? 'text-white' : 'text-slate-900'}`}>{category?.title || "OWASP Category"}</div>
          <div className={`${theme === 'dark' ? 'text-slate-400' : 'text-slate-600'} text-xs leading-5 max-w-2xl`}>
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
                : 'border-[rgba(107,31,58,0.2)] bg-white text-[var(--accent)] hover:bg-[rgba(107,31,58,0.05)]'
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
                      <div className={`${theme === 'dark' ? 'text-violet-200' : 'text-[var(--accent)]'} text-xs font-semibold`}>{finding?.title || "Finding"}</div>
                      <div className={`${theme === 'dark' ? 'text-slate-300' : 'text-slate-700'} text-xs leading-5`}>{finding?.description || finding?.evidence || "No details provided."}</div>
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
                        : 'bg-slate-100 text-[var(--accent)]'
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
                    <pre className={`mt-3 overflow-x-auto rounded-lg px-3 py-3 text-xs ${theme === 'dark' ? 'bg-slate-950 text-cyan-300' : 'bg-slate-50 text-[var(--accent)] border border-slate-200'}`}>{finding.request}</pre>
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
                        <pre className={`mt-3 overflow-x-auto rounded-lg px-3 py-3 text-xs ${theme === 'dark' ? 'bg-slate-950 text-cyan-300' : 'bg-white text-[var(--accent)] border border-[rgba(107,31,58,0.12)]'}`}>{finding.reproduction}</pre>
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
export default function Vulns({ scanData, theme, selectedTarget, resetNonce = 0 }) {
  const [persistedScanData, setPersistedScanData] = useState(() => {
    try {
      const stored = localStorage.getItem(LAST_SCAN_STORAGE_KEY);
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });
  const [isPersistedScanValidated, setIsPersistedScanValidated] = useState(() => !persistedScanData);

  useEffect(() => {
    if (scanData) {
      setPersistedScanData(scanData);
      setIsPersistedScanValidated(true);
      try {
        localStorage.setItem(LAST_SCAN_STORAGE_KEY, JSON.stringify(scanData));
      } catch {
        // Ignore storage failures so the live scan view still renders.
      }
    }
  }, [scanData]);

  useEffect(() => {
    if (!resetNonce) return;
    setPersistedScanData(null);
    setIsPersistedScanValidated(true);
    try {
      localStorage.removeItem(LAST_SCAN_STORAGE_KEY);
    } catch {
      // Ignore storage failures so the view can still reset in memory.
    }
  }, [resetNonce]);

  useEffect(() => {
    if (scanData || !persistedScanData) {
      setIsPersistedScanValidated(true);
      return;
    }

    let cancelled = false;
    setIsPersistedScanValidated(false);

    const validatePersistedScan = async () => {
      try {
        const response = await fetch(`${API_BASE}/stats`, { cache: "no-store" });
        if (!response.ok) throw new Error("Failed to fetch stats");
        const data = await response.json();
        const history = Array.isArray(data?.scan_history) ? data.scan_history : [];

        if (cancelled) return;

        if (history.length === 0) {
          setPersistedScanData(null);
          try {
            localStorage.removeItem(LAST_SCAN_STORAGE_KEY);
          } catch {
            // Ignore storage failures so the page can still show the empty state.
          }
        }
      } catch {
        // If stats validation fails, keep the persisted view instead of blanking unexpectedly.
      } finally {
        if (!cancelled) {
          setIsPersistedScanValidated(true);
        }
      }
    };

    validatePersistedScan();

    return () => {
      cancelled = true;
    };
  }, [scanData, persistedScanData]);

  const effectiveScanData = scanData || (isPersistedScanValidated ? persistedScanData : null);
  const hosts = Array.isArray(effectiveScanData?.assets) ? effectiveScanData.assets : [];
  const inventory = effectiveScanData?.asset_inventory || {};
  const inventorySubdomains = toArray(inventory.subdomains);
  const inventoryServices = toArray(inventory.services);
  const domainIntelligence = inventory.domain_intelligence || {};
  const networkMap = inventory.network_map || {};
  const trafficAnalysis = effectiveScanData?.traffic_analysis || {};
  const protocolUsage = toArray(trafficAnalysis.protocol_usage);
  const suspiciousTraffic = toArray(trafficAnalysis.suspicious_traffic);
  const malwarePatterns = toArray(trafficAnalysis.malware_patterns);
  const ticketExport = effectiveScanData?.ticket_export || {};
  const exportedTickets = toArray(ticketExport.tickets);
  const scanProfile = effectiveScanData?.scan_profile || {};

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
      <div className={`relative z-0 min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'text-[var(--text)]'}`} style={theme === 'dark' ? { fontFamily: "'Segoe UI',system-ui,sans-serif" } : { fontFamily: "'Segoe UI',system-ui,sans-serif", backgroundColor: LIGHT_MAROON_PAGE_BG }}>
        <style>{`html,body,#root{background:${theme === 'dark' ? '#0a0d14' : LIGHT_MAROON_PAGE_BG};min-height:100vh;}`}</style>
        <BlobBg />
        <main className="relative z-10 w-full max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-7 text-left">
          <div className={`mb-6 p-4 rounded-xl border ${theme === 'dark' ? 'border-amber-500/40 bg-[#0f1523]/90 text-amber-300' : 'border-amber-300 bg-white text-amber-700'}`}>
            <strong>No scan data yet.</strong> Run a scan first, then this page will show only that scanned target and keep it after refresh.
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className={`relative z-0 min-h-screen ${theme === 'dark' ? 'bg-[#0a0d14] text-slate-200' : 'text-[var(--text)]'}`} style={theme === 'dark' ? { fontFamily: "'Segoe UI',system-ui,sans-serif" } : { fontFamily: "'Segoe UI',system-ui,sans-serif", backgroundColor: LIGHT_MAROON_PAGE_BG }}>
      <style>{`html,body,#root{background:${theme === 'dark' ? '#0a0d14' : LIGHT_MAROON_PAGE_BG};min-height:100vh;}`}</style>
      <BlobBg />

      <main className="relative z-10 w-full max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 py-4 text-left">

        {/* Query bar */}
        <div className={`sticky top-0 z-30 backdrop-blur-md ${theme === 'dark' ? 'bg-transparent' : 'bg-transparent'} pb-2 pt-2 mb-8`}>
          <div className="mx-auto max-w-[1400px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`font-mono text-2xl font-normal tracking-wide ${theme === 'dark' ? 'text-cyan-300' : 'text-[var(--accent)]'}`}>
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
          <div className={`${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-400/45 text-slate-200 shadow-[0_0_0_1px_rgba(34,211,238,0.12)]' : 'bg-white border-[rgba(107,31,58,0.35)] text-gray-900'} rounded-xl px-4 py-3.5 border shadow-sm`}>
            <div className={`flex items-center gap-1.5 text-[11px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'} mb-3`}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke={theme === 'dark' ? '#22d3ee' : '#6b1f3a'} strokeWidth="2">
                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
              </svg>
              HOSTS UP
            </div>
            <div className={`text-2xl font-bold font-mono ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>{hostsUp}</div>
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
            className={`rounded-lg px-3 py-2 text-white text-xs font-medium ${downloadingFormat ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
            style={{ background: "#6b1f3a" }}
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

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 mb-6">
          <div className={`rounded-xl p-5 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-cyan-500/10 text-slate-200' : 'bg-white border-gray-200 text-gray-900'}`}>
            <div className={`flex items-center gap-2.5 text-xs font-bold tracking-widest mb-3.5 ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>
              <span className={`w-0.5 h-4 rounded flex-shrink-0 ${theme === 'dark' ? 'bg-cyan-400' : 'bg-[var(--accent)]'}`} />
              ASSET INVENTORY
            </div>
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
                <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No subdomains discovered. This can mean DNS brute-force found nothing or the scan target did not resolve matching subdomains.</span>
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

          <div className={`rounded-xl p-5 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-violet-500/10 text-slate-200' : 'bg-white border-gray-200 text-gray-900'}`}>
            <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-violet-400 mb-3.5">
              <span className="w-0.5 h-4 rounded bg-violet-400 flex-shrink-0" />
              TRAFFIC ANALYSIS
            </div>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div>
                <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>STATUS</div>
                <div className={`mt-1 text-sm font-semibold ${trafficAnalysis.enabled ? 'text-emerald-400' : theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>{trafficAnalysis.enabled ? "Enabled" : "Unavailable"}</div>
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
                <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>{trafficAnalysis.note || "No traffic telemetry captured. Scapy may be unavailable or no packets were seen during the capture window."}</span>
              ) : (
                protocolUsage.map((item, index) => (
                  <div key={`${item?.protocol || "protocol"}-${index}`} className="flex items-center justify-between gap-3">
                    <span className={`text-sm font-mono ${theme === 'dark' ? 'text-violet-300' : 'text-[var(--accent)]'}`}>{item.protocol}</span>
                    <span className={`text-xs font-mono ${theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>{item.count}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className={`rounded-xl p-5 border ${theme === 'dark' ? 'bg-[#0f1523]/90 border-amber-500/10 text-slate-200' : 'bg-white border-gray-200 text-gray-900'}`}>
            <div className="flex items-center gap-2.5 text-xs font-bold tracking-widest text-amber-400 mb-3.5">
              <span className="w-0.5 h-4 rounded bg-amber-400 flex-shrink-0" />
              EXPORT AND PROFILE
            </div>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div>
                <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>TICKETS</div>
                <div className={`mt-1 text-2xl font-black font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-600'}`}>{ticketExport.count ?? exportedTickets.length}</div>
              </div>
              <div>
                <div className={`text-[10px] font-bold tracking-widest ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>CREDENTIAL CHECK</div>
                <div className={`mt-1 text-sm font-semibold ${scanProfile.include_credential_scan ? 'text-emerald-400' : theme === 'dark' ? 'text-slate-300' : 'text-gray-700'}`}>{scanProfile.include_credential_scan ? "Enabled" : "Disabled"}</div>
              </div>
            </div>
            <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>TICKET PREVIEW</div>
            <div className="space-y-2 mb-4 max-h-44 overflow-auto pr-1">
              {exportedTickets.length === 0 ? (
                <span className={`${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'} text-sm`}>No ticket export payload was generated.</span>
              ) : (
                exportedTickets.slice(0, 6).map((ticket, index) => (
                  <div key={`${ticket?.title || "ticket"}-${index}`} className={`rounded-md px-3 py-2 border ${theme === 'dark' ? 'border-white/5 bg-white/[0.02]' : 'border-gray-200 bg-gray-50'}`}>
                    <div className={`text-sm font-semibold ${theme === 'dark' ? 'text-slate-100' : 'text-gray-900'}`}>{ticket.title || "Untitled finding"}</div>
                    <div className={`mt-1 text-xs font-mono ${theme === 'dark' ? 'text-amber-300' : 'text-amber-700'}`}>{ticket.asset || "asset"} | {ticket.severity || "UNKNOWN"} | Score {ticket.priority_score ?? 0}</div>
                  </div>
                ))
              )}
            </div>
            <div className={`text-[10px] font-bold tracking-widest mb-2 ${theme === 'dark' ? 'text-slate-500' : 'text-gray-500'}`}>SCAN PROFILE</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(scanProfile).map(([key, value]) => (
                <span key={key} className={`px-2.5 py-1 rounded-full text-xs border ${theme === 'dark' ? 'border-slate-700 bg-slate-900/70 text-slate-300' : 'border-gray-200 bg-gray-50 text-gray-700'}`}>
                  {formatLabel(key)}: {typeof value === "boolean" ? (value ? "On" : "Off") : String(value)}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="mb-4">
          <div className={`flex items-center gap-2 text-xs font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-cyan-400' : 'text-[var(--accent)]'}`}>
            <span className={`w-0.5 h-4 rounded ${theme === 'dark' ? 'bg-cyan-400' : 'bg-[var(--accent)]'}`} />
            SCANNED HOST RESULTS
          </div>
          <p className={`mt-2 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>
            Expand a result card to view ports, services, and vulnerability details.
          </p>
        </div>
        <div className="flex flex-col gap-4">
          {displayedHosts.map((host, index) => {
            const foundPorts = host.open_ports?.length ?? host.ports?.length ?? 0;
            const computedStatus = host.status || (foundPorts > 0 ? "UP" : "DOWN");
            const isSelected = normalizedTarget && hostMatchesTarget(host, normalizedTarget);
            const hostIp = host.resolved_ip || host.ip;
            const relatedSubdomains = inventorySubdomains.filter((item) => item?.resolved_ip && item.resolved_ip === hostIp);

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
                hostname: host.domain || host.hostname || host.resolved_ip || "Unknown",
                ipAddress: host.ip || host.resolved_ip || "Unknown",
                displayHostname: host.domain || host.hostname || host.resolved_ip || host.ip || host.input || "Unknown",
                deviceType: host.device_type || "Unknown Device",
                insecureProtocols: host.insecure_protocols || host.insecureProtocols || [],
                tlsIssues: host.tls_issues || host.tlsIssues || [],
                vulnerabilities: host.vulnerabilities || [],
                credentialScan: host.credential_scan || host.credentialScan || null,
                riskSummary: host.risk_summary || host.riskSummary || null,
                relatedSubdomains,
                domainIntelligence,
                defaultExpanded: false,
                }} />
            );
          })}
        </div>
        <div className={`mt-6 overflow-hidden rounded-[28px] border px-4 py-4 sm:px-6 ${theme === 'dark' ? 'border-violet-400/20 bg-[#0f1523]/90' : 'border-violet-100 bg-white'}`}>
          <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
            <div className="max-w-3xl">
              <div className={`text-[11px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-violet-300' : 'text-[var(--accent)]'}`}>OWASP TOP 10</div>
              <p className={`mt-3 text-xs ${theme === 'dark' ? 'text-slate-400' : 'text-gray-600'}`}>
                {owasp.enabled
                  ? `Scanned target URL: ${owasp.normalizedUrl || 'N/A'}`
                  : "OWASP application checks run only for domain or URL based targets."}
              </p>
            </div>
            <div className="flex flex-wrap items-start justify-end gap-3">
              <div className={`min-w-[132px] rounded-xl px-5 py-3 ${theme === 'dark' ? 'bg-violet-400/6 text-violet-200 ring-1 ring-violet-400/15' : 'bg-white text-[var(--accent)] ring-1 ring-[rgba(107,31,58,0.12)] shadow-sm'}`}>
                <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>CATEGORIES</div>
                <div className="mt-1 text-2xl font-mono font-bold">{owasp.totalCategories}</div>
              </div>
              <div className={`min-w-[132px] rounded-xl px-5 py-3 ${theme === 'dark' ? 'bg-amber-400/6 text-amber-200 ring-1 ring-amber-400/15' : 'bg-white text-amber-700 ring-1 ring-amber-100 shadow-sm'}`}>
                <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>WITH FINDINGS</div>
                <div className="mt-1 text-2xl font-mono font-bold">{owasp.categoriesWithFindings}</div>
              </div>
              <div className={`min-w-[132px] rounded-xl px-5 py-3 ${theme === 'dark' ? 'bg-rose-400/6 text-rose-200 ring-1 ring-rose-400/15' : 'bg-white text-rose-700 ring-1 ring-rose-100 shadow-sm'}`}>
                <div className={`text-[10px] font-bold tracking-[0.18em] ${theme === 'dark' ? 'text-slate-500' : 'text-slate-400'}`}>TOTAL FINDINGS</div>
                <div className="mt-1 text-2xl font-mono font-bold">{owasp.totalFindings}</div>
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

      </main>
    </div>
  );
}
