import React, { useEffect, useRef, useState } from "react";
import shadowLogo from "../assets/Shadow_logo2.png";
import "./LandingPage.css";

/* ── Blob canvas (same palette, calmer movement) ── */
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
      { x: W * 0.15, y: H * 0.3,  r: 380, color: "#1a1a2e", vx: 0.08, vy: 0.06 },
      { x: W * 0.80, y: H * 0.65, r: 320, color: "#6b1f3a", vx: -0.07, vy: 0.09 },
      { x: W * 0.50, y: H * 0.10, r: 220, color: "#e8d5c4", vx: 0.06, vy: -0.05 },
      { x: W * 0.90, y: H * 0.10, r: 200, color: "#6b1f3a", vx: -0.05, vy: 0.08 },
    ];

    let raf;
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = "#f5f0e8";
      ctx.fillRect(0, 0, W, H);
      blobs.forEach(b => {
        b.x += b.vx; b.y += b.vy;
        if (b.x < -b.r) b.x = W + b.r; if (b.x > W + b.r) b.x = -b.r;
        if (b.y < -b.r) b.y = H + b.r; if (b.y > H + b.r) b.y = -b.r;
        const g = ctx.createRadialGradient(b.x, b.y, 0, b.x, b.y, b.r);
        g.addColorStop(0, b.color + "40");
        g.addColorStop(1, b.color + "00");
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2); ctx.fill();
      });
      // hex grid
      ctx.strokeStyle = "rgba(26,26,46,0.04)";
      ctx.lineWidth = 0.7;
      const size = 42;
      const rows = Math.ceil(H / (size * 1.73)) + 2;
      const cols = Math.ceil(W / (size * 2)) + 2;
      for (let r = -1; r < rows; r++) {
        for (let c = -1; c < cols; c++) {
          const cx = c * size * 2 + (r % 2) * size + size;
          const cy = r * size * 1.73 + size;
          ctx.beginPath();
          for (let a = 0; a < 6; a++) {
            const angle = (Math.PI / 3) * a - Math.PI / 6;
            const px = cx + size * 0.88 * Math.cos(angle);
            const py = cy + size * 0.88 * Math.sin(angle);
            a === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
          }
          ctx.closePath(); ctx.stroke();
        }
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);
  return <canvas ref={ref} className="landing-blob-canvas" />;
}

/* ── Typewriter cycling headline ── */
const THREATS = [
  "SQL Injections.",
  "Zero-Day Exploits.",
  "Exposed Credentials.",
];

function CyclingTypewriter() {
  const [index, setIndex] = useState(0);
  const [displayed, setDisplayed] = useState("");
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const word = THREATS[index];
    if (!deleting) {
      if (displayed.length < word.length) {
        const t = setTimeout(() => setDisplayed(word.slice(0, displayed.length + 1)), 65);
        return () => clearTimeout(t);
      } else {
        const t = setTimeout(() => setDeleting(true), 1800);
        return () => clearTimeout(t);
      }
    } else {
      if (displayed.length > 0) {
        const t = setTimeout(() => setDisplayed(displayed.slice(0, -1)), 38);
        return () => clearTimeout(t);
      } else {
        setDeleting(false);
        setIndex(i => (i + 1) % THREATS.length);
      }
    }
  }, [displayed, deleting, index]);

  return (
    <span className="cycling-word">
      {displayed}<span className="tw-cursor">|</span>
    </span>
  );
}

/* ── Count-up ── */
function CountUp({ target, suffix, prefix = "" }) {
  const [val, setVal] = useState(0);
  const ref = useRef(null);
  useEffect(() => {
    const obs = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return;
      obs.disconnect();
      let start = 0;
      const step = Math.ceil(target / 70);
      const id = setInterval(() => {
        start += step;
        if (start >= target) { setVal(target); clearInterval(id); }
        else setVal(start);
      }, 20);
    }, { threshold: 0.4 });
    if (ref.current) obs.observe(ref.current);
    return () => obs.disconnect();
  }, [target]);
  return <span ref={ref}>{prefix}{val.toLocaleString()}{suffix}</span>;
}

/* ── Feature card ── */
function FeatureCard({ number, title, desc, detail }) {
  return (
    <div className="feat-card">
      <span className="feat-num">{number}</span>
      <div className="feat-divider" />
      <h3 className="feat-title">{title}</h3>
      <p className="feat-desc">{desc}</p>
      <p className="feat-detail">{detail}</p>
    </div>
  );
}

export default function LandingPage({ onEnter, onGoAuth }) {
  return (
    <div className="landing landing-visible">
      <BlobBg />

      <nav className="nav">
        <div className="nav-brand">
          <div>
            <img src={shadowLogo} alt="ShadowTrace" className="brand-icon" />
          </div>
        </div>
        <button className="btn-login" onClick={onGoAuth}>Login →</button>
      </nav>

      <section className="hero">
        <div className="hero-inner">
          <div className="hero-badge">
            <span className="badge-pip" />
            Powered by Kristellar Cyberspace
          </div>

          <h1 className="hero-h1">
            We Find <br />
            <CyclingTypewriter />
            <br />
            <span className="hero-h1-sub">Before Attackers Do.</span>
          </h1>

          <p className="hero-p">
            VulnScan AI continuously scans your infrastructure, APIs, and codebase —
            surfacing critical vulnerabilities with full CVSS scoring and
            actionable remediation in real time.
          </p>

          <div className="hero-actions">
            <button className="btn-primary" onClick={onEnter}>Request Early Access</button>
            <button className="btn-text" onClick={(e) => e.preventDefault()}>See How It Works ↓</button>
          </div>

          <div className="scan-bar-wrap">
            <div className="scan-bar-track">
              <div className="scan-bar-fill" />
            </div>
            <span className="scan-bar-label">CONTINUOUS SCAN ACTIVE</span>
          </div>
        </div>

        <div className="hero-card">
          <div className="hcard-header">
            <span className="hcard-dot red" /><span className="hcard-dot yellow" /><span className="hcard-dot green" />
            <span className="hcard-title">threat-report.log</span>
          </div>
          <div className="hcard-body">
            {[
              { sev: "CRIT", msg: "RCE vector — port 8443", color: "#6b1f3a" },
              { sev: "HIGH", msg: "SQLi found — /api/users", color: "#c0622a" },
              { sev: "HIGH", msg: "CVE-2024-3400 matched", color: "#c0622a" },
              { sev: "MED",  msg: "TLS 1.0 still active",  color: "#d4a853" },
              { sev: "LOW",  msg: "Missing X-Frame header", color: "#8a7a6a" },
            ].map(({ sev, msg, color }) => (
              <div className="hcard-row" key={msg}>
                <span className="hcard-sev" style={{ color }}>{sev}</span>
                <span className="hcard-msg">{msg}</span>
              </div>
            ))}
          </div>
          <div className="hcard-footer">
            <span>5 findings · 2 critical</span>
            <span className="hcard-status">● Live</span>
          </div>
        </div>
      </section>

      <section className="stats">
        {[
          { n: 2400000, suf: "+", pre: "", label: "Scans Per Month" },
          { n: 99,      suf: ".7%", pre: "", label: "Detection Rate" },
          { n: 340,     suf: "ms",  pre: "<", label: "Avg. Response Time" },
          { n: 12000,   suf: "+",  pre: "", label: "CVEs Tracked" },
        ].map(({ n, suf, pre, label }) => (
          <div className="stat-block" key={label}>
            <span className="stat-num"><CountUp target={n} suffix={suf} prefix={pre} /></span>
            <span className="stat-label">{label}</span>
            <div className="stat-line" />
          </div>
        ))}
      </section>

      <section className="features">
        <div className="features-header">
          <span className="section-tag">// CORE CAPABILITIES</span>
          <h2 className="section-h2">Built for Modern <br /><em>Security Teams</em></h2>
        </div>
        <div className="feat-grid">
          <FeatureCard
            number="01"
            title="Neural Threat Detection"
            desc="Our AI model analyzes traffic patterns, dependency trees, and code paths to surface zero-days missed by signature scanners."
            detail="Covers OWASP Top 10, CVE library, and custom rule sets."
          />
          <FeatureCard
            number="02"
            title="Continuous Attack Surface Monitoring"
            desc="Live inventory of exposed ports, subdomains, APIs, and cloud assets. Instant alerts the moment a new vector appears."
            detail="Integrates with AWS, GCP, Azure, and on-premise infrastructure."
          />
          <FeatureCard
            number="03"
            title="Instant Remediation Intelligence"
            desc="Every finding ships with a CVSS score, exploit probability, and AI-generated fix guidance tailored to your exact stack."
            detail="Auto-generate PRs to GitHub or GitLab with one click."
          />
        </div>
      </section>

      <section className="cta-section">
        <div className="cta-inner">
          <span className="section-tag">// GET STARTED</span>
          <h2 className="cta-h2">Your Infrastructure Has <br /><em>Vulnerabilities Right Now.</em></h2>
          <p className="cta-p">Join the waitlist. Be first to secure your stack with VulnScan AI.</p>
          <form className="cta-form" onSubmit={(e) => { e.preventDefault(); onEnter(); }}>
            <input type="email" placeholder="your@company.com" className="cta-input" />
            <button type="submit" className="btn-primary">Join Waitlist</button>
          </form>
          <p className="cta-fine">No credit card. No commitment. Early access only.</p>
        </div>
        <div className="cta-deco">
          <div className="deco-ring r1" />
          <div className="deco-ring r2" />
          <div className="deco-ring r3" />
          <span className="deco-label">SCANNING</span>
        </div>
      </section>

      <footer className="mini-footer">
        <span>© 2025 Kristellar Cyberspace Private Limited. All rights reserved.</span>
        <span className="footer-pip"><span className="badge-pip sm" /> Systems Operational</span>
      </footer>
    </div>
  );
}
