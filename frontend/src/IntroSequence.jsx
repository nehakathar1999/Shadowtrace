import { useEffect, useRef, useState } from "react";
import "./IntroSequence.css";

/* ── typewriter hook ── */
function useTypewriter(text, speed, startDelay, active) {
  const [displayed, setDisplayed] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!active) return;
    setDisplayed("");
    setDone(false);
    let i = 0;
    let id;
    const startTimer = setTimeout(() => {
      id = setInterval(() => {
        i++;
        setDisplayed(text.slice(0, i));
        if (i >= text.length) {
          clearInterval(id);
          setDone(true);
        }
      }, speed);
    }, startDelay);

    return () => {
      clearTimeout(startTimer);
      if (id) clearInterval(id);
    };
  }, [text, speed, startDelay, active]);

  return { displayed, done };
}

/* ── Animated blob background (canvas) ── */
function BlobCanvas() {
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
      { x: W * 0.25, y: H * 0.35, r: 320, color: "#1a1a2e", vx: 0.18, vy: 0.12 },
      { x: W * 0.72, y: H * 0.55, r: 280, color: "#6b1f3a", vx: -0.14, vy: 0.16 },
      { x: W * 0.55, y: H * 0.2,  r: 200, color: "#e8d5c4", vx: 0.10, vy: -0.10 },
      { x: W * 0.15, y: H * 0.75, r: 240, color: "#6b1f3a", vx: 0.12, vy: -0.14 },
      { x: W * 0.82, y: H * 0.22, r: 180, color: "#1a1a2e", vx: -0.16, vy: 0.12 },
    ];

    let raf;
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = "#f5f0e8";
      ctx.fillRect(0, 0, W, H);

      blobs.forEach(b => {
        b.x += b.vx;
        b.y += b.vy;
        if (b.x < -b.r) b.x = W + b.r;
        if (b.x > W + b.r) b.x = -b.r;
        if (b.y < -b.r) b.y = H + b.r;
        if (b.y > H + b.r) b.y = -b.r;

        const g = ctx.createRadialGradient(b.x, b.y, 0, b.x, b.y, b.r);
        g.addColorStop(0, b.color + "55");
        g.addColorStop(1, b.color + "00");
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(b.x, b.y, b.r, 0, Math.PI * 2);
        ctx.fill();
      });

      ctx.strokeStyle = "rgba(26,26,46,0.045)";
      ctx.lineWidth = 0.8;
      const size = 38;
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

  return <canvas ref={ref} className="blob-canvas" />;
}

/* ── main intro ── */
export default function IntroSequence({ onComplete }) {
  const [phase, setPhase] = useState(0);
  const [scannerActive, setScannerActive] = useState(false);
  const [exiting, setExiting] = useState(false);
  const [loadPct, setLoadPct] = useState(0);

  const line1 = useTypewriter("Kristellar Cyberspace Private Limited", 55, 1000, phase >= 0);
  const line3 = useTypewriter("AI-Powered Vulnerability Intelligence", 45, 0, phase >= 3);

  useEffect(() => {
    if (line1.done && phase === 0) {
      const t = setTimeout(() => setPhase(1), 600);
      return () => clearTimeout(t);
    }
  }, [line1.done, phase]);

  useEffect(() => {
    if (phase === 1) {
      const t = setTimeout(() => setPhase(2), 1000);
      return () => clearTimeout(t);
    }
  }, [phase]);

  useEffect(() => {
    if (phase === 2) {
      const t = setTimeout(() => setPhase(3), 700);
      return () => clearTimeout(t);
    }
  }, [phase]);

  useEffect(() => {
    if (line3.done && phase === 3) {
      const t = setTimeout(() => {
        setScannerActive(true);
      }, 900);
      return () => clearTimeout(t);
    }
  }, [line3.done, phase]);

  useEffect(() => {
    let id;
    if (!scannerActive) return;
    const t = setTimeout(() => {
      setExiting(true);
      id = setTimeout(onComplete, 900);
    }, 1100);
    return () => {
      clearTimeout(t);
      if (id) clearTimeout(id);
    };
  }, [scannerActive, onComplete]);

  useEffect(() => {
    let pct = 0;
    const id = setInterval(() => {
      pct += Math.random() * 3.5 + 0.5;
      if (pct >= 100) {
        pct = 100;
        clearInterval(id);
      }
      setLoadPct(Math.min(100, Math.round(pct)));
    }, 120);
    return () => clearInterval(id);
  }, []);

  const filled = Math.round(loadPct / 10);
  const loadBar = "█".repeat(filled) + "░".repeat(10 - filled);

  return (
    <div className={`intro ${exiting ? "intro-exit" : ""}`}>
      <BlobCanvas />

      <div className="intro-center">
        <p className="intro-company">
          {line1.displayed}
          {phase === 0 && <span className="cursor">|</span>}
        </p>

        <p className={`intro-presents ${phase >= 1 ? "visible" : ""}`}>
          proudly presents
        </p>

        <div className={`intro-product ${phase >= 2 ? "visible" : ""}`}>
          <span className="product-word">SHADOW</span>
          <span className="product-word accent-word">TRACE</span>
          {/* <span className="product-ai"> AI</span> */}
          {phase >= 2 && <div className="product-glow" />}
        </div>

        <p className="intro-tagline">
          {phase >= 3 && (
            <>
              {line3.displayed}
              {!line3.done && <span className="cursor">|</span>}
            </>
          )}
        </p>
      </div>

      {scannerActive && <div className="scanner-line" />}

      <div className="intro-loader">
        <span className="loader-label">INITIALIZING THREAT ENGINE</span>
        <span className="loader-bar">[{loadBar}] {loadPct}%</span>
      </div>
    </div>
  );
}
