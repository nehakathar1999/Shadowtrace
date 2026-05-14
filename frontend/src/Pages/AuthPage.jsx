import { useState, useEffect, useRef } from "react";
import { API_BASE } from "../lib/api";

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

  return <canvas ref={ref} className="auth-blob-canvas" />;
}

const EyeIcon = ({ open }) => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    {open ? (
      <>
        <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" />
        <circle cx="12" cy="12" r="3" />
      </>
    ) : (
      <>
        <path d="m3 3 18 18" />
        <path d="M10.58 10.58A2 2 0 0 0 12 14a2 2 0 0 0 1.42-.58" />
        <path d="M9.88 5.09A10.94 10.94 0 0 1 12 5c6.5 0 10 7 10 7a17.6 17.6 0 0 1-3.04 3.81" />
        <path d="M6.61 6.61C4.62 8 3.33 10.11 2 12c0 0 3.5 7 10 7a9.77 9.77 0 0 0 4.23-.93" />
      </>
    )}
  </svg>
);

function Field({ label, children, right }) {
  return (
    <label className="block">
      <div className="mb-1.5 flex items-center justify-between gap-3">
        <span style={{ fontSize: '13px', fontWeight: '500', color: 'var(--text)', fontFamily: 'var(--heading)' }}>{label}</span>
        {right}
      </div>
      {children}
    </label>
  );
}

function PasswordInput({ value, onChange, placeholder, visible, onToggle, className }) {
  return (
    <div className="relative">
      <input
        type={visible ? "text" : "password"}
        value={value}
        onChange={onChange}
        style={{
          width: '100%',
          borderRadius: '8px',
          border: '1.5px solid var(--border)',
          background: 'rgba(245,240,232,0.8)',
          padding: '13px 18px',
          fontSize: '14px',
          color: 'var(--text)',
          outline: 'none',
          transition: 'border-color 0.2s',
          fontFamily: 'var(--sans)',
        }}
        placeholder={placeholder}
      />
      <button
        type="button"
        onClick={onToggle}
        aria-label={visible ? "Hide password" : "Show password"}
        style={{
          position: 'absolute',
          right: '8px',
          top: '50%',
          transform: 'translateY(-50%)',
          borderRadius: '6px',
          padding: '6px',
          color: 'var(--text-dim)',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          transition: 'color 0.2s',
        }}
      >
        <EyeIcon open={visible} />
      </button>
    </div>
  );
}

function getPasswordRequirementState(password) {
  const value = String(password || "");
  return {
    hasUppercase: /[A-Z]/.test(value),
    hasNumber: /\d/.test(value),
    hasSymbol: /[^A-Za-z0-9]/.test(value),
  };
}

function isStrongPassword(password) {
  const requirements = getPasswordRequirementState(password);
  return requirements.hasUppercase && requirements.hasNumber && requirements.hasSymbol;
}

function PasswordRequirements({ password }) {
  const requirements = getPasswordRequirementState(password);
  const items = [
    { label: "At least one capital letter", met: requirements.hasUppercase },
    { label: "At least one number", met: requirements.hasNumber },
    { label: "At least one symbol", met: requirements.hasSymbol },
  ];

  return (
    <div style={{
      borderRadius: '16px',
      border: '1px solid var(--border-hi)',
      background: 'rgba(245,240,232,0.92)',
      padding: '16px',
      fontSize: '14px',
      color: 'var(--text)',
    }}>
      <div style={{ fontWeight: '700', marginBottom: '8px', color: 'var(--text)' }}>Password must include:</div>
      <div style={{ marginTop: '8px', display: 'grid', gap: '8px' }}>
        {items.map((item) => (
          <div key={item.label} style={{ color: item.met ? 'var(--accent)' : 'var(--text-dim)' }}>
            {item.met ? '✓' : '•'} {item.label}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AuthPage({ onBack, onAuthSuccess }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
    newPassword: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);

  const isSignup = mode === "signup";
  const isCompactMode = mode === "login" || mode === "signup";
  const isLogin = mode === "login";
  const shouldShowPasswordRequirements =
    (mode === "signup" && form.password.length > 0 && !isStrongPassword(form.password)) ||
    (mode === "forgot" && form.newPassword.length > 0 && !isStrongPassword(form.newPassword));
  const authCardClassName = "relative w-full max-w-[420px] rounded-[30px] border backdrop-blur-xl mx-auto px-8 py-8";
  const inputClassName =
    "w-full rounded-[14px] border border-[rgba(107,31,58,0.18)] bg-[#fff9f2] px-4 py-3 text-base text-[var(--text)] outline-none shadow-[inset_0_1px_1px_rgba(26,26,46,0.06)] transition placeholder:text-[rgba(26,26,46,0.35)] focus:border-[rgba(107,31,58,0.7)] focus:ring-1 focus:ring-[rgba(212,168,83,0.18)]";

  const updateField = (key, value) => {
    setForm((current) => ({ ...current, [key]: value }));
    setError("");
    setSuccess("");
  };

  const switchMode = (nextMode) => {
    setMode(nextMode);
    setError("");
    setSuccess("");
  };

  const submit = async (event) => {
    event.preventDefault();

    if (mode === "forgot") {
      if (!form.email.trim() || !form.newPassword.trim()) {
        setError("Email and new password are required.");
        return;
      }
      if (form.newPassword.length < 6) {
        setError("New password must be at least 6 characters.");
        return;
      }
      if (!isStrongPassword(form.newPassword)) {
        setError("Password must contain at least one capital letter, one number, and one symbol.");
        return;
      }
    } else {
      if (!form.email.trim() || !form.password.trim()) {
        setError("Email and password are required.");
        return;
      }
      if (mode === "signup" && !form.name.trim()) {
        setError("Full name is required.");
        return;
      }
      if (mode === "signup" && form.password !== form.confirmPassword) {
        setError("Passwords do not match.");
        return;
      }
      if (mode === "signup" && !isStrongPassword(form.password)) {
        setError("Password must contain at least one capital letter, one number, and one symbol.");
        return;
      }
    }

    setIsSubmitting(true);
    try {
      const endpoint =
        mode === "login"
          ? "/auth/login"
          : mode === "signup"
            ? "/auth/signup"
            : "/auth/forgot-password";

      const payload =
        mode === "login"
          ? {
              email: form.email.trim(),
              password: form.password,
            }
          : mode === "signup"
            ? {
                name: form.name.trim(),
                email: form.email.trim(),
                password: form.password,
              }
            : {
                email: form.email.trim(),
                new_password: form.newPassword,
              };

      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        setError(data?.detail || data?.error || "Authentication failed.");
        return;
      }

      if (mode === "forgot") {
        setSuccess(data?.message || "Password updated successfully.");
        setForm((current) => ({
          ...current,
          password: "",
          confirmPassword: "",
          newPassword: "",
        }));
        setMode("login");
        return;
      }

      onAuthSuccess(data.user);
    } catch {
      setError("Unable to connect to the server. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="relative min-h-screen overflow-hidden px-5 py-6 sm:px-8" style={{ background: 'linear-gradient(180deg, #f9f2e6 0%, #f5f0e8 60%, #fff9f0 100%)', color: 'var(--text)' }}>
      <style>{`
        input:-webkit-autofill,
        input:-webkit-autofill:hover,
        input:-webkit-autofill:focus,
        textarea:-webkit-autofill,
        textarea:-webkit-autofill:hover,
        textarea:-webkit-autofill:focus {
          box-shadow: 0 0 0px 1000px rgba(245,240,232,0.95) inset !important;
          -webkit-text-fill-color: #1a1a2e !important;
          transition: background-color 5000s ease-in-out 0s;
        }
      `}</style>
      <BlobBg />
      <div className="relative mx-auto flex min-h-[calc(100vh-3rem)] w-full max-w-[720px] items-center justify-center">
        <div
          className={authCardClassName}
          style={{
            background: 'linear-gradient(180deg, rgba(255,250,246,0.98), rgba(245,240,232,0.96))',
            border: '1px solid rgba(107,31,58,0.18)',
            boxShadow: '0 32px 90px rgba(107,31,58,0.12)',
          }}
        >
          <button
            onClick={onBack}
            className="absolute inline-flex items-center gap-2 rounded-full transition"
            style={{
              position: 'absolute',
              top: '16px',
              left: '16px',
              border: '1.5px solid var(--border-hi)',
              background: 'rgba(26,26,46,0.06)',
              color: 'var(--text)',
              fontSize: '12px',
              fontWeight: '600',
              padding: '8px 14px',
              cursor: 'pointer',
              fontFamily: 'var(--heading)',
              backdropFilter: 'blur(8px)',
            }}
            aria-label="Back"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="m15 18-6-6 6-6" />
            </svg>
            Back
          </button>

          <div className={`text-center ${isCompactMode ? "mt-0" : "mt-6"}`}>
            <h1
              style={{
                fontFamily: 'var(--heading)',
                fontWeight: '800',
                color: 'var(--text)',
                letterSpacing: '-0.02em',
                fontSize: isLogin ? '3rem' : '2.65rem',
                lineHeight: '1',
              }}
            >
              {mode === "login" ? "Login" : mode === "signup" ? "Sign Up" : "Forgot Password"}
            </h1>
            <p style={{
              marginTop: '0.5rem',
              fontSize: '15px',
              color: 'var(--text-dim)',
            }}>
              {mode === "login"
                ? "Sign in to continue to your account"
                : mode === "signup"
                  ? "Create your account to continue to the scanner workspace."
                  : "Update your password and return to sign in."}
            </p>
          </div>

          <form onSubmit={submit} className="mt-6 space-y-3.5">
            {mode === "signup" && (
              <Field label="Full Name">
                <input
                  value={form.name}
                  onChange={(e) => updateField("name", e.target.value)}
                  className={inputClassName}
                  placeholder="Enter your name"
                />
              </Field>
            )}

            <Field label="Email Address">
              <input
                type="email"
                value={form.email}
                onChange={(e) => updateField("email", e.target.value)}
                className={inputClassName}
                style={{ background: 'rgba(245,240,232,0.95)' }}
                placeholder={isLogin ? "Enter your email address" : "name@company.com"}
              />
            </Field>

            {mode !== "forgot" && (
              <Field
                label="Password"
                right={
                  mode === "login" ? (
                    <button
                      type="button"
                      onClick={() => switchMode("forgot")}
                      style={{
                        fontSize: '12px',
                        color: 'var(--accent)',
                        background: 'none',
                        border: 'none',
                        cursor: 'pointer',
                        textDecoration: 'underline',
                        fontFamily: 'var(--sans)',
                      }}
                    >
                      Forgot Password?
                    </button>
                  ) : null
                }
              >
                <PasswordInput
                  value={form.password}
                  onChange={(e) => updateField("password", e.target.value)}
                  placeholder={mode === "login" ? "Type your password" : "Create password"}
                  visible={showPassword}
                  onToggle={() => setShowPassword((current) => !current)}
                  className={inputClassName}
                />
              </Field>
            )}

            {mode === "signup" && (
              <Field label="Confirm Password">
                <PasswordInput
                  value={form.confirmPassword}
                  onChange={(e) => updateField("confirmPassword", e.target.value)}
                  placeholder="Confirm password"
                  visible={showConfirmPassword}
                  onToggle={() => setShowConfirmPassword((current) => !current)}
                  className={inputClassName}
                />
              </Field>
            )}

            {mode === "forgot" && (
              <Field label="New Password">
                <PasswordInput
                  value={form.newPassword}
                  onChange={(e) => updateField("newPassword", e.target.value)}
                  placeholder="Enter new password"
                  visible={showNewPassword}
                  onToggle={() => setShowNewPassword((current) => !current)}
                  className={inputClassName}
                />
              </Field>
            )}

            {shouldShowPasswordRequirements && (
              <PasswordRequirements password={mode === "forgot" ? form.newPassword : form.password} />
            )}

            {error && (
              <div style={{
                borderRadius: '14px',
                border: '1px solid rgba(211,67,67,0.3)',
                background: 'rgba(211,67,67,0.08)',
                padding: '12px 16px',
                fontSize: '13px',
                color: 'var(--accent)',
              }}>
                {error}
              </div>
            )}

            {success && (
              <div className="rounded-[18px] border border-emerald-200/80 bg-emerald-50/85 px-4 py-3 text-sm text-emerald-700">
                {success}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full rounded-full bg-[linear-gradient(90deg,#6b1f3a,#d4a853,#8a7a6a)] px-6 py-3 text-lg font-semibold text-white shadow-[0_18px_38px_rgba(107,31,58,0.18)] transition hover:-translate-y-0.5"
            >
              {isSubmitting
                ? "Please wait..."
                : mode === "login"
                  ? "LOGIN"
                  : mode === "signup"
                    ? "SIGN UP"
                    : "UPDATE PASSWORD"}
            </button>
          </form>

          <div className="mt-4 text-center text-sm text-slate-700">
            {mode === "login" && (
              <>
                Don&apos;t have an account?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("signup")}
                  className="cursor-pointer font-medium underline-offset-4 hover:underline"
                  style={{ color: 'var(--accent)' }}
                >
                  Sign up
                </button>
              </>
            )}
            {mode === "signup" && (
              <>
                Already have an account?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("login")}
                  className="cursor-pointer font-medium underline-offset-4 hover:underline"
                  style={{ color: 'var(--accent)' }}
                >
                  Login
                </button>
              </>
            )}
            {mode === "forgot" && (
              <>
                Remembered your password?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("login")}
                  className="cursor-pointer font-medium underline-offset-4 hover:underline"
                  style={{ color: 'var(--accent)' }}
                >
                  Back to login
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
