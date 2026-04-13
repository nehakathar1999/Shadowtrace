import { useState } from "react";
import watermarkLogo from "../assets/STLOGO.png";

const DEFAULT_API_HOST = `${window.location.protocol}//${window.location.hostname}:8000`;
const API_BASE = (import.meta.env.VITE_API_URL || DEFAULT_API_HOST).replace(/\/+$/, "");

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
        <span className="text-sm font-medium text-slate-700">{label}</span>
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
        className={className}
        placeholder={placeholder}
      />
      <button
        type="button"
        onClick={onToggle}
        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 transition hover:text-slate-800"
      >
        <EyeIcon open={visible} />
      </button>
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
  const inputClassName = `w-full rounded-[18px] border border-white/55 bg-white/88 px-4 ${
    isSignup ? "py-2" : isCompactMode ? "py-2.5" : "py-3"
  } text-slate-900 outline-none transition placeholder:text-slate-400 focus:border-sky-300 focus:ring-4 focus:ring-white/30`;

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
    <div className="relative min-h-screen overflow-hidden bg-[linear-gradient(135deg,#eef3ff_0%,#dfe8ff_34%,#cfdcff_70%,#bfd0ff_100%)] px-5 py-6 text-slate-900 sm:px-8">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-24 top-12 h-56 w-56 rounded-full bg-white/30 blur-3xl" />
        <div className="absolute right-8 top-0 h-72 w-72 rounded-full bg-indigo-300/25 blur-3xl" />
        <div className="absolute bottom-6 right-16 h-56 w-56 rounded-full bg-blue-300/20 blur-3xl" />
        <div className="absolute inset-0 flex items-center justify-center opacity-[0.12]">
          <img src={watermarkLogo} alt="" className="w-[920px] max-w-[90vw]" />
        </div>
      </div>

      <div className="relative mx-auto flex min-h-[calc(100vh-3rem)] max-w-[1280px] items-center justify-center">
        <div
          className={`w-full rounded-[30px] border border-white/35 shadow-[0_24px_80px_rgba(37,99,235,0.18)] backdrop-blur-xl ${
            mode === "login" ? "bg-white/18" : "bg-white/28"
          } ${isCompactMode ? "max-w-[430px] px-6 py-5 sm:px-8" : "max-w-[480px] px-7 py-7 sm:px-9"
          }`}
        >
          {/* Back button is temporarily hidden while landing page is disabled. */}
          {/* <button
            onClick={onBack}
            className={`inline-flex items-center gap-2 rounded-full border border-white/50 bg-white/35 text-sm font-medium text-slate-700 transition hover:bg-white/50 ${
              isCompactMode ? "px-4 py-2" : "px-5 py-2.5"
            }`}
            aria-label="Back"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="m15 18-6-6 6-6" />
            </svg>
          </button> */}

          <div className={`text-center ${isCompactMode ? "mt-0" : "mt-6"}`}>
            <h1
              className={`font-semibold tracking-[-0.05em] text-slate-800 ${
                isSignup ? "text-[2.45rem] leading-none" : isCompactMode ? "text-[2.8rem] leading-none" : "text-4xl"
              }`}
            >
              {mode === "login" ? "Welcome Back" : mode === "signup" ? "Create Account" : "Reset Password"}
            </h1>
            <p className={`text-slate-600 ${isSignup ? "mt-1.5 text-[14px]" : isCompactMode ? "mt-2 text-[15px]" : "mt-3 text-base"}`}>
              {mode === "login"
                ? "Sign in to continue to your account"
                : mode === "signup"
                  ? "Create your account to continue to the scanner workspace."
                  : "Update your password and return to sign in."}
            </p>
          </div>

          <form onSubmit={submit} className={`space-y-3 ${isSignup ? "mt-4" : isCompactMode ? "mt-5" : "mt-8"}`}>
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
                placeholder="name@company.com"
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
                      className="text-xs text-indigo-700 underline-offset-4 hover:underline"
                    >
                      Forgot Password?
                    </button>
                  ) : null
                }
              >
                <PasswordInput
                  value={form.password}
                  onChange={(e) => updateField("password", e.target.value)}
                  placeholder={mode === "login" ? "Enter password" : "Create password"}
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

            {error && (
              <div className="rounded-[18px] border border-rose-200/80 bg-rose-50/85 px-4 py-3 text-sm text-rose-700">
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
              className={`w-full rounded-[18px] bg-[linear-gradient(135deg,#5b6ee1,#8047ae)] px-6 ${
                isSignup ? "py-2.25" : isCompactMode ? "py-2.5" : "py-3.5"
              } text-lg font-semibold text-white shadow-[0_18px_38px_rgba(91,110,225,0.28)] transition hover:-translate-y-0.5`}
            >
              {isSubmitting
                ? "Please wait..."
                : mode === "login"
                  ? "Sign In"
                  : mode === "signup"
                    ? "Create Account"
                    : "Update Password"}
            </button>
          </form>

          <div className={`text-center text-sm text-slate-700 ${isSignup ? "mt-3" : isCompactMode ? "mt-4" : "mt-6"}`}>
            {mode === "login" && (
              <>
                Don&apos;t have an account?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("signup")}
                  className="cursor-pointer font-medium text-indigo-700 underline-offset-4 hover:underline"
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
                  className="cursor-pointer font-medium text-indigo-700 underline-offset-4 hover:underline"
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
                  className="cursor-pointer font-medium text-indigo-700 underline-offset-4 hover:underline"
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
