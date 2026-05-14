import React from "react";
import brandLogo from "../assets/Shadow_logo2.png";

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
const Navbar = ({ activeNav, onNavClick, onLogout, authUser }) => {
  const tabs = [
    { name: "Scan", icon: <GlobeIcon /> },
    { name: "Vulns", icon: <ShieldIcon /> },
    // { name: "Map", icon: <MapIcon /> },
    { name: "Stats", icon: <StatsIcon /> },
  ];

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 w-full" style={{ background: 'var(--navbar-bg)', borderBottom: '1px solid var(--navbar-border)', backdropFilter: 'blur(16px)', padding: '0 5vw', height: '64px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      
      {/* LEFT - LOGO */}
      <button
        type="button"
        onClick={() => onNavClick("Scan")}
        className="ml-4 flex items-center transition hover:opacity-80"
      >
        <div
          className="flex items-center rounded-[16px] px-3 py-1.5"
          // style={{
          //   background: "rgba(218, 212, 205, 0.72)",
          //   border: "1px solid rgba(255,255,255,0.55)",
          //   boxShadow: "inset 0 1px 0 rgba(255,255,255,0.35)",
          //   backdropFilter: "blur(6px)",
          // }}
        >
          <img
            src={brandLogo}
            alt="ShadowTrace"
            className="h-40 w-auto object-contain"
          />
        </div>
      </button>

      {/* RIGHT - NAV TABS AND LOGOUT BUTTON */}
      <div className="flex items-center gap-3 ml-auto">
        <div className="flex items-center gap-2">
          {tabs.map((tab) => (
            <button
              key={tab.name}
              onClick={() => onNavClick(tab.name)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg transition-all duration-200"
              style={{
                fontFamily: 'var(--heading)',
                fontSize: '13px',
                fontWeight: '600',
                letterSpacing: '0.04em',
                color: activeNav === tab.name ? 'var(--accent)' : 'var(--navbar-text)',
                background: activeNav === tab.name ? 'var(--navbar-bg-active)' : 'transparent',
                border: activeNav === tab.name ? '1px solid var(--navbar-border-active)' : '1px solid transparent',
              }}
            >
              {tab.icon}
              {tab.name}
            </button>
          ))}
        </div>
        <button
          onClick={onLogout}
          className="flex items-center gap-2 px-3 py-2 rounded-lg transition"
          style={{
            fontFamily: 'var(--heading)',
            fontSize: '13px',
            fontWeight: '600',
            letterSpacing: '0.04em',
            color: 'var(--accent)',
            background: 'transparent',
            border: '1.5px solid var(--navbar-border-active)',
            cursor: 'pointer',
          }}
          title={authUser?.email ? `Logout ${authUser.email}` : "Logout"}
        >
          <LoginIcon />
          Logout
        </button>
      </div>
    </nav>
  );
};

export default Navbar;
