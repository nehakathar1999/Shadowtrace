import React from "react";
import brandLogo from "../assets/STLOGO.png";

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
const SunIcon = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <circle cx="12" cy="12" r="5" />
    <line x1="12" y1="1" x2="12" y2="3" />
    <line x1="12" y1="21" x2="12" y2="23" />
    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
    <line x1="1" y1="12" x2="3" y2="12" />
    <line x1="21" y1="12" x2="23" y2="12" />
    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
  </svg>
);
const MoonIcon = ({ size = 17 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
  </svg>
);

const Navbar = ({ activeNav, onNavClick, theme, toggleTheme, onLogout, authUser }) => {
  const tabs = [
    { name: "Scan", icon: <GlobeIcon /> },
    { name: "Vulns", icon: <ShieldIcon /> },
    // { name: "Map", icon: <MapIcon /> },
    { name: "Stats", icon: <StatsIcon /> },
  ];

  return (
    <nav className={`fixed top-0 left-0 right-0 z-50 w-full ${theme === 'dark' ? 'bg-[#020617]/95 border-cyan-900' : 'bg-white/95 border-gray-200'} backdrop-blur-md px-16 py-3 flex items-center justify-between`}>
      
      {/* LEFT - LOGO */}
      <button
        type="button"
        onClick={() => onNavClick("Scan")}
        className="ml-4 flex items-center transition"
      >
        <img
          src={brandLogo}
          alt="ShadowTrace"
          className="h-12 w-auto object-contain"
        />
      </button>

      {/* RIGHT - NAV TABS, THEME TOGGLE AND LOGOUT BUTTON */}
      <div className="flex items-center gap-5 ml-auto">
        <div className="flex items-center gap-4">
          {tabs.map((tab) => (
            <button
              key={tab.name}
              onClick={() => onNavClick(tab.name)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all duration-200
                ${
                  activeNav === tab.name
                    ? `${theme === 'dark' ? 'bg-cyan-900/40 text-cyan-400 border border-cyan-500' : 'bg-blue-100 text-blue-600 border border-blue-300'}`
                    : `${theme === 'dark' ? 'text-gray-400 hover:text-white hover:bg-gray-800' : 'text-gray-600 hover:text-gray-800 hover:bg-gray-100'}`
                }`}
            >
              {tab.icon}
              {tab.name}
            </button>
          ))}
        </div>
        <button
          onClick={toggleTheme}
          className="flex items-center gap-2 px-3 py-2 rounded-lg text-[var(--navbar-text-secondary)] hover:text-[var(--navbar-text)] hover:bg-[var(--navbar-bg-active)] transition"
        >
          {theme === 'light' ? <MoonIcon /> : <SunIcon />}
        </button>
        <button
          onClick={onLogout}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition ${theme === 'dark' ? 'border-purple-500 text-purple-400 hover:bg-purple-900/30' : 'border-blue-300 text-blue-600 hover:bg-blue-50'}`}
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
