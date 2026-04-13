import { useState, useEffect } from "react"
import VaptScanner from "./Pages/VaptScanner"
import Vulns from "./Pages/Vulns"
import Stats from "./Pages/Stats"
import Navbar from "./Pages/Navbar"
import AuthPage from "./Pages/AuthPage"

const AUTH_STORAGE_KEY = "vapt_scanner_auth_user"

function App() {
  const DEFAULT_API_HOST = `${window.location.protocol}//${window.location.hostname}:8000`
  const API_BASE = (import.meta.env.VITE_API_URL || DEFAULT_API_HOST).replace(/\/+$/, "")
  const [activeNav, setActiveNav] = useState("Scan")
  const [scanData, setScanData] = useState(null)
  const [selectedTarget, setSelectedTarget] = useState(null)
  const [rescanRequest, setRescanRequest] = useState(null)
  const [theme, setTheme] = useState('light')
  const [authUser, setAuthUser] = useState(() => {
    try {
      const stored = localStorage.getItem(AUTH_STORAGE_KEY)
      return stored ? JSON.parse(stored) : null
    } catch {
      return null
    }
  })
  const [entryStage, setEntryStage] = useState(() => {
    try {
      const stored = localStorage.getItem(AUTH_STORAGE_KEY)
      return stored ? "app" : "auth"
    } catch {
      return "auth"
    }
  })
  const [previewMode, setPreviewMode] = useState(() => {
    try {
      const stored = localStorage.getItem(AUTH_STORAGE_KEY)
      return !stored
    } catch {
      return true
    }
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
  }, [theme])

  const toggleTheme = () => {
    setTheme(theme === 'light' ? 'dark' : 'light')
  }

  const onScanComplete = (data) => {
    setScanData(data)
    setSelectedTarget(null)
    setActiveNav("Vulns")
  }

  const handleAuthSuccess = (user) => {
    setAuthUser(user)
    setPreviewMode(false)
    setEntryStage("app")
    setActiveNav("Scan")
    try {
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user))
    } catch {
      // Ignore storage failure and continue with in-memory auth state.
    }
  }

  const handleLogout = () => {
    setAuthUser(null)
    setPreviewMode(false)
    setEntryStage("auth")
    setActiveNav("Scan")
    setSelectedTarget(null)
    try {
      localStorage.removeItem(AUTH_STORAGE_KEY)
    } catch {
      // Ignore storage cleanup failures.
    }
  }

  const onHistorySelect = async (entry) => {
    if (!entry) return
    const reportPath = entry.reportPath
    if (!reportPath) {
      console.error("Missing reportPath in stats entry", entry)
      return
    }

    try {
      const response = await fetch(`${API_BASE}/download_report?path=${encodeURIComponent(reportPath)}&format=json`, {
        headers: { Accept: "application/json" },
      })
      if (!response.ok) {
        throw new Error(`Failed to load report (${response.status})`)
      }
      const realScanData = await response.json()
      setSelectedTarget(entry.target)
      setScanData(realScanData)
      setActiveNav("Vulns")
    } catch (err) {
      console.error("Failed to open real scan report from stats history:", err)
    }
  }

  const handleHistoryDelete = async (entry) => {
    if (!entry?.reportPath) return
    const confirmed = window.confirm(`Delete scan history for ${entry.target}?`)
    if (!confirmed) return false

    try {
      const response = await fetch(`${API_BASE}/scan-history?path=${encodeURIComponent(entry.reportPath)}`, {
        method: "DELETE",
      })
      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data?.detail || `Delete failed (${response.status})`)
      }
      return true
    } catch (err) {
      console.error("Failed to delete scan history entry:", err)
      window.alert(err?.message || "Failed to delete scan history entry.")
      return false
    }
  }

  const handleHistoryRescan = (entry) => {
    const target = entry?.rescanTarget || entry?.target
    if (!target) return
    setSelectedTarget(target)
    setActiveNav("Scan")
    setRescanRequest({
      target,
      nonce: Date.now(),
    })
  }

  // Landing page is temporarily disabled so the app opens directly on auth.
  // if (entryStage === "landing") {
  //   return (
  //     <LandingPage
  //       onEnter={() => {
  //         setPreviewMode(true)
  //         setEntryStage("app")
  //         setActiveNav("Scan")
  //       }}
  //       onGoAuth={() => setEntryStage("auth")}
  //     />
  //   )
  // }

  if (entryStage === "auth") {
    return (
      <AuthPage
        onBack={() => setEntryStage("auth")}
        onAuthSuccess={handleAuthSuccess}
      />
    )
  }

  return (
    <>
      <Navbar
        activeNav={activeNav}
        onNavClick={setActiveNav}
        theme={theme}
        toggleTheme={toggleTheme}
        onLogout={handleLogout}
        authUser={authUser}
      />
      <main style={{ paddingTop: '64px' }}>
        {activeNav === "Scan" && <VaptScanner onScanComplete={onScanComplete} theme={theme} previewMode={previewMode} onRequireLogin={() => setEntryStage("auth")} rescanRequest={rescanRequest} />}
        {activeNav === "Vulns" && <Vulns scanData={scanData} theme={theme} selectedTarget={selectedTarget} />}
        {activeNav === "Stats" && <Stats theme={theme} onHistorySelect={onHistorySelect} onHistoryDelete={handleHistoryDelete} onHistoryRescan={handleHistoryRescan} />}
        {activeNav === "Map" && <div style={{ height: "100vh", background: theme === 'dark' ? '#0a0f1a' : '#f8fafc' }} />}
      </main>
    </>
  )
}

export default App
