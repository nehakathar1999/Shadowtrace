import { useState, useEffect } from "react"
import VaptScanner from "./Pages/VaptScanner"
import Vulns from "./Pages/Vulns"
import Stats from "./Pages/Stats"
import Navbar from "./Pages/Navbar"
import AuthPage from "./Pages/AuthPage"
import LandingPage from "./Pages/LandingPage"
import IntroSequence from "./IntroSequence"
import { API_BASE } from "./lib/api"

const AUTH_STORAGE_KEY = "vapt_scanner_auth_user"
const ACTIVE_NAV_STORAGE_KEY = "vapt_scanner_active_nav"

const readStoredAuthUser = () => {
  try {
    const stored = localStorage.getItem(AUTH_STORAGE_KEY)
    if (!stored) return null
    const parsed = JSON.parse(stored)
    return parsed?.email ? parsed : null
  } catch {
    return null
  }
}

function App() {
  const initialAuthUser = (() => {
    if (typeof window === "undefined") return null
    return readStoredAuthUser()
  })()

  const [activeNav, setActiveNav] = useState(() => {
    if (typeof window === "undefined") return "Scan"
    return localStorage.getItem(ACTIVE_NAV_STORAGE_KEY) || "Scan"
  })
  const [scanData, setScanData] = useState(null)
  const [selectedTarget, setSelectedTarget] = useState(null)
  const [requestedScanTarget, setRequestedScanTarget] = useState(null)
  const [scanRequestNonce, setScanRequestNonce] = useState(0)
  const [vulnsResetNonce, setVulnsResetNonce] = useState(0)
  const theme = 'light'
  const [authUser, setAuthUser] = useState(initialAuthUser)
  const [entryStage, setEntryStage] = useState("intro")

  const normalizeTargetValue = (value) =>
    String(value || "")
      .trim()
      .toLowerCase()
      .replace(/[\\/]+/g, "-")

  const clearCurrentScanView = () => {
    setSelectedTarget(null)
    setScanData(null)
    setVulnsResetNonce((prev) => prev + 1)
  }

  useEffect(() => {
    try {
      localStorage.setItem(ACTIVE_NAV_STORAGE_KEY, activeNav)
    } catch {
      // Ignore storage failures.
    }
  }, [activeNav])

  const onScanComplete = (data) => {
    setScanData(data)
    setSelectedTarget(null)
    setActiveNav("Vulns")
  }

  const handleAuthSuccess = (user) => {
    setAuthUser(user)
    setEntryStage("app")
    setActiveNav("Scan")
    setRequestedScanTarget(null)
    try {
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user))
    } catch {
      // Ignore storage failure and continue with in-memory auth state.
    }
  }

  const handleLogout = () => {
    setAuthUser(null)
    setEntryStage("intro")
    setActiveNav("Scan")
    clearCurrentScanView()
    setRequestedScanTarget(null)
    setScanRequestNonce(0)
    try {
      localStorage.removeItem(AUTH_STORAGE_KEY)
      localStorage.removeItem(ACTIVE_NAV_STORAGE_KEY)
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

  const onHistoryDelete = async (entry) => {
    if (!entry?.reportPath) return false

    try {
      const response = await fetch(`${API_BASE}/reports?path=${encodeURIComponent(entry.reportPath)}`, {
        method: "DELETE",
        headers: { Accept: "application/json" },
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data?.detail || `Failed to delete scan history (${response.status})`)
      }

      const deletedTarget = normalizeTargetValue(entry.target)
      const viewedTarget = normalizeTargetValue(selectedTarget || scanData?.input)

      if (deletedTarget && viewedTarget && deletedTarget === viewedTarget) {
        clearCurrentScanView()
      } else {
        const statsResponse = await fetch(`${API_BASE}/stats`, { cache: "no-store" })
        if (statsResponse.ok) {
          const statsPayload = await statsResponse.json()
          const history = Array.isArray(statsPayload?.scan_history) ? statsPayload.scan_history : []
          if (history.length === 0) {
            clearCurrentScanView()
          }
        }
      }

      return true
    } catch (err) {
      console.error("Failed to delete scan history entry:", err)
      return false
    }
  }

  const onHistoryRescan = (entry) => {
    const target = String(entry?.target || "").trim()
    if (!target) return

    setSelectedTarget(null)
    setScanData(null)
    setActiveNav("Scan")
    setRequestedScanTarget(target)
    setScanRequestNonce((prev) => prev + 1)
  }

  const handleRequestedScanConsumed = () => {
    setRequestedScanTarget(null)
  }

  const handleOpenScanner = () => {
    setEntryStage("auth")
  }

  if (entryStage === "intro") {
    return <IntroSequence onComplete={() => setEntryStage("landing")} />
  }

  if (entryStage === "landing") {
    return (
      <LandingPage
        onEnter={handleOpenScanner}
        onGoAuth={() => setEntryStage("auth")}
      />
    )
  }

  if (entryStage === "auth") {
    return (
      <AuthPage
        onBack={() => setEntryStage("landing")}
        onAuthSuccess={handleAuthSuccess}
      />
    )
  }

  return (
    <>
      <Navbar
        activeNav={activeNav}
        onNavClick={setActiveNav}
        onLogout={handleLogout}
        authUser={authUser}
      />
      <main style={{ paddingTop: '64px' }}>
        {activeNav === "Scan" && (
          <VaptScanner
            onScanComplete={onScanComplete}
            theme={theme}
            requestedScanTarget={requestedScanTarget}
            scanRequestNonce={scanRequestNonce}
            onRequestedScanConsumed={handleRequestedScanConsumed}
          />
        )}
        {activeNav === "Vulns" && (
          <Vulns
            scanData={scanData}
            theme={theme}
            selectedTarget={selectedTarget}
            resetNonce={vulnsResetNonce}
          />
        )}
        {activeNav === "Stats" && (
          <Stats
            theme={theme}
            onHistorySelect={onHistorySelect}
            onHistoryDelete={onHistoryDelete}
            onHistoryRescan={onHistoryRescan}
          />
        )}
        {activeNav === "Map" && <div style={{ height: "100vh", background: '#f8fafc' }} />}
      </main>
    </>
  )
}

export default App
