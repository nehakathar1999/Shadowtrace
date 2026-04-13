import { useState } from "react";

export default function VAPTReportModal({ reportPath, apiBase }) {
  const [loading, setLoading] = useState(false);
  const [toast,   setToast]   = useState(null);

  const showToast = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const handleDownload = async () => {
    if (!reportPath) {
      showToast("⚠ No report path available");
      return;
    }

    setLoading(true);
    try {
      // Call your existing FastAPI download_report endpoint
      const url = `${apiBase}/download_report?path=${encodeURIComponent(reportPath)}&format=pdf&_ts=${Date.now()}`;
      const res  = await fetch(url, { cache: "no-store" });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Unknown error" }));
        throw new Error(err.detail || `Server error ${res.status}`);
      }

      // Get filename from Content-Disposition header if present
      const disposition = res.headers.get("content-disposition");
      const match       = disposition?.match(/filename="?([^"]+)"?/);
      const filename    = match?.[1] ?? `VAPT_Report.pdf`;

      // Trigger browser download
      const blob = await res.blob();
      const burl = URL.createObjectURL(blob);
      const a    = Object.assign(document.createElement("a"), {
        href: burl, download: filename,
      });
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
        URL.revokeObjectURL(burl);
      }, 1500);

      showToast("✓ PDF downloaded successfully");
    } catch (err) {
      showToast(`⚠ ${err.message}`);
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <button
        onClick={handleDownload}
        disabled={loading || !reportPath}
        style={{
          background: !reportPath ? "#444" : loading ? "#b91c1c" : "#dc2626",
          color: "#fff", border: "none", borderRadius: "8px",
          padding: "10px 22px", fontFamily: "inherit",
          fontSize: "14px", fontWeight: 600,
          cursor: loading || !reportPath ? "not-allowed" : "pointer",
          display: "inline-flex", alignItems: "center", gap: "8px",
          opacity: !reportPath ? 0.5 : loading ? 0.8 : 1,
          transition: "opacity 0.15s",
        }}
      >
        {loading ? (
          <span style={{
            width: "14px", height: "14px",
            border: "2px solid rgba(255,255,255,0.3)",
            borderTopColor: "#fff", borderRadius: "50%",
            display: "inline-block", animation: "spin 0.7s linear infinite",
          }} />
        ) : "↓"}
        {loading ? "Generating PDF…" : "Download Report PDF"}
      </button>

      <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>

      {toast && (
        <div style={{
          position: "fixed", bottom: "24px", left: "50%",
          transform: "translateX(-50%)",
          background: "#1e1e26", border: "0.5px solid rgba(255,255,255,0.14)",
          borderRadius: "8px", padding: "10px 18px",
          fontSize: "13px", color: "#f0f0f5",
          zIndex: 10000, pointerEvents: "none",
          boxShadow: "0 4px 20px rgba(0,0,0,0.3)",
        }}>{toast}</div>
      )}
    </>
  );
}
