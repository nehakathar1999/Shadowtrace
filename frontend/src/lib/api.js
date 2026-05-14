const DEFAULT_API_HOST = `${window.location.protocol}//${window.location.hostname}:8000`;

function normalizeApiBase(url) {
  return String(url || "")
    .replace(/\/+$/, "")
    .replace(/\/api$/i, "");
}

export const API_BASE = normalizeApiBase(import.meta.env.VITE_API_URL || DEFAULT_API_HOST);
