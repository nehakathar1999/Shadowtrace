from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

import httpx

from intelligence.product_analysis import compliance_mapping, make_evidence, remediation_plan


HREF_RE = re.compile(r"""href=['"]([^'"]+)['"]""", re.IGNORECASE)
SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.IGNORECASE)
API_PATH_RE = re.compile(r"""['"]((?:/|https?://)[^'"]*(?:api|graphql|swagger|openapi)[^'"]*)['"]""", re.IGNORECASE)
SENSITIVE_KEY_RE = re.compile(r'"(password|token|secret|api[_-]?key|authorization|session)"\s*:', re.IGNORECASE)


def build_request_config(auth: dict | None = None) -> dict:
    auth = auth or {}
    headers = dict(auth.get("headers") or {})
    cookies = dict(auth.get("cookies") or {})
    timeout = float(auth.get("timeout") or 6.0)
    verify = bool(auth.get("verify_tls", False))

    username = auth.get("username")
    password = auth.get("password")
    basic_auth = (username, password) if username and password else None

    bearer = auth.get("bearer_token")
    if bearer and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer}"

    return {
        "headers": headers,
        "cookies": cookies,
        "auth": basic_auth,
        "timeout": timeout,
        "verify": verify,
        "follow_redirects": True,
    }


async def normalize_target_url(target: str, auth: dict | None = None) -> str:
    candidate = str(target or "").strip()
    if candidate.startswith(("http://", "https://")):
        return candidate.rstrip("/")

    config = build_request_config(auth)
    async with httpx.AsyncClient(**config) as client:
        for prefix in ("https://", "http://"):
            try:
                response = await client.get(prefix + candidate)
                if response.status_code < 500:
                    return str(response.request.url).rstrip("/")
            except Exception:
                continue
    return f"http://{candidate}"


async def discover_web_surface(target: str, auth: dict | None = None, max_pages: int = 6) -> dict:
    base_url = await normalize_target_url(target, auth)
    config = build_request_config(auth)

    discovered_pages: list[str] = []
    api_candidates: list[str] = []
    script_urls: list[str] = []
    hidden_routes: list[str] = []
    seen: set[str] = set()

    queue = [base_url]
    async with httpx.AsyncClient(**config) as client:
        while queue and len(discovered_pages) < max_pages:
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            try:
                response = await client.get(current)
            except Exception:
                continue
            if response.status_code >= 500:
                continue

            body = response.text or ""
            discovered_pages.append(current)

            for href in HREF_RE.findall(body):
                absolute = urljoin(current, href.strip())
                if urlparse(absolute).netloc == urlparse(base_url).netloc and absolute not in seen and absolute not in queue:
                    queue.append(absolute)

            for src in SCRIPT_RE.findall(body):
                absolute = urljoin(current, src.strip())
                if absolute not in script_urls:
                    script_urls.append(absolute)

            for match in API_PATH_RE.findall(body):
                absolute = urljoin(current, match.strip())
                if absolute not in api_candidates:
                    api_candidates.append(absolute)

        for script_url in list(script_urls)[:5]:
            try:
                response = await client.get(script_url)
            except Exception:
                continue
            script_body = response.text or ""
            for match in API_PATH_RE.findall(script_body):
                absolute = urljoin(base_url, match.strip())
                if absolute not in api_candidates:
                    api_candidates.append(absolute)

        for path in ("/admin", "/dashboard", "/api", "/api/v1", "/graphql", "/swagger", "/openapi.json", "/docs", "/redoc"):
            probe = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = await client.get(probe)
            except Exception:
                continue
            if response.status_code < 404 and probe not in hidden_routes:
                hidden_routes.append(probe)
                if any(token in probe.lower() for token in ("api", "graphql", "swagger", "openapi")) and probe not in api_candidates:
                    api_candidates.append(probe)

    return {
        "base_url": base_url,
        "pages": discovered_pages,
        "scripts": script_urls,
        "api_candidates": api_candidates,
        "hidden_routes": hidden_routes,
        "auth_context_used": bool(auth),
    }


def _api_finding(title: str, description: str, endpoint: str, severity: str, *, evidence: str, response: httpx.Response | None = None, payload: str | None = None) -> dict:
    return {
        "title": title,
        "category": "API Security",
        "severity": severity,
        "description": description,
        "endpoint": endpoint,
        "validation_state": "confirmed" if response is not None else "validated_version",
        "confidence_score": 90 if response is not None else 70,
        "confidence": "confirmed" if response is not None else "high",
        "business_impact": "API weaknesses can expose records, weaken authorization boundaries, or enable abusive automated access.",
        "proof": make_evidence(
            observed=[evidence],
            request={"method": "GET", "url": endpoint},
            response={
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body_preview": (response.text or "")[:500],
            } if response else None,
            payload=payload,
            conclusion=description,
        ),
        "remediation": remediation_plan("https" if endpoint.startswith("https://") else "http", "API service", "", title),
        "compliance_mapping": compliance_mapping("http", title, severity),
        "source": "api_security_checks",
    }


async def assess_api_endpoints(endpoints: list[str], auth: dict | None = None) -> dict:
    config = build_request_config(auth)
    findings: list[dict] = []
    checked: list[dict] = []

    async with httpx.AsyncClient(**config) as client:
        for endpoint in endpoints[:20]:
            try:
                response = await client.get(endpoint)
            except Exception:
                continue

            checked.append({"endpoint": endpoint, "status_code": response.status_code})
            body = response.text or ""
            content_type = response.headers.get("content-type", "")

            if response.status_code == 200 and any(token in endpoint.lower() for token in ("/admin", "/internal", "/users", "/accounts")):
                findings.append(_api_finding(
                    "Possible API authorization bypass",
                    "A sensitive-looking endpoint returned success without proving an authorization boundary.",
                    endpoint,
                    "HIGH",
                    evidence=f"GET returned HTTP {response.status_code} for a sensitive API route.",
                    response=response,
                ))

            if "application/json" in content_type and SENSITIVE_KEY_RE.search(body):
                findings.append(_api_finding(
                    "Sensitive data exposed in API response",
                    "The API response appears to contain sensitive keys or secrets.",
                    endpoint,
                    "HIGH",
                    evidence="Sensitive-looking keys were present in the JSON response body.",
                    response=response,
                ))

            burst_codes = []
            for _ in range(4):
                try:
                    burst = await client.get(endpoint)
                except Exception:
                    break
                burst_codes.append(burst.status_code)
            if burst_codes and 429 not in burst_codes and response.status_code < 500:
                findings.append(_api_finding(
                    "No visible API rate limiting",
                    "Repeated API requests did not trigger HTTP 429 or similar throttling behavior.",
                    endpoint,
                    "MEDIUM",
                    evidence=f"Burst request status codes: {burst_codes}",
                    response=response,
                ))

    return {
        "checked_endpoints": checked,
        "findings": findings,
        "summary": {
            "checked": len(checked),
            "findings": len(findings),
        },
    }


def _normalize_spec_path(path: str) -> str:
    candidate = str(path or "").strip()
    if not candidate:
        return "/"
    return candidate if candidate.startswith("/") else "/" + candidate


def parse_openapi_document(document: str) -> dict:
    data = json.loads(document)
    servers = data.get("servers") or []
    base_url = ""
    if servers and isinstance(servers[0], dict):
        base_url = str(servers[0].get("url") or "")

    endpoints = []
    for path, methods in (data.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue
            endpoints.append({
                "method": method.upper(),
                "path": _normalize_spec_path(path),
                "auth_required": bool((details or {}).get("security")),
                "summary": (details or {}).get("summary") or "",
            })
    return {"format": "openapi", "base_url": base_url, "endpoints": endpoints}


def parse_postman_collection(document: str) -> dict:
    data = json.loads(document)
    endpoints = []

    def walk(items):
        for item in items or []:
            if "request" in item:
                request = item["request"]
                url = request.get("url")
                raw_url = ""
                path = "/"
                if isinstance(url, dict):
                    raw_url = url.get("raw") or ""
                    path = "/" + "/".join(url.get("path") or [])
                elif isinstance(url, str):
                    raw_url = url
                    parsed = urlparse(raw_url)
                    path = parsed.path or "/"
                endpoints.append({
                    "method": str(request.get("method") or "GET").upper(),
                    "path": _normalize_spec_path(path),
                    "raw_url": raw_url,
                    "auth_required": False,
                    "summary": item.get("name") or "",
                })
            if "item" in item:
                walk(item["item"])

    walk(data.get("item") or [])
    return {"format": "postman", "base_url": "", "endpoints": endpoints}


def parse_api_document(document: str, fmt: str | None = None) -> dict:
    content = str(document or "").strip()
    if not content:
        return {"format": "unknown", "base_url": "", "endpoints": []}

    fmt_name = (fmt or "").lower()
    if fmt_name == "openapi":
        return parse_openapi_document(content)
    if fmt_name == "postman":
        return parse_postman_collection(content)

    data = json.loads(content)
    if "openapi" in data or "swagger" in data:
        return parse_openapi_document(content)
    if "info" in data and "item" in data:
        return parse_postman_collection(content)
    return {"format": "unknown", "base_url": "", "endpoints": []}


async def analyze_api_document(document: str, fmt: str | None = None, base_url: str | None = None, auth: dict | None = None) -> dict:
    parsed = parse_api_document(document, fmt)
    resolved_base = base_url or parsed.get("base_url") or ""

    endpoint_urls = []
    for item in parsed.get("endpoints", []):
        raw_url = item.get("raw_url")
        if raw_url:
            endpoint_urls.append(raw_url)
        elif resolved_base:
            endpoint_urls.append(urljoin(resolved_base.rstrip("/") + "/", item.get("path", "/").lstrip("/")))

    assessment = await assess_api_endpoints(endpoint_urls, auth) if endpoint_urls else {"checked_endpoints": [], "findings": [], "summary": {"checked": 0, "findings": 0}}
    return {
        "spec_format": parsed.get("format"),
        "base_url": resolved_base,
        "declared_endpoints": parsed.get("endpoints", []),
        "runtime_assessment": assessment,
    }


def run_discover_web_surface(target: str, auth: dict | None = None) -> dict:
    return asyncio.run(discover_web_surface(target, auth))


def run_assess_api_endpoints(endpoints: list[str], auth: dict | None = None) -> dict:
    return asyncio.run(assess_api_endpoints(endpoints, auth))


def run_analyze_api_document(document: str, fmt: str | None = None, base_url: str | None = None, auth: dict | None = None) -> dict:
    return asyncio.run(analyze_api_document(document, fmt, base_url, auth))
