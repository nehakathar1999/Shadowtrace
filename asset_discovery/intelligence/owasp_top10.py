import asyncio
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse

import httpx
from intelligence.product_analysis import compliance_mapping, make_evidence, remediation_plan
from intelligence.web_advanced import build_request_config


CATEGORY_DEFINITIONS = [
    {"id": "A01:2025", "title": "Broken Access Control", "short": "A01", "severity": "HIGH"},
    {"id": "A02:2025", "title": "Security Misconfiguration", "short": "A02", "severity": "MEDIUM"},
    {"id": "A03:2025", "title": "Software Supply Chain Failures", "short": "A03", "severity": "HIGH"},
    {"id": "A04:2025", "title": "Cryptographic Failures", "short": "A04", "severity": "HIGH"},
    {"id": "A05:2025", "title": "Injection", "short": "A05", "severity": "HIGH"},
    {"id": "A06:2025", "title": "Insecure Design", "short": "A06", "severity": "MEDIUM"},
    {"id": "A07:2025", "title": "Authentication Failures", "short": "A07", "severity": "HIGH"},
    {"id": "A08:2025", "title": "Software or Data Integrity Failures", "short": "A08", "severity": "HIGH"},
    {"id": "A09:2025", "title": "Security Logging and Alerting Failures", "short": "A09", "severity": "MEDIUM"},
    {"id": "A10:2025", "title": "Mishandling of Exceptional Conditions", "short": "A10", "severity": "MEDIUM"},
]

REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; VAPTScanner/1.0)"}
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.IGNORECASE)


def _response_snapshot(response: httpx.Response | None) -> dict | None:
    if not response:
        return None
    text = response.text or ""
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body_preview": text[:600],
    }


def _normalize_finding(
    category: dict,
    title: str,
    description: str,
    url: str | None = None,
    evidence: str | None = None,
    *,
    request: dict | None = None,
    response: httpx.Response | None = None,
    payload: str | None = None,
    confidence_score: int = 84,
    validation_state: str = "confirmed",
) -> dict:
    return {
        "category_id": category["id"],
        "category": category["title"],
        "severity": category["severity"],
        "title": title,
        "description": description,
        "url": url,
        "evidence": evidence,
        "validation_state": validation_state,
        "confidence_score": confidence_score,
        "confidence": "confirmed" if confidence_score >= 90 else "high" if confidence_score >= 70 else "medium",
        "business_impact": f"{category['title']} can create exploitable web exposure that affects confidentiality, integrity, or access control.",
        "proof": make_evidence(
            observed=[evidence] if evidence else [],
            request=request,
            response=_response_snapshot(response),
            payload=payload,
            conclusion=description,
        ),
        "remediation": remediation_plan("https" if str(url or "").startswith("https://") else "http", "web application", "", title),
        "compliance_mapping": compliance_mapping("http", title, category["severity"]),
        "source": "owasp_web_checks",
    }


async def _request(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response | None:
    try:
        headers = dict(REQUEST_HEADERS)
        headers.update(kwargs.pop("headers", {}) or {})
        return await client.request(method, url, headers=headers, follow_redirects=True, **kwargs)
    except Exception:
        return None


async def normalize_target_url(target: str) -> str:
    return await normalize_target_url_with_auth(target, None)


async def normalize_target_url_with_auth(target: str, auth_context: dict | None) -> str:
    candidate = str(target or "").strip()
    if candidate.startswith(("http://", "https://")):
        return candidate.rstrip("/")

    https_url = f"https://{candidate}"
    http_url = f"http://{candidate}"
    config = build_request_config(auth_context)
    config["timeout"] = 4.0
    async with httpx.AsyncClient(**config) as client:
        https_response = await _request(client, "GET", https_url)
        if https_response and https_response.status_code < 500:
            return str(https_response.request.url).rstrip("/")

        http_response = await _request(client, "GET", http_url)
        if http_response and http_response.status_code < 500:
            return str(http_response.request.url).rstrip("/")

    return http_url


async def _fetch_base_document(base_url: str, auth_context: dict | None = None) -> tuple[str, httpx.Headers]:
    config = build_request_config(auth_context)
    async with httpx.AsyncClient(**config) as client:
        response = await _request(client, "GET", base_url)
        if not response:
            return "", httpx.Headers()
        return response.text, response.headers


def _extract_script_sources(base_url: str, html: str) -> list[str]:
    found = []
    for match in SCRIPT_SRC_RE.findall(html or ""):
        absolute = urljoin(base_url.rstrip("/") + "/", match.strip())
        if absolute not in found:
            found.append(absolute)
    return found


async def _scan_broken_access_control(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[0]
    findings = []
    sensitive_paths = ["/admin", "/dashboard", "/account", "/settings", "/user"]
    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        for path in sensitive_paths:
            url = base_url.rstrip("/") + path
            response = await _request(client, "GET", url)
            if response and response.status_code == 200 and "login" not in response.text.lower():
                findings.append(_normalize_finding(
                    category,
                    "Sensitive endpoint exposed without authentication",
                    f"The endpoint responded successfully without an authenticated workflow: {path}",
                    url,
                    evidence=f"GET {path} returned HTTP {response.status_code} without a login challenge.",
                    request={"method": "GET", "url": url},
                    response=response,
                ))

        baseline = await _request(client, "GET", f"{base_url.rstrip('/')}/user?id=1")
        alternative = await _request(client, "GET", f"{base_url.rstrip('/')}/user?id=2")
        if baseline and alternative and baseline.status_code == 200 and alternative.status_code == 200 and baseline.text != alternative.text:
            findings.append(_normalize_finding(
                category,
                "Possible IDOR behavior",
                "Different object identifiers returned different responses without proving authorization boundaries.",
                f"{base_url.rstrip('/')}/user",
                evidence="The same endpoint returned distinct object data for different numeric identifiers.",
                request={"method": "GET", "url": f"{base_url.rstrip('/')}/user?id=2"},
                response=alternative,
                payload="id=2",
                confidence_score=72,
                validation_state="validated_version",
            ))

        admin_url = base_url.rstrip("/") + "/admin"
        get_response = await _request(client, "GET", admin_url)
        post_response = await _request(client, "POST", admin_url)
        if get_response and post_response and get_response.status_code != post_response.status_code:
            findings.append(_normalize_finding(
                category,
                "HTTP method bypass behavior",
                "The same protected endpoint behaved differently across HTTP methods, which can indicate authorization enforcement gaps.",
                admin_url,
                evidence=f"GET returned {get_response.status_code} while POST returned {post_response.status_code}.",
                request={"method": "POST", "url": admin_url},
                response=post_response,
                confidence_score=74,
                validation_state="validated_version",
            ))

    return findings


async def _scan_security_misconfiguration(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[1]
    findings = []
    html, headers = await _fetch_base_document(base_url, auth_context)
    required_headers = {
        "Content-Security-Policy": "Missing Content-Security-Policy header.",
        "X-Frame-Options": "Missing X-Frame-Options header.",
        "Strict-Transport-Security": "Missing HSTS header.",
        "X-Content-Type-Options": "Missing X-Content-Type-Options header.",
    }
    for header_name, message in required_headers.items():
        if header_name not in headers:
            findings.append(_normalize_finding(
                category,
                "Security header missing",
                message,
                base_url,
                header_name,
                request={"method": "GET", "url": base_url},
                confidence_score=96,
                validation_state="confirmed",
            ))

    if "Server" in headers:
        findings.append(_normalize_finding(category, "Server fingerprint disclosed", "The response includes a Server header that reveals implementation details.", base_url, headers.get("Server"), request={"method": "GET", "url": base_url}, confidence_score=95))
    if "X-Powered-By" in headers:
        findings.append(_normalize_finding(category, "Technology stack disclosed", "The response includes an X-Powered-By header.", base_url, headers.get("X-Powered-By"), request={"method": "GET", "url": base_url}, confidence_score=95))

    sensitive_paths = ["/.env", "/config.json", "/.git/config", "/backup.zip", "/phpinfo.php", "/debug", "/dev", "/console"]
    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        for path in sensitive_paths:
            url = base_url.rstrip("/") + path
            response = await _request(client, "GET", url)
            if response and response.status_code == 200:
                findings.append(_normalize_finding(category, "Sensitive file or debug route exposed", f"The path {path} returned a successful response.", url, evidence=f"GET {path} returned HTTP {response.status_code}.", request={"method": "GET", "url": url}, response=response))

        options_response = await _request(client, "OPTIONS", base_url)
        if options_response:
            allow_header = options_response.headers.get("Allow", "")
            for method in ("PUT", "DELETE", "TRACE"):
                if method in allow_header:
                    findings.append(_normalize_finding(category, "Risky HTTP method enabled", f"The Allow header exposes {method}.", base_url, allow_header, request={"method": "OPTIONS", "url": base_url}, response=options_response))

    return findings


async def _scan_supply_chain(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[2]
    findings = []
    html, _ = await _fetch_base_document(base_url, auth_context)
    scripts = _extract_script_sources(base_url, html)
    vulnerable_libraries = {
        "jquery": ("1.", "2."),
        "angular": ("1.",),
        "bootstrap": ("3.",),
    }
    host = urlparse(base_url).netloc.lower()
    for src in scripts:
        lowered = src.lower()
        for library, versions in vulnerable_libraries.items():
            if library in lowered and any(version in lowered for version in versions):
                findings.append(_normalize_finding(category, "Potentially outdated client library detected", f"The script source suggests an older {library} version is loaded.", src))
        if urlparse(src).netloc and urlparse(src).netloc.lower() != host:
            findings.append(_normalize_finding(category, "Third-party script dependency detected", "External JavaScript was loaded from a different host, which increases software supply chain exposure.", src))
    return findings


async def _scan_cryptographic_failures(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[3]
    findings = []
    html, headers = await _fetch_base_document(base_url, auth_context)
    if base_url.startswith("http://"):
        findings.append(_normalize_finding(category, "Plain HTTP in use", "The target resolved over HTTP rather than HTTPS.", base_url))
    if "Strict-Transport-Security" not in headers:
        findings.append(_normalize_finding(category, "HSTS not configured", "Strict-Transport-Security was not observed in the response headers.", base_url))
    cookie_header = headers.get("set-cookie", "")
    if cookie_header:
        if "Secure" not in cookie_header:
            findings.append(_normalize_finding(category, "Cookie missing Secure flag", "Session or application cookies were issued without the Secure flag.", base_url, cookie_header))
        if "HttpOnly" not in cookie_header:
            findings.append(_normalize_finding(category, "Cookie missing HttpOnly flag", "Session or application cookies were issued without the HttpOnly flag.", base_url, cookie_header))
    if base_url.startswith("https://") and "http://" in (html or ""):
        findings.append(_normalize_finding(category, "Mixed content references detected", "The HTTPS page contains insecure HTTP resource references.", base_url))
    return findings


async def _scan_injection(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[4]
    findings = []
    sql_payloads = ["'", "' OR 1=1--", "' UNION SELECT NULL--"]
    xss_payload = "<script>alert(1)</script>"
    ssti_payloads = ["{{7*7}}", "${7*7}"]
    params = ["id", "q", "search", "input", "cmd"]
    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        for param in params:
            for payload in sql_payloads:
                test_url = f"{base_url}?{param}={payload}"
                response = await _request(client, "GET", test_url)
                if response and any(marker in response.text.lower() for marker in ("sql syntax", "mysql", "syntax error", "unterminated query", "odbc", "pdo")):
                    findings.append(_normalize_finding(category, "Possible SQL injection", f"Database error markers were reflected after injecting parameter {param}.", test_url, evidence=f"Injected parameter {param} caused database error text.", request={"method": "GET", "url": test_url}, response=response, payload=payload, confidence_score=88))

            xss_url = f"{base_url}?{param}={xss_payload}"
            xss_response = await _request(client, "GET", xss_url)
            if xss_response and xss_payload in xss_response.text:
                findings.append(_normalize_finding(category, "Possible reflected XSS", f"The payload submitted through parameter {param} was reflected in the response.", xss_url, evidence=f"Payload for {param} was reflected unencoded in the response body.", request={"method": "GET", "url": xss_url}, response=xss_response, payload=xss_payload, confidence_score=90))

            for payload in ssti_payloads:
                ssti_url = f"{base_url}?{param}={payload}"
                ssti_response = await _request(client, "GET", ssti_url)
                if ssti_response and "49" in ssti_response.text:
                    findings.append(_normalize_finding(category, "Possible template injection", f"Template-like payload submitted through {param} appears to have been evaluated.", ssti_url, evidence=f"Template payload via {param} appeared to evaluate to 49.", request={"method": "GET", "url": ssti_url}, response=ssti_response, payload=payload, confidence_score=86))

    return findings


async def _scan_insecure_design(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[5]
    findings = []
    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        login_url = base_url.rstrip("/") + "/login"
        success_count = 0
        for _ in range(10):
            response = await _request(client, "GET", login_url)
            if response and response.status_code == 200:
                success_count += 1
        if success_count == 10:
            findings.append(_normalize_finding(category, "No rate limiting detected", "Repeated access to a likely authentication route did not trigger throttling behavior.", login_url))

        for path in ("/admin", "/admin/login", "/dashboard", "/debug", "/test", "/backup", "/old", "/dev", "/.env", "/config", "/settings", "/logs"):
            url = base_url.rstrip("/") + path
            response = await _request(client, "GET", url)
            if response and response.status_code == 200:
                findings.append(_normalize_finding(category, "Predictable sensitive route exposed", f"The path {path} was reachable and may indicate weak segregation of sensitive features.", url))

        payload = "<invalid_input_123>"
        validation_url = f"{base_url}?input={payload}"
        validation_response = await _request(client, "GET", validation_url)
        if validation_response and payload in validation_response.text:
            findings.append(_normalize_finding(category, "Input reflected without validation", "The supplied test value was reflected in the response without visible sanitization.", validation_url))

    return findings


async def _scan_auth_failures(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[6]
    findings = []
    login_paths = ["/login", "/user/login", "/admin/login", "/signin", "/auth"]
    default_creds = [("admin", "admin"), ("admin", "password"), ("root", "root"), ("test", "test")]

    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        login_url = None
        for path in login_paths:
            candidate = base_url.rstrip("/") + path
            response = await _request(client, "GET", candidate)
            if response and response.status_code == 200:
                login_url = candidate
                break

        if not login_url:
            return findings

        for username, password in default_creds:
            response = await _request(client, "POST", login_url, data={"username": username, "password": password})
            if response and ("logout" in response.text.lower() or response.status_code in (301, 302, 303, 307, 308)):
                findings.append(_normalize_finding(category, "Default credentials may work", f"The login flow responded positively to {username}:{password}.", login_url, evidence="Default credentials triggered a success-like response.", request={"method": "POST", "url": login_url}, response=response, payload=f"username={username}&password={password}", confidence_score=92))

        repeated_successes = 0
        for _ in range(10):
            response = await _request(client, "POST", login_url, data={"username": "test", "password": "wrongpass"})
            if response and response.status_code in (200, 401):
                repeated_successes += 1
        if repeated_successes == 10:
            findings.append(_normalize_finding(category, "No brute-force protection observed", "Repeated failed login attempts did not trigger visible rate limiting or lockout behavior.", login_url))

        cookie_probe = await _request(client, "GET", login_url)
        if cookie_probe:
            cookies = cookie_probe.headers.get("set-cookie", "")
            if cookies and "Secure" not in cookies:
                findings.append(_normalize_finding(category, "Session cookie missing Secure flag", "Authentication-related cookies were issued without the Secure flag.", login_url, cookies))
            if cookies and "HttpOnly" not in cookies:
                findings.append(_normalize_finding(category, "Session cookie missing HttpOnly flag", "Authentication-related cookies were issued without the HttpOnly flag.", login_url, cookies))

    return findings


async def _scan_data_integrity(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[7]
    findings = []
    html, headers = await _fetch_base_document(base_url, auth_context)
    scripts = _extract_script_sources(base_url, html)
    host = urlparse(base_url).netloc.lower()
    for src in scripts:
        if urlparse(src).scheme in ("http", "https") and "integrity=" not in html.lower():
            findings.append(_normalize_finding(category, "Script resource lacks SRI protection", "A script tag was loaded without an integrity attribute.", src))
        if urlparse(src).netloc and urlparse(src).netloc.lower() != host:
            findings.append(_normalize_finding(category, "Third-party script present", "A third-party hosted script can increase integrity risk if not tightly controlled.", src))

    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        for path in ("/upload", "/file-upload", "/api/upload", "/uploads"):
            url = base_url.rstrip("/") + path
            response = await _request(client, "GET", url)
            if response and response.status_code == 200:
                findings.append(_normalize_finding(category, "Upload endpoint exposed", "A file upload path is reachable and should be reviewed for validation and integrity controls.", url))

        deserialization_probe = await _request(client, "POST", base_url, content='{"test":"data"}')
        if deserialization_probe and any(marker in deserialization_probe.text.lower() for marker in ("exception", "deserialize", "invalid object")):
            findings.append(_normalize_finding(category, "Possible insecure deserialization behavior", "A malformed object submission triggered error text associated with unsafe parsing.", base_url))

    if "Content-Security-Policy" not in headers:
        findings.append(_normalize_finding(category, "CSP header missing", "Content-Security-Policy was not observed, reducing integrity protections in the browser.", base_url))
    if "X-Content-Type-Options" not in headers:
        findings.append(_normalize_finding(category, "X-Content-Type-Options missing", "The response did not include X-Content-Type-Options.", base_url))

    return findings


async def _scan_logging_alert_failures(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[8]
    findings = []
    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        verbose_url = base_url.rstrip("/") + "/nonexistentpage123"
        verbose_response = await _request(client, "GET", verbose_url)
        if verbose_response and any(marker in verbose_response.text.lower() for marker in ("stack trace", "exception", "traceback", "error on line", "debug")):
            findings.append(_normalize_finding(category, "Verbose error details exposed", "The application returned implementation details in an error response.", verbose_url))

        login_url = base_url.rstrip("/") + "/login"
        login_responses = []
        for _ in range(5):
            response = await _request(client, "POST", login_url, data={"username": "invalid", "password": "wrong"})
            if response:
                login_responses.append(response.text)
        if len(login_responses) == 5 and len(set(login_responses)) == 1:
            findings.append(_normalize_finding(category, "No visible response change on repeated failed logins", "Repeated failed authentication attempts returned identical responses, which may indicate weak alerting or detection feedback.", login_url))

        for path in ("/logs", "/log", "/debug", "/admin/logs", "/server-status"):
            url = base_url.rstrip("/") + path
            response = await _request(client, "GET", url)
            if response and response.status_code == 200:
                findings.append(_normalize_finding(category, "Log or debug endpoint exposed", "An operational logging or debugging endpoint was accessible.", url))

    return findings


async def _scan_exception_handling(base_url: str, auth_context: dict | None = None) -> list[dict]:
    category = CATEGORY_DEFINITIONS[9]
    findings = []
    payloads = ["'\"<script>", "{invalid_json:", "../../../../etc/passwd", "%00%00%00"]
    async with httpx.AsyncClient(**build_request_config(auth_context)) as client:
        for payload in payloads:
            url = base_url.rstrip("/") + f"?input={payload}"
            response = await _request(client, "GET", url)
            if response and response.status_code >= 500:
                findings.append(_normalize_finding(category, "Server error on malformed input", "Malformed input triggered a server-side error response.", url))
            if response and any(marker in response.text.lower() for marker in ("exception", "traceback", "stack trace", "error on line")):
                findings.append(_normalize_finding(category, "Exception details exposed", "Malformed input caused debug or exception information to appear in the response.", url))

        oversized_url = base_url.rstrip("/") + f"?data={'A' * 10000}"
        oversized_response = await _request(client, "GET", oversized_url)
        if oversized_response and oversized_response.status_code >= 500:
            findings.append(_normalize_finding(category, "Large input caused instability", "An oversized input payload caused a server-side error.", oversized_url))

        for method in ("PUT", "DELETE", "PATCH"):
            response = await _request(client, method, base_url)
            if response and response.status_code not in (403, 405):
                findings.append(_normalize_finding(category, "Unexpected HTTP method handling", f"The server did not reject an unexpected {method} request.", base_url, method))

    return findings


async def _scan_category(category: dict, scanner, base_url: str, auth_context: dict | None = None) -> dict:
    try:
        findings = await scanner(base_url, auth_context)
        return {
            "id": category["id"],
            "short": category["short"],
            "title": category["title"],
            "severity": category["severity"],
            "status": "completed",
            "findings_count": len(findings),
            "findings": findings,
        }
    except Exception as exc:
        return {
            "id": category["id"],
            "short": category["short"],
            "title": category["title"],
            "severity": category["severity"],
            "status": "error",
            "findings_count": 0,
            "findings": [],
            "error": str(exc),
        }


async def scan_owasp_top_10(target: str, auth_context: dict | None = None) -> dict:
    base_url = await normalize_target_url_with_auth(target, auth_context)
    scanners = [
        _scan_broken_access_control,
        _scan_security_misconfiguration,
        _scan_supply_chain,
        _scan_cryptographic_failures,
        _scan_injection,
        _scan_insecure_design,
        _scan_auth_failures,
        _scan_data_integrity,
        _scan_logging_alert_failures,
        _scan_exception_handling,
    ]
    results = await asyncio.gather(*[
        _scan_category(category, scanner, base_url, auth_context)
        for category, scanner in zip(CATEGORY_DEFINITIONS, scanners)
    ])
    total_findings = sum(item.get("findings_count", 0) for item in results)
    categories_with_findings = sum(1 for item in results if item.get("findings_count", 0) > 0)
    return {
        "enabled": True,
        "target": target,
        "normalized_url": base_url,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_categories": len(results),
            "categories_with_findings": categories_with_findings,
            "total_findings": total_findings,
        },
        "results": results,
        "authenticated_scan": bool(auth_context),
    }
