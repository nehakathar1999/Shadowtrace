from __future__ import annotations

import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import quote

import requests

COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "dev",
    "test",
    "staging",
    "vpn",
    "mail",
    "gateway",
]

NETCRAFT_REPORT_URL = "https://sitereport.netcraft.com/?url={target}"
ROBTEX_FREE_API_BASE = "https://freeapi.robtex.com"
ROBTEX_IPQUERY_LIMIT = 6
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; AssetDiscovery/1.0; +https://example.local)",
}
ROBTEX_DETAIL_TYPES = ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME")
NETCRAFT_FIELD_LABELS = {
    "site_title": "Site title",
    "site_rank": "Site rank",
    "description": "Description",
    "date_first_seen": "Date first seen",
    "primary_language": "Primary language",
    "site": "Site",
    "netblock_owner": "Netblock Owner",
    "hosting_company": "Hosting company",
    "hosting_country": "Hosting country",
    "ipv4_address": "IPv4 address",
    "ipv4_autonomous_systems": "IPv4 autonomous systems",
    "ipv6_address": "IPv6 address",
    "ipv6_autonomous_systems": "IPv6 autonomous systems",
    "reverse_dns": "Reverse DNS",
    "domain": "Domain",
    "nameserver": "Nameserver",
    "domain_registrar": "Domain registrar",
    "nameserver_organisation": "Nameserver organisation",
    "organisation": "Organisation",
    "dns_admin": "DNS admin",
    "top_level_domain": "Top Level Domain",
    "dns_security_extensions": "DNS Security Extensions",
    "robtex_a_records": "Robtex A records",
    "robtex_aaaa_records": "Robtex AAAA records",
    "robtex_cname_records": "Robtex CNAME records",
    "robtex_mx_records": "Robtex MX records",
    "robtex_ns_records": "Robtex NS records",
    "robtex_txt_records": "Robtex TXT records",
    "robtex_soa_records": "Robtex SOA records",
    "robtex_passive_dns": "Robtex passive DNS",
    "robtex_passive_dns_count": "Robtex passive DNS count",
    "robtex_source": "Robtex source",
    "robtex_dnssec_status": "Robtex DNSSEC status",
    "robtex_records_table": "Records",
    "robtex_dns_history_table": "DNS History",
    "robtex_resolution_tree": "DNS Resolution",
}

NETCRAFT_FIELD_ORDER = [
    "site_title",
    "site_rank",
    "description",
    "date_first_seen",
    "primary_language",
    "site",
    "netblock_owner",
    "hosting_company",
    "hosting_country",
    "ipv4_address",
    "ipv4_autonomous_systems",
    "ipv6_address",
    "ipv6_autonomous_systems",
    "reverse_dns",
    "domain",
    "nameserver",
    "domain_registrar",
    "nameserver_organisation",
    "organisation",
    "dns_admin",
    "top_level_domain",
    "dns_security_extensions",
    "robtex_a_records",
    "robtex_aaaa_records",
    "robtex_cname_records",
    "robtex_mx_records",
    "robtex_ns_records",
    "robtex_txt_records",
    "robtex_soa_records",
    "robtex_passive_dns",
    "robtex_passive_dns_count",
    "robtex_source",
    "robtex_dnssec_status",
    "robtex_records_table",
    "robtex_dns_history_table",
    "robtex_resolution_tree",
]

SUPPRESSED_DOMAIN_INTEL_KEYS = {
    "report_url",
    "nameserver_organisation",
    "robtex_source",
    "robtex_a_records",
    "robtex_aaaa_records",
    "robtex_cname_records",
    "robtex_mx_records",
    "robtex_ns_records",
    "robtex_txt_records",
    "robtex_soa_records",
    "robtex_passive_dns",
    "robtex_passive_dns_count",
    "robtex_dnssec_status",
    "robtex_records_table",
    "robtex_dns_history_table",
    "robtex_resolution_tree",
}


def _clean_domain(domain: str) -> str:
    domain = str(domain or "").strip().lower()
    return re.sub(r"^https?://", "", domain).strip("/").split("/")[0]


def _resolve_ip(hostname: str) -> str | None:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def _resolve_ipv4_list(hostname: str) -> list[str]:
    try:
        _, _, addresses = socket.gethostbyname_ex(hostname)
        return sorted(dict.fromkeys(addr for addr in addresses if addr))
    except Exception:
        return []


def _resolve_ipv6_list(hostname: str) -> list[str]:
    try:
        rows = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
    except Exception:
        return []
    values = []
    for row in rows:
        address = row[4][0]
        if address:
            values.append(address)
    return sorted(dict.fromkeys(values))


def _reverse_lookup(value: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(value)
        return hostname
    except Exception:
        return None


def _merge_subdomain_record(store: dict[str, dict], hostname: str, source: str) -> None:
    normalized = _clean_domain(hostname)
    if not normalized or "." not in normalized:
        return

    record = store.setdefault(
        normalized,
        {
            "subdomain": normalized,
            "resolved_ip": None,
            "sources": [],
        },
    )
    if source and source not in record["sources"]:
        record["sources"].append(source)
    if not record.get("resolved_ip"):
        record["resolved_ip"] = _resolve_ip(normalized)
    record["source"] = ",".join(record["sources"])


def _extract_hostnames(text: str, domain: str) -> set[str]:
    escaped_domain = re.escape(domain)
    pattern = re.compile(rf"\b(?:[a-z0-9*_-]+\.)+{escaped_domain}\b", re.IGNORECASE)
    matches = set()
    for match in pattern.findall(text or ""):
        hostname = _clean_domain(match.replace("*.", ""))
        if hostname and hostname != domain and hostname.endswith(f".{domain}"):
            matches.add(hostname)
    return matches


def _run_sublist3r_module(domain: str) -> set[str]:
    try:
        import sublist3r  # type: ignore
    except Exception:
        return set()

    try:
        results = sublist3r.main(
            domain,
            40,
            None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,
            engines=None,
        )
    except Exception:
        return set()

    return {
        _clean_domain(item)
        for item in (results or [])
        if _clean_domain(item).endswith(f".{domain}")
    }


def _run_sublist3r_cli(domain: str) -> set[str]:
    candidate_paths = [
        os.getenv("SUBLIST3R_PATH"),
        shutil.which("sublist3r"),
        shutil.which("sublist3r.py"),
        os.path.join(os.getcwd(), "sublist3r.py"),
        os.path.join(os.getcwd(), "Sublist3r", "sublist3r.py"),
    ]

    for candidate in candidate_paths:
        if not candidate or not os.path.exists(candidate) and not shutil.which(candidate):
            continue

        command = [candidate, "-d", domain]
        if str(candidate).lower().endswith(".py"):
            command = [sys.executable, candidate, "-d", domain]

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        except Exception:
            continue

        combined_output = "\n".join(
            part for part in [completed.stdout, completed.stderr] if part
        )
        matches = _extract_hostnames(combined_output, domain)
        if matches:
            return matches

    return set()


def _fetch_netcraft_html(domain: str, timeout: int = 12) -> tuple[str | None, str]:
    candidates = [
        domain,
        f"http://{domain}",
        f"https://{domain}",
    ]
    headers = dict(REQUEST_HEADERS)
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

    last_url = ""
    for target in candidates:
        report_url = NETCRAFT_REPORT_URL.format(target=quote(target, safe=":/"))
        last_url = report_url
        try:
            response = requests.get(report_url, headers=headers, timeout=timeout)
            if response.ok and response.text:
                return response.text, report_url
        except Exception:
            continue

    return None, last_url


def _fetch_robtex_json(path: str, params: dict[str, str], timeout: int = 12) -> tuple[dict | list | None, str, str | None]:
    url = f"{ROBTEX_FREE_API_BASE}{path}"
    try:
        response = requests.get(url, params=params, headers=REQUEST_HEADERS, timeout=timeout)
        if not response.ok:
            return None, response.url or url, f"HTTP {response.status_code}"
        return response.json(), response.url or url, None
    except Exception as exc:
        return None, url, str(exc)


def _fetch_robtex_ndjson(path: str, params: dict[str, str], timeout: int = 12) -> tuple[list[dict], str, str | None]:
    url = f"{ROBTEX_FREE_API_BASE}{path}"
    try:
        response = requests.get(url, params=params, headers=REQUEST_HEADERS, timeout=timeout)
        if not response.ok:
            return [], response.url or url, f"HTTP {response.status_code}"
        records = []
        for line in (response.text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    records.append(parsed)
            except Exception:
                continue
        return records, response.url or url, None
    except Exception as exc:
        return [], url, str(exc)


def _fetch_robtex_ipquery(ip_address: str, timeout: int = 12) -> dict:
    payload, _, error = _fetch_robtex_json("/ipquery", {"ip": ip_address}, timeout=timeout)
    if isinstance(payload, dict):
        result = dict(payload)
        if error:
            result["_error"] = error
        return result
    return {"_error": error} if error else {}


def _stringify_robtex_value(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        return cleaned or None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        parts = [_stringify_robtex_value(item) for item in value]
        joined = ", ".join(part for part in parts if part)
        return joined or None
    if isinstance(value, dict):
        for key in ("value", "rrdata", "target", "exchange", "host", "hostname", "name", "txt", "string", "mname"):
            cleaned = _stringify_robtex_value(value.get(key))
            if cleaned:
                return cleaned
        pieces = []
        for key in ("priority", "preference", "ttl", "serial", "refresh", "retry", "expire", "minimum"):
            if value.get(key) not in (None, ""):
                pieces.append(f"{key}={value.get(key)}")
        return ", ".join(pieces) or None
    return str(value)


def _format_robtex_timestamp(timestamp: int | str | None) -> str | None:
    try:
        if timestamp in (None, ""):
            return None
        ts = int(timestamp)
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        return None


def _extract_robtex_record_values(payload: dict | list | None, record_type: str) -> list[str]:
    if payload is None:
        return []

    desired = record_type.upper()
    bucket: list[str] = []

    def visit(node):
        if isinstance(node, dict):
            node_type = str(node.get("rrtype") or node.get("type") or "").upper()
            if node_type == desired:
                text = _stringify_robtex_value(node)
                if text:
                    bucket.append(text)
            for key, value in node.items():
                if str(key).lower() in {
                    desired.lower(),
                    desired,
                    f"dns_{desired.lower()}",
                    f"{desired.lower()}_records",
                    f"{desired}_records",
                }:
                    if isinstance(value, list):
                        for item in value:
                            text = _stringify_robtex_value(item)
                            if text:
                                bucket.append(text)
                    else:
                        text = _stringify_robtex_value(value)
                        if text:
                            bucket.append(text)
                elif isinstance(value, (dict, list)):
                    visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(payload)
    return sorted(dict.fromkeys(item for item in bucket if item))


def _extract_robtex_dnssec_status(payload: dict | list | None) -> str | None:
    if payload is None:
        return None

    if isinstance(payload, dict):
        for key, value in payload.items():
            lowered = str(key).lower()
            if lowered in {"dnssec", "dnssec_status", "dnssecstate", "dnssec_state"}:
                text = _stringify_robtex_value(value)
                if text:
                    return text
            if isinstance(value, (dict, list)):
                nested = _extract_robtex_dnssec_status(value)
                if nested:
                    return nested
    elif isinstance(payload, list):
        for item in payload:
            nested = _extract_robtex_dnssec_status(item)
            if nested:
                return nested
    return None


def _summarize_robtex_records(values: list[str], limit: int = 8) -> str | None:
    cleaned = [item for item in values if item]
    if not cleaned:
        return None
    if len(cleaned) <= limit:
        return ", ".join(cleaned)
    remainder = len(cleaned) - limit
    return f"{', '.join(cleaned[:limit])} (+{remainder} more)"


def _compact_text_list(values: list[str], limit: int = 3, separator: str = ", ") -> str:
    cleaned = [item for item in values if item]
    if not cleaned:
        return "Not Present"
    if len(cleaned) <= limit:
        return separator.join(cleaned)
    return f"{separator.join(cleaned[:limit])} (+{len(cleaned) - limit} more)"


def _ip_annotation(ip_data: dict) -> str | None:
    parts = []
    if ip_data.get("bgproute"):
        parts.append(str(ip_data["bgproute"]))
    owner = ip_data.get("whoisdesc") or ip_data.get("asname")
    if owner:
        parts.append(str(owner))
    return " | ".join(parts) if parts else None


def _build_robtex_records_table(record_values: dict[str, list[str]]) -> list[dict]:
    rows = []
    for record_type in ROBTEX_DETAIL_TYPES:
        values = record_values.get(record_type) or []
        if not values:
            continue
        rows.append({
            "type": record_type,
            "count": len(values),
            "sample": _compact_text_list(values, limit=4),
            "values": values,
        })
    return rows


def _build_robtex_history_table(pdns_records: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str], dict] = {}
    for item in pdns_records:
        rrtype = str(item.get("rrtype") or "").upper()
        rrdata = _stringify_robtex_value(item.get("rrdata"))
        if not rrtype or not rrdata:
            continue
        key = (rrtype, rrdata)
        record = grouped.setdefault(key, {
            "type": rrtype,
            "value": rrdata,
            "count": 0,
            "first_seen": None,
            "last_seen": None,
            "active_hosts": set(),
        })
        observed_count = int(item.get("count") or 0)
        record["count"] += observed_count
        first = _format_robtex_timestamp(item.get("time_first"))
        last = _format_robtex_timestamp(item.get("time_last"))
        if first and (record["first_seen"] is None or first < record["first_seen"]):
            record["first_seen"] = first
        if last and (record["last_seen"] is None or last > record["last_seen"]):
            record["last_seen"] = last
        rrname = _clean_domain(item.get("rrname") or "")
        if rrname:
            record["active_hosts"].add(rrname)

    rows = []
    for value in grouped.values():
        rows.append({
            "type": value["type"],
            "value": value["value"],
            "first_seen": value["first_seen"] or "Unknown",
            "last_seen": value["last_seen"] or "Unknown",
            "observations": value["count"],
            "hosts": sorted(value["active_hosts"]),
            "active_host_count": len(value["active_hosts"]),
        })
    return sorted(rows, key=lambda item: (item["type"], item["value"]))


def _build_robtex_resolution_tree(
    domain: str,
    record_values: dict[str, list[str]],
) -> list[dict]:
    ip_cache: dict[str, dict] = {}
    ipquery_count = 0

    def get_ip_details(ip_address: str) -> dict:
        nonlocal ipquery_count
        if ip_address not in ip_cache:
            if ipquery_count >= ROBTEX_IPQUERY_LIMIT:
                ip_cache[ip_address] = {}
            else:
                ip_cache[ip_address] = _fetch_robtex_ipquery(ip_address)
                ipquery_count += 1
        return ip_cache[ip_address]

    rows = []

    for ip_address in record_values.get("A", []) + record_values.get("AAAA", []):
        ip_data = get_ip_details(ip_address)
        rows.append({
            "type": "A" if ":" not in ip_address else "AAAA",
            "value": ip_address,
            "annotation": _ip_annotation(ip_data),
            "children": [
                child for child in [{
                    "type": "PTR",
                    "value": _reverse_lookup(ip_address),
                    "annotation": None,
                }] if child["value"]
            ],
        })

    for parent_type in ("NS", "MX"):
        for hostname in record_values.get(parent_type, []):
            children = []
            for ipv4 in _resolve_ipv4_list(hostname):
                ip_data = get_ip_details(ipv4)
                children.append({
                    "type": "A",
                    "value": ipv4,
                    "annotation": _ip_annotation(ip_data),
                })
                ptr_value = _reverse_lookup(ipv4)
                if ptr_value:
                    children.append({
                        "type": "PTR",
                        "value": ptr_value,
                        "annotation": None,
                    })
            for ipv6 in _resolve_ipv6_list(hostname):
                ip_data = get_ip_details(ipv6)
                children.append({
                    "type": "AAAA",
                    "value": ipv6,
                    "annotation": _ip_annotation(ip_data),
                })
                ptr_value = _reverse_lookup(ipv6)
                if ptr_value:
                    children.append({
                        "type": "PTR",
                        "value": ptr_value,
                        "annotation": None,
                    })
            rows.append({
                "type": parent_type,
                "value": hostname,
                "annotation": None,
                "children": children,
            })

    if record_values.get("TXT"):
        rows.append({
            "type": "TXT",
            "value": _compact_text_list(record_values["TXT"], limit=2, separator=" | "),
            "annotation": None,
            "children": [],
        })
    if record_values.get("SOA"):
        rows.append({
            "type": "SOA",
            "value": _compact_text_list(record_values["SOA"], limit=2, separator=" | "),
            "annotation": None,
            "children": [],
        })

    return rows


def _fetch_robtex_domain_intelligence(domain: str) -> dict:
    lookup_payload, lookup_url, lookup_error = _fetch_robtex_json("/lookup_dns", {"hostname": domain})
    pdns_records, pdns_url, pdns_error = _fetch_robtex_ndjson("/pdns_forward", {"domain": domain})

    details = {}
    display_details = []
    record_map = {
        "A": "robtex_a_records",
        "AAAA": "robtex_aaaa_records",
        "CNAME": "robtex_cname_records",
        "MX": "robtex_mx_records",
        "NS": "robtex_ns_records",
        "TXT": "robtex_txt_records",
        "SOA": "robtex_soa_records",
    }
    record_values = {}

    for record_type, field_key in record_map.items():
        values = _extract_robtex_record_values(lookup_payload, record_type)
        record_values[record_type] = values
        if values:
            details[field_key] = _summarize_robtex_records(values)

    dnssec_status = _extract_robtex_dnssec_status(lookup_payload)
    if dnssec_status:
        details["robtex_dnssec_status"] = dnssec_status

    if pdns_records:
        grouped = defaultdict(list)
        for item in pdns_records:
            rrtype = str(item.get("rrtype") or "").upper()
            rrname = _clean_domain(item.get("rrname") or "")
            rrdata = _stringify_robtex_value(item.get("rrdata"))
            first_seen = _format_robtex_timestamp(item.get("time_first"))
            last_seen = _format_robtex_timestamp(item.get("time_last"))
            if not rrdata:
                continue
            summary = rrdata
            if rrname and rrname != domain:
                summary = f"{rrname} -> {rrdata}"
            if first_seen or last_seen:
                if first_seen and last_seen and first_seen != last_seen:
                    summary = f"{summary} [{first_seen} to {last_seen}]"
                else:
                    summary = f"{summary} [{last_seen or first_seen}]"
            grouped[rrtype].append(summary)

        if grouped:
            combined = []
            for rrtype in sorted(grouped):
                examples = sorted(dict.fromkeys(grouped[rrtype]))
                preview = "; ".join(examples[:3])
                if len(examples) > 3:
                    preview = f"{preview}; +{len(examples) - 3} more"
                combined.append(f"{rrtype}: {preview}")
            details["robtex_passive_dns"] = " | ".join(combined[:6])
            details["robtex_passive_dns_count"] = str(len(pdns_records))

    if lookup_payload or pdns_records:
        details["robtex_source"] = "lookup_dns + pdns_forward" if lookup_payload and pdns_records else "lookup_dns" if lookup_payload else "pdns_forward"

    records_table = _build_robtex_records_table(record_values)
    history_table = _build_robtex_history_table(pdns_records)
    resolution_tree = _build_robtex_resolution_tree(domain, record_values)

    complex_display_items = []
    if records_table:
        complex_display_items.append({
            "key": "robtex_records_table",
            "label": "Records",
            "value": records_table,
            "kind": "records_table",
        })
    if history_table:
        complex_display_items.append({
            "key": "robtex_dns_history_table",
            "label": "DNS History",
            "value": history_table,
            "kind": "history_table",
        })
    if resolution_tree:
        complex_display_items.append({
            "key": "robtex_resolution_tree",
            "label": "DNS Resolution",
            "value": resolution_tree,
            "kind": "resolution_tree",
        })

    for key, value in details.items():
        display_details.append({
            "key": key,
            "label": NETCRAFT_FIELD_LABELS.get(key) or key.replace("_", " ").title(),
            "value": value,
        })
    display_details.extend(complex_display_items)

    notes = []
    if lookup_error:
        notes.append(f"Robtex DNS lookup unavailable ({lookup_error}).")
    if pdns_error:
        notes.append(f"Robtex passive DNS unavailable ({pdns_error}).")

    return {
        "enabled": bool(details),
        "details": details,
        "display_details": display_details,
        "note": " ".join(notes) if notes else None,
        "passive_records": pdns_records,
    }


def _merge_domain_intelligence(base: dict, extra: dict) -> dict:
    merged_details = dict(base.get("details") or {})
    merged_display = list(base.get("display_details") or [])
    existing_keys = {item.get("key") for item in merged_display if item.get("key")}

    for key, value in (extra.get("details") or {}).items():
        if value not in (None, "") and key not in merged_details:
            merged_details[key] = value

    for item in extra.get("display_details") or []:
        key = item.get("key")
        if not key or key in existing_keys:
            continue
        merged_display.append(item)
        existing_keys.add(key)

    notes = [text for text in [base.get("note"), extra.get("note")] if text]

    return {
        "enabled": bool(merged_details),
        "details": merged_details,
        "display_details": merged_display,
        "note": " ".join(dict.fromkeys(notes)) if notes else None,
    }


def _clean_html_value(value: str) -> str:
    value = re.sub(r"<script.*?</script>", "", value or "", flags=re.IGNORECASE | re.DOTALL)
    value = re.sub(r"<style.*?</style>", "", value, flags=re.IGNORECASE | re.DOTALL)
    value = re.sub(r"<br\s*/?>", ", ", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value).strip(" |")
    return value


def _extract_netcraft_field(html_text: str, label: str) -> str | None:
    patterns = [
        rf"<tr[^>]*>\s*<(?:th|td)[^>]*>\s*{re.escape(label)}\s*</(?:th|td)>\s*<(?:td|th)[^>]*>(.*?)</(?:td|th)>",
        rf"<dt[^>]*>\s*{re.escape(label)}\s*</dt>\s*<dd[^>]*>(.*?)</dd>",
    ]
    for pattern in patterns:
        match = re.search(pattern, html_text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            cleaned = _clean_html_value(match.group(1))
            if cleaned:
                return cleaned
    return None


def _normalize_field_key(label: str) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", str(label or "").strip().lower()).strip("_")
    return key


def _extract_netcraft_pairs(html_text: str) -> list[tuple[str, str]]:
    pair_patterns = [
        re.compile(
            r"<tr[^>]*>\s*<(?:th|td)[^>]*>(.*?)</(?:th|td)>\s*<(?:td|th)[^>]*>(.*?)</(?:td|th)>",
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            r"<dt[^>]*>(.*?)</dt>\s*<dd[^>]*>(.*?)</dd>",
            re.IGNORECASE | re.DOTALL,
        ),
    ]

    pairs: list[tuple[str, str]] = []
    seen = set()
    for pattern in pair_patterns:
        for raw_label, raw_value in pattern.findall(html_text or ""):
            label = _clean_html_value(raw_label)
            value = _clean_html_value(raw_value)
            if not label or not value:
                continue
            normalized_key = _normalize_field_key(label)
            if not normalized_key:
                continue
            signature = (normalized_key, value)
            if signature in seen:
                continue
            seen.add(signature)
            pairs.append((label, value))
    return pairs


def lookup_domain_intelligence(domain: str) -> dict:
    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return {
            "enabled": False,
            "details": {},
            "display_details": [],
            "note": "Target is not a valid domain.",
        }

    html_text, _ = _fetch_netcraft_html(domain)
    netcraft = {
        "enabled": False,
        "details": {},
        "display_details": [],
        "note": "Netcraft lookup was unavailable during this scan.",
    }

    if html_text:
        details = {}
        display_details = []

        for label, value in _extract_netcraft_pairs(html_text):
            key = _normalize_field_key(label)
            if key and value and key not in details:
                details[key] = value

        for field_key, label in NETCRAFT_FIELD_LABELS.items():
            value = details.get(field_key) or _extract_netcraft_field(html_text, label)
            if value:
                details[field_key] = value

        ordered_keys = [key for key in NETCRAFT_FIELD_ORDER if key in details]
        remaining_keys = sorted(key for key in details.keys() if key not in ordered_keys)

        for key in ordered_keys + remaining_keys:
            display_details.append({
                "key": key,
                "label": NETCRAFT_FIELD_LABELS.get(key) or key.replace("_", " ").title(),
                "value": details[key],
            })

        netcraft = {
            "enabled": bool(details),
            "details": details,
            "display_details": display_details,
            "note": None if details else "Netcraft returned no parsable fields for this domain.",
        }

    robtex = _fetch_robtex_domain_intelligence(domain)
    merged = _merge_domain_intelligence(netcraft, robtex)
    merged["details"] = {k: v for k, v in (merged.get("details") or {}).items() if k not in SUPPRESSED_DOMAIN_INTEL_KEYS}
    merged["display_details"] = [item for item in (merged.get("display_details") or []) if item.get("key") not in SUPPRESSED_DOMAIN_INTEL_KEYS]
    return merged


def enumerate_subdomains(domain: str, candidates: list[str] | None = None) -> list[dict]:
    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return []

    discovered_map: dict[str, dict] = {}

    for hostname in sorted(_run_sublist3r_module(domain) | _run_sublist3r_cli(domain)):
        _merge_subdomain_record(discovered_map, hostname, "sublist3r")

    for prefix in candidates or COMMON_SUBDOMAINS:
        fqdn = f"{prefix}.{domain}"
        if _resolve_ip(fqdn):
            _merge_subdomain_record(discovered_map, fqdn, "dns_bruteforce")

    robtex = _fetch_robtex_domain_intelligence(domain)
    for item in robtex.get("passive_records") or []:
        hostname = item.get("rrname")
        if hostname:
            _merge_subdomain_record(discovered_map, hostname, "robtex_pdns")

    return sorted(discovered_map.values(), key=lambda item: item["subdomain"])


def build_network_map(assets: list[dict]) -> dict:
    nodes = []
    edges = []
    seen_nodes = set()

    for asset in assets or []:
        host = asset.get("domain") or asset.get("hostname") or asset.get("ip")
        if not host:
            continue
        if host not in seen_nodes:
            nodes.append({
                "id": host,
                "label": host,
                "ip": asset.get("ip"),
                "type": asset.get("device_type") or "asset",
            })
            seen_nodes.add(host)
        for port_info in asset.get("open_ports", []) or []:
            port_node = f"{host}:{port_info.get('port')}"
            if port_node not in seen_nodes:
                nodes.append({
                    "id": port_node,
                    "label": f"{port_info.get('service') or 'service'}:{port_info.get('port')}",
                    "type": "service",
                    "port": port_info.get("port"),
                    "service": port_info.get("service"),
                })
                seen_nodes.add(port_node)
            edges.append({
                "source": host,
                "target": port_node,
                "relationship": "exposes",
            })

    return {"nodes": nodes, "edges": edges}


def summarize_inventory(
    scan_target: str,
    assets: list[dict],
    subdomains: list[dict] | None = None,
    domain_intelligence: dict | None = None,
) -> dict:
    unique_ips = sorted({asset.get("ip") for asset in assets or [] if asset.get("ip")})
    services = sorted({
        (port.get("service") or "unknown").lower()
        for asset in assets or []
        for port in (asset.get("open_ports") or [])
        if port.get("port")
    })
    return {
        "target": scan_target,
        "asset_count": len(assets or []),
        "ip_addresses": unique_ips,
        "services": services,
        "subdomains": subdomains or [],
        "domain_intelligence": domain_intelligence or {},
        "network_map": build_network_map(assets or []),
    }
