from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler


SCHEDULE_STORE = os.path.join("reports", "scheduled_scans.json")
RUN_HISTORY_STORE = os.path.join("reports", "scheduled_scan_runs.json")

scheduler = BackgroundScheduler()
_LOCK = threading.Lock()


def _ensure_store():
    os.makedirs("reports", exist_ok=True)


def _load_json(path: str, default):
    _ensure_store()
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return default


def _save_json(path: str, data):
    _ensure_store()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def list_schedules() -> list[dict]:
    with _LOCK:
        return _load_json(SCHEDULE_STORE, [])


def list_schedule_runs() -> list[dict]:
    with _LOCK:
        return _load_json(RUN_HISTORY_STORE, [])


def save_schedule(target: str, interval_minutes: int, options: dict | None = None) -> dict:
    with _LOCK:
        schedules = _load_json(SCHEDULE_STORE, [])
        schedule = {
            "id": uuid.uuid4().hex,
            "target": target,
            "interval_minutes": max(5, int(interval_minutes or 30)),
            "options": options or {},
            "enabled": True,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "last_run_at": None,
        }
        schedules.append(schedule)
        _save_json(SCHEDULE_STORE, schedules)
    return schedule


def delete_schedule(schedule_id: str) -> bool:
    with _LOCK:
        schedules = _load_json(SCHEDULE_STORE, [])
        updated = [item for item in schedules if item.get("id") != schedule_id]
        if len(updated) == len(schedules):
            return False
        _save_json(SCHEDULE_STORE, updated)
    try:
        scheduler.remove_job(schedule_id)
    except Exception:
        pass
    return True


def record_schedule_run(schedule_id: str, target: str, result: dict, drift: dict | None = None):
    with _LOCK:
        runs = _load_json(RUN_HISTORY_STORE, [])
        runs.append({
            "schedule_id": schedule_id,
            "target": target,
            "ran_at": datetime.utcnow().isoformat() + "Z",
            "report_files": result.get("report_files", {}),
            "summary": result.get("vulnerability_summary", {}),
            "drift": drift or {},
        })
        _save_json(RUN_HISTORY_STORE, runs[-100:])

        schedules = _load_json(SCHEDULE_STORE, [])
        for item in schedules:
            if item.get("id") == schedule_id:
                item["last_run_at"] = datetime.utcnow().isoformat() + "Z"
                item["last_report"] = result.get("report_files", {}).get("json")
        _save_json(SCHEDULE_STORE, schedules)


def compare_reports(path_a: str, path_b: str) -> dict:
    def read(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    first = read(path_a)
    second = read(path_b)

    def vuln_keys(payload: dict) -> set[tuple]:
        keys = set()
        for asset in payload.get("assets", []) or []:
            host = asset.get("domain") or asset.get("hostname") or asset.get("ip")
            for vuln in asset.get("vulnerabilities", []) or []:
                keys.add((host, vuln.get("title"), vuln.get("port"), vuln.get("cve")))
        return keys

    before = vuln_keys(first)
    after = vuln_keys(second)
    added = sorted(after - before)
    resolved = sorted(before - after)

    return {
        "older_report": path_a,
        "newer_report": path_b,
        "new_findings": [
            {"host": item[0], "title": item[1], "port": item[2], "cve": item[3]}
            for item in added
        ],
        "resolved_findings": [
            {"host": item[0], "title": item[1], "port": item[2], "cve": item[3]}
            for item in resolved
        ],
        "summary": {
            "new_findings": len(added),
            "resolved_findings": len(resolved),
        },
    }


def schedule_scan_job(schedule: dict, runner):
    schedule_id = schedule["id"]

    def job():
        result = runner(schedule["target"], schedule.get("options") or {})
        last_report = schedule.get("last_report")
        drift = {}
        current_report = result.get("report_files", {}).get("json")
        if last_report and current_report and os.path.exists(last_report) and os.path.exists(current_report):
            try:
                drift = compare_reports(last_report, current_report)
            except Exception:
                drift = {}
        record_schedule_run(schedule_id, schedule["target"], result, drift)

    scheduler.add_job(job, "interval", minutes=schedule["interval_minutes"], id=schedule_id, replace_existing=True)


def start_scheduler(runner=None):
    if not scheduler.running:
        scheduler.start()
    if runner is None:
        return
    for schedule in list_schedules():
        if schedule.get("enabled"):
            schedule_scan_job(schedule, runner)
