"""Local, atomic persistence and conservative cross-run validation of paired evidence."""
import datetime
import hashlib
import json
import math
import os
import platform
import sqlite3
import statistics
import uuid
from pathlib import Path

SCHEMA_VERSION = 1
QUALITY_POLICY_ID = "adjacent-paired-quality-v1"
ENDPOINT = "https://speed.cloudflare.com/__down?bytes={size}"
COMPARABILITY_REASONS = {
    "CONTROL_VARIABLE_MISMATCH",
    "PAIR_IDENTITY_INVALID",
    "HTTP_PROTOCOL_MISMATCH_OR_MISSING",
}


def default_store_path():
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        root = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(root) / "AdaptiveNetworkOptimizer" / "evidence.sqlite3"


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def network_fingerprint(snapshot):
    """Hash only stable interface, DNS and route configuration; never persist raw identifiers."""
    if not isinstance(snapshot, dict):
        return None
    fields = {
        "interfaces": ("InterfaceIndex", "InterfaceAlias", "AddressFamily", "NlMtu",
                       "InterfaceMetric", "Dhcp", "AutomaticMetric"),
        "dns": ("InterfaceIndex", "InterfaceAlias", "AddressFamily", "ServerAddresses"),
        "routes": ("InterfaceIndex", "DestinationPrefix", "NextHop", "RouteMetric"),
    }
    payload = {}
    for section, names in fields.items():
        values = snapshot.get(section)
        if not isinstance(values, list):
            return None
        rows = []
        for row in values:
            if not isinstance(row, dict):
                return None
            item = {name: row.get(name) for name in names}
            if section == "dns" and isinstance(item.get("ServerAddresses"), list):
                item["ServerAddresses"] = sorted(item["ServerAddresses"])
            rows.append(item)
        if section == "interfaces" and not rows:
            return None
        payload[section] = sorted(rows, key=_json)
    return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()


def _context_id(result, fingerprint):
    plan = result.get("formal_plan") or {}
    candidates = sorted(set(result.get("candidates") or plan.get("candidates") or []))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "quality_policy_id": QUALITY_POLICY_ID,
        "platform": platform.system(),
        "parameter": result.get("parameter"),
        "scope": result.get("scope"),
        "endpoint": ENDPOINT,
        "usage_mode": result.get("usage_mode"),
        "rounds": result.get("rounds"),
        "candidates": candidates,
        "total_bytes": plan.get("total_bytes"),
        "connect_timeout_seconds": plan.get("connect_timeout_seconds"),
        "max_time_seconds": plan.get("max_time_seconds"),
        "load_policy": result.get("load_policy") or {},
        "network_fingerprint": fingerprint,
    }
    return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()


def _connect(path):
    target = Path(path) if path is not None else default_store_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(target), timeout=5.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=FULL")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        connection.close()
        raise RuntimeError("EVIDENCE_SCHEMA_NEWER_THAN_APPLICATION")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            app_version TEXT NOT NULL,
            usage_mode TEXT NOT NULL,
            rounds INTEGER NOT NULL,
            candidates_json TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS pairs (
            run_id TEXT NOT NULL,
            pair_id TEXT NOT NULL,
            concurrency INTEGER NOT NULL,
            round_number INTEGER,
            retest INTEGER NOT NULL,
            context_id TEXT,
            valid INTEGER NOT NULL,
            measurement_valid INTEGER NOT NULL,
            environment_verified INTEGER NOT NULL,
            load_window_verified INTEGER NOT NULL,
            reasons_json TEXT NOT NULL,
            speedup REAL,
            latency_ratio REAL,
            baseline_mbps REAL,
            candidate_mbps REAL,
            baseline_ttfb_ms REAL,
            candidate_ttfb_ms REAL,
            baseline_success INTEGER NOT NULL,
            baseline_planned INTEGER NOT NULL,
            candidate_success INTEGER NOT NULL,
            candidate_planned INTEGER NOT NULL,
            http_version TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (run_id, pair_id, concurrency),
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_pairs_context_candidate
            ON pairs(context_id, concurrency, created_at);
    """)
    connection.execute("PRAGMA user_version=1")
    connection.commit()
    return connection, target


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _build_rows(result, records, run_id, created_at):
    plan = result.get("formal_plan") or {}
    candidates = sorted(set(result.get("candidates") or plan.get("candidates") or []))
    rows = []
    for pair in result.get("pairs") or []:
        environment = pair.get("environment") or {}
        begin = environment.get("begin_index")
        end = environment.get("end_index")
        start_record = records[begin] if isinstance(begin, int) and 0 <= begin < len(records) else None
        end_record = records[end] if isinstance(end, int) and 0 <= end < len(records) else None
        start_snapshot = start_record.get("snapshot") if isinstance(start_record, dict) else None
        end_snapshot = end_record.get("snapshot") if isinstance(end_record, dict) else None
        fingerprint = network_fingerprint(start_snapshot)
        end_fingerprint = network_fingerprint(end_snapshot)
        context_stable = fingerprint is not None and end_fingerprint == fingerprint
        protocol = pair.get("http_version")
        context = _context_id(result, fingerprint) if fingerprint is not None else None
        measurement_valid = pair.get("measurement_valid") is True
        environment_verified = pair.get("environment_verified") is True
        load_verified = pair.get("load_window_verified") is True
        valid = bool(pair.get("valid") is True and measurement_valid and
                     environment_verified and load_verified and context_stable)
        reasons = list(pair.get("reasons") or [])
        if not context_stable:
            reasons.append("HISTORY_NETWORK_CONTEXT_UNVERIFIED")
        candidate = _safe_int(pair.get("concurrency"))
        rows.append({
            "run_id": run_id,
            "pair_id": str(pair.get("pair_id") or "UNKNOWN"),
            "concurrency": candidate,
            "round_number": _safe_int(pair.get("round")),
            "retest": int(bool(pair.get("retest"))),
            "context_id": context,
            "valid": int(valid),
            "measurement_valid": int(measurement_valid),
            "environment_verified": int(environment_verified),
            "load_window_verified": int(load_verified),
            "reasons_json": _json(sorted(set(str(x) for x in reasons))),
            "speedup": pair.get("speedup") if _number(pair.get("speedup")) else None,
            "latency_ratio": pair.get("latency_ratio") if _number(pair.get("latency_ratio")) else None,
            "baseline_mbps": pair.get("baseline_mbps") if _number(pair.get("baseline_mbps")) else None,
            "candidate_mbps": pair.get("candidate_mbps") if _number(pair.get("candidate_mbps")) else None,
            "baseline_ttfb_ms": pair.get("baseline_ttfb_ms") if _number(pair.get("baseline_ttfb_ms")) else None,
            "candidate_ttfb_ms": pair.get("candidate_ttfb_ms") if _number(pair.get("candidate_ttfb_ms")) else None,
            "baseline_success": _safe_int(pair.get("baseline_success")),
            "baseline_planned": max(1, _safe_int(pair.get("baseline_planned"), 1)),
            "candidate_success": _safe_int(pair.get("candidate_success")),
            "candidate_planned": max(1, _safe_int(pair.get("candidate_planned"), candidate or 1)),
            "http_version": protocol,
            "created_at": created_at,
        })
    return rows, candidates


def _history_summary(rows, concurrency, rounds, current_run_id, usage_mode, context_id):
    attempted = len(rows)
    good = []
    comparability_invalid = False
    for row in rows:
        try:
            reasons = json.loads(row["reasons_json"] or "[]")
        except (TypeError, ValueError):
            reasons = ["HISTORY_RECORD_CORRUPT"]
        if any(reason in COMPARABILITY_REASONS for reason in reasons):
            comparability_invalid = True
        if (row["valid"] and _number(row["speedup"]) and row["speedup"] > 0 and
                _number(row["latency_ratio"]) and row["latency_ratio"] > 0):
            good.append(row)
        elif row["valid"]:
            comparability_invalid = True
    protocols = {row["http_version"] for row in good if row["http_version"]}
    if len(protocols) > 1 or any(row["valid"] and not row["http_version"] for row in rows):
        comparability_invalid = True
    ratios = [float(row["speedup"]) for row in good]
    rates = [float(row["candidate_mbps"]) for row in good if _number(row["candidate_mbps"]) and row["candidate_mbps"] > 0]
    baseline_rates = [float(row["baseline_mbps"]) for row in good if _number(row["baseline_mbps"]) and row["baseline_mbps"] > 0]
    latency_values = [float(row["latency_ratio"]) for row in good]
    successful = len(good)
    planned_requests = sum(max(0, _safe_int(row["candidate_planned"])) for row in rows)
    successful_requests = sum(max(0, _safe_int(row["candidate_success"])) for row in rows)
    completion = successful / attempted if attempted else 0.0
    request_rate = successful_requests / planned_requests if planned_requests else 0.0
    spread = max(ratios) / min(ratios) if ratios else None
    mean = statistics.mean(ratios) if ratios else 0
    cv = statistics.pstdev(ratios) / mean if len(ratios) > 1 and mean else (0.0 if ratios else None)
    valid_runs = {row["run_id"] for row in good}
    all_runs = {row["run_id"] for row in rows}
    current_valid = sum(row["run_id"] == current_run_id for row in good)
    reasons = []
    if comparability_invalid:
        reasons.append("COMPARABILITY_EVIDENCE_INVALID")
    if successful < rounds:
        reasons.append("INSUFFICIENT_VALID_PAIRS")
    if completion < .75 or request_rate < .75:
        reasons.append("LOW_COMPLETION_RATE")
    if ratios and (spread > 2 or (len(ratios) > 1 and cv > .35)):
        reasons.append("HIGH_PAIRED_VARIATION")
    if len(valid_runs) < 2:
        reasons.append("INSUFFICIENT_INDEPENDENT_RUNS")
    if current_valid < 1:
        reasons.append("CURRENT_RUN_NOT_CONFIRMED")
    if usage_mode != "controlled":
        reasons.append("SHARED_MODE_OBSERVATION_ONLY")
    median_ratio = statistics.median(ratios) if ratios else None
    latency = statistics.median(latency_values) if latency_values else None
    votes = sum(value >= 1.10 for value in ratios)
    reliability = min(completion, request_rate)
    score = median_ratio ** .65 * reliability ** .25 * min(1, latency) ** .10 if median_ratio and latency and reliability else None
    eligible = not reasons
    if "COMPARABILITY_EVIDENCE_INVALID" in reasons:
        state = "IRRECOVERABLE_COMPARABILITY"
    elif spread is not None and spread > 2:
        state = "IRRECOVERABLE_SPREAD"
    elif usage_mode != "controlled":
        state = "OBSERVATIONAL_ONLY"
    elif eligible and median_ratio is not None:
        if median_ratio >= 1.10 and votes >= math.ceil(2 * successful / 3) and score is not None and score > 1:
            state = "SUPPORTED_GAIN"
        elif median_ratio < 1.10 and successful - votes >= math.ceil(2 * successful / 3):
            state = "SUPPORTED_NO_GAIN"
        else:
            state = "NEEDS_MORE_EVIDENCE"
    else:
        state = "NEEDS_MORE_EVIDENCE"
    return {
        "concurrency": concurrency,
        "context_id": context_id,
        "history_run_count": len(all_runs),
        "history_valid_run_count": len(valid_runs),
        "current_run_valid_pairs": current_valid,
        "planned_rounds": rounds,
        "attempted_rounds": attempted,
        "successful_rounds": successful,
        "paired_rounds": successful,
        "pair_completion_rate": completion,
        "success_rate": request_rate,
        "success_requests": successful_requests,
        "planned_requests": planned_requests,
        "median_mbps": statistics.median(rates) if rates else None,
        "paired_baseline_median_mbps": statistics.median(baseline_rates) if baseline_rates else None,
        "paired_median_speedup": median_ratio,
        "paired_median_speedup_pct": (median_ratio - 1) * 100 if median_ratio is not None else None,
        "variation_ratio": spread,
        "paired_cv": cv,
        "paired_latency_ratio": latency,
        "material_gain_pairs": votes,
        "composite_score": score,
        "eligible": eligible,
        "quality_reasons": sorted(set(reasons)),
        "evidence_state": state,
    }


def persist_and_analyze(result, records, path=None, app_version="0.3.8"):
    """Append one run in a single SQLite transaction and evaluate only identical contexts."""
    pairs = result.get("pairs") or []
    if not pairs:
        return {
            "history_store": {"status": "NO_PAIRS", "stored_pairs": 0, "database": "evidence.sqlite3"},
            "historical_evidence": [],
            "history_cross_run_ready": False,
        }
    run_id = uuid.uuid4().hex
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    records = records if isinstance(records, list) else []
    rows, candidates = _build_rows(result, records, run_id, created_at)
    rounds = _safe_int(result.get("rounds"), 3)
    plan = result.get("formal_plan") or {}
    usage_mode = str(result.get("usage_mode") or "unknown")
    connection = None
    try:
        connection, target = _connect(path)
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "INSERT INTO runs VALUES (?,?,?,?,?,?,?,?)",
            (run_id, created_at, str(app_version), usage_mode, rounds, _json(candidates), _json(plan),
             str(result.get("status") or "Unknown")))
        columns = (
            "run_id,pair_id,concurrency,round_number,retest,context_id,valid,measurement_valid,"
            "environment_verified,load_window_verified,reasons_json,speedup,latency_ratio,baseline_mbps,"
            "candidate_mbps,baseline_ttfb_ms,candidate_ttfb_ms,baseline_success,baseline_planned,"
            "candidate_success,candidate_planned,http_version,created_at"
        )
        placeholders = ",".join("?" for _ in range(23))
        values = [[row[key] for key in columns.split(",")] for row in rows]
        connection.executemany("INSERT INTO pairs (" + columns + ") VALUES (" + placeholders + ")", values)
        connection.commit()

        summaries = []
        for candidate in (c for c in candidates if c > 1):
            contexts = {row["context_id"] for row in rows
                        if row["concurrency"] == candidate and row["context_id"]}
            if len(contexts) != 1:
                state = "CONTEXT_SPLIT" if len(contexts) > 1 else "UNVERIFIED_CONTEXT"
                summaries.append({
                    "concurrency": candidate, "context_id": None, "history_run_count": 0,
                    "history_valid_run_count": 0, "current_run_valid_pairs": 0,
                    "attempted_rounds": 0, "paired_rounds": 0, "eligible": False,
                    "quality_reasons": ["MULTIPLE_NETWORK_CONTEXTS" if len(contexts) > 1 else "NETWORK_CONTEXT_UNAVAILABLE"],
                    "evidence_state": state,
                })
                continue
            context = next(iter(contexts))
            history_rows = connection.execute(
                "SELECT p.*, r.usage_mode FROM pairs p JOIN runs r ON r.run_id=p.run_id "
                "WHERE p.context_id=? AND p.concurrency=? ORDER BY p.created_at,p.run_id,p.pair_id",
                (context, candidate)).fetchall()
            modes = {row["usage_mode"] for row in history_rows}
            mode = next(iter(modes)) if len(modes) == 1 else "mixed"
            summaries.append(_history_summary(history_rows, candidate, rounds, run_id, mode, context))
        expected = {candidate for candidate in candidates if candidate > 1}
        cross_run_ready = bool(expected and {row.get("concurrency") for row in summaries} == expected and
                               all(row.get("evidence_state") in ("SUPPORTED_GAIN", "SUPPORTED_NO_GAIN")
                                   for row in summaries))
        return {
            "history_store": {
                "status": "SAVED",
                "run_id": run_id,
                "stored_pairs": len(rows),
                "contextual_pairs": sum(row["context_id"] is not None for row in rows),
                "database": "evidence.sqlite3",
                "storage_scope": "per-user-local-app-data",
                "schema_version": SCHEMA_VERSION,
                "quality_policy_id": QUALITY_POLICY_ID,
            },
            "historical_evidence": summaries,
            "history_cross_run_ready": cross_run_ready,
        }
    except (OSError, sqlite3.Error, RuntimeError, ValueError, TypeError):
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
        return {
            "history_store": {"status": "FAILED", "stored_pairs": 0, "database": "evidence.sqlite3",
                              "reason": "LOCAL_HISTORY_STORE_UNAVAILABLE"},
            "historical_evidence": [],
            "history_cross_run_ready": False,
        }
    finally:
        if connection is not None:
            connection.close()
