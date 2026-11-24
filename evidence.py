"""Persist paired HTTPS observations and validate independent measurement sessions."""
from collections import defaultdict
from contextlib import closing, contextmanager
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import time
import uuid

import core
import tuning

SCHEMA_VERSION = 2
QUALITY_POLICY_ID = "adjacent-paired-quality-v2"
HISTORY_POLICY_ID = "pilot-speed-band-age-v1"
HISTORY_MAX_AGE_SECONDS = 24 * 60 * 60
SUPPORTED = {"SUPPORTED_GAIN", "SUPPORTED_NO_GAIN"}


def default_store_path():
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
    else:
        root = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(root) / "AdaptiveNetworkOptimizer" / "evidence.sqlite3"


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def network_fingerprint(snapshot):
    """Ignore row enumeration order, but preserve Windows resolver priority."""
    if not isinstance(snapshot, dict) or not snapshot.get("interfaces"):
        return None
    fields = {
        "interfaces": ("InterfaceIndex", "InterfaceAlias", "AddressFamily", "NlMtu",
                       "InterfaceMetric", "Dhcp", "AutomaticMetric"),
        "dns": ("InterfaceIndex", "InterfaceAlias", "AddressFamily", "ServerAddresses"),
        "routes": ("InterfaceIndex", "DestinationPrefix", "NextHop", "RouteMetric"),
    }
    config = {}
    for section, names in fields.items():
        rows = snapshot.get(section)
        if not isinstance(rows, list):
            return None
        values = []
        for row in rows:
            if not isinstance(row, dict) or not all(key in row for key in names):
                return None
            if row["InterfaceIndex"] is None or (section == "dns" and not isinstance(row["ServerAddresses"], list)):
                return None
            values.append([row[key] for key in names])
        config[section] = sorted(values, key=_json)
    return _digest(config)


def pilot_state(plan):
    """Pre-outcome state, independent of candidate success or speedup.
    Fixed power-of-two Mbps bands; uncertain pilot data cannot certify history.
    """
    state = dict(policy=HISTORY_POLICY_ID, status="UNVERIFIED", band=None,
                 lower_mbps=None, upper_mbps=None, median_mbps=None,
                 variation_ratio=None, cv=None, successful_pilots=0)
    speeds = plan.get("pilot_speeds_mbps")
    if not isinstance(speeds, list):
        return state
    state["successful_pilots"] = len(speeds)
    if (len(speeds) not in range(2, tuning.PILOT_COUNT + 1) or
            len(speeds) != plan.get("pilot_success_count") or
            not all(_positive(s) for s in speeds)):
        return state
    median = statistics.median(speeds)
    # Normalize before dispersion calculation, avoiding overflow on malformed values.
    scaled = [s / max(speeds) for s in speeds]
    ratio = max(speeds) / min(speeds)
    cv = statistics.pstdev(scaled) / statistics.mean(scaled)
    if not math.isfinite(ratio) or not _positive(median):
        return state
    state.update(median_mbps=median, variation_ratio=ratio, cv=cv)
    if ratio > 2 or cv > .35:
        state["status"] = "UNSTABLE"
        return state
    band = math.frexp(median)[1] - 1
    # Practical representable bandwidth bounds; no arbitrary clipping into a band.
    if not -40 <= band <= 40:
        return state
    state.update(status="CLASSIFIED", band=band,
                 lower_mbps=2.0 ** band, upper_mbps=2.0 ** (band + 1))
    return state


def _utc_stamp(value):
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return stamp.astimezone(datetime.timezone.utc) if stamp.utcoffset() is not None else None
    except (ValueError, OverflowError):
        return None


def _context_id(result, fingerprint, state):
    plan = result["formal_plan"]
    return _digest({
        "policy": QUALITY_POLICY_ID, "history_policy": HISTORY_POLICY_ID,
        "pilot_speed_band": state["band"], "platform": platform.system(), "network": fingerprint,
        "parameter": result["parameter"], "design": result["design"], "scope": result["scope"],
        "endpoint": tuning.DOWNLOAD_URL, "mode": result["usage_mode"], "rounds": result["rounds"],
        "candidates": sorted(result["candidates"]), "load_policy": result["load_policy"],
        "total_bytes": plan["total_bytes"], "connect_timeout": plan["connect_timeout_seconds"],
        "transfer_timeout": plan["max_time_seconds"],
    })


@contextmanager
def _transaction(path):
    target = Path(path) if path is not None else default_store_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(target), timeout=5.0)) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        # SQLite can return BUSY immediately when two fresh connections both switch journal mode.
        deadline = time.monotonic() + 5
        while True:
            try:
                db.execute("PRAGMA journal_mode=WAL").fetchone()
                break
            except sqlite3.OperationalError as exc:
                if str(exc) != "database is locked" or time.monotonic() >= deadline:
                    raise
                time.sleep(.025)
        db.execute("PRAGMA synchronous=FULL")
        with db:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise ValueError("EVIDENCE_SCHEMA_NEWER_THAN_APPLICATION")
            if version == 0:
                db.execute("""CREATE TABLE runs (
                    run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, app_version TEXT NOT NULL,
                    usage_mode TEXT NOT NULL, rounds INTEGER NOT NULL, candidates_json TEXT NOT NULL,
                    plan_json TEXT NOT NULL, status TEXT NOT NULL)""")
                db.execute("""CREATE TABLE pairs (
                    run_id TEXT NOT NULL, pair_id TEXT NOT NULL, concurrency INTEGER NOT NULL,
                    round_number INTEGER, retest INTEGER NOT NULL, context_id TEXT, valid INTEGER NOT NULL,
                    measurement_valid INTEGER NOT NULL, environment_verified INTEGER NOT NULL,
                    load_window_verified INTEGER NOT NULL, reasons_json TEXT NOT NULL, speedup REAL,
                    latency_ratio REAL, baseline_mbps REAL, candidate_mbps REAL, baseline_ttfb_ms REAL,
                    candidate_ttfb_ms REAL, baseline_success INTEGER NOT NULL, baseline_planned INTEGER NOT NULL,
                    candidate_success INTEGER NOT NULL, candidate_planned INTEGER NOT NULL, http_version TEXT,
                    created_at TEXT NOT NULL, PRIMARY KEY (run_id,pair_id,concurrency),
                    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE)""")
                db.execute("CREATE INDEX idx_pairs_context_candidate ON pairs(context_id,concurrency,created_at)")
            if version < 2:
                # NULL marks legacy rows whose original session and admission gates cannot be verified.
                db.execute("ALTER TABLE runs ADD COLUMN evidence_digest TEXT")
                db.execute("ALTER TABLE runs ADD COLUMN admission_reasons TEXT")
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        with db:
            db.execute("BEGIN IMMEDIATE")
            yield db


def _positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def _admission_reasons(result, plan):
    reasons = []
    if result.get("global_environment_guard_passed") is not True:
        reasons.append("GLOBAL_ENVIRONMENT_UNVERIFIED")
    if (result.get("load_scheduler_enabled") is not True or result.get("load_scheduler_available") is not True
            or result.get("pilot_load_coverage_ok") is not True):
        reasons.append("PILOT_LOAD_UNVERIFIED")
    if (plan.get("pilot_attempt_count") != tuning.PILOT_COUNT or
            plan.get("pilot_success_count") not in range(2, tuning.PILOT_COUNT + 1)):
        reasons.append("PILOT_CALIBRATION_INSUFFICIENT")
    candidates = result.get("candidates") or []
    if (plan.get("frozen") is not True or not all(_positive(plan.get(k)) for k in
            ("total_bytes", "connect_timeout_seconds", "max_time_seconds")) or
            sorted(candidates) != sorted(plan.get("candidates") or []) or 1 not in candidates or
            len(set(candidates)) != len(candidates) or not set(candidates) <= set(tuning.CONCURRENCY_LEVELS) or
            result.get("rounds") not in range(2, 6) or not result.get("load_policy") or
            result.get("parameter") != "parallel_https_requests" or not result.get("scope") or
            result.get("design") != "sequential_adjacent_equal_work_pairs" or
            result.get("usage_mode") not in ("shared", "controlled")):
        reasons.append("HISTORY_CONTROLS_UNVERIFIED")
    if result.get("blocked") is not False or result.get("status") not in ("Completed", "Incomplete"):
        reasons.append("EXPERIMENT_BLOCKED_OR_UNAVAILABLE")
    return reasons


def _attempts(result):
    pairs = list(result.get("pairs") or [])
    finished = {(p["concurrency"], p["pair_id"]) for p in pairs}
    partial = {}
    for batch in result.get("batches") or []:
        candidate, ident = batch["baseline_for"], batch["pair_id"]
        if (candidate, ident) in finished:
            continue
        # A batch actually started. Keep this attempt in the denominator even if its peer never ran.
        pair = partial.setdefault((candidate, ident), dict(
            concurrency=candidate, pair_id=ident, round=batch["round"], retest=batch.get("retest", False),
            reasons=["INCOMPLETE_BATCH"], baseline_success=0, candidate_success=0,
            baseline_planned=1, candidate_planned=candidate))
        field = "baseline_success" if batch["concurrency"] == 1 else "candidate_success"
        pair[field] = batch.get("success", 0)
    return pairs + list(partial.values())


def _build_rows(result, pairs, records, exclusions, state):
    run_id, stamp = result["run_id"], result["started_at_utc"]
    fingerprints = {}

    def boundary(index):
        if type(index) is not int or not 0 <= index < len(records):
            return None
        if index not in fingerprints:
            record = records[index]
            fingerprints[index] = network_fingerprint(record.get("snapshot")) if isinstance(record, dict) else None
        return fingerprints[index]

    # The phase can identify the context of a failed attempt. Only its own two boundaries can validate it.
    for index, record in enumerate(records):
        if isinstance(record, dict) and (record.get("phase") == "tuning" or
                record.get("label") in ("after_performance", "after_tuning")):
            boundary(index)
    rows = []
    for pair in pairs:
        environment = pair.get("environment") or {}
        begin, end = environment.get("begin_index"), environment.get("end_index")
        before, after = boundary(begin), boundary(end)
        bracketed = bool(before and before == after and begin < end)
        reasons = set(pair.get("reasons") or [])
        if not bracketed:
            reasons.add("HISTORY_NETWORK_CONTEXT_UNVERIFIED")
        c = pair["concurrency"]
        if c not in result["candidates"] or c == 1 or not pair.get("pair_id"):
            raise ValueError("INVALID_PAIR_IDENTITY")
        measured = pair.get("measurement_valid") is True
        env_ok = pair.get("environment_verified") is True and bracketed
        load_ok = pair.get("load_window_verified") is True
        metrics = {key: pair.get(key) if _positive(pair.get(key)) else None for key in
                   ("speedup", "latency_ratio", "baseline_mbps", "candidate_mbps", "baseline_ttfb_ms", "candidate_ttfb_ms")}
        protocol = pair.get("http_version")
        if not isinstance(protocol, str) or not protocol.strip():
            protocol = None
        counts = {}
        for side, planned in (("baseline", 1), ("candidate", c)):
            success = pair.get(side + "_success")
            if pair.get(side + "_planned") != planned or type(success) is not int or not 0 <= success <= planned:
                reasons.add("PAIR_IDENTITY_INVALID")
                success = 0
            counts[side + "_planned"] = planned
            counts[side + "_success"] = success
        if measured and (not all(metrics.values()) or not protocol or
                         counts["baseline_success"] != 1 or counts["candidate_success"] != c):
            reasons.add("PAIR_IDENTITY_INVALID")
        rows.append(dict(run_id=run_id, created_at=stamp, pair_id=pair["pair_id"], concurrency=c,
                         round_number=pair["round"], retest=int(bool(pair.get("retest"))),
                         valid=int(pair.get("valid") is True and measured and env_ok and load_ok and not reasons),
                         measurement_valid=int(measured), environment_verified=int(env_ok),
                         load_window_verified=int(load_ok), reasons_json=_json(sorted(reasons)),
                         http_version=protocol, **metrics, **counts))
    networks = set(fingerprints.values()) - {None}
    if len(networks) != 1:
        exclusions.append("MULTIPLE_NETWORK_CONTEXTS" if networks else "NETWORK_CONTEXT_UNAVAILABLE")
    context = _context_id(result, networks.pop(), state) if not exclusions else None
    for row in rows:
        row["context_id"] = context
    return rows, context


def _history_summary(db, context, candidate, rounds, run_id, mode, as_of):
    sessions = defaultdict(list)
    excluded = {"expired": set(), "future": set(), "invalid_time": set()}
    for record in db.execute(
            "SELECT p.* FROM pairs p JOIN runs r ON r.run_id=p.run_id "
            "WHERE p.context_id=? AND p.concurrency=? AND r.admission_reasons='[]' ORDER BY p.created_at,p.run_id,p.pair_id",
            (context, candidate)):
        pair = dict(record)
        stamp = _utc_stamp(pair["created_at"])
        # Age is evaluated against the new measurement start, not report export or replay time.
        # All attempts in a session share a timestamp, including failed/incomplete pairs.
        reason = ("invalid_time" if stamp is None else "future" if stamp > as_of else
                  "expired" if (as_of - stamp).total_seconds() > HISTORY_MAX_AGE_SECONDS else None)
        if reason:
            excluded[reason].add(pair["run_id"])
            continue
        pair["pair_id"] = (pair["run_id"], pair["pair_id"])
        pair["reasons"] = json.loads(pair["reasons_json"])
        pair["environment_verified"] = bool(pair["environment_verified"])
        pair["load_window_verified"] = bool(pair["load_window_verified"])
        sessions[pair["run_id"]].append(pair)

    def protocols(group):
        return {p["http_version"] for p in group if p["http_version"]}

    current_protocols = protocols(sessions.get(run_id, []))
    # Assign protocols by whole candidate-session so an unmeasurable failure cannot disappear.
    # Sessions with no readable protocol count as failures in the matching network/workload.
    compatible = {rid: group for rid, group in sessions.items()
                  if rid == run_id or not protocols(group) or protocols(group) == current_protocols}
    pairs = [p for group in compatible.values() for p in group]
    row = tuning.summarize_pairs(pairs, [candidate], rounds, pooled=True)[0]
    state = tuning.evidence_state(row, rounds)
    reasons = row["quality_reasons"]
    valid = {rid: [p for p in group if p["valid"]] for rid, group in compatible.items()}
    valid_runs = sum(bool(group) for group in valid.values())
    current_valid = len(valid.get(run_id, []))
    if len(current_protocols) != 1:
        reasons.append("HISTORY_PROTOCOL_UNVERIFIED")
    if valid_runs < 2:
        reasons.append("INSUFFICIENT_INDEPENDENT_RUNS")
    if not current_valid:
        reasons.append("CURRENT_RUN_NOT_CONFIRMED")
    if mode != "controlled":
        reasons.append("SHARED_MODE_OBSERVATION_ONLY")
    session_states = set()
    for rid, group in valid.items():
        if len(group) >= rounds:
            local = tuning.summarize_pairs(compatible[rid], [candidate], rounds)[0]
            session_states.add(tuning.evidence_state(local, rounds))
    if SUPPORTED <= session_states:
        reasons.append("CONFLICTING_SESSION_DIRECTION")
    if state in SUPPORTED and valid_runs >= 2:
        gain = state == "SUPPORTED_GAIN"
        confirming = set()
        for rid, group in valid.items():
            votes = sum((p["speedup"] >= tuning.MIN_SPEEDUP) == gain for p in group)
            if tuning.direction_supported(votes, len(group)):
                confirming.add(rid)
        if run_id not in confirming or len(confirming) < 2:
            reasons.append("INDEPENDENT_DIRECTION_UNCONFIRMED")
    if reasons:
        row.update(eligible=False, composite_score=None)
    if mode != "controlled":
        state = "OBSERVATIONAL_ONLY"
    elif state not in ("IRRECOVERABLE_SPREAD", "IRRECOVERABLE_COMPARABILITY") and (state not in SUPPORTED or reasons):
        state = "NEEDS_MORE_EVIDENCE"
    row.update(context_id=context, evidence_state=state, history_run_count=len(compatible),
               history_valid_run_count=valid_runs, current_run_valid_pairs=current_valid,
               quality_reasons=sorted(set(reasons)),
               history_expired_run_count=len(excluded["expired"]),
               history_future_run_count=len(excluded["future"]),
               history_invalid_time_run_count=len(excluded["invalid_time"]))
    return row


def _outcome(status, *, rows=(), summaries=(), ready=False, **info):
    return {"history_store": dict(status=status, stored_pairs=len(rows), database="evidence.sqlite3", **info),
            "historical_evidence": list(summaries), "history_cross_run_ready": ready}


def persist_and_analyze(result, records, path=None, app_version=core.VERSION):
    """Write once per measurement session. Evaluate and commit in the same database snapshot."""
    try:
        attempts = _attempts(result)
        if not attempts:
            return _outcome("NO_PAIRS")
        run_id = result.get("run_id")
        if (not isinstance(run_id, str) or len(run_id) != 32 or uuid.UUID(hex=run_id).hex != run_id
                or not result.get("started_at_utc")):
            return _outcome("UNVERIFIED_SESSION", reason="MISSING_MEASUREMENT_SESSION_ID")
        plan = result.get("formal_plan") or {}
        candidates = sorted(result.get("candidates") or [])
        rounds, mode = result["rounds"], result["usage_mode"]
        exclusions = _admission_reasons(result, plan)
        state = pilot_state(plan)
        as_of = _utc_stamp(result["started_at_utc"])
        if state["status"] != "CLASSIFIED":
            exclusions.append("HISTORY_PILOT_STATE_" + state["status"])
        if as_of is None:
            exclusions.append("HISTORY_SESSION_TIME_UNVERIFIED")
        rows, context = _build_rows(result, attempts, records or [], exclusions, state)
        metadata = (run_id, result["started_at_utc"], str(app_version), mode, rounds, _json(candidates),
                    _json(plan), result["status"])
        digest = _digest([metadata, exclusions, rows])
        with _transaction(path) as db:
            stored = db.execute("SELECT evidence_digest FROM runs WHERE run_id=?", (run_id,)).fetchone()
            if stored is None:
                db.execute("INSERT INTO runs (run_id,created_at,app_version,usage_mode,rounds,candidates_json,"
                           "plan_json,status,evidence_digest,admission_reasons) VALUES (?,?,?,?,?,?,?,?,?,?)",
                           (*metadata, digest, _json(exclusions)))
                columns = list(rows[0])
                db.executemany(f"INSERT INTO pairs ({','.join(columns)}) VALUES ({','.join(':'+k for k in columns)})", rows)
            elif stored["evidence_digest"] != digest:
                return _outcome("FAILED", reason="SESSION_ID_CONFLICT")
            summaries = [_history_summary(db, context, c, rounds, run_id, mode, as_of)
                         for c in candidates if c > 1] if context else []
            ready = bool(tuning.same_protocol(summaries) and
                         all(s["evidence_state"] in SUPPORTED for s in summaries))
            return _outcome("SAVED" if stored is None else "ALREADY_SAVED", rows=rows, summaries=summaries,
                            ready=ready, run_id=run_id, contextual_pairs=len(rows) if context else 0,
                            admission_reasons=exclusions, storage_scope="per-user-local-app-data",
                            schema_version=SCHEMA_VERSION, quality_policy_id=QUALITY_POLICY_ID,
                            history_policy_id=HISTORY_POLICY_ID, pilot_state=state,
                            history_max_age_seconds=HISTORY_MAX_AGE_SECONDS,
                            history_as_of_utc=as_of.isoformat() if as_of is not None else None)
    except (OSError, sqlite3.Error, KeyError, ValueError, TypeError, OverflowError):
        return _outcome("FAILED", reason="LOCAL_HISTORY_STORE_UNAVAILABLE")
