from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import datetime
import csv
import json
import sqlite3
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import evidence
import tuning


def snapshot(dns="1.1.1.1"):
    return {
        "interfaces": [
            {"InterfaceIndex": 16, "InterfaceAlias": "WLAN", "AddressFamily": 2,
             "NlMtu": 1500, "InterfaceMetric": 35, "Dhcp": 1, "AutomaticMetric": 1}
        ],
        "dns": [
            {"InterfaceIndex": 16, "InterfaceAlias": "WLAN", "AddressFamily": 2,
             "ServerAddresses": [dns]}
        ],
        "routes": [
            {"InterfaceIndex": 16, "DestinationPrefix": "0.0.0.0/0",
             "NextHop": "192.168.1.1", "RouteMetric": 10}
        ],
    }


def make_result(candidate_rows, usage_mode="controlled", dns="1.1.1.1"):
    records = []
    pairs = []
    for candidate, attempts in candidate_rows.items():
        for index, item in enumerate(attempts, 1):
            begin = len(records)
            snap = snapshot(dns)
            records.append({"snapshot": snap})
            records.append({"snapshot": snapshot(dns)})
            valid = item.get("valid", True)
            env_ok = item.get("environment_verified", True)
            load_ok = item.get("load_window_verified", True)
            pairs.append({
                "pair_id": "C%d-R%d" % (candidate, index),
                "concurrency": candidate,
                "round": index,
                "retest": False,
                "valid": bool(valid and env_ok and load_ok),
                "measurement_valid": bool(item.get("measurement_valid", True)),
                "environment_verified": bool(env_ok),
                "load_window_verified": bool(load_ok),
                "reasons": [] if valid and env_ok and load_ok else ["SYNTHETIC_INVALID_PAIR"],
                "speedup": item.get("speedup", 1.25),
                "latency_ratio": item.get("latency_ratio", 1.1),
                "baseline_mbps": 1.0,
                "candidate_mbps": 1.25,
                "baseline_ttfb_ms": 110.0,
                "candidate_ttfb_ms": 100.0,
                "baseline_success": 1,
                "baseline_planned": 1,
                "candidate_success": candidate if item.get("requests_ok", True) else 0,
                "candidate_planned": candidate,
                "http_version": "2",
                "environment": {"begin_index": begin, "end_index": begin + 1},
            })
    return {
        "run_id": uuid.uuid4().hex,
        "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "Completed",
        "blocked": False,
        "design": "sequential_adjacent_equal_work_pairs",
        "parameter": "parallel_https_requests",
        "global_environment_guard_passed": True,
        "load_scheduler_enabled": True,
        "load_scheduler_available": True,
        "pilot_load_coverage_ok": True,
        "scope": "Cloudflare HTTPS fixed workload",
        "usage_mode": usage_mode,
        "rounds": 3,
        "candidates": [1] + sorted(candidate_rows),
        "formal_plan": {
            "frozen": True,
            "pilot_attempt_count": 3,
            "pilot_success_count": 3,
            "pilot_speeds_mbps": [1.0, 1.05, 1.1],
            "total_bytes": 524288,
            "connect_timeout_seconds": 5,
            "max_time_seconds": 20,
            "candidates": [1] + sorted(candidate_rows),
        },
        "load_policy": {"threshold_cap_mbps": 0.5, "stable_intervals": 3},
        "pairs": pairs,
    }, records


class EvidenceTests(unittest.TestCase):
    def test_network_fingerprint_ignores_enumeration_order(self):
        first = snapshot()
        second = snapshot()
        second["interfaces"].reverse()
        second["dns"].reverse()
        second["routes"].reverse()
        self.assertEqual(evidence.network_fingerprint(first), evidence.network_fingerprint(second))

    def test_cross_run_accumulation_requires_independent_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            first, records1 = make_result({2: [{}, {}]})
            one = evidence.persist_and_analyze(first, records1, path=path)
            self.assertEqual(one["history_store"]["status"], "SAVED")
            self.assertFalse(one["history_cross_run_ready"])
            self.assertEqual(one["historical_evidence"][0]["evidence_state"], "NEEDS_MORE_EVIDENCE")

            second, records2 = make_result({2: [{}, {}]})
            two = evidence.persist_and_analyze(second, records2, path=path)
            self.assertTrue(two["history_cross_run_ready"])
            row = two["historical_evidence"][0]
            self.assertEqual(row["evidence_state"], "SUPPORTED_GAIN")
            self.assertEqual(row["history_valid_run_count"], 2)
            self.assertEqual(row["paired_rounds"], 4)

    def test_invalid_attempts_remain_in_completion_denominator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            first, records1 = make_result({2: [{}, {}, {}]})
            evidence.persist_and_analyze(first, records1, path=path)
            second, records2 = make_result({2: [{}, {"valid": False}, {"valid": False}, {"valid": False}]})
            result = evidence.persist_and_analyze(second, records2, path=path)
            row = result["historical_evidence"][0]
            self.assertEqual(row["attempted_rounds"], 7)
            self.assertEqual(row["paired_rounds"], 4)
            self.assertLess(row["pair_completion_rate"], .75)
            self.assertIn("LOW_COMPLETION_RATE", row["quality_reasons"])
            self.assertNotEqual(row["evidence_state"], "SUPPORTED_GAIN")

    def test_candidate_histories_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            first, records1 = make_result({2: [{}, {}], 4: [{"valid": False}, {"valid": False}]})
            evidence.persist_and_analyze(first, records1, path=path)
            second, records2 = make_result({2: [{}, {}], 4: [{"valid": False}, {"valid": False}]})
            result = evidence.persist_and_analyze(second, records2, path=path)
            rows = {row["concurrency"]: row for row in result["historical_evidence"]}
            self.assertEqual(rows[2]["evidence_state"], "SUPPORTED_GAIN")
            self.assertNotEqual(rows[4]["evidence_state"], "SUPPORTED_GAIN")
            self.assertFalse(result["history_cross_run_ready"])

    def test_shared_mode_is_observational_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            first, records1 = make_result({2: [{}, {}, {}]}, usage_mode="shared")
            evidence.persist_and_analyze(first, records1, path=path)
            second, records2 = make_result({2: [{}, {}]}, usage_mode="shared")
            result = evidence.persist_and_analyze(second, records2, path=path)
            self.assertEqual(result["historical_evidence"][0]["evidence_state"], "OBSERVATIONAL_ONLY")
            self.assertFalse(result["history_cross_run_ready"])

    def test_changed_network_context_is_not_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            first, records1 = make_result({2: [{}, {}, {}]}, dns="1.1.1.1")
            evidence.persist_and_analyze(first, records1, path=path)
            second, records2 = make_result({2: [{}, {}, {}]}, dns="8.8.8.8")
            result = evidence.persist_and_analyze(second, records2, path=path)
            row = result["historical_evidence"][0]
            self.assertEqual(row["history_valid_run_count"], 1)
            self.assertFalse(result["history_cross_run_ready"])

    def test_transaction_rolls_back_partial_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            result, records = make_result({2: [{}, {}]})
            result["pairs"].append(dict(result["pairs"][0]))
            failed = evidence.persist_and_analyze(result, records, path=path)
            self.assertEqual(failed["history_store"]["status"], "FAILED")
            connection = sqlite3.connect(path)
            try:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 0)
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            finally:
                connection.close()


class HistoryIntegrityTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "history.sqlite3"

    def save(self, run):
        return evidence.persist_and_analyze(*run, path=self.path)

    def test_round_trip_replay_and_conflicting_identity(self):
        run = make_result({2: [{}, {}]})
        first = self.save(run)
        replay = self.save(json.loads(json.dumps(run)))
        self.assertEqual(replay["history_store"]["status"], "ALREADY_SAVED")
        self.assertEqual(first["historical_evidence"], replay["historical_evidence"])
        self.assertFalse(replay["history_cross_run_ready"])
        run[0]["pairs"][0]["speedup"] = 2
        conflict = self.save(run)
        self.assertEqual(conflict["history_store"]["reason"], "SESSION_ID_CONFLICT")
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT count(*),max(speedup) FROM pairs").fetchone(), (2, 1.25))

    def test_concurrent_writers_count_each_run_once(self):
        first, second = make_result({2: [{}, {}]}), make_result({2: [{}, {}]})
        barrier = threading.Barrier(4)
        def save_at_barrier(run):
            barrier.wait(timeout=5)
            return self.save(run)["history_store"]["status"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(save_at_barrier, (first, second, first, second)))
        self.assertCountEqual(statuses, ["SAVED", "SAVED", "ALREADY_SAVED", "ALREADY_SAVED"])
        summary = self.save(second)["historical_evidence"][0]
        self.assertEqual((summary["history_run_count"], summary["paired_rounds"]), (2, 4))

    def test_unidentified_report_cannot_create_a_session(self):
        run = make_result({2: [{}, {}, {}]})
        del run[0]["run_id"]
        legacy = self.save(run)
        self.assertEqual(legacy["history_store"]["status"], "UNVERIFIED_SESSION")
        self.assertFalse(legacy["history_cross_run_ready"])
        self.assertFalse(self.path.exists())

    def test_observation_only_runs_never_lend_or_borrow_formal_evidence(self):
        cases = [
            ({"global_environment_guard_passed": False}, {}, "GLOBAL_ENVIRONMENT_UNVERIFIED"),
            ({"pilot_load_coverage_ok": False}, {}, "PILOT_LOAD_UNVERIFIED"),
            ({"load_scheduler_enabled": False}, {}, "PILOT_LOAD_UNVERIFIED"),
            ({}, {"pilot_success_count": 1}, "PILOT_CALIBRATION_INSUFFICIENT"),
            ({}, {"frozen": False}, "HISTORY_CONTROLS_UNVERIFIED"),
            ({"blocked": True, "status": "Blocked"}, {}, "EXPERIMENT_BLOCKED_OR_UNAVAILABLE"),
        ]
        for fields, plan, reason in cases:
            with self.subTest(reason=reason):
                run = make_result({2: [{}, {}, {}]})
                run[0].update(fields)
                run[0]["formal_plan"].update(plan)
                result = self.save(run)
                self.assertEqual(result["history_store"]["stored_pairs"], 3)
                self.assertIn(reason, result["history_store"]["admission_reasons"])
                self.assertFalse(result["history_cross_run_ready"])
        first_clean = self.save(make_result({2: [{}, {}, {}]}))
        self.assertEqual(first_clean["historical_evidence"][0]["history_run_count"], 1)
        self.assertFalse(first_clean["history_cross_run_ready"])

    def test_failed_boundaries_and_unknown_protocol_stay_in_the_denominator(self):
        first = make_result({2: [{"valid": False}, {"valid": False}, {"valid": False}]})
        first[1][0]["label"] = "after_performance"
        for pair in first[0]["pairs"]:
            pair.update(environment={}, measurement_valid=False, http_version=None)
        self.save(first)
        self.save(make_result({2: [{}, {}]}))
        result = self.save(make_result({2: [{}, {}]}))
        row = result["historical_evidence"][0]
        self.assertEqual((row["attempted_rounds"], row["paired_rounds"]), (7, 4))
        self.assertIn("LOW_COMPLETION_RATE", row["quality_reasons"])
        self.assertFalse(result["history_cross_run_ready"])

    def test_protocol_cohorts_are_independent_and_never_drop_their_failures(self):
        first = make_result({2: [{}, {}, {}]})
        for pair in first[0]["pairs"]:
            pair["http_version"] = "1.1"
        self.save(first)
        second = make_result({2: [{}, {"valid": False}]})
        second[0]["pairs"][1].update(measurement_valid=False, http_version=None)
        b = self.save(second)
        self.assertEqual(b["historical_evidence"][0]["history_run_count"], 1)
        result = self.save(make_result({2: [{}, {}]}))
        row = result["historical_evidence"][0]
        self.assertEqual((row["http_version"], row["paired_rounds"], row["attempted_rounds"]), ("2", 3, 4))
        self.assertTrue(result["history_cross_run_ready"])

    def test_resolver_priority_and_frozen_controls_isolate_history(self):
        for change in ("resolver_priority", "timeout", "workload", "load_policy", "rounds", "mode", "candidates"):
            with self.subTest(change=change):
                self.path = self.path.with_name(change + ".sqlite3")
                first = make_result({2: [{}, {}, {}]})
                second = make_result({2: [{}, {}, {}], 4: [{}]} if change == "candidates" else {2: [{}, {}, {}]})
                for _, records in (first, second):
                    for record in records:
                        record["snapshot"]["dns"][0]["ServerAddresses"] = ["1.1.1.1", "8.8.8.8"]
                if change == "resolver_priority":
                    for record in second[1]:
                        record["snapshot"]["dns"][0]["ServerAddresses"].reverse()
                elif change == "timeout":
                    second[0]["formal_plan"]["connect_timeout_seconds"] += 1
                elif change == "workload":
                    second[0]["formal_plan"]["total_bytes"] //= 2
                elif change == "load_policy":
                    second[0]["load_policy"]["stable_intervals"] += 1
                elif change == "rounds":
                    second[0]["rounds"] = 5
                elif change == "mode":
                    second[0]["usage_mode"] = "shared"
                self.save(first)
                result = self.save(second)
                self.assertEqual(result["historical_evidence"][0]["history_run_count"], 1)
                self.assertFalse(result["history_cross_run_ready"])

    def test_a_started_but_unfinished_pair_counts_once(self):
        first = make_result({2: [{}, {}]})
        first[0]["status"] = "Incomplete"
        first[0]["batches"] = [dict(baseline_for=2, concurrency=1, pair_id="C2-R3", round=3, success=1)]
        self.assertEqual(self.save(first)["history_store"]["stored_pairs"], 3)
        result = self.save(make_result({2: [{}, {}]}))
        row = result["historical_evidence"][0]
        self.assertEqual((row["attempted_rounds"], row["paired_rounds"]), (5, 4))
        self.assertEqual(row["success_rate"], .8)
        self.assertTrue(result["history_cross_run_ready"])

    def test_prior_majority_cannot_overrule_a_contrary_current_session(self):
        for _ in range(2):
            self.save(make_result({2: [{}, {}, {}]}))
        result = self.save(make_result({2: [{"speedup": .99}]}))
        row = result["historical_evidence"][0]
        self.assertGreater(row["paired_median_speedup"], 1.10)
        self.assertIn("INDEPENDENT_DIRECTION_UNCONFIRMED", row["quality_reasons"])
        self.assertFalse(result["history_cross_run_ready"])
        self.assertIsNone(row["composite_score"])

    def test_conflicting_certified_sessions_remain_visible(self):
        self.save(make_result({2: [{"speedup": .99} for _ in range(3)]}))
        self.save(make_result({2: [{}, {}, {}]}))
        current = make_result({2: [{}, {}, {}]})
        result = self.save(current)
        self.assertIn("CONFLICTING_SESSION_DIRECTION", result["historical_evidence"][0]["quality_reasons"])
        self.assertFalse(result["history_cross_run_ready"])
        single_run = dict(current[0], selected_concurrency=2, recommendation_allowed=True)
        decision = tuning.apply_history_evidence(single_run, result)
        self.assertEqual(decision["decision"], "CONFLICTING_SESSION_EVIDENCE")
        self.assertIsNone(decision["selected_concurrency"])

    def test_inconsistent_protocol_between_candidates_blocks_only_global_comparison(self):
        for _ in range(2):
            run = make_result({2: [{}, {}], 4: [{}, {}]})
            for pair in run[0]["pairs"]:
                if pair["concurrency"] == 4:
                    pair["http_version"] = "3"
            history = self.save(run)
        self.assertTrue(all(row["evidence_state"] == "SUPPORTED_GAIN" for row in history["historical_evidence"]))
        self.assertFalse(history["history_cross_run_ready"])
        result = tuning.apply_history_evidence(run[0], history)
        self.assertIsNone(result.get("selected_concurrency"))

    def test_summary_failure_rolls_back_and_retry_succeeds(self):
        run = make_result({2: [{}, {}]})
        with patch("evidence._history_summary", side_effect=sqlite3.OperationalError("read failed")):
            self.assertEqual(self.save(run)["history_store"]["status"], "FAILED")
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT count(*) FROM pairs").fetchone()[0], 0)
        self.assertEqual(self.save(run)["history_store"]["status"], "SAVED")

    def test_previous_schema_preserves_old_rows_without_certifying_them(self):
        self.save(make_result({2: [{}, {}]}))
        # Recreate the original v1 runs table; its pairs and their foreign keys survive the migration.
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("""CREATE TABLE runs_v1 (run_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                        app_version TEXT NOT NULL, usage_mode TEXT NOT NULL, rounds INTEGER NOT NULL,
                        candidates_json TEXT NOT NULL, plan_json TEXT NOT NULL, status TEXT NOT NULL)""")
            db.execute("INSERT INTO runs_v1 SELECT run_id,created_at,app_version,usage_mode,rounds,"
                       "candidates_json,plan_json,status FROM runs")
            db.execute("DROP TABLE runs")
            db.execute("ALTER TABLE runs_v1 RENAME TO runs")
            db.execute("PRAGMA user_version=1")
        result = self.save(make_result({2: [{}, {}]}))
        self.assertFalse(result["history_cross_run_ready"])
        self.assertEqual(result["historical_evidence"][0]["history_valid_run_count"], 1)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pairs").fetchone()[0], 4)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_current_run_must_pass_global_gates_before_promoting_history(self):
        self.save(make_result({2: [{}, {}, {}]}))
        run = make_result({2: [{}, {}]})
        history = self.save(run)
        self.assertTrue(history["history_cross_run_ready"])
        result = tuning.apply_history_evidence(run[0], history)
        self.assertEqual(result["selected_concurrency"], 2)
        replay_on_another_run = tuning.apply_history_evidence(make_result({2: [{}, {}]})[0], history)
        self.assertFalse(replay_on_another_run["history_cross_run_ready"])
        self.assertIsNone(replay_on_another_run.get("selected_concurrency"))
        for fields in ({"global_environment_guard_passed": False}, {"status": "Incomplete"},
                       {"usage_mode": "unknown"}, {"pilot_load_coverage_ok": False}, {"blocked": True}):
            with self.subTest(fields=fields):
                result = tuning.apply_history_evidence(dict(run[0], **fields), history)
                self.assertIsNone(result.get("selected_concurrency"))

    def test_history_score_and_thresholds_match_single_run_rules(self):
        for speedups, expected in (([1.1, 1.1, 1.09], "SUPPORTED_GAIN"),
                                   ([1.09, 1.09, 1.1], "SUPPORTED_NO_GAIN"),
                                   ([.7, .7, 1.41], "IRRECOVERABLE_SPREAD")):
            with self.subTest(speedups=speedups):
                self.path = self.path.with_name(expected + ".sqlite3")
                for _ in range(2):
                    run = make_result({2: [{"speedup": x} for x in speedups]})
                    history = self.save(run)
                local = tuning.summarize_pairs(run[0]["pairs"], [2], 3)[0]
                hist = history["historical_evidence"][0]
                self.assertEqual(tuning.evidence_state(local, 3), expected)
                self.assertEqual(hist["evidence_state"], expected)
                self.assertEqual(hist["composite_score"], local["composite_score"])

    def test_measurement_to_database_to_report(self):
        import monitor
        from test_tuning import FakeLoadMonitor, fake_batch

        snap = snapshot()
        snap.update(adapter_status="Measured", adapters=[
            dict(Name="WLAN", ifIndex=16, Status="Up", MediaConnectionState=1)])
        wlan = dict(status="Measured", interfaces=[dict(name="WLAN", signal_percent=99, rx_mbps=866, tx_mbps=866)])
        ids = set()
        for session in range(3):
            def batch(*args, **kwargs):
                b = fake_batch(*args, **kwargs)
                if session == 2 and b["concurrency"] == 2 and b["round"] in (1, 2):
                    b.update(status="Failed", actual_bytes=0, aggregate_mbps=None, success=0)
                return b

            observer = monitor.Monitor(reader=lambda: snap, wlan=lambda: wlan)
            observer.start_load_sampler = lambda: FakeLoadMonitor()
            observer.checkpoint("after_performance", "tuning")
            with patch("tuning.run_batch", side_effect=batch):
                r = tuning.run(threading.Event(), exe="curl", seed=5, candidates=(1, 2),
                               usage_mode="controlled", observer=observer)
            observer.checkpoint("after_tuning", "done")
            r = tuning.apply_environment_gate(r, observer.evidence("tuning"))
            ids.add(r["run_id"])
            single_run_allowed = r["recommendation_allowed"]
            r = tuning.apply_history_evidence(r, self.save((r, observer.records)))
            observer.close()
        self.assertEqual(len(ids), 3)
        self.assertFalse(single_run_allowed)
        self.assertTrue(r["global_environment_guard_passed"])
        self.assertFalse(r["candidate_local_evidence"][0]["local_evidence_certified"])
        self.assertEqual(r["evidence_source"], "CROSS_RUN_HISTORY")
        self.assertEqual(r["selected_concurrency"], 2)
        html = tuning.report_html(r)
        self.assertIn("本次候选的局部认证", html)
        self.assertIn("跨次验证", html)
        tuning.write_csvs(self.path.parent, r)
        with (self.path.parent / "tuning_history.csv").open(encoding="utf-8-sig", newline="") as file:
            row = next(csv.DictReader(file))
        self.assertEqual((row["history_valid_run_count"], row["paired_rounds"], row["attempted_rounds"]),
                         ("3", "7", "9"))


class HistoryStateAndAgeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "state.sqlite3"
        self.now = datetime.datetime(2026, 1, 2, tzinfo=datetime.timezone.utc)

    def run_at(self, speeds, seconds=0, attempts=None):
        run, records = make_result({2: attempts if attempts is not None else [{}, {}, {}]})
        run["started_at_utc"] = (self.now + datetime.timedelta(seconds=seconds)).isoformat()
        run["formal_plan"]["pilot_speeds_mbps"] = speeds
        return run, records

    def save(self, run):
        return evidence.persist_and_analyze(*run, path=self.path)

    def test_fixed_band_boundary_and_pre_outcome_state(self):
        self.assertEqual(evidence.pilot_state({"pilot_speeds_mbps": [.5, .5, .5],
                                               "pilot_success_count": 3})["band"], -1)
        first = self.run_at([.38, .41, .44], -1)
        second = self.run_at([.62, .95, 1.0])
        a, b = self.save(first), self.save(second)
        self.assertNotEqual(a["historical_evidence"][0]["context_id"], b["historical_evidence"][0]["context_id"])
        self.assertEqual(b["historical_evidence"][0]["history_run_count"], 1)
        self.assertFalse(b["history_cross_run_ready"])
        third = self.run_at([.40, .42, .46], 1)
        c = self.save(third)
        self.assertEqual(c["historical_evidence"][0]["history_run_count"], 2)
        self.assertTrue(c["history_cross_run_ready"])

    def test_unstable_or_unknown_pilots_are_archived_without_deleting_pairs(self):
        for speeds, status in (([.62, .95, 1.29], "UNSTABLE"), ([], "UNVERIFIED")):
            run = self.run_at(speeds)
            report = self.save(run)
            self.assertEqual(report["history_store"]["status"], "SAVED")
            self.assertEqual(report["history_store"]["stored_pairs"], 3)
            self.assertIn("HISTORY_PILOT_STATE_" + status, report["history_store"]["admission_reasons"])
            self.assertFalse(report["history_cross_run_ready"])
            self.assertEqual(report["historical_evidence"], [])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM pairs").fetchone()[0], 6)

    def test_expiry_inclusive_boundary_and_future_exclusion(self):
        speeds = [1.0, 1.05, 1.1]
        self.save(self.run_at(speeds, -86401, [{"speedup": .7}] * 3))
        self.save(self.run_at(speeds, -86400))
        self.save(self.run_at(speeds, 1))
        current = self.run_at(speeds)
        out = self.save(current)
        row = out["historical_evidence"][0]
        self.assertEqual((row["history_run_count"], row["paired_rounds"]), (2, 6))
        self.assertEqual(row["history_expired_run_count"], 1)
        self.assertEqual(row["history_future_run_count"], 1)
        self.assertTrue(out["history_cross_run_ready"])
        self.assertEqual(self.save(current)["historical_evidence"], out["historical_evidence"])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM pairs").fetchone()[0], 12)

    def test_recent_failed_attempts_and_conflicts_not_filtered_by_outcome(self):
        speeds = [1.0, 1.05, 1.1]
        self.save(self.run_at(speeds, -2, [{"speedup": .99}] * 3))
        self.save(self.run_at(speeds, -1, [{"valid": False}] * 3))
        out = self.save(self.run_at(speeds))
        row = out["historical_evidence"][0]
        self.assertEqual((row["attempted_rounds"], row["paired_rounds"]), (9, 6))
        self.assertIn("CONFLICTING_SESSION_DIRECTION", row["quality_reasons"])
        self.assertIn("LOW_COMPLETION_RATE", row["quality_reasons"])
        self.assertFalse(out["history_cross_run_ready"])

    def test_naive_session_time_archived(self):
        run = self.run_at([1.0, 1.05, 1.1])
        run[0]["started_at_utc"] = "2026-01-02T00:00:00"
        out = self.save(run)
        self.assertIn("HISTORY_SESSION_TIME_UNVERIFIED", out["history_store"]["admission_reasons"])
        self.assertEqual(out["history_store"]["stored_pairs"], 3)
        self.assertFalse(out["history_cross_run_ready"])


if __name__ == "__main__":
    unittest.main()
