import sqlite3
import tempfile
import unittest
from pathlib import Path

import evidence


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
        "status": "Completed",
        "parameter": "parallel_https_requests",
        "scope": "Cloudflare HTTPS fixed workload",
        "usage_mode": usage_mode,
        "rounds": 3,
        "candidates": [1] + sorted(candidate_rows),
        "formal_plan": {
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


if __name__ == "__main__":
    unittest.main()
