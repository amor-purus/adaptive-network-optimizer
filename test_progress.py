import unittest

from progress import StageProgress, stage_plan


class StageProgressTests(unittest.TestCase):
    def test_optional_stages_and_order(self):
        for mtu in (False, True):
            for tune in (False, True):
                with self.subTest(mtu=mtu, tune=tune):
                    p = StageProgress(mtu, tune)
                    keys = [key for key, _ in stage_plan(mtu, tune)]
                    self.assertEqual("mtu" in keys, mtu)
                    self.assertEqual("tuning" in keys, tune)
                    self.assertEqual("history" in keys, tune)
                    self.assertEqual(p.total, 7 + int(mtu) + 2 * int(tune))
                    for i, key in enumerate(keys):
                        p.enter(key)
                        self.assertEqual(p.completed, i)
                        self.assertNotIn("100%", p.label())
                    p.finish()
                    self.assertEqual(p.completed, p.total)
                    self.assertIn("100%", p.label())

    def test_cancel_and_failure_keep_last_completed_stage(self):
        for cancelled in (False, True):
            p = StageProgress(True, True)
            p.enter("configuration")
            p.enter("dns")
            p.abort(cancelled=cancelled)
            self.assertEqual(p.completed, 1)
            self.assertFalse(p.finish())
            self.assertFalse(p.enter("dns_validation"))
            self.assertIn("已取消" if cancelled else "失败", p.label())
            self.assertNotIn("100%", p.label())

    def test_no_premature_success_or_skipped_stage(self):
        p = StageProgress(True, True)
        with self.assertRaises(ValueError):
            p.finish()
        with self.assertRaises(ValueError):
            p.enter("dns")
        p.enter("configuration")
        with self.assertRaises(ValueError):
            p.finish()
        self.assertEqual(p.completed, 0)

    def test_second_run_resets_without_changing_first(self):
        p = StageProgress(False, False)
        for key, _ in p.stages:
            p.enter(key)
        p.finish()
        fresh = StageProgress(True, True)
        self.assertEqual(fresh.completed, 0)
        self.assertEqual(fresh.state, "running")
        self.assertEqual(p.state, "complete")


class DetailTests(unittest.TestCase):
    def test_missing_metric_not_zero(self):
        from progress import metric
        for value in (None, float("nan"), float("inf"), "1", True):
            self.assertEqual(metric(value, " ms"), "未测得")
        self.assertEqual(metric(0, " ms"), "0.00 ms")

    def test_batch_reports_actual_bytes_and_failure(self):
        from progress import batch_detail
        text = batch_detail(dict(success=1, planned=2, actual_bytes=10,
                                 expected_bytes=20, status="Failed"))
        self.assertIn("1/2", text)
        self.assertIn("10/20 字节", text)
        self.assertIn("未完整成功", text)
        self.assertIn("未测得", text)
