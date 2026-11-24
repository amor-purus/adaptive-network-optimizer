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
