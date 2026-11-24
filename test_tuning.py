import threading
import tempfile
from pathlib import Path
import unittest
import tuning as t
import core

def good(size,speed=1.0):
    return dict(status='OK',bytes=size,effective_mbps=speed,total_ms=1000,ttfb_ms=100,http_status=200)

class TuningTests(unittest.TestCase):
    def test_split_sizes_exact_and_minimum(self):
        for n in (1,2,4,8):
            sizes=t.split_sizes(t.AGGREGATE_BYTES,n)
            self.assertEqual(len(sizes),n)
            self.assertEqual(sum(sizes),t.AGGREGATE_BYTES)
            self.assertGreaterEqual(min(sizes),t.MIN_WORKER_BYTES)
            self.assertLessEqual(max(sizes)-min(sizes),1)

    def test_split_rejects_small_or_invalid(self):
        with self.assertRaises(ValueError):t.split_sizes(1024,8)
        with self.assertRaises(ValueError):t.split_sizes(1024,0)

    def test_batch_runs_workers_concurrently(self):
        barrier=threading.Barrier(4)
        def probe(exe,url,expected,cap,stop):
            barrier.wait(timeout=3)
            return good(expected)
        r=t.run_batch('curl',4,1,threading.Event(),probe,total_bytes=t.AGGREGATE_BYTES)
        self.assertEqual(r['status'],'OK')
        self.assertEqual(r['success'],4)
        self.assertEqual(r['actual_bytes'],t.AGGREGATE_BYTES)
        self.assertGreater(r['aggregate_mbps'],0)
        self.assertEqual(len(r['worker_rows']),4)

    def test_batch_failure_has_no_aggregate_rate(self):
        calls=[]
        def probe(exe,url,expected,cap,stop):
            calls.append(expected)
            return good(expected) if len(calls)==1 else dict(status='Failed',bytes=10,effective_mbps=None)
        r=t.run_batch('curl',2,1,threading.Event(),probe,total_bytes=t.AGGREGATE_BYTES)
        self.assertEqual(r['status'],'Failed')
        self.assertIsNone(r['aggregate_mbps'])
        self.assertEqual(r['success'],1)

    def test_summary_rejects_incomplete_and_variable_candidate(self):
        batches=[]
        for c,speeds in ((1,[10,10,10]),(2,[10,10,30]),(4,[12,12])):
            for i,s in enumerate(speeds,1):
                batches.append(dict(concurrency=c,round=i,status='OK',aggregate_mbps=s,worker_rows=[]))
        rows=t.summarize_batches(batches,(1,2,4),3)
        by={x['concurrency']:x for x in rows}
        self.assertTrue(by[1]['eligible'])
        self.assertIn('HIGH_VARIATION',by[2]['quality_reasons'])
        self.assertIn('INCOMPLETE_ROUNDS',by[4]['quality_reasons'])

    def test_decision_prefers_lowest_near_best_candidate(self):
        batches=[]
        for c,speed in ((1,10),(2,10.8),(4,12),(8,12.3)):
            for i in range(1,4):
                batches.append(dict(concurrency=c,round=i,status='OK',aggregate_mbps=speed,worker_rows=[]))
        d=t.decide(t.summarize_batches(batches,(1,2,4,8),3),(1,2,4,8),True,False)
        self.assertTrue(d['comparison_ready'])
        self.assertEqual(d['selected_concurrency'],4)
        self.assertEqual(d['decision'],'LOWEST_CONCURRENCY_NEAR_BEST')

    def test_no_material_gain_keeps_one(self):
        batches=[]
        for c,speed in ((1,10),(2,10.5),(4,9.8)):
            for i in range(1,4):
                batches.append(dict(concurrency=c,round=i,status='OK',aggregate_mbps=speed,worker_rows=[]))
        d=t.decide(t.summarize_batches(batches,(1,2,4),3),(1,2,4),True,False)
        self.assertEqual(d['selected_concurrency'],1)
        self.assertEqual(d['decision'],'NO_MATERIAL_GAIN')

    def test_missing_baseline_blocks_recommendation(self):
        batches=[dict(concurrency=2,round=i,status='OK',aggregate_mbps=20,worker_rows=[]) for i in range(1,4)]
        d=t.decide(t.summarize_batches(batches,(1,2),3),(1,2),True,False)
        self.assertFalse(d['comparison_ready'])
        self.assertIsNone(d['selected_concurrency'])

    def test_environment_gate_requires_configuration_and_telemetry(self):
        result=dict(comparison_ready=True,selected_concurrency=4,decision='OK')
        bad=t.apply_environment_gate(result,dict(complete=True,observed_stable=True,telemetry_complete=False,telemetry_observed_stable=False))
        self.assertFalse(bad['recommendation_allowed'])
        self.assertIsNone(bad['selected_concurrency'])
        good_env=dict(complete=True,observed_stable=True,telemetry_complete=True,telemetry_observed_stable=True)
        good_result=t.apply_environment_gate(result,good_env)
        self.assertTrue(good_result['recommendation_allowed'])
        self.assertEqual(good_result['selected_concurrency'],4)

    def test_run_fixed_budget_randomized_and_complete(self):
        r=t.run(threading.Event(),lambda _:None,exe='curl',probe=lambda exe,url,expected,cap,stop:good(expected),
                rounds=2,candidates=(1,2),total_bytes=128*1024,phase_seconds=100,seed=7,clock=lambda:0)
        self.assertEqual(r['status'],'Completed')
        self.assertEqual(len(r['batches']),4)
        self.assertEqual(r['requested_budget_bytes'],4*128*1024)
        self.assertEqual(r['reserved_bytes'],r['requested_budget_bytes'])
        self.assertEqual(len(r['randomized_order']),2)

    def test_run_stops_after_rate_limit(self):
        def probe(exe,url,expected,cap,stop):
            return dict(status='Failed',bytes=0,http_status=429,error_category='HTTP_BLOCKED')
        r=t.run(threading.Event(),lambda _:None,exe='curl',probe=probe,rounds=2,candidates=(1,2),total_bytes=128*1024,phase_seconds=100,seed=1,clock=lambda:0)
        self.assertEqual(r['status'],'Blocked')
        self.assertTrue(r['blocked'])
        self.assertFalse(r['recommendation_allowed'])

    def test_run_respects_time_budget(self):
        r=t.run(threading.Event(),lambda _:None,exe='curl',probe=lambda *a:good(65536),
                rounds=2,candidates=(1,2),total_bytes=128*1024,phase_seconds=1,seed=1,clock=lambda:0)
        self.assertEqual(r['status'],'Incomplete')
        self.assertEqual(r['batches'],[])
        self.assertTrue(r['time_budget_exhausted'])

    def test_cancel(self):
        stop=threading.Event();stop.set()
        with self.assertRaises(core.Cancelled):
            t.run(stop,exe='curl',probe=lambda *a:good(65536),rounds=2,candidates=(1,2),total_bytes=128*1024)

    def test_report_exports(self):
        result=dict(status='Completed',selected_concurrency=4,decision_note='<script>',aggregate_bytes_per_batch=1,
                    requested_budget_bytes=2,reserved_bytes=2,environment_stable=True,
                    summary=[dict(concurrency=1,attempted_rounds=3,successful_rounds=3,median_mbps=1,p95_mbps=1,
                                  ttfb_median_ms=10,eligible=True,quality_reasons=[])],
                    batches=[dict(concurrency=1,round=1,status='OK',elapsed_s=1,aggregate_mbps=1,success=1,planned=1,
                                  expected_bytes=1,actual_bytes=1,ttfb_median_ms=10,error_categories=[],http_blocked=False,
                                  worker_rows=[dict(worker=1,status='OK',expected_bytes=1,bytes=1,effective_mbps=1,
                                                    ttfb_ms=10,total_ms=10,http_status=200)])])
        with tempfile.TemporaryDirectory() as d:
            t.write_csvs(Path(d),result)
            self.assertTrue((Path(d)/'tuning_batches.csv').exists())
            self.assertTrue((Path(d)/'tuning_workers.csv').exists())
            self.assertIn('&lt;script&gt;',t.report_html(result))

if __name__=='__main__':unittest.main()
