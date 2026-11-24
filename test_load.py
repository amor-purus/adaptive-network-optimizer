import threading,time,unittest,load
class CounterSource:
    def __init__(self,increment=100):self.rx=0;self.tx=0;self.increment=increment
    def sample(self):
        started=time.monotonic();self.rx+=self.increment;self.tx+=self.increment//2;finished=time.monotonic()
        return dict(status="Measured",started=started,finished=finished,interfaces=[dict(index=16,luid=7,type=71,rx=self.rx,tx=self.tx,hardware=True,oper=1,media_state=1)])
class LoadTests(unittest.TestCase):
    def test_idle_window_requires_three_contiguous_intervals(self):
        sampler=load.LoadSampler(CounterSource(100).sample,interval=.01,threshold_mbps=1,stable_intervals=3).start()
        try:
            result=sampler.wait_for_idle(threading.Event(),.5);self.assertEqual(result["status"],"IDLE_WINDOW");self.assertEqual(result["interval_count"],3)
        finally:sampler.close()
    def test_busy_timeout_is_not_idle(self):
        sampler=load.LoadSampler(CounterSource(100000).sample,interval=.01,threshold_mbps=.5,stable_intervals=3).start()
        try:
            result=sampler.wait_for_idle(threading.Event(),.08);self.assertEqual(result["status"],"BUSY_TIMEOUT");self.assertFalse(result["idle"]);self.assertGreater(result["max_total_mbps"],.5)
        finally:sampler.close()
    def test_virtual_interface_is_not_used_for_idle_decision(self):
        def sample():
            now=time.monotonic()
            return dict(status="Measured",started=now,finished=now,interfaces=[dict(index=43,luid=8,type=53,rx=100,tx=100,hardware=False,oper=1,media_state=1)])
        sampler=load.LoadSampler(sample,interval=.01).start()
        try:time.sleep(.03);self.assertEqual(sampler.current_state()["status"],"UNAVAILABLE")
        finally:sampler.close()
    def test_interface_change_resets_contiguous_window(self):
        calls=[0]
        def sample():
            now=time.monotonic();calls[0]+=1;index=16 if calls[0]<4 else 17
            return dict(status="Measured",started=now,finished=now,interfaces=[dict(index=index,luid=index,type=71,rx=calls[0]*10,tx=calls[0]*5,hardware=True,oper=1,media_state=1)])
        sampler=load.LoadSampler(sample,interval=.01,threshold_mbps=10,stable_intervals=3).start()
        try:time.sleep(.045);self.assertNotEqual(sampler.current_state()["status"],"IDLE")
        finally:sampler.close()
    def test_evidence_contains_no_absolute_counters(self):
        sampler=load.LoadSampler(CounterSource().sample,interval=.01).start()
        try:
            time.sleep(.02);evidence=sampler.evidence();self.assertGreaterEqual(evidence["sample_count"],2)
            self.assertNotIn("rx",evidence["samples"][-1]);self.assertIn("rx_mbps",evidence["samples"][-1])
        finally:sampler.close()
class IsolatedLoadTests(unittest.TestCase):
    def setUp(self):
        self.now=0.;self.rx=0;self.tx=0;self.rate=.02;self.index=16
        def source():
            return dict(status="Measured",started=self.now,finished=self.now,interfaces=[
                dict(index=self.index,luid=self.index,type=71,rx=self.rx,tx=self.tx,hardware=True,oper=1,media_state=1)])
        self.s=load.LoadSampler(source,clock=lambda:self.now);self.s._capture()
    def advance(self,n=1,rate=None):
        for _ in range(n):
            self.now+=1;self.rx+=int((self.rate if rate is None else rate)*125000);self.s._capture()
    def test_no_reuse_of_overlapping_samples(self):
        self.advance(3);self.assertTrue(self.s.current_state()['idle'])
        self.s.begin_experiment();self.advance(2,rate=.01)
        self.assertFalse(self.s.current_state()['idle']);self.s.end_experiment()
        self.assertFalse(self.s.current_state()['idle']);self.advance(3)
        self.assertFalse(self.s.current_state()['idle']);self.advance()
        state=self.s.current_state();self.assertTrue(state['idle'])
        self.assertGreaterEqual(state['window_start_s'],state['cooldown_until_s'])
        self.assertEqual(self.s.evidence()['excluded_test_or_cooldown_intervals'],3)
    def test_dynamic_baseline_bounded_and_excludes_test(self):
        self.advance(8);before=self.s.current_state()
        self.assertEqual(before['baseline_mode'],'ADAPTIVE_BOUNDED')
        self.assertAlmostEqual(before['threshold_mbps'],.1)
        self.s.begin_experiment();self.advance(10,rate=.49);self.s.end_experiment()
        self.assertEqual(self.s.current_state()['baseline_count'],8)
        self.advance(5,rate=.7);self.assertFalse(self.s.current_state()['idle'])
        self.assertLessEqual(self.s.current_state()['threshold_mbps'],.5)
        self.assertEqual(self.s.current_state()['baseline_count'],8)
    def test_interface_change_clears_baseline(self):
        self.advance(8);self.index=17;self.advance()
        self.assertEqual(self.s.current_state()['baseline_count'],0)
        self.assertFalse(self.s.current_state()['idle'])
    def test_sample_ids_remain_unique_when_buffer_wraps(self):
        from collections import deque
        self.s.samples=deque(maxlen=3);self.advance(8)
        self.assertEqual([x['sample_index'] for x in self.s.evidence()['samples']],[7,8,9])
    def test_cooldown_with_fractional_boundary(self):
        self.advance(3);self.s.begin_experiment();self.advance()
        self.now+=.4;self.s.end_experiment();self.now-=.4
        self.advance(4);self.assertFalse(self.s.current_state()['idle'])
        self.advance();self.assertTrue(self.s.current_state()['idle'])
if __name__=="__main__":unittest.main()
