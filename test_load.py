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
if __name__=="__main__":unittest.main()
