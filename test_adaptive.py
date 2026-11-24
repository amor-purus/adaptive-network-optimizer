import threading
import unittest
from unittest.mock import patch
import adaptive as a
import performance as p
import core

class AdaptiveTests(unittest.TestCase):
    def test_size(self):
        self.assertEqual(a.choose_size({'status':'OK','effective_mbps':.876},a.KIB*1024),256*a.KIB)
        self.assertEqual(a.choose_size({'status':'Failed'},a.KIB*1024),64*a.KIB)
    def test_fixed_size_and_extra(self):
        calls=[]
        def probe(size):
            calls.append(size);return dict(status='Failed' if len(calls)==2 else 'OK',effective_mbps=1,http_version='1.1',http_status=200,bytes=size)
        r=a.sample_download(probe,threading.Event(),lambda _:None,3,1024*a.KIB)
        self.assertEqual(calls[0],a.PILOT);self.assertEqual(len(set(calls[1:])),1);self.assertEqual(len(r['rows']),5);self.assertTrue(r['quality']['usable']);self.assertLessEqual(r['reserved_bytes'],r['requested_budget_bytes'])
    def test_blocked(self):
        r=a.sample_download(lambda n:dict(status='Failed',http_status=429),threading.Event(),lambda _:None,3,1024*a.KIB)
        self.assertEqual(r['rows'],[]);self.assertFalse(r['quality']['usable']);self.assertTrue(r['blocked'])
    def test_deadline(self):
        ticks=iter([0,200]);r=a.sample_download(lambda n:self.fail('unexpected request'),threading.Event(),lambda _:None,3,1024*a.KIB,clock=lambda:next(ticks,200))
        self.assertFalse(r['quality']['usable']);self.assertEqual(r['reserved_bytes'],0)
    def test_quality(self):
        rows=[dict(status='OK',effective_mbps=n,expected_bytes=100,http_version='1.1') for n in (1,1,3)]
        self.assertIn('HIGH_VARIATION',a.quality(rows)['reasons']);self.assertFalse(a.quality(rows[:1])['usable'])
        rows[-1].update(effective_mbps=1,expected_bytes=200);self.assertIn('MIXED_SAMPLE_SIZE',a.quality(rows)['reasons'])
    def test_partial_timeout(self):
        r=p.parse_curl('200|1.1|198.18.0.76|0.01|0.02|0.5|1|20|200308',28,200308,1048576,1048576)
        self.assertEqual(r['error_category'],'BODY_TRANSFER_TIMEOUT');self.assertEqual(r['ttfb_ms'],1000);self.assertEqual(r['total_ms'],20000);self.assertIsNone(r['effective_mbps']);self.assertEqual(r['bytes'],200308)
    def test_tls_error(self):
        r=p.parse_curl('000|0||0.01|0.02|0|0|5|0',35,0,0,1024)
        self.assertEqual(r['error_category'],'TLS_ERROR');self.assertIsNone(r['tls_ms']);self.assertEqual(r['tcp_ms'],10)
    def test_tcp_error(self):
        with patch('socket.create_connection',side_effect=OSError(101,'network unreachable')):
            r=core.tcp_probe('2001:4860:4860::8888',threading.Event(),1)
        self.assertEqual(r['errors'][0]['errno'],101);self.assertEqual(r['success'],0)
    def test_icmp_exception_evidence(self):
        samples=[dict(status='Exception',ms=None,error_type='SocketException',socket_error=10051)]*5
        with patch('core.run_powershell',return_value=samples):r=p.icmp_probe('2001:4860:4860::8888',threading.Event())
        self.assertEqual(r['status'],'Unavailable');self.assertIsNone(r['loss_percent']);self.assertEqual(r['samples'][0]['socket_error'],10051)
    def test_baseline_gate(self):
        s=dict(interfaces=[dict(InterfaceIndex=1)],dns=[],routes=[]);perf=dict(scope='actual',download_experiment=dict(quality=dict(usable=True)))
        self.assertTrue(p.baseline(perf,s,s)['download_quality_usable']);self.assertFalse(p.baseline(perf,s,{})['download_quality_usable']);self.assertFalse(p.baseline(perf,s,s)['comparison_ready'])

if __name__=='__main__':unittest.main()
