import copy
import tempfile
from pathlib import Path
import threading
import unittest
from unittest.mock import patch
import core
import performance as p

GOOD='200|2|1.1.1.1|0.01|0.02|0.04|1|2|1000000'
class PerformanceTests(unittest.TestCase):
    def test_phases(self):
        r=p.parse_curl(GOOD,0,1000000,1000000,1000000)
        self.assertEqual((r['status'],r['dns_ms'],r['tcp_ms'],r['tls_ms'],r['ttfb_ms'],r['effective_mbps'],r['body_mbps']),('OK',10,10,20,1000,4,8))
    def test_body_rate_requires_one_second_window(self):
        short='200|2|1.1.1.1|0.01|0.02|0.04|0.1|0.2|1000000'
        r=p.parse_curl(short,0,1000000,1000000,1000000)
        self.assertEqual(r['status'],'OK')
        self.assertIsNone(r['body_mbps'])
        self.assertEqual(r['body_rate_status'],'INSUFFICIENT_WINDOW')

    def test_connect_timeout_not_misclassified_by_starttransfer_timer(self):
        raw='000|0||0.029222|0|0|5.004689|5.004697|0'
        r=p.parse_curl(raw,28,0,512*1024,512*1024)
        self.assertEqual(r['error_category'],'TCP_CONNECT_TIMEOUT')
        self.assertEqual(r['failure_phase'],'tcp_connect')
        self.assertIsNone(r['ttfb_ms'])
        self.assertAlmostEqual(r['dns_ms'],29.222)
        self.assertIsNone(r['tcp_ms'])

    def test_timeout_phase_requires_completed_predecessor(self):
        tls=p.parse_curl('000|0|1.1.1.1|0.01|0.02|0|0|5|0',28,0,1024,1024)
        first=p.parse_curl('000|0|1.1.1.1|0.01|0.02|0.04|0|5|0',28,0,1024,1024)
        body=p.parse_curl('200|2|1.1.1.1|0.01|0.02|0.04|1|5|100',28,100,1024,1024)
        self.assertEqual((tls['error_category'],tls['failure_phase']),('TLS_HANDSHAKE_TIMEOUT','tls_handshake'))
        self.assertEqual((first['error_category'],first['failure_phase']),('FIRST_BYTE_TIMEOUT','server_response'))
        self.assertEqual((body['error_category'],body['failure_phase']),('BODY_TRANSFER_TIMEOUT','body_transfer'))

    def test_bad_telemetry(self):
        for s in ('',GOOD.replace('0.02','nan'),GOOD.replace('0.04','0.001')):
            self.assertEqual(p.parse_curl(s,0,1000000,1000000,1000000)['status'],'Failed')
    def test_bad_download(self):
        for code,actual,expected,cap in [(1,1000000,1000000,1000000),(0,5,1000000,1000000),(0,1000000,4,1000000),(0,1000000,1000000,5)]:
            self.assertEqual(p.parse_curl(GOOD,code,actual,expected,cap)['status'],'Failed')
        self.assertEqual(p.parse_curl(GOOD.replace('200|','429|'),0,1000000,1000000,1000000)['http_status'],429)
    def test_zero_body(self):
        r=p.parse_curl(GOOD.replace('200|','204|').replace('|1000000','|0'),0,0,0,1024)
        self.assertEqual(r['status'],'OK');self.assertIsNone(r['effective_mbps'])
    def test_jitter(self):
        self.assertEqual(p.jitter([10,14,None,100,106]),5)
        self.assertIsNone(p.jitter([1,None,5]));self.assertEqual(p.stats([1,None,5])['success'],2)
    def test_summary_gap(self):
        rows=[dict(target='A',round=i,status='OK',ttfb_ms=t) for i,t in [(1,10),(3,30)]]
        s=p.summarize_https(rows,['A','B'],3);self.assertIsNone(s[0]['ttfb_jitter_ms']);self.assertEqual(s[0]['success'],2);self.assertEqual(s[1]['attempted'],0)
    def test_icmp(self):
        with patch('core.run_powershell',return_value=[dict(status='Success',ms=10),dict(status='TimedOut',ms=None),dict(status='Success',ms=12)]):
            r=p.icmp_probe('1.1.1.1',threading.Event(),3);self.assertAlmostEqual(r['loss_percent'],33.333);self.assertIsNone(r['jitter_ms'])
        with patch('core.run_powershell',side_effect=core.ProbeError('no')):
            self.assertIsNone(p.icmp_probe('1.1.1.1',threading.Event())['loss_percent'])
    def test_baseline(self):
        s=dict(interfaces=[dict(InterfaceIndex=1,InterfaceAlias='FlClash')],dns=[],routes=[]);x=dict(scope='actual')
        b=p.baseline(x,s,s);self.assertTrue(b['configuration_observed_stable']);self.assertFalse(b['comparison_ready']);self.assertEqual(b['environment'],'proxy_or_tun_suspected')
        self.assertFalse(p.baseline(x,s,{})['configuration_observed_stable'])
    def test_cancel(self):
        stop=threading.Event();stop.set()
        with self.assertRaises(core.Cancelled):p.collect(stop)
    def test_collect_without_curl(self):
        with patch('core.tcp_probe',side_effect=lambda ip,*a,**k:dict(ip=ip,samples_ms=[1,2,None,4,5],success=4,attempted=5,median_ms=3)),patch('performance.curl_path',return_value=None):
            r=p.collect(threading.Event(),icmp=False);self.assertEqual(len(r['tcp']),6);self.assertTrue(r['warnings']);self.assertEqual(r['received_body_bytes'],0)
    def test_rate_limit(self):
        row=p.parse_curl(GOOD.replace('200|','429|'),0,1000000,1000000,1000000)
        with patch('core.tcp_probe',return_value=dict(samples_ms=[1]*5)),patch('performance.curl_path',return_value='curl'),patch('performance.https_probe',return_value=None,side_effect=lambda *a:dict(row)) as mock:
            r=p.collect(threading.Event(),icmp=False);self.assertEqual(mock.call_count,3);self.assertEqual(len(r['https_summary']),4)
    def test_report(self):
        with tempfile.TemporaryDirectory() as d:
            perf=dict(scope='<script>',https_samples=[],https_summary=[],tcp=[],icmp=[],warnings=[])
            p.write_csvs(Path(d),perf);self.assertTrue((Path(d)/'performance_https_samples.csv').exists());self.assertIn('&lt;script&gt;',p.report_html(perf,{}))

if __name__=='__main__':unittest.main()
