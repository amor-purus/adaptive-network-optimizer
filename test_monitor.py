import copy
import tempfile
from pathlib import Path
import unittest
import monitor as m

BASE={'interfaces':[{'InterfaceIndex':16,'AddressFamily':2,'InterfaceAlias':'WLAN','AutomaticMetric':1,'InterfaceMetric':50}],'dns':[],'routes':[]}
def changed(value):
    x=copy.deepcopy(BASE);x['interfaces'][0]['InterfaceMetric']=value;return x
def rec(label,s,n):
    return dict(label=label,elapsed_s=n,observed_at='test',snapshot=s,wlan={'status':'Unavailable','interfaces':[]})
class MonitorTests(unittest.TestCase):
    def test_metric(self):
        d=m.diff(BASE,changed(45));self.assertEqual(len(d),1);self.assertEqual(d[0]['kind'],'automatic_metric_possible');self.assertEqual(d[0]['actor'],'unknown')
    def test_unknown_metric(self):
        a=copy.deepcopy(BASE);b=changed(45);a['interfaces'][0]['AutomaticMetric']=0;b['interfaces'][0]['AutomaticMetric']=0
        self.assertEqual(m.diff(a,b)[0]['kind'],'metric_change_unknown_cause')
    def test_transient_change(self):
        rs=[rec('start',BASE,0),rec('periodic',changed(45),15),rec('after_dns',BASE,30)]
        e=m.phase_evidence(rs,'dns');self.assertFalse(e['observed_stable']);self.assertEqual(len(e['changes']),2)
        g=m.apply_dns_gate(dict(reason_codes=[],messages=[],recommendation_allowed=True),e);self.assertFalse(g['recommendation_allowed'])
    def test_missing(self):
        rs=[rec('start',BASE,0),rec('periodic',{},15),rec('after_dns',BASE,30)]
        self.assertFalse(m.phase_evidence(rs,'dns')['complete'])
    def test_stage_boundary(self):
        rs=[rec('start',BASE,0),rec('after_dns',changed(45),10),rec('after_performance',changed(35),20)]
        self.assertEqual(len(m.phase_evidence(rs,'performance')['changes']),1)
        b=m.apply_baseline(dict(configuration_observed_stable=True,download_quality_usable=True),m.phase_evidence(rs,'performance'));self.assertFalse(b['download_quality_usable'])
    def test_telemetry_separate(self):
        b=copy.deepcopy(BASE);b['adapters']=[{'LinkSpeed':'100 Mbps'}]
        self.assertEqual(m.diff(BASE,b),[])
    def test_wlan_privacy(self):
        x=m.parse_wlan(' Name : Wi-Fi\n SSID : private\n BSSID : 00:11:22:33:44:55\n Signal : 70%\n Receive rate (Mbps) : 433.3\n Transmit rate (Mbps) : 100\n')
        self.assertEqual(x,[dict(name='Wi-Fi',signal_percent=70,rx_mbps=433.3,tx_mbps=100)])
        self.assertEqual(m.parse_wlan('Access denied'),[])
    def test_wlan_chinese(self):
        self.assertEqual(m.parse_wlan(' 名称 : WLAN\n 信号 : 80%\n 接收速率 (Mbps) : 300\n 传输速率 (Mbps) : 200')[0]['rx_mbps'],300)
    def test_duplicate_routes(self):
        a=copy.deepcopy(BASE);b=copy.deepcopy(BASE);a['routes']=[dict(InterfaceIndex=1,DestinationPrefix='0.0.0.0/0',NextHop='1.1.1.1',RouteMetric=1)]*2
        self.assertEqual(m.diff(a,b)[0]['field'],'record')
    def test_ipv6(self):
        tcp=[dict(ip='::1',attempted=2,success=0,errors=[{'winerror':10013},{'winerror':10013}])]
        x=m.ipv6_diagnosis(tcp,[],{});self.assertEqual(x['wsaeacces_count'],2);self.assertEqual(x['classification'],'LOCAL_ACCESS_DENIAL_INDICATED')
    def test_monitor_checkpoints(self):
        a=m.Monitor(reader=lambda:BASE,wlan=lambda:{'status':'Unavailable','interfaces':[]})
        a.checkpoint('start');a.start();a.checkpoint('after_dns','performance');a.checkpoint('after_performance','done');a.close()
        self.assertTrue(a.evidence('dns')['observed_stable']);self.assertTrue(a.evidence('performance')['observed_stable'])
    def test_tuning_phase_and_telemetry_stability(self):
        def full(label,seconds,rate=866.7):
            snap=copy.deepcopy(BASE)
            snap.update(adapter_status='Measured',adapters=[dict(Name='WLAN',ifIndex=16,Status='Up',LinkSpeed=str(rate)+' Mbps',ReceiveLinkSpeed=int(rate*1000000),TransmitLinkSpeed=int(rate*1000000),MediaConnectionState=1)])
            return dict(label=label,phase='tuning',elapsed_s=seconds,observed_at='test',snapshot=snap,wlan=dict(status='Measured',interfaces=[dict(name='WLAN',signal_percent=99,rx_mbps=rate,tx_mbps=rate)]))
        rs=[full('after_performance',0),full('periodic',45),full('after_tuning',90)]
        e=m.phase_evidence(rs,'tuning')
        self.assertTrue(e['complete']);self.assertTrue(e['observed_stable'])
        self.assertTrue(e['telemetry_complete']);self.assertTrue(e['telemetry_observed_stable'])
        changed=[full('after_performance',0),full('periodic',45,433.3),full('after_tuning',90)]
        e2=m.phase_evidence(changed,'tuning')
        self.assertFalse(e2['telemetry_observed_stable']);self.assertGreater(len(e2['telemetry_changes']),0)

    def test_tuning_rejects_unavailable_wireless_telemetry(self):
        a=dict(label='after_performance',elapsed_s=0,snapshot=dict(BASE,adapter_status='Measured',adapters=[dict(Name='WLAN',Status='Up')]),wlan=dict(status='Unavailable',interfaces=[]))
        b=dict(label='after_tuning',elapsed_s=1,snapshot=dict(BASE,adapter_status='Measured',adapters=[dict(Name='WLAN',Status='Up')]),wlan=dict(status='Unavailable',interfaces=[]))
        e=m.phase_evidence([a,b],'tuning')
        self.assertFalse(e['telemetry_complete'])

    def test_exports(self):
        env=dict(timeline=[rec('start',BASE,0)],phases=[],ipv6_diagnosis={'note':'<script>'})
        with tempfile.TemporaryDirectory() as d:
            m.write_csvs(Path(d),env);self.assertTrue((Path(d)/'environment_changes.csv').exists())
            self.assertTrue((Path(d)/'network_telemetry_changes.csv').exists())
        self.assertIn('&lt;script&gt;',m.report_html(env))
if __name__=='__main__':unittest.main()
