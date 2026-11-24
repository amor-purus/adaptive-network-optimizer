import copy
import unittest
import core
import validity

DOMAIN='www.example.com'
SERVERS={'1.1.1.1':'A','8.8.8.8':'B'}
CURRENT={'1.1.1.1':['WLAN']}
BASE={'interfaces':[{'InterfaceIndex':1,'InterfaceAlias':'WLAN'}],'dns':[{'InterfaceIndex':1,'InterfaceAlias':'WLAN','ServerAddresses':['1.1.1.1']}],'routes':[{'InterfaceIndex':1,'DestinationPrefix':'0.0.0.0/0','NextHop':'192.168.1.1'}]}

def rows(answer='93.184.216.34'):
    return [dict(server=ip,domain=DOMAIN,status='OK',ms=1.0,answers=[answer]) for ip in SERVERS for _ in range(3)]

class ValidityTests(unittest.TestCase):
    def gate(self,data=None,before=BASE,after=BASE,current=CURRENT):
        return validity.assess(rows() if data is None else data,before,after,current)
    def test_clean_and_shared_public_ip(self):
        g=self.gate();self.assertTrue(g['recommendation_allowed']);self.assertEqual(g['environment'],'no_known_proxy_indicators')
        self.assertIsNotNone(core.summarize_dns(rows(),SERVERS,[DOMAIN],3,CURRENT,g)[1])
    def test_fake_ip_regression(self):
        # Synthetic reproduction of all DNS candidates returning one fake address.
        r=rows('198.18.0.69');g=self.gate(r)
        self.assertEqual(g['fake_ip_samples'],6);self.assertIn('FAKE_IP_RESPONSE',g['reason_codes'])
        s,choice,_=core.summarize_dns(r,SERVERS,[DOMAIN],3,CURRENT,g)
        self.assertIsNone(choice);self.assertTrue(all(x['sample_complete'] and not x['eligible'] for x in s))
    def test_fake_range_and_mixed_answers(self):
        self.assertTrue(validity.fake_ip('198.19.255.255'));self.assertFalse(validity.fake_ip('198.20.0.1'))
        r=rows();r[0]['answers'].append('198.19.0.1');self.assertFalse(self.gate(r)['recommendation_allowed'])
    def test_proxy_adapter_and_split_route(self):
        b=copy.deepcopy(BASE);b['interfaces'].append({'InterfaceIndex':2,'InterfaceAlias':'FlClash'});b['routes'].append({'InterfaceIndex':2,'DestinationPrefix':'128.0.0.0/1','NextHop':'198.18.0.2'})
        g=self.gate(before=b,after=b);self.assertEqual(g['environment'],'proxy_or_tun_suspected');self.assertFalse(g['recommendation_allowed']);self.assertEqual(len(g['proxy_indicators']),2)
    def test_generic_adapter_fake_dns(self):
        b=copy.deepcopy(BASE);b['dns'][0]['ServerAddresses']=['198.18.0.2'];self.assertIn('PROXY_OR_TUN_INDICATOR',self.gate(before=b,after=b)['reason_codes'])
    def test_other_non_public_and_missing(self):
        for addr in ('127.0.0.1','192.168.1.1','224.0.0.1','203.0.113.1'):
            self.assertIn('NON_PUBLIC_RESPONSE',self.gate(rows(addr))['reason_codes'])
        r=rows();r[0]['answers']=[];self.assertIn('MISSING_ANSWER_EVIDENCE',self.gate(r)['reason_codes'])
    def test_changed_or_missing_config(self):
        b=copy.deepcopy(BASE);b['routes'][0]['NextHop']='192.168.1.2'
        self.assertIn('NETWORK_CONFIGURATION_CHANGED',self.gate(after=b)['reason_codes'])
        self.assertIn('SNAPSHOT_UNAVAILABLE',self.gate(after={})['reason_codes'])
        self.assertIn('NO_CURRENT_DNS_BASELINE',self.gate(current={})['reason_codes'])
    def test_enumeration_order(self):
        b=copy.deepcopy(BASE);b['interfaces'].append({'InterfaceIndex':2,'InterfaceAlias':'vEthernet (Default Switch)'})
        a=copy.deepcopy(b);a['interfaces'].reverse();self.assertTrue(self.gate(before=b,after=a)['recommendation_allowed'])
    def test_fail_closed_without_gate(self):
        self.assertIsNone(core.summarize_dns(rows(),SERVERS,[DOMAIN],3,CURRENT)[1])

if __name__=='__main__':unittest.main()
