import ctypes
import unittest
import os
import traffic as t
def sample(rx=100,tx=50,when=0,**kw):
    r=dict(index=16,luid=7,type=71,hardware=True,oper=1,media_state=1,rx=rx,tx=tx);r.update(kw)
    return dict(status='Measured',started=when,finished=when+.01,interfaces=[r])
class TrafficTests(unittest.TestCase):
    def test_abi(self):
        self.assertEqual(ctypes.sizeof(t.IfRow),1352)
        self.assertEqual(t.IfRow.in_octets.offset,1208)
        self.assertEqual(t.IfRow.out_octets.offset,1280)
    def test_delta(self):
        d=t.delta(sample(),sample(1100,250,2),500)
        self.assertEqual(d['status'],'Measured');self.assertEqual(d['interfaces'][0]['rx_bytes'],1000)
        self.assertEqual(d['interfaces'][0]['rx_to_test_body_ratio'],2)
        self.assertNotIn('background_bytes',d)
    def test_invalid(self):
        for after in (sample(10,10,2),sample(1000,300,2,luid=8),sample(1000,300,2,oper=2),dict(status='Unavailable',started=2,finished=2,interfaces=[])):
            self.assertEqual(t.delta(sample(),after)['status'],'Unavailable')
    def test_no_cross_interface_sum(self):
        a=sample();b=sample(1000,500,2)
        a['interfaces'].append(dict(a['interfaces'][0],index=43,hardware=False))
        b['interfaces'].append(dict(b['interfaces'][0],index=43,hardware=False))
        d=t.delta(a,b,100);self.assertEqual(len(d['interfaces']),2);self.assertNotIn('rx_bytes',d)
    def test_native_call(self):
        r=t.sample([1]);self.assertIn(r['status'],('Measured','Partial','Unavailable'))
        if os.name=='nt':
            # The Windows loopback interface is normally index 1; verify actual ABI/API, not just fallback.
            self.assertEqual(r['status'],'Measured',r)
            self.assertEqual(r['interfaces'][0]['index'],1)
            self.assertGreater(r['interfaces'][0]['luid'],0)
            self.assertEqual(r['interfaces'][0]['type'],24)
if __name__=='__main__':unittest.main()
