import socketserver
import socket
import struct
import threading
import tempfile
from pathlib import Path
import unittest
import core

DOMAIN='www.example.com'
def reply(q, flags=0x8180, address=b'\x01\x02\x03\x04'):
    return q[:2]+struct.pack('!5H',flags,1,1 if not flags&0x200 else 0,0,0)+q[12:]+(b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+address if not flags&0x200 else b'')
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        q,s=self.request;s.sendto(reply(q,0x8380),self.client_address)
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        n=struct.unpack('!H',core.recv_exact(self.request,2,core.time.monotonic()+2))[0]
        q=core.recv_exact(self.request,n,core.time.monotonic()+2); r=reply(q);self.request.sendall(struct.pack('!H',len(r))+r)
class Tests(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(core.domain_name('WWW.Example.COM.'),DOMAIN)
        for s in ('foo','http://foo.com','a..com','-a.com'):
            with self.assertRaises(ValueError):core.domain_name(s)
    def test_reply(self):
        q=core.query_packet(DOMAIN,123); self.assertEqual(core.parse_reply(reply(q),DOMAIN,123),['1.2.3.4'])
        self.assertIsNone(core.parse_reply(reply(q,0x8380),DOMAIN,123))
        with self.assertRaises(core.ProbeError):core.parse_reply(reply(q),DOMAIN,124)
        with self.assertRaises(core.ProbeError):core.parse_reply(reply(q)[:-1],DOMAIN,123)
    def test_cname(self):
        q=core.query_packet(DOMAIN,123); target=core.name_wire('target.example.com')
        rr=b'\xc0\x0c'+struct.pack('!HHIH',5,1,60,len(target))+target
        a=target+struct.pack('!HHIH',1,1,60,4)+b'\x01\x02\x03\x04'
        p=q[:2]+struct.pack('!5H',0x8180,1,2,0,0)+q[12:]+rr+a
        self.assertEqual(core.parse_reply(p,DOMAIN,123),['1.2.3.4'])
    def test_bad_pointer(self):
        with self.assertRaises(core.ProbeError):core.decode_name(b'\xc0\x00',0)
    def test_udp_tcp(self):
        tcp=socketserver.TCPServer(('127.0.0.1',0),TCP); udp=socketserver.UDPServer(tcp.server_address,UDP)
        for s in (tcp,udp):threading.Thread(target=s.serve_forever,daemon=True).start()
        try:self.assertEqual(core.dns_probe('127.0.0.1',DOMAIN,port=tcp.server_address[1])[1:],(['1.2.3.4'],'UDP+TCP'))
        finally:
            for s in (tcp,udp):s.shutdown();s.server_close()
    def test_recommend(self):
        servers={'a':'A','b':'B'}; rows=[dict(server=ip,status='OK',ms=ms) for ip,ms in [('a',10),('b',11)] for _ in range(3)]
        self.assertEqual(core.summarize_dns(rows,servers,[DOMAIN],3,{'b':[]},{'recommendation_allowed':True})[1]['server'],'b')
        self.assertIsNone(core.summarize_dns(rows[:-1],servers,[DOMAIN],3,{},{'recommendation_allowed':True})[1])
        rows[0]['status']='Failed';self.assertEqual(core.summarize_dns(rows,servers,[DOMAIN],3,{},{'recommendation_allowed':True})[1]['server'],'b')
    def test_benchmark_rotation(self):
        rows=core.dns_benchmark({'a':'A','b':'B'},[DOMAIN],2,threading.Event(),probe=lambda *args:(5,[],'UDP'))
        self.assertEqual([r['server'] for r in rows],['a','b','b','a'])
    def test_mtu(self):
        self.assertEqual(core.mtu_probe('1.1.1.1',threading.Event(),ping=lambda ip,n:n<=1372)['observed_mtu'],1400)
        self.assertIsNone(core.mtu_probe('1.1.1.1',threading.Event(),ping=lambda *a:False)['observed_mtu'])
        self.assertEqual(core.mtu_probe('1.1.1.1',threading.Event(),ping=lambda *a:True)['observed_mtu'],1500)
    def test_cancel(self):
        stop=threading.Event();stop.set()
        with self.assertRaises(core.Cancelled):core.dns_benchmark({'a':'A'},[DOMAIN],3,stop)
    def test_report(self):
        with tempfile.TemporaryDirectory() as t:
            p=core.save_report(Path(t)/'report',dict(dns_samples=[],dns_summary=[],recommendation=None,note='<script>',tcp=[],mtu=None,warnings=[]))
            self.assertIn('&lt;script&gt;',(p/'report.html').read_text(encoding='utf-8'))
            self.assertTrue((p/'report.json').exists())
    def test_current_servers(self):
        s=dict(interfaces=[dict(InterfaceIndex=1,AddressFamily=2)],dns=[dict(InterfaceIndex=1,AddressFamily=2,ServerAddresses=['192.168.0.1'],InterfaceAlias='WiFi'),dict(InterfaceIndex=2,AddressFamily=2,ServerAddresses=['8.8.8.8'],InterfaceAlias='Off')]); self.assertEqual(core.current_servers(s),{'192.168.0.1':['WiFi']})

if __name__=='__main__':unittest.main()
