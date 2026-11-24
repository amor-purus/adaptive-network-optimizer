"""Read-only network measurements; Python 3.10+, no third-party dependencies."""
import csv
import datetime
import html
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import statistics
import struct
import subprocess
import time

PRESETS={'Cloudflare':'1.1.1.1','Google':'8.8.8.8','Quad9':'9.9.9.9','AliDNS':'223.5.5.5','DNSPod':'119.29.29.29'}
DOMAINS=('www.microsoft.com','www.github.com','www.youtube.com','www.baidu.com')

class ProbeError(Exception): pass
class Cancelled(Exception): pass

def check_cancel(stop):
    if stop.is_set(): raise Cancelled()

def domain_name(s):
    s=s.strip().rstrip('.').encode('idna').decode('ascii').lower()
    if len(s)>253 or '.' not in s or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in s.split('.')):
        raise ValueError('请输入合法的公开域名。')
    return s

def name_wire(s):
    return b''.join(bytes([len(x)])+x.encode('ascii') for x in domain_name(s).split('.'))+b'\0'

def query_packet(domain,tid):
    return struct.pack('!6H',tid,0x0100,1,0,0,0)+name_wire(domain)+struct.pack('!HH',1,1)

def decode_name(data,pos):
    labels=[]; visited=set(); end=None; length=0
    while True:
        if pos>=len(data) or pos in visited: raise ProbeError('DNS 名称无效')
        visited.add(pos); n=data[pos]; pos+=1
        if n&0xc0==0xc0:
            if pos>=len(data): raise ProbeError('DNS 指针截断')
            pointer=((n&63)<<8)|data[pos]
            if pointer>=pos-1: raise ProbeError('DNS 压缩指针无效')
            if end is None: end=pos+1
            pos=pointer; continue
        if n&0xc0 or pos+n>len(data): raise ProbeError('DNS 标签无效')
        if not n: return b'.'.join(labels).lower(),end if end is not None else pos
        length+=n+1
        if length>254: raise ProbeError('DNS 名称过长')
        labels.append(data[pos:pos+n]); pos+=n

def parse_reply(data,domain,tid):
    if len(data)<12: raise ProbeError('DNS 响应截断')
    ident,flags,qd,an,_,_=struct.unpack_from('!6H',data)
    if ident!=tid or not flags&0x8000 or flags&0x7800 or qd!=1: raise ProbeError('DNS 响应身份不匹配')
    q,pos=decode_name(data,12)
    if pos+4>len(data) or q!=domain_name(domain).encode() or struct.unpack_from('!HH',data,pos)!=(1,1): raise ProbeError('DNS 问题不匹配')
    if flags&0x0200: return None
    if flags&15: raise ProbeError('DNS RCODE '+str(flags&15))
    pos+=4; addresses={}; aliases={}
    for _ in range(an):
        owner,pos=decode_name(data,pos)
        if pos+10>len(data): raise ProbeError('DNS 记录截断')
        typ,cls,ttl,n=struct.unpack_from('!HHIH',data,pos); pos+=10
        if pos+n>len(data): raise ProbeError('DNS 数据截断')
        if cls==1 and typ==1 and n==4: addresses.setdefault(owner,[]).append(str(ipaddress.IPv4Address(data[pos:pos+4])))
        if cls==1 and typ==5:
            target,end=decode_name(data,pos)
            if end!=pos+n: raise ProbeError('CNAME 长度错误')
            aliases[owner]=target
        pos+=n
    seen=set()
    while q not in seen:
        if q in addresses: return sorted(set(addresses[q]))
        seen.add(q)
        if q not in aliases: break
        q=aliases[q]
    raise ProbeError('无有效 A 记录')

def recv_exact(sock,n,deadline):
    data=bytearray()
    while len(data)<n:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError('DNS deadline exceeded')
        sock.settimeout(remaining)
        chunk=sock.recv(n-len(data))
        if not chunk: raise ProbeError('TCP DNS 响应提前结束')
        data.extend(chunk)
    return bytes(data)

def dns_probe(server,domain,timeout=1.5,port=53):
    ip=ipaddress.IPv4Address(server); tid=secrets.randbelow(65536); packet=query_packet(domain,tid)
    start=time.monotonic(); deadline=start+timeout; transport='UDP'
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        s.settimeout(timeout); s.connect((str(ip),port)); s.send(packet); data=s.recv(65535)
    records=parse_reply(data,domain,tid)
    if records is None:
        transport='UDP+TCP'
        with socket.create_connection((str(ip),port),timeout=max(.001,deadline-time.monotonic())) as s:
            s.settimeout(max(.001,deadline-time.monotonic())); s.sendall(struct.pack('!H',len(packet))+packet)
            n=struct.unpack('!H',recv_exact(s,2,deadline))[0]; records=parse_reply(recv_exact(s,n,deadline),domain,tid)
            if records is None: raise ProbeError('TCP DNS 仍返回截断响应')
    return round((time.monotonic()-start)*1000,3),records,transport

def run_powershell(script):
    if os.name!='nt': raise ProbeError('此项需 Windows 运行')
    prefix="[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $ErrorActionPreference='Stop'; "
    try:
        p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',prefix+script],capture_output=True,timeout=20,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    except subprocess.TimeoutExpired as e: raise ProbeError('读取网络配置超时') from e
    if p.returncode: raise ProbeError('无法读取 Windows 网络配置')
    return json.loads(p.stdout.decode('utf-8-sig'))

def snapshot():
    script=r'''$a=@(Get-NetIPInterface | Where-Object {$_.ConnectionState -eq 'Connected'} | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,NlMtu,InterfaceMetric,Dhcp,AutomaticMetric); $d=@(Get-DnsClientServerAddress | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses); $r=@(Get-NetRoute | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')} | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric); $ad=@();$ast='Measured';try{$ad=@(Get-NetAdapter | Select-Object Name,ifIndex,Status,LinkSpeed,ReceiveLinkSpeed,TransmitLinkSpeed,MediaConnectionState)}catch{$ast='Unavailable'}; @{interfaces=$a;dns=$d;routes=$r;adapters=$ad;adapter_status=$ast}|ConvertTo-Json -Depth 5 -Compress'''
    return run_powershell(script)

def current_servers(snap):
    active={x['InterfaceIndex'] for x in snap.get('interfaces',[]) if int(x['AddressFamily'])==2}
    result={}
    for d in snap.get('dns',[]):
        if d['InterfaceIndex'] not in active or int(d['AddressFamily'])!=2: continue
        for addr in d.get('ServerAddresses') or []:
            try: ip=str(ipaddress.IPv4Address(addr))
            except ValueError: continue
            result.setdefault(ip,[]).append(str(d['InterfaceAlias']))
    return result

def percentile(values,p):
    return sorted(values)[max(0,math.ceil(len(values)*p)-1)]

def summarize_dns(rows,servers,domains,rounds,current,validity=None):
    allowed=bool(validity and validity.get('recommendation_allowed') is True)
    summary=[]; required=len(domains)*rounds
    for ip,label in servers.items():
        rs=[r for r in rows if r['server']==ip]; good=[r['ms'] for r in rs if r['status']=='OK']
        summary.append({'server':ip,'name':label,'current':ip in current,'attempted':len(rs),'planned':required,'success':len(good),'median_ms':round(statistics.median(good),3) if good else None,'p95_ms':round(percentile(good,.95),3) if good else None,'sample_complete':len(rs)==required and len(good)==required,'eligible':allowed and len(rs)==required and len(good)==required})
    if len(rows)!=required*len(servers): return summary,None,'测试未完成，不推荐变更。'
    if not allowed: return summary,None,'实验有效性未通过；保留原始观测，不推荐 DNS 变更。'
    valid=[r for r in summary if r['eligible']]
    if not valid: return summary,None,'没有全部成功的候选 DNS。'
    best=min(valid,key=lambda r:(r['median_ms'],r['p95_ms']))
    existing=[r for r in valid if r['current'] and r['median_ms']<=best['median_ms']*1.10+2 and r['p95_ms']<=best['p95_ms']*1.20+5]
    choice=min(existing,key=lambda r:r['median_ms']) if existing else best
    return summary,choice,'仅比较 IPv4 DNS 的直接 UDP/TCP 53 查询；不代表浏览器、DoH、系统缓存或真实网站速度。'

def dns_benchmark(servers,domains,rounds,stop,emit=lambda _:None,probe=dns_probe):
    rows=[]; ips=list(servers)
    for r in range(rounds):
        for j,domain in enumerate(domains):
            for k in range(len(ips)):
                check_cancel(stop); ip=ips[(k+j+r)%len(ips)]; emit(f'DNS {r+1}/{rounds}：{servers[ip]} / {domain}')
                row={'round':r+1,'domain':domain,'server':ip,'status':'Failed','ms':None,'transport':'','answers':[],'error':''}
                try:
                    ms,answers,transport=probe(ip,domain); row.update(status='OK',ms=ms,answers=answers,transport=transport)
                except (OSError,ProbeError) as e: row['error']='超时或网络错误' if isinstance(e,OSError) else str(e)
                rows.append(row)
                if stop.wait(.04): raise Cancelled()
    return rows

def tcp_probe(ip,stop,rounds=5):
    rows=[]; errors=[]; ip=str(ipaddress.ip_address(ip))
    for _ in range(rounds):
        check_cancel(stop); start=time.monotonic()
        try:
            with socket.create_connection((ip,443),timeout=1.5): pass
            rows.append(round((time.monotonic()-start)*1000,3)); errors.append(None)
        except OSError as e:
            rows.append(None); errors.append({"type":type(e).__name__,"errno":e.errno,"winerror":getattr(e,"winerror",None)})
    valid=[x for x in rows if x is not None]
    return {'ip':ip,'port':443,'samples_ms':rows,'errors':errors,'success':len(valid),'attempted':len(rows),'median_ms':round(statistics.median(valid),3) if valid else None}

def ping_df(ip,payload):
    ip=str(ipaddress.IPv4Address(ip))
    p=subprocess.run(['ping.exe','-4','-n','1','-w','1200','-f','-l',str(payload),ip],capture_output=True,timeout=5,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    return bool(re.search(rb'\bTTL\s*=\s*\d+',p.stdout,re.I))

def mtu_probe(ip,stop,emit=lambda _:None,ping=ping_df):
    trials=[]
    def test(n):
        check_cancel(stop); emit(f'MTU：测试 {n+28} 字节 IPv4 包')
        hits=0
        for _ in range(3):
            check_cancel(stop)
            hits+=int(ping(ip,n))
        trials.append({'packet_bytes':n+28,'success':hits,'attempted':3})
        return hits==3
    if not test(32): return {'target':ip,'observed_mtu':None,'trials':trials,'note':'小包不稳定或 ICMP 被阻止，无法估计。'}
    if test(1472): return {'target':ip,'observed_mtu':1500,'trials':trials,'note':'1500 字节通过；未探测巨帧。'}
    lo,hi=32,1472
    while hi-lo>1:
        mid=(hi+lo)//2
        if test(mid): lo=mid
        else: hi=mid
    if not test(lo): return {'target':ip,'observed_mtu':None,'trials':trials,'note':'重复验证不一致，不推荐 MTU。'}
    return {'target':ip,'observed_mtu':lo+28,'trials':trials,'note':'仅为此路径、此时段成功通过的估计包大小；丢包或 ICMP 策略会干扰，不自动修改 MTU。'}

def save_report(directory,data):
    root=Path(directory); root.mkdir(parents=True,exist_ok=False)
    (root/'report.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    for name,rows in [('dns_samples.csv',data['dns_samples']),('dns_summary.csv',data['dns_summary'])]:
        with (root/name).open('w',encoding='utf-8-sig',newline='') as f:
            if rows:
                w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
            else: f.write('status\nno_data\n')
    perf_html=''
    if 'performance' in data:
        import performance
        performance.write_csvs(root,data['performance'])
        perf_html=performance.report_html(data['performance'],data.get('performance_baseline',{}))
    if 'environment_monitor' in data:
        import monitor
        monitor.write_csvs(root,data['environment_monitor'])
        perf_html+=monitor.report_html(data['environment_monitor'])
    if 'tuning_experiment' in data:
        import tuning
        tuning.write_csvs(root,data['tuning_experiment'])
        perf_html+=tuning.report_html(data['tuning_experiment'])
    esc=lambda x:html.escape(str(x)); s=data['dns_summary']; choice=data['recommendation']
    table='<table><tr><th>DNS</th><th>成功/计划</th><th>中位 ms</th><th>P95 ms</th><th>当前配置</th></tr>'+''.join('<tr>'+''.join('<td>'+esc(x)+'</td>' for x in (r['name']+' '+r['server'],f"{r['success']}/{r['planned']}",r['median_ms'],r['p95_ms'],r['current']))+'</tr>' for r in s)+'</table>'
    validity=data.get('validity',{}); gate=validity.get('recommendation_allowed') is True
    if not gate: choice=None
    validity_text=esc('；'.join(validity.get('messages',[])) or ('未发现已知干扰迹象，不代表已证明直连。' if gate else '实验有效性未通过。'))
    valid=[r for r in s if gate and r['eligible']]; top=max((r['median_ms'] for r in valid),default=1) or 1
    bars=''.join('<p>'+esc(r['name'])+' '+esc(r['server'])+' — '+str(r['median_ms'])+' ms</p><div style="height:12px;background:#285eb3;width:%.2f%%"></div>'%(100*r['median_ms']/top) for r in valid)
    details=esc(json.dumps({'tcp':data['tcp'],'mtu':data['mtu'],'warnings':data['warnings'],'validity':data.get('validity',{})},ensure_ascii=False,indent=2))
    (root/'report.html').write_text('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>网络优化报告</title><style>body{font:16px/1.6 system-ui;max-width:1000px;margin:32px auto;padding:0 16px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px;text-align:left}pre{white-space:pre-wrap}</style><h1>自适应网络优化报告</h1><p>推荐 DNS 候选：'+esc(choice['server'] if choice else '无')+'</p><p>'+esc(data['note'])+'</p><h2>实验有效性</h2><p>'+esc(validity.get('environment','environment_unverified'))+'：'+validity_text+'</p><p>下表为原始观测；仅通过有效性检查且完整成功的候选绘图。TCP/MTU 仅代表当前实际路径。</p>'+bars+table+'<h2>连接及 MTU 诊断</h2><pre>'+details+'</pre>'+perf_html+'<p>系统配置未修改。JSON 包含本地网卡、路由和 DNS 信息，分享前请检查。</p></html>',encoding='utf-8')
    return root
