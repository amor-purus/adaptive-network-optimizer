"""Bounded current-path performance measurements, independent of DNS recommendation."""
import csv
import html
import ipaddress
import math
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import tempfile
import time
import core
import validity

MIB=1024**2
HTTPS_TARGETS=(('Cloudflare','https://speed.cloudflare.com/__down?bytes=0',0),('Google','https://www.gstatic.com/generate_204',0),('GitHub','https://api.github.com/zen',None))
IP_TARGETS=('1.1.1.1','8.8.8.8','9.9.9.9','2606:4700:4700::1111','2001:4860:4860::8888','2620:fe::fe')
FIELDS=('http_code','http_version','remote_ip','time_namelookup','time_connect','time_appconnect','time_starttransfer','time_total','size_download')
FORMAT='|'.join('%{'+x+'}' for x in FIELDS)


def curl_path():
    return shutil.which('curl.exe') or shutil.which('curl')


def jitter(values):
    pairs=[abs(b-a) for a,b in zip(values,values[1:]) if a is not None and b is not None]
    return round(statistics.mean(pairs),3) if pairs else None


def stats(values):
    good=[x for x in values if x is not None]
    return {'success':len(good),'attempted':len(values),'median':round(statistics.median(good),3) if good else None,'p95':round(core.percentile(good,.95),3) if good else None,'jitter_ms':jitter(values)}


def parse_curl(output, code, actual, expected, cap):
    row=dict(status='Failed',exit_code=code,http_status=None,http_version='',remote_ip='',bytes=actual,dns_ms=None,tcp_ms=None,tls_ms=None,ttfb_ms=None,total_ms=None,body_mbps=None,effective_mbps=None,error='')
    fields=output.strip().split('|')
    if len(fields)!=len(FIELDS):
        row['error']='curl 遥测缺失'; return row
    try:
        status=int(fields[0]); size=float(fields[8]); times=list(map(float,fields[3:8]))
        if not all(math.isfinite(x) and x>=0 for x in [size,*times]):raise ValueError()
        if fields[2]:ipaddress.ip_address(fields[2])
    except ValueError:
        row['error']='curl 遥测无效'; return row
    row.update(http_status=status,http_version=fields[1],remote_ip=fields[2])
    if status in (403,429):row['error']='HTTP '+str(status)+'：停止该目标';return row
    if code or not 200<=status<300 or size!=actual or actual>cap or (expected is not None and actual!=expected):
        row['error']='HTTP/退出码/字节数验证失败';return row
    dns,tcp,tls,first,total=times
    if not (0<=dns<=tcp<=tls<=first<=total and tls>0 and total>0):
        row['error']='连接阶段遥测不完整或顺序异常';return row
    row.update(status='OK',dns_ms=round(dns*1000,3),tcp_ms=round((tcp-dns)*1000,3),tls_ms=round((tls-tcp)*1000,3),ttfb_ms=round(first*1000,3),total_ms=round(total*1000,3))
    if expected and actual:
        row['effective_mbps']=round(actual*8/total/1e6,3)
        if total-first>=.001:row['body_mbps']=round(actual*8/(total-first)/1e6,3)
    return row


def https_probe(exe,url,expected,cap,stop):
    core.check_cancel(stop)
    with tempfile.TemporaryDirectory(prefix='ano-https-') as tmp:
        body=Path(tmp)/'body'; meta=Path(tmp)/'meta'
        # Use existing environment proxy rules; no proxy override, redirects, retries or TLS bypass.
        args=[exe,'--disable','--silent','--show-error','--proto','=https','--connect-timeout','5','--max-time','20','--max-filesize',str(cap),'--header','Accept-Encoding: identity','--header','Cache-Control: no-cache','--output',str(body),'--write-out',FORMAT,'--',url]
        killed=False
        with meta.open('wb') as out:
            p=subprocess.Popen(args,stdout=out,stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            try:
                deadline=time.monotonic()+25
                while p.poll() is None:
                    if stop.wait(.025):raise core.Cancelled()
                    if time.monotonic()>deadline or (body.exists() and body.stat().st_size>cap):
                        killed=True;break
            finally:
                if p.poll() is None:p.kill()
                p.wait()
        actual=body.stat().st_size if body.exists() else 0
        row=parse_curl(meta.read_text(encoding='utf-8',errors='replace'),p.returncode,actual,expected,cap)
        if killed:row.update(status='Failed',error='超过时间或样本预算，已终止')
        return row


def icmp_probe(ip,stop,rounds=5):
    core.check_cancel(stop)
    ip=str(ipaddress.ip_address(ip))
    # .NET Ping status avoids localized ping.exe text parsing.
    script="$p=New-Object System.Net.NetworkInformation.Ping; try {$r=@(1..%d | ForEach-Object {try {$x=$p.Send('%s',1200); @{status=$x.Status.ToString();ms=if($x.Status -eq 'Success'){$x.RoundtripTime}else{$null}}}catch{@{status='Exception';ms=$null}}}); ConvertTo-Json -InputObject $r -Compress}finally{$p.Dispose()}"%(rounds,ip)
    try:
        samples=core.run_powershell(script)
        if not isinstance(samples,list) or len(samples)!=rounds:raise ValueError()
        values=[float(r['ms']) if r['status']=='Success' and r['ms'] is not None else None for r in samples]
        if any(v is not None and (not math.isfinite(v) or v<0) for v in values) or all(r['status']=='Exception' for r in samples):raise ValueError()
    except (core.ProbeError,OSError,ValueError,KeyError,TypeError):
        return dict(ip=ip,status='Unavailable',samples=[],loss_percent=None,median_ms=None,p95_ms=None,jitter_ms=None,success=None,attempted=0)
    core.check_cancel(stop)
    s=stats(values)
    return dict(ip=ip,status='Measured',samples=samples,loss_percent=round(100*(rounds-s['success'])/rounds,3),median_ms=s['median'],p95_ms=s['p95'],jitter_ms=s['jitter_ms'],success=s['success'],attempted=rounds)


def summarize_https(rows,targets,rounds):
    summary=[]
    for label in targets:
        rs=sorted((r for r in rows if r['target']==label),key=lambda r:r['round'])
        by_round={r['round']:r for r in rs if r['status']=='OK'}
        values=lambda key:[by_round.get(n,{}).get(key) for n in range(1,rounds+1)]
        t=stats(values('ttfb_ms')); speeds=[v for v in values('effective_mbps') if v is not None]; body=[v for v in values('body_mbps') if v is not None]
        med=lambda key:stats(values(key))['median']
        summary.append(dict(target=label,success=t['success'],attempted=len(rs),planned=rounds,ttfb_median_ms=t['median'],ttfb_p95_ms=t['p95'],ttfb_jitter_ms=t['jitter_ms'],dns_median_ms=med('dns_ms'),tcp_median_ms=med('tcp_ms'),tls_median_ms=med('tls_ms'),total_median_ms=med('total_ms'),effective_mbps_median=round(statistics.median(speeds),3) if speeds else None,body_mbps_median=round(statistics.median(body),3) if body else None))
    return summary


def collect(stop,emit=lambda _:None,rounds=3,sample_mib=1,icmp=True,https=True):
    if rounds not in (3,5) or sample_mib not in (1,2,4):raise ValueError('性能测试配置无效')
    result=dict(https_samples=[],https_summary=[],tcp=[],icmp=[],warnings=[],plan=dict(rounds=rounds,sample_mib=sample_mib,https=https,icmp=icmp),scope='当前实际路径；可能经过代理/TUN，不能推断物理链路或直连性能。')
    for ip in IP_TARGETS:
        core.check_cancel(stop);emit('TCP 443：'+ip)
        row=core.tcp_probe(ip,stop,rounds=5);s=stats(row['samples_ms']);row.update(p95_ms=s['p95'],jitter_ms=s['jitter_ms']);result['tcp'].append(row)
        if icmp:
            emit('ICMP：'+ip);result['icmp'].append(icmp_probe(ip,stop))
    exe=curl_path()
    if https and not exe:result['warnings'].append('未找到 curl，跳过 HTTPS 测量。')
    if https and exe:
        targets=list(HTTPS_TARGETS)+[('Cloudflare 下载','https://speed.cloudflare.com/__down?bytes='+str(sample_mib*MIB),sample_mib*MIB)]
        blocked=set()
        for r in range(rounds):
            for j in range(len(targets)):
                label,url,expected=targets[(r+j)%len(targets)]
                if label in blocked:continue
                core.check_cancel(stop);emit(f'HTTPS {r+1}/{rounds}：{label}')
                try:row=https_probe(exe,url,expected,expected if expected else 256*1024,stop)
                except (OSError,subprocess.SubprocessError):
                    row=parse_curl('',-1,0,expected,0);row['error']='无法执行 curl'
                row.update(target=label,round=r+1,expected_bytes=expected)
                result['https_samples'].append(row)
                if row['http_status'] in (403,429):
                    blocked.add(label)
                    if label.startswith('Cloudflare'):blocked.update(('Cloudflare','Cloudflare 下载'))
                if stop.wait(.3):raise core.Cancelled()
        result['https_summary']=summarize_https(result['https_samples'],[x[0] for x in targets],rounds)
    result['received_body_bytes']=sum(r['bytes'] for r in result['https_samples'])
    return result


def baseline(perf,before,after):
    complete=all(isinstance(s.get(k),list) for s in (before,after) for k in ('interfaces','dns','routes')) and bool(before.get('interfaces')) and bool(after.get('interfaces'))
    stable=complete and validity.signature(before)==validity.signature(after)
    return dict(configuration_observed_stable=bool(stable),environment='proxy_or_tun_suspected' if validity.indicators(before) or validity.indicators(after) else 'no_known_proxy_indicators' if complete else 'environment_unverified',scope=perf['scope'],comparison_ready=False,note='本次基线仅记录；后续须在相同目标、协议、代理节点、测试规模和可比时段进行独立实验。快照一致不证明中间路径不变。')


def write_csvs(root,perf):
    for key in ('https_samples','https_summary','tcp','icmp'):
        rows=perf.get(key,[])
        with (root/('performance_'+key+'.csv')).open('w',encoding='utf-8-sig',newline='') as f:
            if not rows:f.write('status\nno_data\n');continue
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def report_html(perf,base):
    esc=lambda v:html.escape(str(v if v is not None else '—'))
    def table(rows,cols):
        return '<table><tr>'+''.join('<th>'+esc(label)+'</th>' for _,label in cols)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(r.get(key))+'</td>' for key,_ in cols)+'</tr>' for r in rows)+'</table>' if rows else '<p>无数据或未启用。</p>'
    return '<h2>实际传输性能（当前路径）</h2><p>'+esc(perf.get('scope'))+'</p><p>'+esc(base.get('note'))+'</p><p>配置快照一致：'+esc(base.get('configuration_observed_stable'))+'；环境：'+esc(base.get('environment'))+'</p><p>curl 使用当前环境代理规则；TCP 可能连接代理，TLS 阶段可能含代理 CONNECT；解析时间不等于公网 DNS 耗时。不会强制直连。</p><h3>HTTPS（Mbps 为十进制，含建连的有效速度）</h3>'+table(perf.get('https_summary',[]),[('target','目标'),('success','成功'),('planned','计划'),('dns_median_ms','解析 ms'),('tcp_median_ms','TCP ms'),('tls_median_ms','TLS ms'),('ttfb_median_ms','TTFB ms'),('ttfb_p95_ms','P95 ms'),('ttfb_jitter_ms','抖动 ms'),('effective_mbps_median','有效 Mbps'),('body_mbps_median','正文 Mbps')])+'<h3>TCP 443</h3>'+table(perf.get('tcp',[]),[('ip','目标'),('success','成功'),('attempted','尝试'),('median_ms','中位 ms'),('p95_ms','P95 ms'),('jitter_ms','抖动 ms')])+'<h3>ICMP（无应答率，不等同全链路丢包率）</h3>'+table(perf.get('icmp',[]),[('ip','目标'),('status','状态'),('success','成功'),('attempted','尝试'),('loss_percent','无应答 %'),('median_ms','中位 ms'),('jitter_ms','抖动 ms')])+'<p>正文接收字节：'+esc(perf.get('received_body_bytes'))+'；'+esc('；'.join(perf.get('warnings',[])))+'</p>'
