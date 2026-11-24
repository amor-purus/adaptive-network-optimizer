"""Read-only sampled network environment observation (Windows); no configuration writes."""
import csv
import datetime
import html
import ipaddress
import json
import os
import re
import subprocess
import threading
import time
import core
import validity

INTERVAL=45
MAX_PERIODIC=120
SECTIONS=('interfaces','dns','routes')
KEYS={'interfaces':('InterfaceIndex','AddressFamily'),'dns':('InterfaceIndex','AddressFamily'),'routes':('InterfaceIndex','DestinationPrefix','NextHop')}
LABELS={'name':'(?:Name|名称|名前)','signal_percent':'(?:Signal|信号|信号强度|信號|シグナル|信号の品質)','rx_mbps':'(?:Receive rate \(Mbps\)|接收速率\s*\(Mbps\)|接收速率\s*[(（]Mbps[)）]|受信速度\s*[(（]Mbps[)）]|受信レート\s*[(（]Mbps[)）])','tx_mbps':'(?:Transmit rate \(Mbps\)|传输速率\s*[(（]Mbps[)）]|发送速率\s*[(（]Mbps[)）]|傳輸速率\s*[(（]Mbps[)）]|送信速度\s*[(（]Mbps[)）]|送信レート\s*[(（]Mbps[)）])'}


def parse_wlan(text):
    # Whitelist only adapter name, signal and numeric link rates. Never export SSID/BSSID/MAC/profile.
    result=[]; row=None
    for line in text.splitlines():
        for field,label in LABELS.items():
            m=re.match(r'^\s*'+label+r'\s*[:：]\s*(.*?)\s*$',line,re.I)
            if not m:continue
            if field=='name':
                if row and any(k in row for k in ('signal_percent','rx_mbps','tx_mbps')):result.append(row)
                row={'name':m.group(1)}
            elif row is not None:
                n=re.fullmatch(r'(\d+(?:[.,]\d+)?)\s*%?',m.group(1))
                if n:
                    v=float(n.group(1).replace(',','.'))
                    if v>=0 and (field!='signal_percent' or v<=100):row[field]=v
            break
    if row and any(k in row for k in ('signal_percent','rx_mbps','tx_mbps')):result.append(row)
    return result


def wlan_snapshot():
    if os.name!='nt':return {'status':'Unavailable','reason':'WINDOWS_REQUIRED','interfaces':[]}
    try:
        p=subprocess.run(['netsh.exe','wlan','show','interfaces'],capture_output=True,timeout=5,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        raw=p.stdout.decode('oem',errors='replace')
        rows=parse_wlan(raw)
        return {'status':'Measured' if p.returncode==0 and rows else 'Unavailable','reason':None if p.returncode==0 and rows else 'NO_PARSEABLE_WLAN_METRICS','exit_code':p.returncode,'interfaces':rows if p.returncode==0 else []}
    except (OSError,subprocess.SubprocessError,LookupError):
        return {'status':'Unavailable','reason':'WLAN_QUERY_FAILED','interfaces':[]}


def complete(snap):
    return bool(snap.get('interfaces')) and all(isinstance(snap.get(k),list) for k in SECTIONS)


def diff(before,after):
    if not complete(before) or not complete(after):return []
    changes=[]
    for section in SECTIONS:
        keys=KEYS[section]
        def index(s):
            # Group duplicate identities instead of silently dropping route entries.
            out={}
            for r in s[section]:
                k=tuple(r.get(x) for x in keys)
                out.setdefault(k,[]).append(r)
            return out
        a,b=index(before),index(after)
        for key in sorted(set(a)|set(b),key=str):
            old,new=a.get(key,[]),b.get(key,[])
            if len(old)!=1 or len(new)!=1:
                if sorted(map(lambda x:json.dumps(x,sort_keys=True),old))!=sorted(map(lambda x:json.dumps(x,sort_keys=True),new)):
                    changes.append(dict(section=section,identity=list(key),field='record',before=old,after=new,kind='configuration_change',actor='unknown'))
                continue
            x,y=old[0],new[0]
            for field in sorted(set(x)|set(y)):
                if field in x and field in y and x[field]==y[field]:continue
                kind='configuration_change'
                if section=='interfaces' and field=='InterfaceMetric':
                    enabled=lambda v: v==1 or str(v).lower()=='enabled'
                    kind='automatic_metric_possible' if enabled(x.get('AutomaticMetric')) and enabled(y.get('AutomaticMetric')) else 'metric_change_unknown_cause'
                changes.append(dict(section=section,identity=list(key),field=field,before=x.get(field),after=y.get(field),before_present=field in x,after_present=field in y,kind=kind,actor='unknown'))
    return changes


class Monitor:
    """One periodic reader, serialized with checkpoints; no overlapping snapshot reads."""
    def __init__(self,interval=INTERVAL,limit=MAX_PERIODIC,reader=core.snapshot,wlan=wlan_snapshot):
        self.interval=interval;self.limit=limit;self.reader=reader;self.wlan=wlan
        self.lock=threading.Lock();self.stop=threading.Event();self.records=[];self.phase='dns';self.periodic=0;self.t0=time.monotonic();self.thread=None
    def _capture(self,label):
        t=time.monotonic(); stamp=datetime.datetime.now().astimezone().isoformat()
        try:s=self.reader();s=s if isinstance(s,dict) else {}
        except (core.ProbeError,OSError,ValueError,TypeError):s={}
        try:w=self.wlan()
        except (OSError,ValueError,TypeError):w={'status':'Unavailable','reason':'WLAN_QUERY_FAILED','interfaces':[]}
        self.records.append(dict(label=label,phase=self.phase,observed_at=stamp,elapsed_s=round(t-self.t0,3),capture_seconds=round(time.monotonic()-t,3),snapshot=s,wlan=w))
        return s
    def checkpoint(self,label,next_phase=None):
        with self.lock:
            s=self._capture(label)
            if next_phase:self.phase=next_phase
            return s
    def start(self):
        def loop():
            while not self.stop.wait(self.interval):
                with self.lock:
                    if self.stop.is_set() or self.phase=='done' or self.periodic>=self.limit:return
                    self._capture('periodic');self.periodic+=1
        self.thread=threading.Thread(target=loop,daemon=True);self.thread.start()
    def close(self):
        self.stop.set()
        if self.thread:self.thread.join()
    def evidence(self,phase):
        with self.lock:
            records=list(self.records)
        return phase_evidence(records,phase)


def telemetry_available(record):
    snap=record.get('snapshot') or {}
    if snap.get('adapter_status')!='Measured' or not isinstance(snap.get('adapters'),list):return False
    active_wifi=[a for a in snap['adapters'] if a.get('Status')=='Up' and re.search(r'wlan|wi-?fi|wireless',str(a.get('Name','')),re.I)]
    if active_wifi and record.get('wlan',{}).get('status')!='Measured':return False
    return True


def telemetry_diff(before,after):
    changes=[]
    for section,key_fields,fields in (
        ('adapters',('ifIndex','Name'),('Status','LinkSpeed','ReceiveLinkSpeed','TransmitLinkSpeed','MediaConnectionState')),
        ('wlan',('name',),('signal_percent','rx_mbps','tx_mbps'))):
        left=before.get('snapshot',{}).get(section,[]) if section=='adapters' else before.get('wlan',{}).get('interfaces',[])
        right=after.get('snapshot',{}).get(section,[]) if section=='adapters' else after.get('wlan',{}).get('interfaces',[])
        def keyed(rows):
            out={}
            for row in rows or []:out[tuple(row.get(k) for k in key_fields)]=row
            return out
        a,b=keyed(left),keyed(right)
        for key in sorted(set(a)|set(b),key=str):
            x,y=a.get(key,{}),b.get(key,{})
            for field in fields:
                if x.get(field)!=y.get(field):
                    changes.append(dict(section=section,identity=list(key),field=field,before=x.get(field),after=y.get(field)))
    return changes


def _rate_value(value,field):
    if value is None:return None
    try:
        if field in ('rx_mbps','tx_mbps'):
            number=float(value)
            return number*1_000_000 if number>=0 else None
        if field in ('ReceiveLinkSpeed','TransmitLinkSpeed'):
            number=float(value)
            return number if number>=0 else None
        text=str(value).strip().lower().replace(',','')
        match=re.fullmatch(r'(\\d+(?:\\.\\d+)?)\\s*(bps|kbps|mbps|gbps)',text)
        if not match:return None
        factor={'bps':1,'kbps':1_000,'mbps':1_000_000,'gbps':1_000_000_000}[match.group(2)]
        return float(match.group(1))*factor
    except (TypeError,ValueError,OverflowError):
        return None


def classify_telemetry_change(change):
    """Treat small radio/link-rate movement as noise; adapter state changes remain hard failures."""
    field=change.get('field')
    if field in ('Status','MediaConnectionState'):
        return dict(severity='significant',reason='ADAPTER_STATE_CHANGED')
    if field=='signal_percent':
        try:
            delta=abs(float(change.get('after'))-float(change.get('before')))
        except (TypeError,ValueError,OverflowError):
            return dict(severity='significant',reason='SIGNAL_TELEMETRY_INCOMPLETE')
        if delta<=5:
            return dict(severity='tolerated',reason='WITHIN_SIGNAL_TOLERANCE')
        return dict(severity='significant',reason='SIGNAL_CHANGE_EXCEEDS_5_POINTS',delta=round(delta,3))
    if field in ('LinkSpeed','ReceiveLinkSpeed','TransmitLinkSpeed','rx_mbps','tx_mbps'):
        before=_rate_value(change.get('before'),field)
        after=_rate_value(change.get('after'),field)
        if before is None or after is None or before<=0 or after<=0:
            return dict(severity='significant',reason='LINK_RATE_TELEMETRY_INCOMPLETE')
        delta=abs(after-before)/max(abs(before),abs(after))
        if delta<=.25:
            return dict(severity='tolerated',reason='WITHIN_LINK_RATE_TOLERANCE',relative_change=round(delta,4))
        return dict(severity='significant',reason='LINK_RATE_CHANGE_EXCEEDS_25_PERCENT',relative_change=round(delta,4))
    return dict(severity='significant',reason='UNCLASSIFIED_TELEMETRY_CHANGE')


def telemetry_stability(changes):
    classified=[dict(c,**classify_telemetry_change(c)) for c in changes]
    tolerated=[c for c in classified if c['severity']=='tolerated']
    significant=[c for c in classified if c['severity']!='tolerated']
    return dict(stable=not significant,tolerated_changes=tolerated,
                significant_changes=significant,classified_changes=classified,
                policy=dict(signal_tolerance_percentage_points=5,link_rate_relative_tolerance=.25,
                            adapter_status_and_media_state='no_change_allowed'))


def phase_evidence(records,phase):
    bounds={'dns':('start','after_dns'),'performance':('after_dns','after_performance'),
            'tuning':('after_performance','after_tuning')}
    if phase not in bounds:raise ValueError('未知实验阶段')
    start,end=bounds[phase]
    a=next((i for i,r in enumerate(records) if r['label']==start),None)
    b=next((i for i,r in enumerate(records) if r['label']==end),None)
    rs=records[a:b+1] if a is not None and b is not None and a<b else []
    changes=[];telemetry_changes=[]
    for x,y in zip(rs,rs[1:]):
        for c in diff(x['snapshot'],y['snapshot']):
            changes.append(dict(c,from_elapsed_s=x['elapsed_s'],to_elapsed_s=y['elapsed_s'],observed_at=y['observed_at']))
        for c in telemetry_diff(x,y):
            telemetry_changes.append(dict(c,from_elapsed_s=x['elapsed_s'],to_elapsed_s=y['elapsed_s'],observed_at=y['observed_at']))
    ok=bool(rs) and all(complete(r['snapshot']) for r in rs)
    telemetry_ok=bool(rs) and all(telemetry_available(r) for r in rs)
    assessment=telemetry_stability(telemetry_changes)
    return dict(phase=phase,samples=len(rs),complete=ok,observed_stable=bool(ok and not changes),changes=changes,
                telemetry_complete=telemetry_ok,
                telemetry_observed_stable=bool(telemetry_ok and assessment['stable']),
                telemetry_changes=assessment['classified_changes'],
                telemetry_tolerated_changes=assessment['tolerated_changes'],
                telemetry_significant_changes=assessment['significant_changes'],
                telemetry_tolerance_policy=assessment['policy'],
                scope='配置变化仍严格拦截；无线信号变化不超过 5 个百分点、链路速率变化不超过 25% 时按遥测噪声容差处理。适配器连接状态变化仍严格拦截。仅为离散采样观察，不能证明采样间隙持续不变。')


def apply_dns_gate(gate,evidence):
    if evidence['observed_stable']:return gate
    gate=dict(gate,reason_codes=list(gate['reason_codes']),messages=list(gate['messages']),recommendation_allowed=False)
    code='NETWORK_CONFIGURATION_CHANGED' if evidence['changes'] else 'TIMELINE_INCOMPLETE'
    if code not in gate['reason_codes']:
        gate['reason_codes'].append(code);gate['messages'].append('DNS 时间线发现配置变化或采样不完整，禁止推荐。')
    return gate


def apply_baseline(base,evidence):
    base=dict(base)
    base['configuration_observed_stable']=bool(base['configuration_observed_stable'] and evidence['observed_stable'])
    base['download_quality_usable']=bool(base.get('download_quality_usable') and base['configuration_observed_stable'])
    base['comparison_ready']=False
    return base


def ipv6_diagnosis(tcp,icmp,system):
    v6=[r for r in tcp if ipaddress.ip_address(r['ip']).version==6]
    errors=[e for r in v6 for e in r.get('errors',[]) if isinstance(e,dict)]
    denied=sum(e.get('winerror')==10013 for e in errors)
    attempts=sum(r['attempted'] for r in v6)
    return dict(tcp_attempts=attempts,tcp_success=sum(r['success'] for r in v6),wsaeacces_count=denied,
                classification='LOCAL_ACCESS_DENIAL_INDICATED' if denied else 'UNDETERMINED',
                icmp_unavailable_targets=[r['ip'] for r in icmp if ipaddress.ip_address(r['ip']).version==6 and r['status']=='Unavailable'],
                system=system,note='10013 表示套接字访问被拒绝；防火墙、WFP、第三方过滤器或其他本地约束均可能相关，不能凭此确定责任组件。防火墙配置和绑定状态仅为只读旁证。')


def system_evidence():
    # Independent try/catch; no rule changes, no event-log or packet capture.
    script=r'''$o=@{}; try{$o.firewall=@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction);$o.firewall_status='Measured'}catch{$o.firewall=@();$o.firewall_status='Unavailable'}; try{$o.ipv6_bindings=@(Get-NetAdapterBinding -ComponentID ms_tcpip6 | Select-Object Name,Enabled,ComponentID);$o.bindings_status='Measured'}catch{$o.ipv6_bindings=@();$o.bindings_status='Unavailable'}; try{$o.ipv6_address_counts=@(Get-NetIPAddress -AddressFamily IPv6 | Group-Object InterfaceIndex,AddressState | Select-Object Name,Count);$o.address_status='Measured'}catch{$o.ipv6_address_counts=@();$o.address_status='Unavailable'}; $o|ConvertTo-Json -Depth 5 -Compress'''
    try:
        out=core.run_powershell(script)
        return out if isinstance(out,dict) else {'status':'Unavailable'}
    except (core.ProbeError,OSError,ValueError,TypeError):return {'status':'Unavailable'}


def write_csvs(root,env):
    def write(name,rows,fields):
        with (root/name).open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
    changes=[dict(c,phase=p['phase']) for p in env['phases'] for c in p['changes']]
    fields=['phase','section','identity','field','before','after','kind','actor','from_elapsed_s','to_elapsed_s','observed_at','before_present','after_present']
    write('environment_changes.csv',changes,fields)
    telemetry=[dict(c,phase=p['phase']) for p in env['phases'] for c in p.get('telemetry_changes',[])]
    write('network_telemetry_changes.csv',telemetry,['phase','section','identity','field','before','after','severity','reason','delta','relative_change','from_elapsed_s','to_elapsed_s','observed_at'])
    rows=[]
    for r in env['timeline']:
        for a in r['snapshot'].get('adapters',[]):
            rows.append(dict(elapsed_s=r['elapsed_s'],label=r['label'],name=a.get('Name'),link_speed=a.get('LinkSpeed'),rx_bps=a.get('ReceiveLinkSpeed'),tx_bps=a.get('TransmitLinkSpeed')))
    write('adapter_link_timeline.csv',rows,['elapsed_s','label','name','link_speed','rx_bps','tx_bps'])
    rows=[]
    for r in env['timeline']:
        for a in r['wlan'].get('interfaces',[]):
            rows.append(dict(elapsed_s=r['elapsed_s'],label=r['label'],name=a.get('name'),signal_percent=a.get('signal_percent'),rx_mbps=a.get('rx_mbps'),tx_mbps=a.get('tx_mbps')))
    write('wlan_timeline.csv',rows,['elapsed_s','label','name','signal_percent','rx_mbps','tx_mbps'])


def report_html(env):
    esc=lambda x:html.escape(str(x))
    changes=[dict(c,phase=p['phase']) for p in env['phases'] for c in p['changes']]
    telemetry=[dict(c,phase=p['phase']) for p in env['phases'] for c in p.get('telemetry_changes',[])]
    table='<table><tr><th>阶段</th><th>秒</th><th>对象</th><th>字段</th><th>之前</th><th>之后</th><th>判断</th></tr>'+''.join('<tr>'+''.join('<td>'+esc(c.get(k))+'</td>' for k in ('phase','to_elapsed_s','identity','field','before','after','kind'))+'</tr>' for c in changes)+'</table>'
    telemetry_table='<table><tr><th>阶段</th><th>秒</th><th>对象</th><th>字段</th><th>之前</th><th>之后</th></tr>'+''.join('<tr>'+''.join('<td>'+esc(c.get(k))+'</td>' for k in ('phase','to_elapsed_s','identity','field','before','after'))+'</tr>' for c in telemetry)+'</table>'
    tolerated=sum(1 for p in env['phases'] for c in p.get('telemetry_tolerated_changes',[]))
    significant=sum(1 for p in env['phases'] for c in p.get('telemetry_significant_changes',[]))
    return '<h2>网络环境动态感知</h2><p>配置采样间隔：'+esc(INTERVAL)+' 秒；定期采样及阶段快照不会确认修改者，也不会证明采样间隙无变化。</p><p>采样数：'+esc(len(env['timeline']))+'；无线可测次数：'+esc(sum(r['wlan']['status']=='Measured' for r in env['timeline']))+'</p>'+table+'<h3>链路/无线遥测变化</h3><p>容差内变化：'+esc(tolerated)+'；超出容差或无法判定：'+esc(significant)+'。信号强度容差 ±5 个百分点；链路速率相对变化容差 25%；适配器连接状态变化不容差。</p>'+telemetry_table+'<h3>链路与无线时间线（不含 SSID/BSSID）</h3><pre>'+esc(json.dumps([dict(elapsed_s=r['elapsed_s'],label=r['label'],adapters=r['snapshot'].get('adapters',[]),wlan=r['wlan']) for r in env['timeline']],ensure_ascii=False,indent=2))+'</pre><h3>IPv6 与本地过滤旁证</h3><pre>'+esc(json.dumps(env['ipv6_diagnosis'],ensure_ascii=False,indent=2))+'</pre>'
