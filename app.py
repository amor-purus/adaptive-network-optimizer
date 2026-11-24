"""Windows 11 desktop app. No administrator rights required."""
import datetime
import ipaddress
import os
from pathlib import Path
import queue
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import uuid
import core
import validity
import performance

class App:
    def __init__(self, root):
        self.root=root; self.stop=threading.Event(); self.queue=queue.Queue(); self.busy=False; self.report=None
        root.title('自适应网络优化工具 0.2.1'); root.geometry('950x800'); root.minsize(760,660)
        f=ttk.Frame(root,padding=20); f.pack(fill='both',expand=True)
        ttk.Label(f,text='自适应网络优化工具',font=('Microsoft YaHei UI',20)).pack(anchor='w')
        ttk.Label(f,text='无侵入式网络实验 · 先测量，再推荐 · 不修改任何系统配置').pack(anchor='w',pady=(4,14))
        ttk.Label(f,text='公开测试域名（逗号分隔，不要填写内部或私人域名）').pack(anchor='w')
        self.domains=ttk.Entry(f); self.domains.insert(0,','.join(core.DOMAINS)); self.domains.pack(fill='x')
        opts=ttk.Frame(f); opts.pack(fill='x',pady=10)
        self.rounds=tk.StringVar(value='3'); self.mtu=tk.BooleanVar(value=True); self.target=tk.StringVar(value='1.1.1.1')
        ttk.Label(opts,text='重复轮数').grid(row=0,column=0,sticky='w')
        ttk.Combobox(opts,textvariable=self.rounds,values=('3','5'),state='readonly',width=7).grid(row=1,column=0,sticky='w',padx=(0,10))
        ttk.Label(opts,text='MTU IPv4 测试目标').grid(row=0,column=1,sticky='w')
        ttk.Entry(opts,textvariable=self.target,width=20).grid(row=1,column=1,sticky='w')
        ttk.Checkbutton(opts,text='探测 MTU',variable=self.mtu).grid(row=1,column=2,padx=12)
        self.https=tk.BooleanVar(value=True); self.icmp=tk.BooleanVar(value=True); self.sample=tk.StringVar(value='1')
        perf=ttk.LabelFrame(f,text='实际网络性能（当前路径）',padding=8); perf.pack(fill='x',pady=(0,8))
        ttk.Checkbutton(perf,text='HTTPS 延迟与下载测速',variable=self.https).grid(row=0,column=0,sticky='w')
        ttk.Checkbutton(perf,text='ICMP 多目标测试',variable=self.icmp).grid(row=0,column=1,padx=10,sticky='w')
        ttk.Label(perf,text='单轮下载上限 MiB').grid(row=0,column=2,sticky='w')
        ttk.Combobox(perf,textvariable=self.sample,values=('1','2','4'),state='readonly',width=6).grid(row=0,column=3,padx=5)
        self.selected={}
        servers=ttk.LabelFrame(f,text='公开 DNS 候选（当前网卡的 IPv4 DNS 自动加入）',padding=8); servers.pack(fill='x',pady=(0,12))
        for i,(label,ip) in enumerate(core.PRESETS.items()):
            v=tk.BooleanVar(value=True); self.selected[ip]=v
            ttk.Checkbutton(servers,text=f'{label} {ip}',variable=v).grid(row=i//3,column=i%3,sticky='w',padx=3)
        actions=ttk.Frame(f); actions.pack(fill='x')
        self.go=ttk.Button(actions,text='开始分析与优化推荐',command=self.begin); self.go.pack(side='left')
        self.cancel=ttk.Button(actions,text='取消',state='disabled',command=self.stop.set); self.cancel.pack(side='left',padx=8)
        self.open=ttk.Button(actions,text='打开 HTML 报告',state='disabled',command=self.open_report); self.open.pack(side='left')
        self.status=tk.StringVar(value='就绪'); ttk.Label(f,textvariable=self.status,wraplength=780).pack(anchor='w',pady=12)
        self.table=ttk.Treeview(f,columns=('name','server','success','median','p95','current'),show='headings',height=8)
        for k,t,w in [('name','DNS 服务',140),('server','服务器',115),('success','成功/计划',90),('median','中位 ms',85),('p95','P95 ms',85),('current','当前配置',90)]:
            self.table.heading(k,text=t); self.table.column(k,width=w,anchor='center')
        self.table.pack(fill='both',expand=True)
        self.logbox=tk.Text(f,height=8,wrap='word',state='disabled'); self.logbox.pack(fill='x',pady=(12,0))
        root.after(100,self.poll); root.protocol('WM_DELETE_WINDOW',self.close)
    def log(self,s):
        self.logbox.config(state='normal'); self.logbox.insert('end',s+'\n'); self.logbox.see('end'); self.logbox.config(state='disabled')
    def begin(self):
        if self.busy:return
        try:
            domains=list(dict.fromkeys(core.domain_name(s) for s in self.domains.get().split(',') if s.strip()))
            if not 1<=len(domains)<=8:raise ValueError('请选择 1～8 个公开域名。')
            rounds=int(self.rounds.get()); mtu=self.mtu.get(); target=str(ipaddress.IPv4Address(self.target.get())) if mtu else None
            if mtu and not ipaddress.ip_address(target).is_global:raise ValueError('MTU 目标须为公开 IPv4 地址。')
        except (ValueError,UnicodeError) as e:messagebox.showerror('输入错误',str(e));return
        https=self.https.get(); icmp=self.icmp.get(); sample=int(self.sample.get())
        servers={ip:label for label,ip in core.PRESETS.items() if self.selected[ip].get()}
        if not messagebox.askyesno('确认测量',f'将查询所选 DNS，测试多个公网目标的连接。HTTPS 下载样本计划上限 {sample*(rounds+2)+0.125 if https else 0} MiB（含预探测和最多两次补测），另有小请求、协议及错误开销（非硬流量上限）。服务商可能记录请求；不会修改系统设置。继续？'):return
        self.stop.clear(); self.busy=True; self.go.config(state='disabled'); self.cancel.config(state='normal'); self.open.config(state='disabled'); self.report=None
        for item in self.table.get_children():self.table.delete(item)
        def task():
            warnings=[]; snap={}; current={}
            def emit(s):self.queue.put(('progress',s))
            try:
                emit('读取网卡、路由及 DNS 配置…')
                try:snap=core.snapshot(); current=core.current_servers(snap)
                except (core.ProbeError,OSError,ValueError) as e:warnings.append('读取系统配置失败，当前 DNS 未纳入比较。')
                for ip,names in current.items():servers[ip]=servers.get(ip,'当前 DNS')
                if not servers:raise core.ProbeError('没有候选 DNS。')
                if len(servers)>20:raise core.ProbeError('候选超过 20 个，停止以限制请求。')
                rows=core.dns_benchmark(servers,domains,rounds,self.stop,emit)
                emit('验证实验有效性并重新读取网络配置…')
                after={}
                try:after=core.snapshot()
                except (core.ProbeError,OSError,ValueError):warnings.append('无法取得实验后网络快照。')
                gate=validity.assess(rows,snap,after,current)
                summary,choice,note=core.summarize_dns(rows,servers,domains,rounds,current,gate)
                warnings.extend(gate['messages'])
                warnings.append('VPN/代理、DoH、IPv6 DNS、分流及 CDN 可能使真实体验不同；不应仅凭 DNS 延迟变更系统。')
                emit('采集实际网络传输性能…')
                perf=performance.collect(self.stop,emit,rounds,sample,icmp,https)
                tcp=perf['tcp']
                mt=None
                if mtu:
                    try:mt=core.mtu_probe(target,self.stop,emit)
                    except (OSError,subprocess.SubprocessError,core.ProbeError):warnings.append('MTU 探测无法运行；DNS 和 TCP 结果仍保留。')
                core.check_cancel(self.stop)
                final_snap={}
                try:final_snap=core.snapshot()
                except (core.ProbeError,OSError,ValueError):warnings.append('无法取得性能实验后网络快照。')
                base=performance.baseline(perf,after,final_snap)
                warnings.extend(perf['warnings'])
                data={'performance':perf,'performance_baseline':base,'snapshot_after_performance':final_snap,'created':datetime.datetime.now().astimezone().isoformat(),'domains':domains,'rounds':rounds,'version':'0.2.1','snapshot':snap,'snapshot_after_dns':after,'validity':gate,'current_dns':current,'dns_samples':rows,'dns_summary':summary,'recommendation':choice,'note':note,'tcp':tcp,'mtu':mt,'warnings':warnings}
                directory=Path.home()/'Downloads'/'AdaptiveNetworkOptimizer'/(datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8])
                report=core.save_report(directory,data); self.queue.put(('result',(data,report)))
            except core.Cancelled:self.queue.put(('error','已取消；未完成的实验不生成推荐。'))
            except Exception as e:self.queue.put(('error',str(e) if isinstance(e,core.ProbeError) else '测量失败：'+type(e).__name__))
            finally:self.queue.put(('done',None))
        threading.Thread(target=task,daemon=True).start()
    def open_report(self):
        if self.report:os.startfile(str(self.report/'report.html'))
    def poll(self):
        try:
            while True:
                kind,data=self.queue.get_nowait()
                if kind=='progress':self.status.set(data)
                elif kind=='error':self.status.set(data);self.log(data)
                elif kind=='result':
                    result,self.report=data
                    for r in result['dns_summary']:
                        self.table.insert('','end',values=(r['name'],r['server'],f"{r['success']}/{r['planned']}",r['median_ms'] if r['median_ms'] is not None else '—',r['p95_ms'] if r['p95_ms'] is not None else '—','是' if r['current'] else '否'))
                    choice=result['recommendation']; msg='推荐 DNS 候选：'+choice['server'] if choice else '无可靠 DNS 推荐'
                    self.status.set(msg); self.log(msg); self.log(result['note'])
                    self.log('实验环境：'+result['validity']['environment']+'；'+result['validity']['scope'])
                    for h in result['performance']['https_summary']:
                        self.log(f"HTTPS {h['target']}：{h['success']}/{h['planned']}，TTFB {h['ttfb_median_ms']} ms，有效速度 {h['effective_mbps_median']} Mbps")
                    self.log('下载质量：'+str(result['performance'].get('download_experiment',{}).get('quality',{})))
                    for i in result['performance']['icmp']:
                        self.log(f"ICMP {i['ip']}：无应答 {i['loss_percent']}%，抖动 {i['jitter_ms']} ms")
                    for t in result['tcp']:self.log(f"TCP {t['ip']}：{t['success']}/{t['attempted']}，中位 {t['median_ms']} ms")
                    if result['mtu']:self.log('MTU 估计：'+str(result['mtu']['observed_mtu'])+'；'+result['mtu']['note'])
                    for w in result['warnings']:self.log(w)
                    self.log('报告：'+str(self.report)); self.open.config(state='normal')
                elif kind=='done':self.busy=False; self.go.config(state='normal'); self.cancel.config(state='disabled')
        except queue.Empty:pass
        self.root.after(100,self.poll)
    def close(self):
        if self.busy:self.stop.set();messagebox.showinfo('取消','请等待当前有超时限制的探测返回，再关闭窗口。')
        else:self.root.destroy()

if __name__=='__main__':
    root=tk.Tk(); App(root); root.mainloop()
