"""Bounded adaptive HTTPS concurrency tuning with paired retest and conservative scoring."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import math
from pathlib import Path
import random
import secrets
import statistics
import time
import core
import performance

CONCURRENCY_LEVELS=(1,2,4,8)
ROUNDS=3
AGGREGATE_BYTES=512*1024
MIN_WORKER_BYTES=64*1024
BASE_WORKER_BYTES=128*1024
MAX_WORKER_BYTES=256*1024
TARGET_BODY_SECONDS=1.25
PHASE_SECONDS=600
MAX_BATCH_SECONDS=26
DEFAULT_CONNECT_TIMEOUT=5
MAX_CONNECT_TIMEOUT=10
DOWNLOAD_URL='https://speed.cloudflare.com/__down?bytes={size}'


def split_sizes(total_bytes,workers):
    if not isinstance(total_bytes,int) or not isinstance(workers,int) or workers<1:
        raise ValueError('样本大小和并发数必须为正整数。')
    base,remainder=divmod(total_bytes,workers)
    sizes=[base+(1 if i<remainder else 0) for i in range(workers)]
    if min(sizes)<MIN_WORKER_BYTES:
        raise ValueError('每个并发请求至少需要 64 KiB 样本。')
    return sizes


def _valid(row,expected):
    try:
        speed=float(row.get('effective_mbps'))
        elapsed=float(row.get('total_ms'))
        received=int(row.get('bytes'))
        return (row.get('status')=='OK' and received==expected and
                math.isfinite(speed) and speed>0 and math.isfinite(elapsed) and elapsed>0)
    except (TypeError,ValueError,OverflowError):
        return False


def _failed(size,error='PROBE_EXCEPTION'):
    return dict(status='Failed',bytes=0,expected_bytes=size,effective_mbps=None,
                total_ms=None,ttfb_ms=None,http_status=None,error_category=error,
                failure_phase=None)


def _body_rates(batch):
    rates=[]
    for row in batch.get('worker_rows',[]):
        if row.get('status')!='OK':
            continue
        try:
            size=int(row.get('bytes') or 0)
            total=float(row.get('total_ms'))
            ttfb=float(row.get('ttfb_ms') or 0)
            effective=float(row.get('effective_mbps'))
            window=(total-ttfb)/1000
            rate=size*8/window/1e6 if size>0 and window>=0.1 else effective
            if math.isfinite(rate) and rate>0:
                rates.append(rate)
        except (TypeError,ValueError,OverflowError):
            continue
    return rates


def choose_worker_bytes(concurrency,previous_batch=None,base_total_bytes=AGGREGATE_BYTES):
    """Target a measurable body window; clamp and limit each round's size change to 2x."""
    if concurrency not in CONCURRENCY_LEVELS:
        raise ValueError('并发数必须为 1、2、4 或 8。')
    base=max(BASE_WORKER_BYTES,math.ceil(base_total_bytes/concurrency))
    base=min(MAX_WORKER_BYTES,max(MIN_WORKER_BYTES,base))
    if not previous_batch:
        return base,dict(mode='initial',estimated_body_mbps=None,target_body_seconds=TARGET_BODY_SECONDS)
    rates=_body_rates(previous_batch)
    previous=int(previous_batch.get('sample_bytes_per_worker') or base)
    if not rates:
        return min(MAX_WORKER_BYTES,max(MIN_WORKER_BYTES,previous)),dict(
            mode='bounded_fallback',estimated_body_mbps=None,target_body_seconds=TARGET_BODY_SECONDS)
    estimated=statistics.median(rates)
    target=math.ceil(estimated*1e6*TARGET_BODY_SECONDS/8)
    raw=min(MAX_WORKER_BYTES,max(MIN_WORKER_BYTES,target))
    lower=max(MIN_WORKER_BYTES,previous//2)
    upper=min(MAX_WORKER_BYTES,previous*2)
    chosen=min(upper,max(lower,raw))
    return int(chosen),dict(mode='adaptive',estimated_body_mbps=round(estimated,3),
                            target_body_seconds=TARGET_BODY_SECONDS,unclamped_target_bytes=target)


def choose_connect_timeout(previous_batch=None):
    """Use recent successful DNS+TCP+TLS phase P95; keep a conservative 5–10 s bound."""
    values=[]
    if previous_batch:
        for row in previous_batch.get('worker_rows',[]):
            try:
                parts=[float(row.get(k)) for k in ('dns_ms','tcp_ms','tls_ms')]
                if all(math.isfinite(x) and x>=0 for x in parts):
                    values.append(sum(parts))
            except (TypeError,ValueError,OverflowError):
                continue
    if not values:
        return DEFAULT_CONNECT_TIMEOUT
    p95=core.percentile(values,.95)
    return max(DEFAULT_CONNECT_TIMEOUT,min(MAX_CONNECT_TIMEOUT,math.ceil(p95/1000*2+2)))


def run_batch(exe,concurrency,round_number,stop,probe=None,total_bytes=AGGREGATE_BYTES,
              clock=time.monotonic,connect_timeout=DEFAULT_CONNECT_TIMEOUT,retest=False,sample_plan=None):
    """Run one synchronized batch; aggregate rate uses batch wall-clock, not summed worker rates."""
    core.check_cancel(stop)
    default_probe=probe is None
    if default_probe:
        probe=performance.https_probe
    sizes=split_sizes(total_bytes,concurrency)
    started=clock()
    rows=[None]*concurrency
    with ThreadPoolExecutor(max_workers=concurrency,thread_name_prefix='ano-tune') as pool:
        if default_probe:
            futures={pool.submit(probe,exe,DOWNLOAD_URL.format(size=size),size,size,stop,
                                 connect_timeout=connect_timeout):(i,size)
                     for i,size in enumerate(sizes)}
        else:
            futures={pool.submit(probe,exe,DOWNLOAD_URL.format(size=size),size,size,stop):(i,size)
                     for i,size in enumerate(sizes)}
        for future in as_completed(futures):
            index,size=futures[future]
            try:
                row=future.result()
                if not isinstance(row,dict):row=_failed(size,'INVALID_PROBE_RESULT')
            except core.Cancelled:
                raise
            except Exception as exc:
                row=_failed(size,type(exc).__name__.upper())
            row=dict(row)
            row['worker']=index+1
            row['expected_bytes']=size
            rows[index]=row
    elapsed=max(clock()-started,0.001)
    valid=[r for r,size in zip(rows,sizes) if r is not None and _valid(r,size)]
    complete=len(valid)==concurrency
    actual=sum(max(0,int(r.get('bytes') or 0)) for r in rows if r is not None)
    speed=round(actual*8/elapsed/1e6,3) if complete else None
    ttfb=[float(r['ttfb_ms']) for r in valid if isinstance(r.get('ttfb_ms'),(int,float)) and math.isfinite(float(r['ttfb_ms']))]
    categories=sorted({str(r.get('error_category') or r.get('error') or 'INCOMPLETE')
                       for r in rows if r is not None and not _valid(r,r.get('expected_bytes'))})
    blocked=any(r and r.get('http_status') in (403,429) for r in rows)
    return dict(concurrency=concurrency,round=round_number,status='OK' if complete else 'Failed',
                expected_bytes=total_bytes,actual_bytes=actual,elapsed_s=round(elapsed,4),
                aggregate_mbps=speed,success=len(valid),planned=concurrency,
                sample_bytes_per_worker=min(sizes),connect_timeout_seconds=connect_timeout,
                retest=bool(retest),sample_plan=sample_plan or {},
                ttfb_median_ms=round(statistics.median(ttfb),3) if ttfb else None,
                error_categories=categories,http_blocked=blocked,worker_rows=rows)


def summarize_batches(batches,candidates=CONCURRENCY_LEVELS,rounds=ROUNDS):
    baseline_by_round={b.get('round'):b for b in batches
                       if b.get('concurrency')==1 and b.get('status')=='OK' and
                       isinstance(b.get('aggregate_mbps'),(int,float)) and b.get('aggregate_mbps',0)>0}
    result=[]
    for concurrency in candidates:
        rows=[r for r in batches if r.get('concurrency')==concurrency]
        good=[r for r in rows if r.get('status')=='OK' and
              isinstance(r.get('aggregate_mbps'),(int,float)) and r['aggregate_mbps']>0]
        speeds=[float(r['aggregate_mbps']) for r in good]
        reasons=[]
        if len(rows)<rounds:reasons.append('INCOMPLETE_ROUNDS')
        if len(good)<rounds:reasons.append('FAILED_BATCH')
        variation=max(speeds)/min(speeds) if speeds and min(speeds)>0 else None
        if variation is not None and variation>2:
            reasons.append('HIGH_VARIATION')
        elif len(speeds)>1:
            mean=statistics.mean(speeds)
            cv=statistics.pstdev(speeds)/mean if mean>0 else 0
            if cv>.35:reasons.append('HIGH_VARIATION')
        ttfb=[float(w['ttfb_ms']) for b in good for w in b.get('worker_rows',[])
              if isinstance(w.get('ttfb_ms'),(int,float)) and math.isfinite(float(w['ttfb_ms']))]
        planned=sum(int(b.get('planned',concurrency) or concurrency) for b in rows)
        succeeded=sum(int(b.get('success',concurrency if b.get('status')=='OK' else 0) or 0) for b in rows)
        success_rate=succeeded/planned if planned else 0.0
        paired=[]
        if concurrency==1:
            paired=[1.0 for b in good if b.get('round') in baseline_by_round]
        else:
            for b in good:
                baseline=baseline_by_round.get(b.get('round'))
                if baseline and baseline.get('aggregate_mbps',0)>0:
                    paired.append(float(b['aggregate_mbps'])/float(baseline['aggregate_mbps']))
        if concurrency>1 and len(paired)<rounds:
            reasons.append('PAIRED_ROUNDS_INCOMPLETE')
        median_speedup=statistics.median(paired) if paired else None
        sample_sizes=[int(b['sample_bytes_per_worker']) for b in rows if isinstance(b.get('sample_bytes_per_worker'),int)]
        result.append(dict(concurrency=concurrency,planned_rounds=rounds,attempted_rounds=len(rows),
                           successful_rounds=len(good),median_mbps=round(statistics.median(speeds),3) if speeds else None,
                           p95_mbps=round(core.percentile(speeds,.95),3) if speeds else None,
                           min_mbps=round(min(speeds),3) if speeds else None,
                           max_mbps=round(max(speeds),3) if speeds else None,
                           variation_ratio=round(variation,3) if variation is not None else None,
                           ttfb_median_ms=round(statistics.median(ttfb),3) if ttfb else None,
                           success_requests=succeeded,planned_requests=planned,
                           success_rate=round(success_rate,4),paired_rounds=len(paired),
                           paired_median_speedup=round(median_speedup,4) if median_speedup is not None else None,
                           paired_median_speedup_pct=round((median_speedup-1)*100,2) if median_speedup is not None else None,
                           median_sample_bytes_per_worker=round(statistics.median(sample_sizes)) if sample_sizes else None,
                           eligible=not reasons,quality_reasons=reasons))
    return result


def select_retest_candidate(summary):
    """Choose at most one promising but not yet reliable challenger for a paired retest."""
    by={r['concurrency']:r for r in summary}
    baseline=by.get(1)
    challengers=[r for r in summary if r['concurrency']>1 and
                 r.get('median_mbps') is not None and r.get('successful_rounds',0)>0]
    if not challengers:
        return None
    if baseline and baseline.get('eligible') and all(r.get('eligible') for r in challengers):
        return None
    best=max(challengers,key=lambda r:(r.get('median_mbps') or 0,r.get('success_rate') or 0,-r['concurrency']))
    return best['concurrency']


def maximum_budget_bytes(rounds=ROUNDS,candidates=CONCURRENCY_LEVELS):
    candidates=tuple(candidates)
    main=rounds*sum(c*MAX_WORKER_BYTES for c in candidates)
    challengers=[c for c in candidates if c>1]
    paired=(1+max(challengers))*MAX_WORKER_BYTES if challengers else 0
    return main+paired


def _score_candidate(row,baseline):
    speedup=row.get('paired_median_speedup')
    if speedup is None and row.get('median_mbps') and baseline.get('median_mbps'):
        speedup=row['median_mbps']/baseline['median_mbps']
    speedup=float(speedup or 0)
    throughput_component=min(max(speedup,0),2.0)/2.0
    success_component=float(row.get('success_rate') or 0)
    base_ttfb=baseline.get('ttfb_median_ms')
    candidate_ttfb=row.get('ttfb_median_ms')
    if isinstance(base_ttfb,(int,float)) and isinstance(candidate_ttfb,(int,float)) and base_ttfb>0 and candidate_ttfb>0:
        latency_component=min(1.0,float(base_ttfb)/float(candidate_ttfb))
        latency_evidence='MEASURED'
    else:
        latency_component=.5
        latency_evidence='MISSING'
    score=100*(.65*throughput_component+.25*success_component+.10*latency_component)
    return round(score,2),dict(throughput=round(throughput_component,4),
                               success_rate=round(success_component,4),
                               latency=round(latency_component,4),
                               latency_evidence=latency_evidence,
                               paired_speedup=round(speedup,4))


def decide(summary,candidates=CONCURRENCY_LEVELS,complete=True,blocked=False,required_rounds=ROUNDS):
    by={r['concurrency']:r for r in summary}
    baseline=by.get(1)
    eligible=[r for r in summary if r.get('eligible') and r.get('median_mbps') is not None]
    other=[r for r in eligible if r['concurrency']>1 and r.get('paired_rounds',0)>=required_rounds
           and r.get('paired_median_speedup') is not None]
    ready=bool(complete and not blocked and baseline and baseline.get('eligible') and
               baseline.get('paired_rounds',0)>=required_rounds and other)
    if not ready:
        reason='HTTP_BLOCKED' if blocked else 'INCOMPLETE_EXPERIMENT' if not complete else 'NO_RELIABLE_COMPARISON'
        return dict(comparison_ready=False,selected_concurrency=None,decision=reason,
                    composite_score=None,score_weights={'throughput':.65,'success_rate':.25,'latency':.10},
                    decision_note='缺少完整、可靠的单并发基线或配对候选，不给出最优并发建议。')
    for row in eligible:
        score,components=_score_candidate(row,baseline)
        row['composite_score']=score
        row['score_components']=components
    challengers=[r for r in other if r['paired_median_speedup']>=1.10]
    if not challengers:
        return dict(comparison_ready=True,selected_concurrency=1,decision='NO_MATERIAL_GAIN',
                    composite_score=baseline.get('composite_score'),
                    score_weights={'throughput':.65,'success_rate':.25,'latency':.10},
                    decision_note='配对实验显示更高并发未带来至少 10% 的中位吞吐量改善，建议保持单并发。')
    best=max(challengers,key=lambda r:r['composite_score'])
    if best['composite_score']<=baseline.get('composite_score',0):
        return dict(comparison_ready=True,selected_concurrency=1,decision='NO_COMPOSITE_GAIN',
                    composite_score=baseline.get('composite_score'),
                    score_weights={'throughput':.65,'success_rate':.25,'latency':.10},
                    decision_note='吞吐量提升不足以抵消成功率或首字节延迟的损失，建议保持单并发。')
    threshold=best['composite_score']*.95
    options=[r for r in challengers if r['composite_score']>=threshold]
    chosen=min(options,key=lambda r:r['concurrency'])
    return dict(comparison_ready=True,selected_concurrency=chosen['concurrency'],
                decision='LOWEST_CONCURRENCY_NEAR_BEST_COMPOSITE_SCORE',
                composite_score=chosen['composite_score'],
                selected_speedup_pct=chosen.get('paired_median_speedup_pct'),
                score_weights={'throughput':.65,'success_rate':.25,'latency':.10},
                decision_note='按配对吞吐量、请求成功率和 TTFB 综合评分；选择达到最高综合得分 95% 以上的最低并发度。')


def run(stop,emit=lambda _:None,exe=None,probe=None,rounds=ROUNDS,candidates=CONCURRENCY_LEVELS,
        total_bytes=AGGREGATE_BYTES,phase_seconds=PHASE_SECONDS,seed=None,clock=time.monotonic):
    candidates=tuple(candidates)
    if not candidates or 1 not in candidates or any(c not in CONCURRENCY_LEVELS for c in candidates) or len(set(candidates))!=len(candidates):
        raise ValueError('并发候选必须从 1、2、4、8 中选择且包含 1。')
    if not isinstance(rounds,int) or not 1<=rounds<=5:raise ValueError('轮数必须为 1～5。')
    split_sizes(max(total_bytes,MIN_WORKER_BYTES*max(candidates)),max(candidates))
    core.check_cancel(stop)
    budget=maximum_budget_bytes(rounds,candidates)
    if exe is None:exe=performance.curl_path()
    if not exe:
        return dict(status='Unavailable',reason='CURL_UNAVAILABLE',candidates=list(candidates),batches=[],
                    summary=[],selected_concurrency=None,comparison_ready=False,recommendation_allowed=False,
                    decision='CURL_UNAVAILABLE',decision_note='未找到 curl，无法执行并发实验。',
                    requested_budget_bytes=budget,reserved_bytes=0,composite_score=None,
                    scope='当前实际 HTTPS 路径；可能经过系统代理或 TUN。')
    if seed is None:seed=secrets.randbits(32)
    rng=random.Random(seed);deadline=clock()+phase_seconds
    batches=[];orders=[];previous={};reserved=0
    blocked=False;time_exhausted=False;budget_exhausted=False

    def execute_batch(concurrency,round_number,retest=False):
        nonlocal reserved,blocked,time_exhausted,budget_exhausted
        core.check_cancel(stop)
        worker_bytes,sample_plan=choose_worker_bytes(concurrency,previous.get(concurrency),total_bytes)
        batch_bytes=worker_bytes*concurrency
        if clock()+MAX_BATCH_SECONDS>deadline:
            time_exhausted=True
            return None
        if reserved+batch_bytes>budget:
            budget_exhausted=True
            return None
        timeout=choose_connect_timeout(previous.get(concurrency))
        emit(('配对补测' if retest else '并发寻优')+'：第 %d 轮，%d 路并发，每线程 %d KiB，连接超时 %d 秒'%
             (round_number,concurrency,round(worker_bytes/1024),timeout))
        batch=run_batch(exe,concurrency,round_number,stop,probe,batch_bytes,clock,
                        connect_timeout=timeout,retest=retest,sample_plan=sample_plan)
        batch['sample_bytes_per_worker']=worker_bytes
        batch['sample_plan']=sample_plan
        batch['connect_timeout_seconds']=timeout
        batch['retest']=bool(retest)
        batches.append(batch)
        reserved+=batch_bytes
        if batch['status']=='OK':
            previous[concurrency]=batch
        if batch['http_blocked']:
            blocked=True
        return batch

    main_count=0
    for round_number in range(1,rounds+1):
        order=list(candidates);rng.shuffle(order);orders.append(order)
        for concurrency in order:
            batch=execute_batch(concurrency,round_number)
            if batch is None or blocked:
                break
            main_count+=1
        if blocked or main_count<len(candidates)*round_number:
            break
    completed=main_count==len(candidates)*rounds
    summary=summarize_batches(batches,candidates,rounds)
    retest_candidate=None;retest_status='NotNeeded';retest_order=[]
    if completed and not blocked:
        retest_candidate=select_retest_candidate(summary)
        if retest_candidate is not None:
            retest_order=[1,retest_candidate];rng.shuffle(retest_order);orders.append(retest_order)
            done=0;retest_status='Incomplete'
            for concurrency in retest_order:
                batch=execute_batch(concurrency,rounds+1,True)
                if batch is None:
                    break
                done+=1
                if blocked:
                    break
            if done==2 and not blocked:
                retest_status='Completed'
            elif time_exhausted:
                retest_status='Skipped_TimeBudget'
            elif budget_exhausted:
                retest_status='Skipped_Budget'
            elif blocked:
                retest_status='Blocked'
            summary=summarize_batches(batches,candidates,rounds)
    status='Blocked' if blocked else 'Completed' if completed else 'Incomplete'
    decision=decide(summary,candidates,completed,blocked,rounds)
    return dict(status=status,parameter='parallel_https_requests',candidates=list(candidates),rounds=rounds,
                aggregate_bytes_per_batch=total_bytes,requested_budget_bytes=budget,
                reserved_bytes=reserved,seed=seed,randomized_order=orders,batches=batches,summary=summary,
                time_budget_seconds=phase_seconds,time_budget_exhausted=time_exhausted,
                budget_exhausted=budget_exhausted,retest_candidate=retest_candidate,retest_status=retest_status,
                retest_order=retest_order,blocked=blocked,**decision,recommendation_allowed=False,
                environment_stable=False,
                sample_policy=dict(min_worker_bytes=MIN_WORKER_BYTES,base_worker_bytes=BASE_WORKER_BYTES,
                                   max_worker_bytes=MAX_WORKER_BYTES,target_body_seconds=TARGET_BODY_SECONDS,
                                   max_change_factor_per_round=2),
                timeout_policy=dict(default_connect_timeout_seconds=DEFAULT_CONNECT_TIMEOUT,
                                    max_connect_timeout_seconds=MAX_CONNECT_TIMEOUT,
                                    adaptive_source='previous successful DNS+TCP+TLS phase P95',
                                    max_transfer_timeout_seconds=20),
                scope='Cloudflare HTTPS 下载端点的当前实际路径；可能经过系统代理/TUN，不代表物理链路，也不等同 yt-dlp -N 的最优值。')


def apply_environment_gate(result,evidence):
    result=dict(result)
    result['environment_evidence']=evidence
    stable=bool(evidence.get('complete') and evidence.get('observed_stable') and
                evidence.get('telemetry_complete') and evidence.get('telemetry_observed_stable'))
    result['environment_stable']=stable
    result['recommendation_allowed']=bool(stable and result.get('comparison_ready'))
    if not stable:
        result['measurement_comparison_ready']=bool(result.get('comparison_ready'))
        result['comparison_ready']=False
        result['selected_concurrency']=None
        result['decision']='ENVIRONMENT_UNSTABLE_OR_UNVERIFIED'
        result['decision_note']='实验期间配置发生变化，或链路遥测超出容差/不完整；保留测量结果，但不推荐并发参数。'
    elif not result['recommendation_allowed']:
        result['selected_concurrency']=None
    return result


def write_csvs(root,result):
    import csv
    batches=result.get('batches',[])
    with (root/'tuning_batches.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['concurrency','round','retest','status','expected_bytes','actual_bytes','sample_bytes_per_worker',
                'elapsed_s','aggregate_mbps','success','planned','success_rate','ttfb_median_ms',
                'connect_timeout_seconds','error_categories','http_blocked']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for row in batches:w.writerow({k:row.get(k) for k in fields})
    workers=[dict(concurrency=b['concurrency'],round=b['round'],retest=b.get('retest',False),**w)
             for b in batches for w in b.get('worker_rows',[])]
    with (root/'tuning_workers.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['concurrency','round','retest','worker','status','expected_bytes','bytes','effective_mbps',
                'ttfb_ms','total_ms','http_status','error_category','failure_phase','error']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for row in workers:w.writerow({k:row.get(k) for k in fields})
    with (root/'tuning_summary.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['concurrency','planned_rounds','attempted_rounds','successful_rounds','median_mbps','p95_mbps',
                'min_mbps','max_mbps','variation_ratio','ttfb_median_ms','success_requests','planned_requests',
                'success_rate','paired_rounds','paired_median_speedup_pct','median_sample_bytes_per_worker',
                'composite_score','eligible','quality_reasons']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for row in result.get('summary',[]):w.writerow({k:row.get(k) for k in fields})


def report_html(result):
    esc=lambda x:html.escape(str(x if x is not None else '—'))
    cols=('concurrency','attempted_rounds','successful_rounds','median_mbps','p95_mbps','ttfb_median_ms',
          'success_rate','paired_rounds','paired_median_speedup_pct','composite_score','eligible','quality_reasons')
    labels=('并发数','尝试轮数','成功轮数','中位聚合 Mbps','P95 Mbps','TTFB 中位 ms',
            '请求成功率','配对轮数','配对速度提升 %','综合得分','合格','质量原因')
    summary=result.get('summary',[])
    table='<table><tr>'+''.join('<th>'+x+'</th>' for x in labels)+'</tr>'+''.join(
        '<tr>'+''.join('<td>'+esc(r.get(k))+'</td>' for k in cols)+'</tr>' for r in summary)+'</table>'
    batches=result.get('batches',[])
    batch_table='<table><tr><th>并发</th><th>轮次</th><th>类型</th><th>状态</th><th>每线程 KiB</th><th>连接超时 s</th><th>总耗时 s</th><th>聚合 Mbps</th><th>成功请求</th></tr>'+''.join(
        '<tr>'+''.join('<td>'+esc(v)+'</td>' for v in (b.get('concurrency'),b.get('round'),
        '配对补测' if b.get('retest') else '正式实验',b.get('status'),
        round((b.get('sample_bytes_per_worker') or 0)/1024),b.get('connect_timeout_seconds'),
        b.get('elapsed_s'),b.get('aggregate_mbps'),str(b.get('success'))+'/'+str(b.get('planned'))))+'</tr>'
        for b in batches)+'</table>'
    selected=result.get('selected_concurrency')
    return '<h2>自动并发参数寻优（应用层 HTTPS）</h2><p>状态：'+esc(result.get('status'))+'；建议并发：'+esc(selected)+'</p><p>'+esc(result.get('decision_note'))+'</p><p>最坏情况正文预算上限 '+esc(result.get('requested_budget_bytes'))+' 字节；实际预留 '+esc(result.get('reserved_bytes'))+' 字节。</p><p>样本策略：每线程 64–256 KiB，目标正文窗口 '+esc(TARGET_BODY_SECONDS)+' 秒；根据上一轮有效样本调整，每轮变化不超过 2 倍。最多对单并发基线和一个候选进行一次配对补测。连接超时依据上一轮 DNS+TCP+TLS 阶段 P95 自适应，范围 5–10 秒。</p><p>配对比较按同轮候选吞吐量比值计算；综合评分权重为吞吐量 65%、成功率 25%、TTFB 10%。环境稳定性：'+esc(result.get('environment_stable'))+'；配对补测：'+esc(result.get('retest_status'))+'</p>'+table+'<h3>逐轮实验</h3>'+batch_table+'<p>只测试当前 HTTPS 路径，可能经过代理/TUN。结果不是 Wi-Fi 链路速率，也不能直接视为 yt-dlp -N 的最佳值。不会修改系统设置。</p>'
