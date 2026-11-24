"""Controlled HTTPS concurrency experiments: calibrate once, compare adjacent equal-work pairs."""
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
PILOT_BYTES=128*1024
TARGET_SECONDS=8
MAX_TOTAL_BYTES=512*1024
MAX_TRANSFER_SECONDS=20
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
                                 connect_timeout=connect_timeout,max_time=MAX_TRANSFER_SECONDS):(i,size)
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



def _positive(x):
    return isinstance(x,(int,float)) and not isinstance(x,bool) and math.isfinite(x) and x>0


def calibrate(pilot,candidates,cap):
    """Use pilot only; freeze workload and timeout before any formal observations."""
    if not isinstance(cap,int) or not 128*1024<=cap<=MAX_TOTAL_BYTES:
        raise ValueError('总样本上限须为 128–512 KiB。')
    speed=pilot.get('aggregate_mbps') if pilot.get('status')=='OK' else None
    target=int(min(cap,speed*1e6*TARGET_SECONDS/8)) if _positive(speed) else PILOT_BYTES
    total=max(PILOT_BYTES,2**int(math.log2(max(PILOT_BYTES,target))))
    total=min(total,cap)
    timings=[]
    for w in pilot.get('worker_rows',[]):
        if w.get('status')!='OK':continue
        parts=[w.get(k) for k in ('dns_ms','tcp_ms','tls_ms')]
        if all(isinstance(x,(int,float)) and math.isfinite(x) and x>=0 for x in parts):
            timings.append(sum(parts))
    timeout=max(5,min(10,math.ceil(core.percentile(timings,.95)*.002+2))) if timings else 10
    active=[c for c in candidates if total>=c*MIN_WORKER_BYTES]
    return dict(total_bytes=total,connect_timeout_seconds=timeout,max_time_seconds=MAX_TRANSFER_SECONDS,
                candidates=active,excluded_candidates=[c for c in candidates if c not in active],
                pilot_speed_mbps=speed,target_seconds=TARGET_SECONDS,
                mode='pilot_calibrated' if _positive(speed) else 'conservative_fallback',
                frozen=True)


def maximum_budget_bytes(rounds=ROUNDS,candidates=CONCURRENCY_LEVELS,total_bytes=MAX_TOTAL_BYTES):
    challengers=sum(c>1 for c in candidates)
    return PILOT_BYTES+2*(rounds*challengers+int(challengers>0))*total_bytes


def _batch_protocol(b):
    versions={w.get('http_version') for w in b.get('worker_rows',[]) if w.get('status')=='OK'}
    return next(iter(versions)) if len(versions)==1 and None not in versions and '' not in versions else None


def evaluate_pair(baseline,challenger,plan):
    """Fail closed if either batch lacks evidence or differs from frozen conditions."""
    reasons=[]
    if baseline.get('concurrency')!=1 or challenger.get('concurrency') not in plan['candidates'] or challenger.get('concurrency')==1:
        reasons.append('PAIR_IDENTITY_INVALID')
    if (not baseline.get('pair_id') or baseline.get('pair_id')!=challenger.get('pair_id') or
        baseline.get('round')!=challenger.get('round') or baseline.get('baseline_for')!=challenger.get('concurrency') or
        challenger.get('baseline_for')!=challenger.get('concurrency') or
        not isinstance(baseline.get('sequence'),int) or not isinstance(challenger.get('sequence'),int) or
        abs(baseline['sequence']-challenger['sequence'])!=1):
        reasons.append('PAIR_IDENTITY_INVALID')
    for b in (baseline,challenger):
        if b.get('expected_bytes')!=plan['total_bytes'] or b.get('connect_timeout_seconds')!=plan['connect_timeout_seconds'] or b.get('max_time_seconds')!=plan['max_time_seconds']:
            reasons.append('CONTROL_VARIABLE_MISMATCH')
        if (b.get('status')!='OK' or b.get('actual_bytes')!=plan['total_bytes'] or
            b.get('success')!=b.get('concurrency') or b.get('planned')!=b.get('concurrency') or
            len(b.get('worker_rows',[]))!=b.get('concurrency') or not _positive(b.get('aggregate_mbps'))):
            reasons.append('INCOMPLETE_BATCH')
        else:
            sizes=split_sizes(plan['total_bytes'],b['concurrency'])
            if not all(_valid(w,size) for w,size in zip(b['worker_rows'],sizes)):
                reasons.append('INCOMPLETE_BATCH')
    if 'INCOMPLETE_BATCH' not in reasons and (not _batch_protocol(baseline) or _batch_protocol(baseline)!=_batch_protocol(challenger)):
        reasons.append('HTTP_PROTOCOL_MISMATCH_OR_MISSING')
    bt,ct=baseline.get('ttfb_median_ms'),challenger.get('ttfb_median_ms')
    if not _positive(bt) or not _positive(ct):reasons.append('TTFB_MISSING')
    reasons=sorted(set(reasons))
    return dict(pair_id=baseline.get('pair_id'),concurrency=challenger.get('concurrency'),
                round=challenger.get('round'),retest=challenger.get('retest',False),
                valid=not reasons,reasons=reasons,baseline_mbps=baseline.get('aggregate_mbps'),
                candidate_mbps=challenger.get('aggregate_mbps'),baseline_ttfb_ms=bt,candidate_ttfb_ms=ct,
                speedup=challenger['aggregate_mbps']/baseline['aggregate_mbps'] if not reasons else None,
                latency_ratio=bt/ct if not reasons else None,
                baseline_success=baseline.get('success',0),baseline_planned=baseline.get('planned',1),
                candidate_success=challenger.get('success',0),candidate_planned=challenger.get('planned',challenger.get('concurrency',0)),
                baseline_first=baseline.get('sequence',0)<challenger.get('sequence',0),
                http_version=_batch_protocol(baseline) if not reasons else None)


def summarize_pairs(pairs,candidates,rounds):
    result=[]
    for c in candidates:
        if c==1:continue
        rows=[p for p in pairs if p['concurrency']==c]
        good=[p for p in rows if p['valid']]
        ratios=[p['speedup'] for p in good]; rates=[p['candidate_mbps'] for p in good]
        base_rates=[p['baseline_mbps'] for p in good]
        n=len(rows); success=len(good); completion=success/n if n else 0
        planned=sum(p['candidate_planned'] for p in rows); succeeded=sum(p['candidate_success'] for p in rows)
        request_rate=succeeded/planned if planned else 0
        reasons=[]
        if len([p for p in rows if not p['retest']])!=rounds:reasons.append('INCOMPLETE_FORMAL_PAIRS')
        if len(set(p['pair_id'] for p in rows))!=n:reasons.append('DUPLICATE_PAIR')
        if success<rounds:reasons.append('INSUFFICIENT_VALID_PAIRS')
        if completion<.75 or request_rate<.75:reasons.append('LOW_COMPLETION_RATE')
        spread=max(ratios)/min(ratios) if ratios else None
        if ratios and (spread>2 or (len(ratios)>1 and statistics.pstdev(ratios)/statistics.mean(ratios)>.35)):
            reasons.append('HIGH_PAIRED_VARIATION')
        # Protocol/workload mismatches are not random failures and cannot be repaired by success counts.
        if any(any(x in p['reasons'] for x in ('CONTROL_VARIABLE_MISMATCH','PAIR_IDENTITY_INVALID','HTTP_PROTOCOL_MISMATCH_OR_MISSING')) for p in rows):
            reasons.append('COMPARABILITY_EVIDENCE_INVALID')
        ratio=statistics.median(ratios) if ratios else None
        latency=statistics.median([p['latency_ratio'] for p in good]) if good else None
        votes=sum(v>=1.10 for v in ratios)
        reliability=min(completion,request_rate)
        # Relative utility, baseline=1. Monotonic in speed, no artificial twofold cap.
        score=ratio**.65*reliability**.25*min(1,latency)**.10 if ratio and latency and reliability else None
        result.append(dict(concurrency=c,planned_rounds=rounds,attempted_rounds=n,successful_rounds=success,
                           paired_rounds=success,pair_completion_rate=completion,success_rate=request_rate,
                           success_requests=succeeded,planned_requests=planned,
                           median_mbps=statistics.median(rates) if rates else None,
                           paired_baseline_median_mbps=statistics.median(base_rates) if base_rates else None,
                           baseline_variation_ratio=max(base_rates)/min(base_rates) if base_rates else None,
                           paired_median_speedup=ratio,paired_median_speedup_pct=(ratio-1)*100 if ratio else None,
                           variation_ratio=spread,paired_latency_ratio=latency,material_gain_pairs=votes,
                           ttfb_median_ms=statistics.median([p['candidate_ttfb_ms'] for p in good]) if good else None,
                           composite_score=score if not reasons else None,eligible=not reasons,quality_reasons=reasons))
    return result


def decide(summary,complete=True,blocked=False):
    eligible=[r for r in summary if r['eligible']]
    if not complete or blocked or not eligible:
        return dict(comparison_ready=False,provisional_concurrency=None,composite_score=None,
                    decision='HTTP_BLOCKED' if blocked else 'INCOMPLETE_EXPERIMENT' if not complete else 'NO_RELIABLE_COMPARISON',
                    decision_note='没有足够的可比配对证据，拒绝推荐。')
    gains=[r for r in eligible if r['paired_median_speedup']>=1.10 and
           r['material_gain_pairs']>=math.ceil(2*r['paired_rounds']/3) and r['composite_score']>1]
    if not gains:
        return dict(comparison_ready=True,provisional_concurrency=1,composite_score=1,
                    decision='NO_MATERIAL_GAIN',decision_note='合格候选未显示一致的实质改善；保守保留单并发，不代表未合格候选较慢。')
    best=max(r['composite_score'] for r in gains)
    chosen=min((r for r in gains if r['composite_score']>=best*.95),key=lambda r:r['concurrency'])
    return dict(comparison_ready=True,provisional_concurrency=chosen['concurrency'],
                composite_score=chosen['composite_score'],decision='NEAR_BEST_PAIRED_UTILITY',
                decision_note='从合格配对中选择接近最高相对效用（95%）的最低并发；仅适用于本次固定工作量与当前路径。')


def run(stop,emit=lambda _:None,exe=None,probe=None,rounds=ROUNDS,candidates=CONCURRENCY_LEVELS,
        total_bytes=MAX_TOTAL_BYTES,phase_seconds=PHASE_SECONDS,seed=None,clock=time.monotonic):
    candidates=tuple(candidates)
    if 1 not in candidates or len(candidates)<2 or len(set(candidates))!=len(candidates) or any(c not in CONCURRENCY_LEVELS for c in candidates):
        raise ValueError('候选须包含 1 及至少一个 2/4/8。')
    if not isinstance(rounds,int) or not 2<=rounds<=5:raise ValueError('轮数须为 2–5。')
    if not isinstance(total_bytes,int) or not PILOT_BYTES<=total_bytes<=MAX_TOTAL_BYTES:raise ValueError('总样本上限无效。')
    core.check_cancel(stop)
    budget=maximum_budget_bytes(rounds,candidates,total_bytes)
    result=dict(status='Incomplete',parameter='parallel_https_requests',design='adjacent_equal_work_pairs',
                requested_candidates=list(candidates),candidates=[],rounds=rounds,requested_budget_bytes=budget,
                reserved_bytes=0,received_body_bytes=0,time_budget_seconds=phase_seconds,time_budget_exhausted=False,
                budget_exhausted=False,pilot=None,formal_plan=None,batches=[],pairs=[],summary=[],randomized_order=[],
                retest_status='NotNeeded',retest_candidate=None,blocked=False,comparison_ready=False,
                recommendation_allowed=False,selected_concurrency=None,provisional_concurrency=None,
                scope='当前 Cloudflare HTTPS 路径与固定工作量，可能经过代理/TUN；非物理带宽或 yt-dlp -N 参数。')
    exe=exe or performance.curl_path()
    if not exe:
        result.update(status='Unavailable',decision='CURL_UNAVAILABLE',decision_note='未找到 curl。');return result
    seed=secrets.randbits(32) if seed is None else seed
    result['seed']=seed
    rng=random.Random(seed);deadline=clock()+phase_seconds
    def reserve(size,seconds):
        if clock()+seconds>deadline:result['time_budget_exhausted']=True;return False
        if result['reserved_bytes']+size>budget:result['budget_exhausted']=True;return False
        return True
    if not reserve(PILOT_BYTES,MAX_BATCH_SECONDS):
        result.update(decision='INCOMPLETE_EXPERIMENT',decision_note='预探测预算不足。');return result
    emit('并发实验预探测：128 KiB；此样本不进入正式比较。')
    pilot=run_batch(exe,1,0,stop,probe,PILOT_BYTES,clock,connect_timeout=5)
    result['pilot']=pilot;result['reserved_bytes']+=PILOT_BYTES
    result['received_body_bytes']+=pilot['actual_bytes']
    if pilot['http_blocked']:
        result.update(status='Blocked',blocked=True,decision='HTTP_BLOCKED',decision_note='预探测收到 HTTP 403/429，停止该实验。');return result
    plan=calibrate(pilot,candidates,total_bytes);result['formal_plan']=plan
    result['aggregate_bytes_per_batch']=plan['total_bytes'];result['candidates']=plan['candidates']
    challengers=[c for c in plan['candidates'] if c>1]
    if not challengers:
        result.update(decision='NO_COMPARABLE_CANDIDATE',decision_note='样本预算不足以比较候选。');return result
    emit('正式实验锁定：%d KiB/批，连接超时 %d 秒，候选 %s'%(plan['total_bytes']//1024,plan['connect_timeout_seconds'],plan['candidates']))
    initial_order={c:bool(rng.randrange(2)) for c in challengers}
    def pair(c,r,retest=False):
        core.check_cancel(stop)
        size=plan['total_bytes']
        if not reserve(size*2,MAX_BATCH_SECONDS*2):return False
        ident='C%d-R%d'%(c,r)
        first=initial_order[c] if r%2 else not initial_order[c]
        order=[1,c] if first else [c,1]
        result['randomized_order'].append(dict(pair_id=ident,order=order))
        measured={}
        for n in order:
            core.check_cancel(stop)
            if not reserve(size,MAX_BATCH_SECONDS):return False
            emit(('配对补测' if retest else '相邻配对')+' %s：%d 路'%(ident,n))
            b=run_batch(exe,n,r,stop,probe,size,clock,connect_timeout=plan['connect_timeout_seconds'],retest=retest)
            b.update(pair_id=ident,baseline_for=c,sequence=len(result['batches'])+1,max_time_seconds=plan['max_time_seconds'])
            result['batches'].append(b);measured[n]=b
            result['reserved_bytes']+=size;result['received_body_bytes']+=b['actual_bytes']
            if b['http_blocked']:
                result['blocked']=True;return False
        result['pairs'].append(evaluate_pair(measured[1],measured[c],plan))
        return True
    complete=True
    for r in range(1,rounds+1):
        order=list(challengers);rng.shuffle(order)
        for c in order:
            if not pair(c,r):complete=False;break
        if not complete:break
    summary=summarize_pairs(result['pairs'],plan['candidates'],rounds)
    # One supplementary pair total. Preserve all failures; never replace a bad pair.
    if complete and not result['blocked']:
        doubtful=[s for s in summary if not s['eligible'] and s['paired_rounds']>0 and
                  'COMPARABILITY_EVIDENCE_INVALID' not in s['quality_reasons']]
        if doubtful:
            best=max(doubtful,key=lambda s:(s['paired_rounds'],s['paired_median_speedup'] or 0,-s['concurrency']))
            c=best['concurrency'];result['retest_candidate']=c
            before=len(result['batches'])
            done=pair(c,rounds+1,True)
            result['retest_status']='Completed' if done else 'Skipped_or_incomplete'
            if not done and len(result['batches'])!=before:complete=False
            summary=summarize_pairs(result['pairs'],plan['candidates'],rounds)
    result['summary']=summary
    result.update(decide(summary,complete,result['blocked']))
    result['status']='Blocked' if result['blocked'] else 'Completed' if complete else 'Incomplete'
    return result


def apply_environment_gate(result,evidence):
    result=dict(result)
    result['environment_evidence']=evidence
    stable=bool(evidence.get('complete') and evidence.get('observed_stable') and evidence.get('telemetry_complete') and
                evidence.get('tuning_telemetry_acceptable',evidence.get('telemetry_observed_stable',False)))
    result['environment_stable']=stable
    result['recommendation_allowed']=bool(stable and result.get('comparison_ready') and result.get('provisional_concurrency') is not None)
    result['selected_concurrency']=result['provisional_concurrency'] if result['recommendation_allowed'] else None
    if not stable:
        result['measurement_comparison_ready']=bool(result.get('comparison_ready'))
        result['comparison_ready']=False
        if result.get('decision') not in ('HTTP_BLOCKED','CURL_UNAVAILABLE','INCOMPLETE_EXPERIMENT'):
            result['decision']='ENVIRONMENT_UNSTABLE_OR_UNVERIFIED'
            result['decision_note']='配置或遥测不完整/异常；保留配对证据，不推荐。'
    return result


def write_csvs(root,result):
    import csv
    def write(name,rows,fields):
        with (root/name).open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
            for r in rows:w.writerow({k:r.get(k) for k in fields})
    batches=result.get('batches',[])
    write('tuning_batches.csv',batches,['pair_id','baseline_for','sequence','concurrency','round','retest','status','expected_bytes','actual_bytes','elapsed_s','aggregate_mbps','success','planned','ttfb_median_ms','connect_timeout_seconds','max_time_seconds','error_categories'])
    workers=[dict(w,pair_id=b.get('pair_id'),concurrency=b['concurrency'],round=b['round']) for b in batches for w in b.get('worker_rows',[])]
    write('tuning_workers.csv',workers,['pair_id','concurrency','round','worker','status','expected_bytes','bytes','effective_mbps','ttfb_ms','total_ms','http_status','http_version','error_category','failure_phase'])
    write('tuning_pairs.csv',result.get('pairs',[]),['pair_id','concurrency','round','retest','baseline_first','valid','reasons','baseline_mbps','candidate_mbps','speedup','latency_ratio','baseline_success','baseline_planned','candidate_success','candidate_planned','http_version'])
    write('tuning_summary.csv',result.get('summary',[]),['concurrency','planned_rounds','attempted_rounds','successful_rounds','pair_completion_rate','success_rate','paired_baseline_median_mbps','median_mbps','baseline_variation_ratio','paired_median_speedup_pct','variation_ratio','paired_latency_ratio','material_gain_pairs','composite_score','eligible','quality_reasons'])


def report_html(result):
    esc=lambda x:html.escape(str(x if x is not None else '—'))
    def table(rows,fields):
        return '<table><tr>'+''.join('<th>'+esc(k)+'</th>' for k in fields)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(r.get(k))+'</td>' for k in fields)+'</tr>' for r in rows)+'</table>'
    return '<h2>等工作量相邻配对寻优</h2><p>建议并发：'+esc(result.get('selected_concurrency'))+'；'+esc(result.get('decision_note'))+'</p><p>预探测独立，正式条件锁定：'+esc(result.get('formal_plan'))+'；正文计划上限 '+esc(result.get('requested_budget_bytes'))+' 字节；实际预留 '+esc(result.get('reserved_bytes'))+'；接收 '+esc(result.get('received_body_bytes'))+'。</p><p>效用基线为 1：配对速度比^0.65 × 完成可靠性^0.25 × 延迟惩罚^0.10。未通过质量门槛不评分。无线速率上升仅为旁证，不证明负载因果。结果仅适用于当前路径及工作量。</p>'+table(result.get('summary',[]),['concurrency','paired_rounds','pair_completion_rate','paired_baseline_median_mbps','median_mbps','paired_median_speedup_pct','variation_ratio','composite_score','eligible','quality_reasons'])+'<h3>原始配对</h3>'+table(result.get('pairs',[]),['pair_id','baseline_first','valid','reasons','baseline_mbps','candidate_mbps','speedup','latency_ratio'])
