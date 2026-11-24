"""Controlled HTTPS concurrency experiments: calibrate once, compare adjacent equal-work pairs."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import traffic
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
PILOT_COUNT=3
MAX_EXTRA_PAIRS=4
MAX_EXTRA_PER_CANDIDATE=3
EXPLORATION_SECONDS=16
TARGET_SECONDS=8
MAX_TOTAL_BYTES=512*1024
MAX_TRANSFER_SECONDS=20
PHASE_SECONDS=600
MAX_BATCH_SECONDS=26
# A snapshot can take 20 s + WLAN 5 s; periodic lock contention may add another 25 s.
BOUNDARY_RESERVE_SECONDS=52
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
    elapsed=clock()-started
    valid=[r for r,size in zip(rows,sizes) if r is not None and _valid(r,size)]
    complete=len(valid)==concurrency and math.isfinite(elapsed) and elapsed>0
    actual=sum(max(0,int(r.get('bytes') or 0)) for r in rows if r is not None)
    speed=actual*8/elapsed/1e6 if complete else None
    ttfb=[float(r['ttfb_ms']) for r in valid if isinstance(r.get('ttfb_ms'),(int,float)) and math.isfinite(float(r['ttfb_ms']))]
    categories=sorted({str(r.get('error_category') or r.get('error') or 'INCOMPLETE')
                       for r in rows if r is not None and not _valid(r,r.get('expected_bytes'))})
    blocked=any(r and r.get('http_status') in (403,429) for r in rows)
    return dict(concurrency=concurrency,round=round_number,status='OK' if complete else 'Failed',
                expected_bytes=total_bytes,actual_bytes=actual,elapsed_s=elapsed,
                aggregate_mbps=speed,success=len(valid),planned=concurrency,
                sample_bytes_per_worker=min(sizes),connect_timeout_seconds=connect_timeout,
                retest=bool(retest),sample_plan=sample_plan or {},
                ttfb_median_ms=statistics.median(ttfb) if ttfb else None,
                error_categories=categories,http_blocked=blocked,worker_rows=rows)



def _positive(x):
    return isinstance(x,(int,float)) and not isinstance(x,bool) and math.isfinite(x) and x>0


def raw_speed(batch):
    elapsed=batch.get('elapsed_s'); actual=batch.get('actual_bytes')
    return actual*8/elapsed/1e6 if batch.get('status')=='OK' and _positive(elapsed) and _positive(actual) else None


def calibrate(pilots,candidates,cap):
    """Three independent pilots, median calibration and bounded pre-formal exploration."""
    if not isinstance(cap,int) or not PILOT_BYTES<=cap<=MAX_TOTAL_BYTES:
        raise ValueError('总样本上限须为 128–512 KiB。')
    speeds=[raw_speed(p) for p in pilots if p.get('actual_bytes')==PILOT_BYTES]
    speeds=[s for s in speeds if _positive(s)]
    speed=statistics.median(speeds) if len(speeds)>=2 else None
    target=int(min(cap,speed*1e6*TARGET_SECONDS/8)) if speed else PILOT_BYTES
    total=min(cap,max(PILOT_BYTES,2**int(math.log2(max(PILOT_BYTES,target)))))
    initial_total=total
    # Only expand before freezing controls. Require a majority of successful pilots,
    # and the slowest successful pilot to support the larger workload within 16 s.
    if speed:
        for c in sorted(candidates):
            needed=max(PILOT_BYTES,c*MIN_WORKER_BYTES)
            if needed<=cap and needed*8/(min(speeds)*1e6)<=EXPLORATION_SECONDS:
                total=max(total,needed)
    timings=[]
    for p in pilots:
        for w in p.get('worker_rows',[]):
            if w.get('status')!='OK':continue
            parts=[w.get(k) for k in ('dns_ms','tcp_ms','tls_ms')]
            if all(isinstance(x,(int,float)) and math.isfinite(x) and x>=0 for x in parts):
                timings.append(sum(parts))
    timeout=max(5,min(10,math.ceil(core.percentile(timings,.95)*.002+2))) if timings else 10
    if len(speeds)<PILOT_COUNT:timeout=10
    active=[c for c in candidates if total>=c*MIN_WORKER_BYTES]
    return dict(total_bytes=total,initial_total_bytes=initial_total,connect_timeout_seconds=timeout,
                max_time_seconds=MAX_TRANSFER_SECONDS,candidates=active,
                excluded_candidates=[c for c in candidates if c not in active],
                pilot_speed_mbps=speed,pilot_success_count=len(speeds),pilot_attempt_count=len(pilots),
                pilot_speeds_mbps=speeds,target_seconds=TARGET_SECONDS,exploration_seconds=EXPLORATION_SECONDS,
                exploration_expanded=total>initial_total,
                mode='median_pilot_calibrated' if speed else 'conservative_fallback',frozen=True)


def maximum_budget_bytes(rounds=ROUNDS,candidates=CONCURRENCY_LEVELS,total_bytes=MAX_TOTAL_BYTES):
    challengers=sum(c>1 for c in candidates)
    return PILOT_COUNT*PILOT_BYTES+2*(rounds*challengers+min(MAX_EXTRA_PAIRS,MAX_EXTRA_PER_CANDIDATE*challengers))*total_bytes


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
            len(b.get('worker_rows',[]))!=b.get('concurrency') or not _positive(raw_speed(b))):
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
    bs,cs=raw_speed(baseline),raw_speed(challenger)
    return dict(pair_id=baseline.get('pair_id'),concurrency=challenger.get('concurrency'),
                round=challenger.get('round'),retest=challenger.get('retest',False),
                valid=not reasons,reasons=reasons,baseline_mbps=bs,
                candidate_mbps=cs,baseline_ttfb_ms=bt,candidate_ttfb_ms=ct,
                baseline_elapsed_s=baseline.get('elapsed_s'),candidate_elapsed_s=challenger.get('elapsed_s'),
                speedup=baseline['elapsed_s']/challenger['elapsed_s'] if not reasons else None,
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
                           environment_verified_pairs=sum(p.get('environment_verified') is True for p in rows),
                           environment_unverified_pairs=sum(p.get('environment_verified') is False for p in rows),
                           paired_rounds=success,pair_completion_rate=completion,success_rate=request_rate,
                           success_requests=succeeded,planned_requests=planned,
                           median_mbps=statistics.median(rates) if rates else None,
                           paired_baseline_median_mbps=statistics.median(base_rates) if base_rates else None,
                           baseline_variation_ratio=max(base_rates)/min(base_rates) if base_rates else None,
                           paired_median_speedup=ratio,paired_median_speedup_pct=(ratio-1)*100 if ratio else None,
                           variation_ratio=spread,paired_cv=statistics.pstdev(ratios)/statistics.mean(ratios) if ratios else None,
                           paired_latency_ratio=latency,material_gain_pairs=votes,
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


def evidence_state(row,rounds):
    """Descriptive evidence categories, not statistical confidence levels."""
    n=row['attempted_rounds']; valid=row['paired_rounds']; reasons=row['quality_reasons']
    remaining=max(0,rounds+MAX_EXTRA_PER_CANDIDATE-n)
    if 'COMPARABILITY_EVIDENCE_INVALID' in reasons or 'DUPLICATE_PAIR' in reasons:
        return 'IRRECOVERABLE_COMPARABILITY'
    # Adding positive observations can never reduce the observed max/min ratio.
    if row['variation_ratio'] is not None and row['variation_ratio']>2:
        return 'IRRECOVERABLE_SPREAD'
    if valid+remaining<rounds or (n+remaining and (valid+remaining)/(n+remaining)<.75):
        return 'IRRECOVERABLE_COMPLETION'
    if row['eligible']:
        if (row['paired_median_speedup']>=1.10 and row['material_gain_pairs']>=math.ceil(2*valid/3)
            and row['composite_score']>1):
            return 'SUPPORTED_GAIN'
        if row['paired_median_speedup']<1.10 and valid-row['material_gain_pairs']>=math.ceil(2*valid/3):
            return 'SUPPORTED_NO_GAIN'
    return 'NEEDS_MORE_EVIDENCE' if remaining else 'PAIR_LIMIT_REACHED'


def annotate(summary,rounds):
    for row in summary:row['evidence_state']=evidence_state(row,rounds)
    return summary


def run(stop,emit=lambda _:None,exe=None,probe=None,rounds=ROUNDS,candidates=CONCURRENCY_LEVELS,
        total_bytes=MAX_TOTAL_BYTES,phase_seconds=PHASE_SECONDS,seed=None,clock=time.monotonic,observer=None,usage_mode='shared'):
    if usage_mode not in ('shared','controlled'):raise ValueError('未知使用模式')
    candidates=tuple(candidates)
    if 1 not in candidates or len(candidates)<2 or len(set(candidates))!=len(candidates) or any(c not in CONCURRENCY_LEVELS for c in candidates):
        raise ValueError('候选须包含 1 及至少一个 2/4/8。')
    if not isinstance(rounds,int) or not 2<=rounds<=5:raise ValueError('轮数须为 2–5。')
    if not isinstance(total_bytes,int) or not PILOT_BYTES<=total_bytes<=MAX_TOTAL_BYTES:raise ValueError('总样本上限无效。')
    core.check_cancel(stop)
    budget=maximum_budget_bytes(rounds,candidates,total_bytes)
    result=dict(status='Incomplete',parameter='parallel_https_requests',design='sequential_adjacent_equal_work_pairs',
                requested_candidates=list(candidates),candidates=[],rounds=rounds,requested_budget_bytes=budget,
                reserved_bytes=0,received_body_bytes=0,time_budget_seconds=phase_seconds,time_budget_exhausted=False,
                budget_exhausted=False,pilot=None,pilots=[],formal_plan=None,batches=[],pairs=[],summary=[],randomized_order=[],
                sampling_trace=[],extra_pairs=0,extra_pair_limit=MAX_EXTRA_PAIRS,stop_reason=None,evidence_level='INSUFFICIENT',
                measurement_evidence_level='INSUFFICIENT',environment_evidence_level='UNVERIFIED',
                measurement_summary=[],pilot_environment=None,pair_monitoring_enabled=observer is not None,
                usage_mode=usage_mode,load_attribution='UNAVAILABLE',boundary_budget_trace=[],
                load_scheduler_enabled=callable(getattr(observer,'start_load_sampler',None)),load_schedule=[],
                load_window_coverage_ok=False,load_policy=dict(threshold_mbps=0.5,stable_intervals=3,sample_interval_seconds=1.0,shared_wait_seconds=8,controlled_wait_seconds=20),
                retest_status='NotNeeded',retest_candidate=None,blocked=False,comparison_ready=False,
                recommendation_allowed=False,selected_concurrency=None,provisional_concurrency=None,
                scope='当前 Cloudflare HTTPS 路径与固定工作量，可能经过代理/TUN；非物理带宽或 yt-dlp -N 参数。')
    exe=exe or performance.curl_path()
    if not exe:
        result.update(status='Unavailable',decision='CURL_UNAVAILABLE',decision_note='未找到 curl。');return result
    seed=secrets.randbits(32) if seed is None else seed
    result['seed']=seed
    rng=random.Random(seed);deadline=clock()+phase_seconds
    origin=observer.t0 if observer is not None else clock()
    load_monitor=None
    starter=getattr(observer,'start_load_sampler',None) if observer is not None else None
    if callable(starter):
        try:load_monitor=starter()
        except (OSError,ValueError,TypeError):load_monitor=None
    result['load_scheduler_available']=load_monitor is not None
    result['load_scheduler_enabled']=callable(starter)
    def boundary_cost():
        if observer is None:return 0
        estimator=getattr(observer,'boundary_reserve',None)
        return estimator() if estimator else BOUNDARY_RESERVE_SECONDS
    def mark(label):
        if observer is None:return None
        core.check_cancel(stop)
        try:return observer.mark(label)
        except (core.ProbeError,OSError,ValueError,TypeError):return None
    def window(begin,end,started,finished):
        if observer is None:return dict(verified=False,reasons=['PAIR_MONITORING_UNAVAILABLE'])
        try:return observer.window(begin,end,started,finished)
        except (core.ProbeError,OSError,ValueError,TypeError):return dict(verified=False,reasons=['PAIR_MONITORING_FAILED'])
    def measure(n,r,size,timeout,retest=False):
        sampler=getattr(observer,'traffic_sample',None)
        before=sampler() if sampler else None
        started=clock()-origin;stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
        b=run_batch(exe,n,r,stop,probe,size,clock,connect_timeout=timeout,retest=retest)
        b.update(started_elapsed_s=started,finished_elapsed_s=clock()-origin,
                 started_at_utc=stamp,finished_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        if sampler:b['traffic']=traffic.delta(before,sampler(),b['actual_bytes'])
        else:b['traffic']=dict(status='Unavailable',interfaces=[],reason='NO_COUNTER_PROVIDER')
        return b
    def reserve(size,seconds):
        if clock()+seconds>deadline:result['time_budget_exhausted']=True;return False
        if result['reserved_bytes']+size>budget:result['budget_exhausted']=True;return False
        return True
    def wait_load(stage,timeout):
        if not result['load_scheduler_enabled']:return dict(stage=stage,status='NOT_ENABLED',waited_seconds=0,action='PROCEED_TEST_HARNESS')
        if load_monitor is None:entry=dict(status='LOAD_MONITOR_UNAVAILABLE',waited_seconds=0)
        else:
            try:entry=load_monitor.wait_for_idle(stop,timeout)
            except (OSError,ValueError,TypeError):entry=dict(status='LOAD_MONITOR_ERROR',waited_seconds=0)
        entry=dict(entry,stage=stage,timeout_seconds=timeout)
        entry['action']='PROCEED_IDLE' if entry.get('status')=='IDLE_WINDOW' else 'PROCEED_SHARED_OBSERVATION' if usage_mode=='shared' else 'SKIP'
        result['load_schedule'].append(entry)
        return entry
    def schedule_pilot(index):
        if not result['load_scheduler_enabled']:return wait_load('pilot_%d'%(index+1),0),True
        reserve_seconds=MAX_BATCH_SECONDS+boundary_cost();remaining=max(0,deadline-clock()-reserve_seconds)
        limit=8 if usage_mode=='shared' else 20
        entry=wait_load('pilot_%d'%(index+1),min(limit,remaining))
        return entry,entry.get('status')=='IDLE_WINDOW' or usage_mode=='shared'
    def schedule_pair_boundary(label,reserve_seconds):
        if not result['load_scheduler_enabled']:return mark('pair_'+label+'_begin'),dict(stage=label,status='NOT_ENABLED',action='PROCEED_TEST_HARNESS')
        limit=8 if usage_mode=='shared' else 20
        remaining=max(0,deadline-clock()-reserve_seconds);wait_deadline=clock()+min(limit,remaining)
        begin=None;last=None
        for attempt in range(3):
            timeout=max(0,wait_deadline-clock());entry=wait_load(label,timeout);last=entry
            if entry.get('status')=='IDLE_WINDOW':
                begin=mark('pair_'+label+'_begin')
                try:confirmed=load_monitor.current_state().get('idle') if load_monitor is not None else False
                except (OSError,ValueError,TypeError):confirmed=False
                entry['boundary_confirmation']='IDLE_AFTER_FULL_SNAPSHOT' if confirmed else 'LOAD_ROSE_DURING_FULL_SNAPSHOT'
                if confirmed:return begin,entry
                if wait_deadline-clock()>0:continue
                entry['status']='BUSY_AFTER_BOUNDARY'
            if usage_mode=='shared':
                begin=mark('pair_'+label+'_begin');entry['action']='PROCEED_SHARED_OBSERVATION'
                return begin,entry
            return None,entry
        if usage_mode=='shared':
            begin=mark('pair_'+label+'_begin')
            if last is None:last=dict(stage=label,status='LOAD_WINDOW_UNAVAILABLE')
            last['action']='PROCEED_SHARED_OBSERVATION'
            return begin,last
        return None,last or dict(stage=label,status='LOAD_WINDOW_UNAVAILABLE',action='SKIP')
    if not reserve(PILOT_BYTES,MAX_BATCH_SECONDS+2*boundary_cost()):
        result.update(stop_reason='PILOT_BUDGET',decision='INCOMPLETE_EXPERIMENT',decision_note='预探测预算不足。');return result
    pilot_begin=mark('tuning_pilot_begin')
    for pindex in range(PILOT_COUNT):
        core.check_cancel(stop)
        load_window,load_proceed=schedule_pilot(pindex)
        if not load_proceed:
            result.update(stop_reason='LOAD_WINDOW_UNAVAILABLE',decision='LOAD_WINDOW_UNAVAILABLE',decision_note='受控模式等待低负载窗口超时；未在繁忙网络中启动预探测。')
            return result
        if not reserve(PILOT_BYTES,MAX_BATCH_SECONDS+boundary_cost()):
            result.update(stop_reason='PILOT_BUDGET',decision='INCOMPLETE_EXPERIMENT',decision_note='预探测预算不足。');return result
        emit('独立预探测 %d/%d：128 KiB；不进入正式比较。'%(pindex+1,PILOT_COUNT))
        pilot=measure(1,0,PILOT_BYTES,5)
        pilot['pilot_index']=pindex+1
        pilot['load_window']=load_window
        pilot['load_window_verified']=(not result['load_scheduler_enabled']) or load_window.get('status')=='IDLE_WINDOW'
        result['pilots'].append(pilot)
        if pindex==0:result['pilot']=pilot
        result['reserved_bytes']+=PILOT_BYTES;result['received_body_bytes']+=pilot['actual_bytes']
        if pilot['http_blocked']:
            result.update(status='Blocked',blocked=True,stop_reason='HTTP_BLOCKED',decision='HTTP_BLOCKED',decision_note='预探测收到 HTTP 403/429，停止该实验。');return result
    pilot_end=mark('tuning_pilot_end')
    result['pilot_environment']=window(pilot_begin,pilot_end,result['pilots'][0]['started_elapsed_s'],result['pilots'][-1]['finished_elapsed_s'])
    plan=calibrate(result['pilots'],candidates,total_bytes);result['formal_plan']=plan
    result['aggregate_bytes_per_batch']=plan['total_bytes'];result['candidates']=plan['candidates']
    challengers=[c for c in plan['candidates'] if c>1]
    if not challengers:
        result.update(decision='NO_COMPARABLE_CANDIDATE',decision_note='样本预算不足以比较候选。');return result
    emit('正式实验锁定：%d KiB/批，连接超时 %d 秒，候选 %s'%(plan['total_bytes']//1024,plan['connect_timeout_seconds'],plan['candidates']))
    initial_order={c:bool(rng.randrange(2)) for c in challengers}
    def pair(c,r,retest=False):
        core.check_cancel(stop)
        size=plan['total_bytes']
        reserve_seconds=MAX_BATCH_SECONDS*2+2*boundary_cost()
        result['boundary_budget_trace'].append(dict(candidate=c,round=r,reserve_per_boundary_s=boundary_cost(),remaining_s=max(0,deadline-clock())))
        if not reserve(size*2,reserve_seconds):return False
        ident='C%d-R%d'%(c,r)
        first=initial_order[c] if r%2 else not initial_order[c]
        order=[1,c] if first else [c,1]
        result['randomized_order'].append(dict(pair_id=ident,order=order))
        measured={}
        begin,load_window=schedule_pair_boundary(ident,reserve_seconds)
        if begin is None and result['load_scheduler_enabled']:
            result['load_window_unavailable']=True
            result['load_window_stop_reason']='受控模式在等待期限内未检测到连续低负载窗口。'
            return False
        if not reserve(size*2,MAX_BATCH_SECONDS*2+boundary_cost()):return False
        for n in order:
            core.check_cancel(stop)
            if not reserve(size,MAX_BATCH_SECONDS+boundary_cost()):return False
            emit(('配对补测' if retest else '相邻配对')+' %s：%d 路'%(ident,n))
            b=measure(n,r,size,plan['connect_timeout_seconds'],retest)
            b.update(pair_id=ident,baseline_for=c,sequence=len(result['batches'])+1,max_time_seconds=plan['max_time_seconds'])
            result['batches'].append(b);measured[n]=b
            result['reserved_bytes']+=size;result['received_body_bytes']+=b['actual_bytes']
            if b['http_blocked']:
                result['blocked']=True;return False
        end=mark('pair_'+ident+'_end')
        p=evaluate_pair(measured[1],measured[c],plan)
        evidence=window(begin,end,measured[order[0]]['started_elapsed_s'],measured[order[-1]]['finished_elapsed_s'])
        load_verified=(not result['load_scheduler_enabled']) or (load_window.get('status')=='IDLE_WINDOW' and load_window.get('boundary_confirmation','IDLE_AFTER_FULL_SNAPSHOT')=='IDLE_AFTER_FULL_SNAPSHOT')
        p.update(measurement_valid=bool(p['valid'] and load_verified),
                  measurement_reasons=list(p['reasons'])+([] if load_verified else ['PAIR_LOAD_WINDOW_NOT_IDLE']),environment=evidence,
                  environment_verified=evidence['verified'],load_window=load_window,load_window_verified=load_verified)
        if not load_verified:
            p['valid']=False
            p['reasons']=sorted(set(p['reasons']+['PAIR_LOAD_WINDOW_NOT_IDLE']))
        # With no observer the measurement engine remains testable but cannot issue a recommendation.
        # In the GUI every attempt, including contaminated attempts, stays in the denominator.
        if observer is not None and not evidence['verified']:
            p['valid']=False
            p['reasons']=sorted(set(p['reasons']+['PAIR_ENVIRONMENT_NOT_VERIFIED']))
        result['pairs'].append(p)
        return True
    complete=True
    for r in range(1,rounds+1):
        order=list(challengers);rng.shuffle(order)
        for c in order:
            if not pair(c,r):complete=False;break
        if not complete:break
    summary=annotate(summarize_pairs(result['pairs'],plan['candidates'],rounds),rounds)
    def trace():
        result['sampling_trace'].append(dict(extra_pairs=result['extra_pairs'],states=[
            dict(concurrency=s['concurrency'],attempted=s['attempted_rounds'],valid=s['paired_rounds'],
                 state=s['evidence_state'],reasons=s['quality_reasons']) for s in summary]))
    trace()
    # Minimum coverage first. Additional pairs only for unresolved, recoverable candidates.
    # Fair priority: least sampled first, then lower concurrency; never erase failures.
    if complete and not result['blocked']:
        while result['extra_pairs']<MAX_EXTRA_PAIRS:
            pending=[s for s in summary if s['evidence_state']=='NEEDS_MORE_EVIDENCE']
            if not pending:break
            chosen=min(pending,key=lambda s:(s['attempted_rounds'],s['concurrency']))
            c=chosen['concurrency'];r=chosen['attempted_rounds']+1
            result['retest_candidate']=c
            before=len(result['batches'])
            done=pair(c,r,True)
            if not done:
                result['retest_status']='Skipped_or_incomplete'
                if len(result['batches'])!=before:complete=False
                break
            result['extra_pairs']+=1;result['retest_status']='Completed'
            summary=annotate(summarize_pairs(result['pairs'],plan['candidates'],rounds),rounds)
            trace()
    result['summary']=summary
    raw_pairs=[dict(p,valid=p['measurement_valid'],reasons=p['measurement_reasons']) for p in result['pairs']]
    raw_summary=annotate(summarize_pairs(raw_pairs,plan['candidates'],rounds),rounds)
    result['measurement_summary']=raw_summary
    pilot_load_ok=(not result['load_scheduler_enabled']) or (len(result['pilots'])==PILOT_COUNT and all(p.get('load_window_verified') for p in result['pilots']))
    pair_load_ok=(not result['load_scheduler_enabled']) or (bool(result['pairs']) and all(p.get('load_window_verified') for p in result['pairs']))
    result['load_window_coverage_ok']=bool(pilot_load_ok and pair_load_ok and complete)
    raw_decision=decide(raw_summary,complete,result['blocked'])
    raw_resolved=bool(raw_summary) and all(s['evidence_state'] in ('SUPPORTED_GAIN','SUPPORTED_NO_GAIN') for s in raw_summary)
    result['measurement_evidence_level']=('SUPPORTED_WITHIN_TESTED_SCOPE' if raw_resolved and raw_decision['comparison_ready'] and len(plan['pilot_speeds_mbps'])>=2 and result['load_window_coverage_ok'] else 'TENTATIVE' if raw_decision['comparison_ready'] else 'INSUFFICIENT')
    result['measurement_provisional_concurrency']=raw_decision['provisional_concurrency']
    result['pair_environment_coverage_ok']=bool(observer is not None and summary and all(
        s['environment_verified_pairs']>=rounds and s['environment_verified_pairs']/max(1,s['attempted_rounds'])>=.75 for s in summary))
    result['environment_evidence_level']='PAIR_COVERAGE_MET' if result['pair_environment_coverage_ok'] else 'INSUFFICIENT' if observer is not None else 'UNVERIFIED'
    states=[s['evidence_state'] for s in summary]
    resolved=bool(states) and all(s in ('SUPPORTED_GAIN','SUPPORTED_NO_GAIN') for s in states)
    if result['blocked']:reason='HTTP_BLOCKED'
    elif result.get('load_window_unavailable'):reason='LOAD_WINDOW_UNAVAILABLE'
    elif result['time_budget_exhausted']:reason='TIME_BUDGET'
    elif result['budget_exhausted']:reason='BYTE_BUDGET'
    elif not complete:reason='INCOMPLETE_FORMAL_COVERAGE'
    elif resolved:reason='EVIDENCE_SUFFICIENT'
    elif result['extra_pairs']>=MAX_EXTRA_PAIRS:reason='EXTRA_PAIR_LIMIT'
    elif 'PAIR_LIMIT_REACHED' in states:reason='CANDIDATE_PAIR_LIMIT'
    else:reason='NO_RECOVERABLE_CANDIDATE'
    result['stop_reason']=reason
    result.update(decide(summary,complete,result['blocked']))
    if result['comparison_ready'] and resolved and len(plan['pilot_speeds_mbps'])>=2:
        result['evidence_level']='SUPPORTED_WITHIN_TESTED_SCOPE'
    elif result['comparison_ready']:
        result['evidence_level']='TENTATIVE'
        result['comparison_ready']=False
        result['decision']='TENTATIVE_ONLY'
        if result['provisional_concurrency']==1 and 'SUPPORTED_NO_GAIN' not in states:
            result['provisional_concurrency']=None
        result['decision_note']='存在初步比较，但候选或预探测证据不足；不正式推荐。'
    result['status']='Blocked' if result['blocked'] else 'Completed' if complete else 'Incomplete'

    return result


def apply_environment_gate(result,evidence):
    result=dict(result)
    result['environment_evidence']=evidence
    # Global configuration and adapter state are still hard constraints. Radio tolerances
    # are evaluated inside each pair, not against an unrelated pilot or between-pair sample.
    global_state_changes=[c for c in evidence.get('telemetry_changes',[]) if c.get('field') in ('Status','MediaConnectionState')]
    native_changes=[dict(pair_id=b.get('pair_id'),pilot_index=b.get('pilot_index'),index=r.get('index'),reason=r.get('reason')) for b in result.get('pilots',[])+result.get('batches',[]) for r in b.get('traffic',{}).get('interfaces',[]) if r.get('reason') in ('INTERFACE_IDENTITY_CHANGED','INTERFACE_STATE_CHANGED')]
    result['native_state_changes']=native_changes
    load_ok=(not result.get('load_scheduler_enabled')) or bool(result.get('load_window_coverage_ok'))
    result['load_environment_guard_passed']=load_ok
    global_ok=bool(evidence.get('complete') and evidence.get('observed_stable') and evidence.get('adapter_state_coverage') and not global_state_changes and not native_changes and load_ok)
    stable=bool(global_ok and result.get('pair_environment_coverage_ok'))
    result['global_environment_guard_passed']=global_ok
    result['environment_stable']=stable
    result['environment_evidence_level']='VERIFIED_PAIR_SCOPE' if stable else 'INSUFFICIENT'
    result['measurement_comparison_ready']=result.get('measurement_evidence_level')=='SUPPORTED_WITHIN_TESTED_SCOPE'
    result['combined_comparison_ready_before_global_gate']=bool(result.get('comparison_ready'))
    result['recommendation_allowed']=bool(stable and result.get('comparison_ready') and result.get('provisional_concurrency') is not None)
    result['selected_concurrency']=result['provisional_concurrency'] if result['recommendation_allowed'] else None
    result['traffic_coverage']=dict(batches=len(result.get('pilots',[]))+len(result.get('batches',[])),measured=sum(b.get('traffic',{}).get('status')=='Measured' for b in result.get('pilots',[])+result.get('batches',[])))
    result['shared_load_observation_concurrency']=None
    if result.get('usage_mode')=='shared' and result['recommendation_allowed']:
        result['shared_load_observation_concurrency']=result['selected_concurrency']
        result['selected_concurrency']=None
        result['recommendation_allowed']=False
        result['comparison_ready']=False
        result['evidence_level']='TENTATIVE'
        result['decision']='SHARED_LOAD_OBSERVATION_ONLY'
        result['decision_note']='日常使用模式：共享负载下的观察方向，不是受控参数推荐。'
    if not stable:
        result['evidence_level']='INSUFFICIENT'
        result['comparison_ready']=False
        if result.get('decision') not in ('HTTP_BLOCKED','CURL_UNAVAILABLE','INCOMPLETE_EXPERIMENT'):
            result['decision']='ENVIRONMENT_UNSTABLE_OR_UNVERIFIED'
            result['decision_note']='全局配置/连接状态或局部配对环境覆盖不足；保留测量证据，不推荐。'
    return result


def write_csvs(root,result):
    import csv
    def write(name,rows,fields):
        with (root/name).open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
            for r in rows:w.writerow({k:r.get(k) for k in fields})
    batches=result.get('batches',[])
    traffic_rows=[dict(pair_id=b.get('pair_id'),pilot_index=b.get('pilot_index'),concurrency=b.get('concurrency'),round=b.get('round'),test_body_bytes=b.get('actual_bytes'),interval_seconds=b.get('traffic',{}).get('interval_seconds'),**r) for b in result.get('pilots',[])+batches for r in b.get('traffic',{}).get('interfaces',[])]
    write('tuning_traffic.csv',traffic_rows,['pair_id','pilot_index','concurrency','round','index','status','reason','hardware','type','test_body_bytes','interval_seconds','rx_bytes','tx_bytes','rx_mbps','tx_mbps','rx_to_test_body_ratio'])
    pilot_rows=[dict(p,load_window_status=p.get('load_window',{}).get('status'),load_wait_seconds=p.get('load_window',{}).get('waited_seconds')) for p in result.get('pilots',[])]
    write('tuning_pilots.csv',pilot_rows,['pilot_index','status','expected_bytes','actual_bytes','elapsed_s','aggregate_mbps','started_elapsed_s','finished_elapsed_s','started_at_utc','finished_at_utc','error_categories','load_window_status','load_wait_seconds'])
    write('tuning_load_schedule.csv',result.get('load_schedule',[]),['stage','status','action','waited_seconds','timeout_seconds','median_total_mbps','max_total_mbps','threshold_mbps','interval_count','boundary_confirmation','reason'])
    write('tuning_sampling_trace.csv',[dict(extra_pairs=x['extra_pairs'],**s) for x in result.get('sampling_trace',[]) for s in x['states']],['extra_pairs','concurrency','attempted','valid','state','reasons'])
    write('tuning_batches.csv',batches,['pair_id','baseline_for','sequence','concurrency','round','retest','status','expected_bytes','actual_bytes','elapsed_s','aggregate_mbps','started_elapsed_s','finished_elapsed_s','started_at_utc','finished_at_utc','success','planned','ttfb_median_ms','connect_timeout_seconds','max_time_seconds','error_categories'])
    workers=[dict(w,pair_id=b.get('pair_id'),concurrency=b['concurrency'],round=b['round']) for b in batches for w in b.get('worker_rows',[])]
    write('tuning_workers.csv',workers,['pair_id','concurrency','round','worker','status','expected_bytes','bytes','effective_mbps','ttfb_ms','total_ms','http_status','http_version','error_category','failure_phase'])
    pair_rows=[dict(p,environment_reasons=p.get('environment',{}).get('reasons'),environment_begin_index=p.get('environment',{}).get('begin_index'),environment_end_index=p.get('environment',{}).get('end_index'),load_window_status=p.get('load_window',{}).get('status'),load_wait_seconds=p.get('load_window',{}).get('waited_seconds')) for p in result.get('pairs',[])]
    write('tuning_pairs.csv',pair_rows,['pair_id','concurrency','round','retest','baseline_first','valid','reasons','measurement_valid','measurement_reasons','environment_verified','environment_reasons','environment_begin_index','environment_end_index','load_window_status','load_wait_seconds','baseline_mbps','candidate_mbps','baseline_elapsed_s','candidate_elapsed_s','speedup','latency_ratio','baseline_success','baseline_planned','candidate_success','candidate_planned','http_version'])
    write('tuning_measurement_summary.csv',result.get('measurement_summary',[]),['concurrency','paired_rounds','pair_completion_rate','paired_median_speedup_pct','paired_cv','composite_score','eligible','evidence_state','quality_reasons'])
    write('tuning_summary.csv',result.get('summary',[]),['concurrency','planned_rounds','attempted_rounds','successful_rounds','pair_completion_rate','environment_verified_pairs','environment_unverified_pairs','success_rate','paired_baseline_median_mbps','median_mbps','baseline_variation_ratio','paired_median_speedup_pct','variation_ratio','paired_cv','paired_latency_ratio','material_gain_pairs','composite_score','eligible','quality_reasons','evidence_state'])


def report_html(result):
    esc=lambda x:html.escape(str(x if x is not None else '—'))
    labels={'concurrency':'并发数','paired_rounds':'有效配对数','pair_completion_rate':'配对完成率','paired_baseline_median_mbps':'配对基线中位 Mbps','median_mbps':'候选中位 Mbps','paired_median_speedup_pct':'配对中位提升 %','variation_ratio':'配对比值波动倍数','composite_score':'相对效用','eligible':'合格','quality_reasons':'质量原因','evidence_state':'证据状态','pair_id':'配对编号','baseline_first':'基线先测','valid':'联合有效','measurement_valid':'测量有效','environment_verified':'环境验证','reasons':'原因','baseline_mbps':'基线 Mbps','candidate_mbps':'候选 Mbps','speedup':'速度比','latency_ratio':'基线/候选 TTFB 比'}
    def table(rows,fields):
        return '<table><tr>'+''.join('<th>'+esc(labels.get(k,k))+'</th>' for k in fields)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(r.get(k))+'</td>' for k in fields)+'</tr>' for r in rows)+'</table>'
    load_table=table(result.get('load_schedule',[]),['stage','status','waited_seconds','median_total_mbps','max_total_mbps','action'])
    return '<h2>序贯等工作量相邻配对寻优</h2><p>模式：'+esc(result.get('usage_mode'))+'；低负载窗口覆盖：'+esc(result.get('load_window_coverage_ok'))+'；共享负载观察候选：'+esc(result.get('shared_load_observation_concurrency'))+'。物理网卡总流量包含所有应用与协议，不进行进程归因。</p><h3>负载感知调度</h3><p>阈值 0.5 Mbps；连续 3 个约 1 秒区间。共享模式最多等待 8 秒，受控模式最多等待 20 秒。</p>'+load_table+'<p>监测开销：'+esc(result.get('monitoring_overhead'))+'</p><p>测量证据：'+esc(result.get('measurement_evidence_level'))+'；环境证据：'+esc(result.get('environment_evidence_level'))+'；最终等级：'+esc(result.get('evidence_level'))+'；停止原因：'+esc(result.get('stop_reason'))+'；额外配对数：'+esc(result.get('extra_pairs'))+'。证据等级是工程规则，不是统计置信概率。</p><p>建议并发：'+esc(result.get('selected_concurrency'))+'；'+esc(result.get('decision_note'))+'</p><p>预探测独立，正式条件锁定：'+esc(result.get('formal_plan'))+'；正文计划上限 '+esc(result.get('requested_budget_bytes'))+' 字节；实际预留 '+esc(result.get('reserved_bytes'))+'；接收 '+esc(result.get('received_body_bytes'))+'。</p><p>效用基线为 1：配对速度比^0.65 × 完成可靠性^0.25 × 延迟惩罚^0.10。未通过质量门槛不评分。结果仅适用于当前路径及工作量。</p>'+table(result.get('summary',[]),['concurrency','paired_rounds','pair_completion_rate','paired_baseline_median_mbps','median_mbps','paired_median_speedup_pct','variation_ratio','composite_score','eligible','quality_reasons','evidence_state'])+'<h3>原始配对</h3>'+table(result.get('pairs',[]),['pair_id','baseline_first','measurement_valid','environment_verified','valid','reasons','baseline_mbps','candidate_mbps','speedup','latency_ratio'])
