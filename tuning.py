"""Conservative application-layer HTTPS concurrency tuning; read-only and byte-bounded."""
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
PHASE_SECONDS=330
MAX_BATCH_SECONDS=26
DOWNLOAD_URL='https://speed.cloudflare.com/__down?bytes={size}'


def split_sizes(total_bytes,workers):
    if not isinstance(total_bytes,int) or not isinstance(workers,int) or workers<1:
        raise ValueError('样本大小和并发数必须是正整数。')
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
                total_ms=None,ttfb_ms=None,http_status=None,error_category=error)


def run_batch(exe,concurrency,round_number,stop,probe=None,total_bytes=AGGREGATE_BYTES,clock=time.monotonic):
    """Run one synchronized batch; aggregate rate uses batch wall-clock, not summed worker rates."""
    core.check_cancel(stop)
    if probe is None:probe=performance.https_probe
    sizes=split_sizes(total_bytes,concurrency)
    started=clock()
    rows=[None]*concurrency
    with ThreadPoolExecutor(max_workers=concurrency,thread_name_prefix='ano-tune') as pool:
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
    categories=sorted({str(r.get('error_category') or r.get('error') or 'INCOMPLETE') for r in rows if r is not None and not _valid(r,r.get('expected_bytes'))})
    blocked=any(r and r.get('http_status') in (403,429) for r in rows)
    return dict(concurrency=concurrency,round=round_number,status='OK' if complete else 'Failed',
                expected_bytes=total_bytes,actual_bytes=actual,elapsed_s=round(elapsed,4),
                aggregate_mbps=speed,success=len(valid),planned=concurrency,
                ttfb_median_ms=round(statistics.median(ttfb),3) if ttfb else None,
                error_categories=categories,http_blocked=blocked,worker_rows=rows)


def summarize_batches(batches,candidates=CONCURRENCY_LEVELS,rounds=ROUNDS):
    result=[]
    for concurrency in candidates:
        rows=[r for r in batches if r.get('concurrency')==concurrency]
        good=[r for r in rows if r.get('status')=='OK' and isinstance(r.get('aggregate_mbps'),(int,float)) and r['aggregate_mbps']>0]
        speeds=[float(r['aggregate_mbps']) for r in good]
        reasons=[]
        if len(rows)<rounds:reasons.append('INCOMPLETE_ROUNDS')
        if len(good)<rounds:reasons.append('FAILED_BATCH')
        if speeds and max(speeds)>2*min(speeds):reasons.append('HIGH_VARIATION')
        ttfb=[float(w['ttfb_ms']) for b in good for w in b.get('worker_rows',[])
              if isinstance(w.get('ttfb_ms'),(int,float)) and math.isfinite(float(w['ttfb_ms']))]
        result.append(dict(concurrency=concurrency,planned_rounds=rounds,attempted_rounds=len(rows),
                           successful_rounds=len(good),median_mbps=round(statistics.median(speeds),3) if speeds else None,
                           p95_mbps=round(core.percentile(speeds,.95),3) if speeds else None,
                           min_mbps=round(min(speeds),3) if speeds else None,
                           max_mbps=round(max(speeds),3) if speeds else None,
                           variation_ratio=round(max(speeds)/min(speeds),3) if speeds and min(speeds)>0 else None,
                           ttfb_median_ms=round(statistics.median(ttfb),3) if ttfb else None,
                           eligible=not reasons,quality_reasons=reasons))
    return result


def decide(summary,candidates=CONCURRENCY_LEVELS,complete=True,blocked=False):
    by={r['concurrency']:r for r in summary}
    baseline=by.get(1)
    eligible=[r for r in summary if r.get('eligible') and r.get('median_mbps') is not None]
    other=[r for r in eligible if r['concurrency']>1]
    ready=bool(complete and not blocked and baseline and baseline.get('eligible') and other)
    if not ready:
        reason='HTTP_BLOCKED' if blocked else 'INCOMPLETE_EXPERIMENT' if not complete else 'NO_RELIABLE_COMPARISON'
        return dict(comparison_ready=False,selected_concurrency=None,decision=reason,
                    decision_note='缺少完整、可靠的单并发基线或可比较候选，不给出最优并发建议。')
    best=max(eligible,key=lambda r:r['median_mbps'])
    base_speed=baseline['median_mbps']
    if best['median_mbps']<base_speed*1.10:
        return dict(comparison_ready=True,selected_concurrency=1,decision='NO_MATERIAL_GAIN',
                    decision_note='更高并发未带来至少 10% 的中位吞吐量改善，建议保持单并发。')
    threshold=max(best['median_mbps']*.95,base_speed*1.10)
    options=[r for r in other if r['median_mbps']>=threshold]
    if not options:
        return dict(comparison_ready=True,selected_concurrency=best['concurrency'],decision='BEST_MEASURED_CANDIDATE',
                    decision_note='已选择吞吐量最高的合格候选；未发现达到 95% 最佳速度的更低并发候选。')
    chosen=min(options,key=lambda r:r['concurrency'])
    return dict(comparison_ready=True,selected_concurrency=chosen['concurrency'],
                decision='LOWEST_CONCURRENCY_NEAR_BEST',
                decision_note='选择达到最佳中位吞吐量 95% 以上且至少改善 10% 的最低并发度，以避免无收益地增加并发。')


def run(stop,emit=lambda _:None,exe=None,probe=None,rounds=ROUNDS,candidates=CONCURRENCY_LEVELS,
        total_bytes=AGGREGATE_BYTES,phase_seconds=PHASE_SECONDS,seed=None,clock=time.monotonic):
    candidates=tuple(candidates)
    if not candidates or 1 not in candidates or any(c not in (1,2,4,8) for c in candidates) or len(set(candidates))!=len(candidates):
        raise ValueError('并发候选必须从 1、2、4、8 中选择且包含 1。')
    if not isinstance(rounds,int) or not 1<=rounds<=5:raise ValueError('轮数必须为 1～5。')
    split_sizes(total_bytes,max(candidates))
    core.check_cancel(stop)
    if exe is None:exe=performance.curl_path()
    if not exe:
        return dict(status='Unavailable',reason='CURL_UNAVAILABLE',candidates=list(candidates),batches=[],
                    summary=[],selected_concurrency=None,comparison_ready=False,recommendation_allowed=False,
                    decision='CURL_UNAVAILABLE',decision_note='未找到 curl，无法执行并发实验。',
                    requested_budget_bytes=len(candidates)*rounds*total_bytes,reserved_bytes=0,
                    scope='当前实际 HTTPS 路径；可能经过系统代理或 TUN。')
    if seed is None:seed=secrets.randbits(32)
    rng=random.Random(seed);deadline=clock()+phase_seconds
    batches=[];orders=[];blocked=False;time_exhausted=False
    for round_number in range(1,rounds+1):
        order=list(candidates);rng.shuffle(order);orders.append(order)
        for concurrency in order:
            core.check_cancel(stop)
            if clock()+MAX_BATCH_SECONDS>deadline:
                time_exhausted=True;break
            emit('并发寻优：第 %d/%d 轮，%d 路并发'%(round_number,rounds,concurrency))
            batch=run_batch(exe,concurrency,round_number,stop,probe,total_bytes,clock)
            batches.append(batch)
            if batch['http_blocked']:
                blocked=True;break
        if time_exhausted or blocked:break
    completed=len(batches)==len(candidates)*rounds
    status='Blocked' if blocked else 'Completed' if completed else 'Incomplete'
    summary=summarize_batches(batches,candidates,rounds)
    decision=decide(summary,candidates,completed,blocked)
    return dict(status=status,parameter='parallel_https_requests',candidates=list(candidates),rounds=rounds,
                aggregate_bytes_per_batch=total_bytes,requested_budget_bytes=len(candidates)*rounds*total_bytes,
                reserved_bytes=len(batches)*total_bytes,seed=seed,randomized_order=orders,batches=batches,
                summary=summary,time_budget_seconds=phase_seconds,time_budget_exhausted=time_exhausted,
                blocked=blocked,**decision,recommendation_allowed=False,environment_stable=False,
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
        result['decision_note']='实验期间配置或链路遥测不稳定/不完整；保留测量结果，但不推荐并发参数。'
    elif not result['recommendation_allowed']:
        result['selected_concurrency']=None
    return result


def write_csvs(root,result):
    batches=result.get('batches',[])
    with (root/'tuning_batches.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['concurrency','round','status','expected_bytes','actual_bytes','elapsed_s','aggregate_mbps','success','planned','ttfb_median_ms','error_categories','http_blocked']
        import csv
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for row in batches:w.writerow({k:row.get(k) for k in fields})
    workers=[dict(concurrency=b['concurrency'],round=b['round'],**w) for b in batches for w in b.get('worker_rows',[])]
    with (root/'tuning_workers.csv').open('w',encoding='utf-8-sig',newline='') as f:
        import csv
        fields=['concurrency','round','worker','status','expected_bytes','bytes','effective_mbps','ttfb_ms','total_ms','http_status','error_category','error']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for row in workers:w.writerow({k:row.get(k) for k in fields})
    with (root/'tuning_summary.csv').open('w',encoding='utf-8-sig',newline='') as f:
        import csv
        fields=['concurrency','planned_rounds','attempted_rounds','successful_rounds','median_mbps','p95_mbps','min_mbps','max_mbps','variation_ratio','ttfb_median_ms','eligible','quality_reasons']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader()
        for row in result.get('summary',[]):w.writerow({k:row.get(k) for k in fields})


def report_html(result):
    esc=lambda x:html.escape(str(x if x is not None else '—'))
    cols=('concurrency','attempted_rounds','successful_rounds','median_mbps','p95_mbps','ttfb_median_ms','eligible','quality_reasons')
    labels=('并发数','已测轮数','成功轮数','中位聚合 Mbps','P95 Mbps','TTFB 中位 ms','合格','质量原因')
    summary=result.get('summary',[])
    table='<table><tr>'+''.join('<th>'+x+'</th>' for x in labels)+'</tr>'+''.join('<tr>'+''.join('<td>'+esc(r.get(k))+'</td>' for k in cols)+'</tr>' for r in summary)+'</table>'
    batches=result.get('batches',[])
    batch_table='<table><tr><th>并发</th><th>轮次</th><th>状态</th><th>总耗时 s</th><th>聚合 Mbps</th><th>成功请求</th></tr>'+''.join('<tr>'+''.join('<td>'+esc(b.get(k))+'</td>' for k in ('concurrency','round','status','elapsed_s','aggregate_mbps','success'))+'</tr>' for b in batches)+'</table>'
    selected=result.get('selected_concurrency')
    return '<h2>自动并发参数寻优（应用层 HTTPS）</h2><p>状态：'+esc(result.get('status'))+'；建议并发：'+esc(selected)+'</p><p>'+esc(result.get('decision_note'))+'</p><p>每个候选每轮固定总正文预算 '+esc(result.get('aggregate_bytes_per_batch'))+' 字节；全程计划预算 '+esc(result.get('requested_budget_bytes'))+' 字节，实际预留 '+esc(result.get('reserved_bytes'))+' 字节。</p><p>候选顺序按轮随机化；聚合速度按整批墙钟时间计算，而非累加各工作线程的速度。环境稳定性：'+esc(result.get('environment_stable'))+'</p>'+table+'<h3>逐轮实验</h3>'+batch_table+'<p>只测试当前 HTTPS 路径，可能经过代理/TUN。结果不是 Wi-Fi 链路速率，也不能直接视为 yt-dlp -N 的最佳值。不会修改系统设置。</p>'
