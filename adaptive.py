"""Bounded sampling policy; pilot data never enters the fixed-size comparison."""
import statistics
import math
import time

KIB=1024
PILOT=128*KIB
MIN_SIZE=64*KIB
MAX_EXTRA=2
PHASE_SECONDS=210
REQUEST_RESERVE_SECONDS=26


def choose_size(pilot, ceiling):
    rate=pilot.get('effective_mbps')
    if pilot.get('status')!='OK' or not rate or rate<=0:
        return MIN_SIZE
    # Aim for ~4 seconds total, choose a power of two at or below the ceiling.
    budget=min(ceiling,rate*1e6*4/8)
    return max(MIN_SIZE,2**int(math.log2(max(MIN_SIZE,budget))))


def quality(rows,minimum=3):
    good=[r for r in rows if r.get('status')=='OK' and isinstance(r.get('effective_mbps'),(int,float)) and r['effective_mbps']>0]
    speeds=[r['effective_mbps'] for r in good]
    reasons=[]
    if len(good)<minimum:reasons.append('INSUFFICIENT_SUCCESS')
    if not rows or len(good)/len(rows)<.8:reasons.append('LOW_COMPLETION_RATE')
    if speeds and max(speeds)>2*min(speeds):reasons.append('HIGH_VARIATION')
    if len({r.get('expected_bytes') for r in rows})>1:reasons.append('MIXED_SAMPLE_SIZE')
    if len({r.get('http_version') for r in good})>1:reasons.append('MIXED_PROTOCOL')
    return dict(usable=not reasons,reasons=reasons,success=len(good),attempted=len(rows),median_mbps=statistics.median(speeds) if speeds else None)


def sample_download(probe,stop,emit,rounds,ceiling,clock=time.monotonic):
    deadline=clock()+PHASE_SECONDS
    budget=PILOT+(rounds+MAX_EXTRA)*ceiling
    reserved=0; rows=[]; pilot=None; blocked=False
    def run(size,phase,n):
        nonlocal reserved,blocked
        if stop.is_set() or blocked or reserved+size>budget or clock()+REQUEST_RESERVE_SECONDS>deadline:return None
        reserved+=size
        emit(f'下载{phase} {n}：{size//KIB} KiB')
        r=probe(size);r.update(target='Cloudflare 下载',round=n,expected_bytes=size,phase=phase)
        if r.get('http_status') in (403,429):blocked=True
        return r
    pilot=run(PILOT,'pilot',0)
    size=choose_size(pilot or {},ceiling)
    for n in range(1,rounds+MAX_EXTRA+1):
        if n>rounds and quality(rows,rounds)['usable']:break
        row=run(size,'measurement',n)
        if row is None:break
        rows.append(row)
    q=quality(rows,rounds)
    if blocked:q['reasons'].append('HTTP_BLOCKED');q['usable']=False
    return dict(pilot=pilot,rows=rows,selected_bytes=size,requested_budget_bytes=budget,reserved_bytes=reserved,time_budget_seconds=PHASE_SECONDS,blocked=blocked,quality=q)
