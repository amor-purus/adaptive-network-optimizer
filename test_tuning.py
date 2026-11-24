import threading
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import tuning as t
import core

def good(size):
    return dict(status='OK',bytes=size,effective_mbps=1,total_ms=1000,ttfb_ms=100,http_status=200,http_version='2',dns_ms=10,tcp_ms=10,tls_ms=100)

def fake_batch(exe,c,r,stop,probe=None,total_bytes=t.AGGREGATE_BYTES,clock=None,connect_timeout=5,retest=False,sample_plan=None):
    sizes=t.split_sizes(total_bytes,c); rows=[good(s) for s in sizes]
    return dict(concurrency=c,round=r,status='OK',expected_bytes=total_bytes,actual_bytes=total_bytes,elapsed_s=total_bytes*8/1e6/(1 if r==0 else c),
        aggregate_mbps=1 if r==0 else float(c),success=c,planned=c,ttfb_median_ms=100,
        connect_timeout_seconds=connect_timeout,http_blocked=False,worker_rows=rows,retest=retest)

class FakeObserver:
    t0=0
    def __init__(self,bad=()):
        self.labels=[];self.bad=set(bad)
    def mark(self,label):
        self.labels.append(label);return len(self.labels)-1
    def window(self,begin,end,started,finished):
        label=self.labels[begin]
        ok=label not in self.bad
        return dict(verified=ok,reasons=[] if ok else ['PAIR_TELEMETRY_OUTSIDE_POLICY'],begin_index=begin,end_index=end)

class FakeLoadMonitor:
    def __init__(self,status='IDLE_WINDOW'):self.status=status
    def wait_for_idle(self,stop,timeout):return dict(status=self.status,waited_seconds=0,median_total_mbps=.1 if self.status=='IDLE_WINDOW' else 2.0)
    def current_state(self):return dict(idle=self.status=='IDLE_WINDOW')

class TuningTests(unittest.TestCase):
    def run_fake(self,func=fake_batch,**kwargs):
        with patch('tuning.run_batch',side_effect=func):
            return t.run(threading.Event(),exe='curl',seed=4,clock=lambda:0,usage_mode=kwargs.pop('usage_mode','controlled'),**kwargs)
    def test_exact_split_and_invalid(self):
        for c in (1,2,4,8):
            sizes=t.split_sizes(t.AGGREGATE_BYTES,c)
            self.assertEqual(sum(sizes),t.AGGREGATE_BYTES)
            self.assertGreaterEqual(min(sizes),t.MIN_WORKER_BYTES)
            self.assertLessEqual(max(sizes)-min(sizes),1)
        with self.assertRaises(ValueError):t.split_sizes(1,8)
        with self.assertRaises(ValueError):t.split_sizes(1,0)
    def test_batch_concurrency(self):
        barrier=threading.Barrier(4)
        def probe(exe,url,expected,cap,stop):
            barrier.wait(timeout=3);return good(expected)
        b=t.run_batch('curl',4,1,threading.Event(),probe)
        self.assertEqual(b['success'],4);self.assertEqual(b['actual_bytes'],t.AGGREGATE_BYTES)
        self.assertGreater(b['aggregate_mbps'],0)
    def test_batch_failure(self):
        def probe(*args):return dict(status='Failed',bytes=0)
        b=t.run_batch('curl',2,1,threading.Event(),probe)
        self.assertIsNone(b['aggregate_mbps']);self.assertEqual(b['success'],0)
    def test_pilot_not_formal_and_controls_locked(self):
        r=self.run_fake()
        self.assertEqual(r['status'],'Completed');self.assertEqual(len(r['pairs']),9)
        self.assertEqual(len(r['batches']),18);self.assertEqual(r['pilot']['round'],0);self.assertEqual(len(r['pilots']),3)
        self.assertEqual({b['expected_bytes'] for b in r['batches']},{r['formal_plan']['total_bytes']})
        self.assertEqual({b['connect_timeout_seconds'] for b in r['batches']},{r['formal_plan']['connect_timeout_seconds']})
        self.assertEqual({b['max_time_seconds'] for b in r['batches']},{20})
        self.assertEqual(r['reserved_bytes'],t.PILOT_COUNT*t.PILOT_BYTES+sum(b['expected_bytes'] for b in r['batches']))
        self.assertLessEqual(r['reserved_bytes'],r['requested_budget_bytes'])
        self.assertIsNone(r['selected_concurrency']);self.assertEqual(r['provisional_concurrency'],8)
    def test_balanced_adjacent_pairs(self):
        r=self.run_fake()
        for i in range(0,len(r['batches']),2):
            a,b=r['batches'][i:i+2]
            self.assertEqual(a['pair_id'],b['pair_id']);self.assertIn(1,(a['concurrency'],b['concurrency']))
        for c in (2,4,8):
            order=[p['baseline_first'] for p in r['pairs'] if p['concurrency']==c]
            self.assertNotEqual(order[0],order[1]);self.assertEqual(order[0],order[2])
    def test_slow_pilot_adapts_candidates(self):
        p=dict(status='OK',actual_bytes=t.PILOT_BYTES,elapsed_s=t.PILOT_BYTES*8/1e6/.05,worker_rows=[good(t.PILOT_BYTES)])
        x=t.calibrate([p]*3,(1,2,4,8),t.MAX_TOTAL_BYTES)
        self.assertEqual(x['total_bytes'],128*1024);self.assertEqual(x['candidates'],[1,2])
        self.assertEqual(x['excluded_candidates'],[4,8])
    def test_timeout_frozen_and_bounded(self):
        for timing,expected in [(300,5),(3000,8),(30000,10)]:
            p=dict(status='OK',actual_bytes=t.PILOT_BYTES,elapsed_s=1,worker_rows=[dict(good(1),dns_ms=0,tcp_ms=0,tls_ms=timing)])
            self.assertEqual(t.calibrate([p]*3,(1,2),t.MAX_TOTAL_BYTES)['connect_timeout_seconds'],expected)
        self.assertEqual(t.calibrate([], (1,2),t.MAX_TOTAL_BYTES)['connect_timeout_seconds'],10)
    def test_reject_mismatched_workload(self):
        r=self.run_fake();a,b=sorted(r['batches'][:2],key=lambda x:x['concurrency'])
        b=dict(b,expected_bytes=b['expected_bytes']*2)
        self.assertIn('CONTROL_VARIABLE_MISMATCH',t.evaluate_pair(a,b,r['formal_plan'])['reasons'])
    def test_reject_nonadjacent_pair(self):
        r=self.run_fake();a,b=sorted(r['batches'][:2],key=lambda x:x['concurrency'])
        b=dict(b,sequence=b['sequence']+10)
        self.assertIn('PAIR_IDENTITY_INVALID',t.evaluate_pair(a,b,r['formal_plan'])['reasons'])
    def test_reject_mismatched_timeout_and_protocol(self):
        r=self.run_fake();a,b=sorted(r['batches'][:2],key=lambda x:x['concurrency'])
        b=dict(b,connect_timeout_seconds=10,worker_rows=[dict(w,http_version='1.1') for w in b['worker_rows']])
        p=t.evaluate_pair(a,b,r['formal_plan'])
        self.assertFalse(p['valid']);self.assertIn('HTTP_PROTOCOL_MISMATCH_OR_MISSING',p['reasons'])
        self.assertIn('CONTROL_VARIABLE_MISMATCH',p['reasons'])
    def test_paired_ratios_control_baseline_drift(self):
        r=self.run_fake();pairs=[dict(p,baseline_mbps=rate,candidate_mbps=2*rate,speedup=2)
          for p,rate in zip([x for x in r['pairs'] if x['concurrency']==2],[1,3,6])]
        s=t.summarize_pairs(pairs,[1,2],3)[0]
        self.assertTrue(s['eligible']);self.assertEqual(s['baseline_variation_ratio'],6)
        self.assertEqual(s['paired_median_speedup'],2)
    def test_reject_unstable_ratios(self):
        r=self.run_fake();pairs=[dict(p,speedup=x) for p,x in zip([p for p in r['pairs'] if p['concurrency']==2],[1,2,6])]
        self.assertIn('HIGH_PAIRED_VARIATION',t.summarize_pairs(pairs,[1,2],3)[0]['quality_reasons'])
    def test_score_no_saturation(self):
        r=self.run_fake();scores=[s['composite_score'] for s in r['summary']]
        self.assertEqual(scores,sorted(scores));self.assertEqual(len(set(scores)),3)
    def test_no_gain(self):
        def same(*a,**kw):
            b=fake_batch(*a,**kw);return dict(b,aggregate_mbps=1,elapsed_s=b['actual_bytes']*8/1e6)
        r=self.run_fake(same);self.assertEqual(r['provisional_concurrency'],1)
    def test_one_retest_keeps_failure(self):
        def flaky(*a,**kw):
            b=fake_batch(*a,**kw)
            if b['concurrency']==2 and b['round']==1:
                b.update(status='Failed',aggregate_mbps=None,success=0,actual_bytes=0)
            return b
        r=self.run_fake(flaky,candidates=(1,2))
        self.assertEqual(r['retest_status'],'Completed');self.assertEqual(len(r['pairs']),4)
        self.assertEqual(sum(p['valid'] for p in r['pairs']),3)
        self.assertEqual(r['summary'][0]['pair_completion_rate'],.75)
        self.assertTrue(r['summary'][0]['eligible'])
    def test_rate_limit_stops_pilot(self):
        def blocked(*a,**kw):return dict(fake_batch(*a,**kw),http_blocked=True)
        r=self.run_fake(blocked);self.assertEqual(r['status'],'Blocked');self.assertEqual(r['batches'],[])
    def test_budget_prevents_partial_pair_start(self):
        r=self.run_fake(phase_seconds=50);self.assertTrue(r['time_budget_exhausted'])
        self.assertEqual(r['batches'],[]);self.assertFalse(r['comparison_ready'])
    def test_missing_or_unstable_environment(self):
        r=self.run_fake()
        self.assertIsNone(t.apply_environment_gate(r,{})['selected_concurrency'])
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_complete=True,telemetry_observed_stable=False,tuning_telemetry_acceptable=True)
        self.assertIsNone(t.apply_environment_gate(r,e)['selected_concurrency'])
        r=self.run_fake(observer=FakeObserver())
        self.assertEqual(t.apply_environment_gate(r,e)['selected_concurrency'],8)
        e['observed_stable']=False
        self.assertIsNone(t.apply_environment_gate(r,e)['selected_concurrency'])
    def test_cancel(self):
        stop=threading.Event();stop.set()
        with self.assertRaises(core.Cancelled):t.run(stop,exe='curl')
    def test_median_pilot_and_safe_expansion(self):
        def pilot(speed):
            return dict(status='OK',actual_bytes=t.PILOT_BYTES,elapsed_s=t.PILOT_BYTES*8/1e6/speed,worker_rows=[good(t.PILOT_BYTES)])
        p=t.calibrate([pilot(.13),pilot(.15),pilot(5)],(1,2,4,8),t.MAX_TOTAL_BYTES)
        self.assertAlmostEqual(p['pilot_speed_mbps'],.15)
        self.assertEqual(p['candidates'],[1,2])
        p=t.calibrate([pilot(.15),pilot(.16),pilot(.17)],(1,2,4,8),t.MAX_TOTAL_BYTES)
        self.assertEqual(p['candidates'],[1,2,4]);self.assertTrue(p['exploration_expanded'])
    def test_raw_ratio_ignores_rounded_display(self):
        r=self.run_fake();a,b=sorted(r['batches'][:2],key=lambda x:x['concurrency'])
        b=dict(b,aggregate_mbps=999)
        p=t.evaluate_pair(a,b,r['formal_plan'])
        self.assertAlmostEqual(p['speedup'],a['elapsed_s']/b['elapsed_s'])
    def test_sequential_stops_when_resolved(self):
        r=self.run_fake()
        self.assertEqual(r['extra_pairs'],0);self.assertEqual(r['stop_reason'],'EVIDENCE_SUFFICIENT')
        self.assertEqual(r['evidence_level'],'SUPPORTED_WITHIN_TESTED_SCOPE')
    def test_mixed_evidence_gets_multiple_pairs(self):
        def mixed(*a,**kw):
            b=fake_batch(*a,**kw)
            if b['concurrency']==2:
                speed=1.2 if b['round']%2 else 1.0
                b.update(aggregate_mbps=speed,elapsed_s=b['actual_bytes']*8/1e6/speed)
            return b
        r=self.run_fake(mixed,candidates=(1,2),rounds=5)
        self.assertEqual(r['extra_pairs'],3);self.assertEqual(len(r['pairs']),8)
        self.assertFalse(r['comparison_ready']);self.assertEqual(r['evidence_level'],'TENTATIVE')
        self.assertEqual(r['stop_reason'],'CANDIDATE_PAIR_LIMIT')
    def test_irrecoverable_spread_stops_without_retry(self):
        def varying(*a,**kw):
            b=fake_batch(*a,**kw)
            if b['concurrency']==2:
                speed=4 if b['round']==1 else 1
                b.update(aggregate_mbps=speed,elapsed_s=b['actual_bytes']*8/1e6/speed)
            return b
        r=self.run_fake(varying,candidates=(1,2))
        self.assertEqual(r['extra_pairs'],0)
        self.assertEqual(r['summary'][0]['evidence_state'],'IRRECOVERABLE_SPREAD')
        self.assertEqual(r['stop_reason'],'NO_RECOVERABLE_CANDIDATE')
        self.assertFalse(r['comparison_ready'])
    def test_tentative_never_applied_even_stable(self):
        r=dict(comparison_ready=False,provisional_concurrency=2,evidence_level='TENTATIVE')
        e=dict(complete=True,observed_stable=True,telemetry_complete=True,tuning_telemetry_acceptable=True)
        self.assertIsNone(t.apply_environment_gate(r,e)['selected_concurrency'])
    def test_pilot_failures_prevent_formal_recommendation(self):
        calls=[]
        def partial(*a,**kw):
            b=fake_batch(*a,**kw)
            if b['round']==0:
                calls.append(1)
                if len(calls)>1:b.update(status='Failed',actual_bytes=0,aggregate_mbps=None,success=0)
            return b
        r=self.run_fake(partial,candidates=(1,2))
        self.assertEqual(r['formal_plan']['pilot_success_count'],1)
        self.assertEqual(r['formal_plan']['connect_timeout_seconds'],10)
        self.assertEqual(r['evidence_level'],'TENTATIVE')
        self.assertFalse(r['comparison_ready'])
    def test_global_extra_budget_and_fairness(self):
        def mixed(*a,**kw):
            b=fake_batch(*a,**kw)
            if b['concurrency']>1:
                speed=1.2 if b['round']%2 else 1
                b.update(aggregate_mbps=speed,elapsed_s=b['actual_bytes']*8/1e6/speed)
            return b
        r=self.run_fake(mixed,rounds=5)
        self.assertEqual(r['extra_pairs'],4)
        self.assertEqual(r['stop_reason'],'EXTRA_PAIR_LIMIT')
        self.assertEqual([s['attempted_rounds'] for s in r['summary']],[7,6,6])
        self.assertFalse(r['recommendation_allowed'])
        self.assertLessEqual(r['reserved_bytes'],r['requested_budget_bytes'])
    def test_contaminated_pair_is_retained_and_retested(self):
        o=FakeObserver(['pair_C2-R1_begin'])
        r=self.run_fake(candidates=(1,2),observer=o)
        self.assertEqual(r['extra_pairs'],1)
        self.assertEqual(len(r['pairs']),4)
        p=r['pairs'][0]
        self.assertTrue(p['measurement_valid']);self.assertFalse(p['environment_verified']);self.assertFalse(p['valid'])
        self.assertEqual(r['summary'][0]['pair_completion_rate'],.75)
        self.assertEqual(r['measurement_summary'][0]['paired_rounds'],4)
        self.assertEqual(r['summary'][0]['paired_rounds'],3)
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_changes=[])
        self.assertEqual(t.apply_environment_gate(r,e)['selected_concurrency'],2)

    def test_pilot_radio_change_not_global_radio_veto(self):
        r=self.run_fake(candidates=(1,2),observer=FakeObserver(['tuning_pilot_begin']))
        self.assertFalse(r['pilot_environment']['verified'])
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_complete=True,
               tuning_telemetry_acceptable=False,telemetry_changes=[dict(field='signal_percent')])
        gated=t.apply_environment_gate(r,e)
        self.assertEqual(gated['selected_concurrency'],2)
        self.assertEqual(gated['environment_evidence_level'],'GLOBAL_GUARD_PASSED')
        e['telemetry_changes'].append(dict(field='Status'))
        gated=t.apply_environment_gate(r,e)
        self.assertIsNone(gated['selected_concurrency'])
        self.assertEqual(gated['measurement_evidence_level'],'SUPPORTED_WITHIN_TESTED_SCOPE')
        self.assertEqual(gated['environment_evidence_level'],'INSUFFICIENT')

    def test_missing_local_coverage_never_recommends(self):
        r=self.run_fake(candidates=(1,2),observer=FakeObserver(['pair_C2-R%d_begin'%n for n in range(1,7)]))
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_changes=[])
        self.assertFalse(r['pair_environment_coverage_ok'])
        self.assertIsNone(t.apply_environment_gate(r,e)['selected_concurrency'])
        self.assertEqual(r['measurement_evidence_level'],'SUPPORTED_WITHIN_TESTED_SCOPE')

    def test_batch_timestamps_and_boundary_budget(self):
        r=self.run_fake(candidates=(1,2),observer=FakeObserver())
        self.assertTrue(all('started_at_utc' in b and 'finished_elapsed_s' in b for b in r['batches']+r['pilots']))
        r=self.run_fake(candidates=(1,2),observer=FakeObserver(),phase_seconds=135)
        self.assertTrue(r['time_budget_exhausted']);self.assertEqual(r['batches'],[])

    def test_real_monitor_integration_without_network(self):
        import monitor
        snap=dict(interfaces=[dict(InterfaceIndex=16,AddressFamily=2)],dns=[],routes=[],
                  adapter_status='Measured',adapters=[dict(Name='WLAN',ifIndex=16,Status='Up',MediaConnectionState=1)])
        wlan=dict(status='Measured',interfaces=[dict(name='WLAN',signal_percent=99,rx_mbps=866.7,tx_mbps=866.7)])
        observer=monitor.Monitor(reader=lambda:snap,wlan=lambda:wlan)
        observer.checkpoint('after_performance','tuning')
        observer.start_load_sampler=lambda:FakeLoadMonitor()
        with patch('tuning.run_batch',side_effect=fake_batch):
            r=t.run(threading.Event(),exe='curl',seed=4,candidates=(1,2),observer=observer,usage_mode='controlled')
        observer.checkpoint('after_tuning','done')
        self.assertEqual(len(r['pairs']),3)
        for p in r['pairs']:
            e=p['environment'];self.assertTrue(e['verified'])
            before=observer.records[e['begin_index']];after=observer.records[e['end_index']]
            self.assertLessEqual(before['capture_end_s'],e['started_elapsed_s'])
            self.assertLessEqual(e['finished_elapsed_s'],after['capture_start_s'])
        gated=t.apply_environment_gate(r,observer.evidence('tuning'))
        self.assertEqual(gated['selected_concurrency'],2)
        self.assertEqual(gated['environment_evidence_level'],'GLOBAL_GUARD_PASSED')

    def test_shared_mode_is_observation_not_formal_recommendation(self):
        r=self.run_fake(candidates=(1,2),observer=FakeObserver(),usage_mode='shared')
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_changes=[])
        gated=t.apply_environment_gate(r,e)
        self.assertEqual(gated['shared_load_observation_concurrency'],2)
        self.assertIsNone(gated['selected_concurrency'])
        self.assertFalse(gated['recommendation_allowed'])
        self.assertEqual(gated['evidence_level'],'TENTATIVE')

    def test_native_state_change_blocks_even_if_full_snapshots_stable(self):
        r=self.run_fake(candidates=(1,2),observer=FakeObserver())
        r['batches'][0]['traffic']=dict(status='Unavailable',interfaces=[dict(index=16,reason='INTERFACE_STATE_CHANGED')])
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_changes=[])
        gated=t.apply_environment_gate(r,e)
        self.assertFalse(gated['recommendation_allowed'])
        self.assertFalse(gated['global_environment_guard_passed'])
        self.assertEqual(len(gated['native_state_changes']),1)

    def test_controlled_mode_stops_when_no_idle_window(self):
        observer=FakeObserver();observer.start_load_sampler=lambda:FakeLoadMonitor('BUSY_TIMEOUT')
        with patch('tuning.run_batch',side_effect=fake_batch):
            r=t.run(threading.Event(),exe='curl',seed=4,candidates=(1,2),observer=observer,usage_mode='controlled')
        self.assertEqual(r['stop_reason'],'LOAD_WINDOW_UNAVAILABLE');self.assertEqual(r['pilots'],[]);self.assertEqual(r['batches'],[])
        self.assertFalse(r['recommendation_allowed'])

    def test_shared_busy_window_is_retained_but_not_comparable(self):
        observer=FakeObserver();observer.start_load_sampler=lambda:FakeLoadMonitor('BUSY_TIMEOUT')
        with patch('tuning.run_batch',side_effect=fake_batch):
            r=t.run(threading.Event(),exe='curl',seed=4,candidates=(1,2),observer=observer,usage_mode='shared')
        self.assertEqual(len(r['pilots']),3);self.assertTrue(all(not p['load_window_verified'] for p in r['pilots']))
        self.assertTrue(r['pairs']);self.assertTrue(all(not p['valid'] for p in r['pairs']))
        self.assertFalse(r['load_window_coverage_ok'])
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_changes=[])
        self.assertFalse(t.apply_environment_gate(r,e)['recommendation_allowed'])

    def test_independent_elimination_does_not_certify_global_optimum(self):
        def varying(*a,**kw):
            b=fake_batch(*a,**kw)
            if b['concurrency']==8:
                speed=8 if b['round']==1 else 1
                b.update(aggregate_mbps=speed,elapsed_s=b['actual_bytes']*8/1e6/speed)
            return b
        r=self.run_fake(varying,observer=FakeObserver())
        self.assertEqual([p['round'] for p in r['pairs'] if p['concurrency']==8],[1,2])
        self.assertEqual(r['eliminated_candidates'][0]['skipped_formal_pairs'],1)
        self.assertEqual(r['qualified_subset_candidates'],[1,2,4])
        self.assertEqual(r['qualified_subset_concurrency'],4)
        e=dict(complete=True,observed_stable=True,adapter_state_coverage=True,telemetry_changes=[])
        gated=t.apply_environment_gate(r,e)
        self.assertTrue(gated['qualified_subset_environment_verified'])
        self.assertFalse(gated['recommendation_allowed'])
        self.assertIsNone(gated['selected_concurrency'])
        e['observed_stable']=False
        self.assertFalse(t.apply_environment_gate(r,e)['qualified_subset_environment_verified'])
        self.assertFalse(r['comparison_ready'])
        self.assertIsNone(r['selected_concurrency'])
    def test_local_evidence_survives_another_candidates_failure(self):
        def mixed(*a,**kw):
            b=fake_batch(*a,**kw)
            if b['concurrency']==4:
                b.update(status='Failed',actual_bytes=0,aggregate_mbps=None,success=0)
            return b
        r=self.run_fake(mixed,candidates=(1,2,4),observer=FakeObserver())
        gated=t.apply_environment_gate(r,dict(complete=True,observed_stable=True,
            adapter_state_coverage=True,telemetry_changes=[]))
        local={x['concurrency']:x for x in gated['candidate_local_evidence']}
        self.assertTrue(local[2]['local_evidence_certified'])
        self.assertFalse(local[4]['local_evidence_certified'])
        self.assertTrue(gated['global_environment_guard_passed'])
        self.assertFalse(gated['recommendation_allowed'])
        self.assertEqual(gated['qualified_subset_locally_certified'],[2])

    def test_global_configuration_gate_does_not_erase_local_candidate_evidence(self):
        r=self.run_fake(candidates=(1,2),observer=FakeObserver())
        gated=t.apply_environment_gate(r,dict(complete=True,observed_stable=False,
            adapter_state_coverage=True,telemetry_changes=[]))
        self.assertTrue(gated['candidate_local_evidence'][0]['local_evidence_certified'])
        self.assertFalse(gated['global_environment_guard_passed'])
        self.assertFalse(gated['recommendation_allowed'])
        self.assertEqual(gated['candidate_local_evidence'][0]['evidence_state'],'SUPPORTED_GAIN')

    def test_candidate_load_failure_is_not_a_global_load_veto(self):
        class CandidateLoad(FakeLoadMonitor):
            def __init__(self):super().__init__();self.calls=0
            def wait_for_idle(self,stop,timeout):
                self.calls+=1
                status='BUSY_TIMEOUT' if self.calls==8 else 'IDLE_WINDOW'
                return dict(status=status,waited_seconds=0,median_total_mbps=.1 if status=='IDLE_WINDOW' else 2.0)
        observer=FakeObserver()
        load=CandidateLoad()
        observer.start_load_sampler=lambda:load
        r=self.run_fake(candidates=(1,2,4),observer=observer,usage_mode='shared')
        gated=t.apply_environment_gate(r,dict(complete=True,observed_stable=True,
            adapter_state_coverage=True,telemetry_changes=[]))
        self.assertTrue(gated['pilot_load_environment_guard_passed'])
        self.assertTrue(gated['global_environment_guard_passed'])
        self.assertFalse(gated['recommendation_allowed'])
        self.assertTrue(any(not x['load_coverage_passed'] for x in gated['candidate_local_evidence']))

    def test_load_isolation_marks_all_batches_but_does_not_split_pairs(self):
        class Marker(FakeLoadMonitor):
            def __init__(self):super().__init__();self.events=[]
            def begin_experiment(self):self.events.append('begin');return dict(idle=True)
            def end_experiment(self):self.events.append('end')
        o=FakeObserver();mark=Marker();o.start_load_sampler=lambda:mark
        r=self.run_fake(observer=o,candidates=(1,2))
        self.assertEqual(mark.events,['begin','end']*9)
        self.assertTrue(all(b['load_isolation_marked'] for b in r['pilots']+r['batches']))
        self.assertEqual(len(r['load_schedule']),6)
    def test_raw_measurement_retained_under_busy_load(self):
        o=FakeObserver();o.start_load_sampler=lambda:FakeLoadMonitor('BUSY_TIMEOUT')
        r=self.run_fake(observer=o,candidates=(1,2),usage_mode='shared')
        self.assertTrue(all(p['measurement_valid'] and not p['valid'] for p in r['pairs']))
        self.assertGreater(r['measurement_summary'][0]['paired_rounds'],0)
        self.assertFalse(r['comparison_ready'])
    def test_traffic_alignment_checks_entire_counter_envelope(self):
        before=dict(started=1.,finished=1.01);after=dict(started=2.01,finished=2.02)
        self.assertEqual(t.traffic_alignment(before,after,1.02,2.)['window_alignment'],'ALIGNED')
        self.assertEqual(t.traffic_alignment(dict(before,started=.5),after,1.02,2.)['window_alignment'],'UNVERIFIED_OR_WIDE')
        self.assertEqual(t.traffic_alignment(before,dict(after,started=1.99),1.02,2.)['window_alignment'],'UNVERIFIED_OR_WIDE')
        self.assertEqual(t.traffic_alignment({},after,1.02,2.)['window_alignment'],'UNVERIFIED_OR_WIDE')
    def test_exports(self):
        r=self.run_fake();r['decision_note']='<script>'
        with tempfile.TemporaryDirectory() as d:
            t.write_csvs(Path(d),r)
            self.assertTrue((Path(d)/'tuning_pairs.csv').exists())
            self.assertTrue((Path(d)/'tuning_load_schedule.csv').exists())
            self.assertIn('&lt;script&gt;',t.report_html(r))
if __name__=='__main__':unittest.main()
