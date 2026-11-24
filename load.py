"""Low-overhead physical-interface load sampling for experiment scheduling."""
from collections import deque
import datetime, math, threading, time
DEFAULT_INTERVAL_SECONDS=1.0
DEFAULT_IDLE_THRESHOLD_MBPS=0.5
DEFAULT_STABLE_INTERVALS=3
class LoadSampler:
    def __init__(self,sample_fn,interval=DEFAULT_INTERVAL_SECONDS,threshold_mbps=DEFAULT_IDLE_THRESHOLD_MBPS,stable_intervals=DEFAULT_STABLE_INTERVALS,max_samples=1200,clock=time.monotonic):
        if not callable(sample_fn):raise ValueError("sample_fn must be callable")
        if not isinstance(interval,(int,float)) or interval<=0:raise ValueError("interval must be positive")
        if not isinstance(threshold_mbps,(int,float)) or threshold_mbps<0:raise ValueError("threshold_mbps must be non-negative")
        if not isinstance(stable_intervals,int) or stable_intervals<1:raise ValueError("stable_intervals must be positive")
        self.sample_fn=sample_fn;self.interval=float(interval);self.threshold_mbps=float(threshold_mbps);self.stable_intervals=stable_intervals
        self.samples=deque(maxlen=max_samples);self.clock=clock;self.condition=threading.Condition();self.stop_event=threading.Event()
        self.thread=None;self._capture_lock=threading.Lock();self._previous=None;self._previous_finished=None
    def _capture(self):
        with self._capture_lock:
            try:
                raw=self.sample_fn()
                if not isinstance(raw,dict):raw={}
            except Exception as exc:
                now=self.clock();raw={"status":"Unavailable","reason":type(exc).__name__,"interfaces":[],"started":now,"finished":now}
            started=raw.get("started",self.clock());finished=raw.get("finished",self.clock())
            try:
                started=float(started);finished=float(finished)
                if not math.isfinite(started) or not math.isfinite(finished) or finished<started:raise ValueError
            except (TypeError,ValueError,OverflowError):started=finished=self.clock()
            physical={}
            for row in raw.get("interfaces",[]):
                if not isinstance(row,dict) or row.get("hardware") is not True or row.get("oper")!=1 or row.get("media_state")!=1:continue
                try:
                    key=(int(row["index"]),int(row["luid"]),int(row["type"]));rx=int(row["rx"]);tx=int(row["tx"])
                    if key[0]<=0 or key[1]<=0 or min(rx,tx)<0:continue
                except (KeyError,TypeError,ValueError,OverflowError):continue
                physical[key]=(rx,tx)
            record=dict(sample_index=0,captured_at=datetime.datetime.now().astimezone().isoformat(),finished=finished,
                capture_seconds=max(0.0,finished-started),source_status=raw.get("status","Unavailable"),source_reason=raw.get("reason"),
                interval_status="Unavailable",interval_seconds=None,rx_mbps=None,tx_mbps=None,total_mbps=None,
                active_physical_interfaces=len(physical),interfaces=[],reason="NO_ACTIVE_PHYSICAL_COUNTERS")
            if raw.get("status")=="Measured" and physical:
                previous=self._previous;previous_finished=self._previous_finished
                if previous is not None and set(previous)==set(physical):
                    elapsed=finished-previous_finished
                    if 0.5<=elapsed<=max(2.5,self.interval*2.5):
                        rx_total=tx_total=0;rows=[];valid=True
                        for key in sorted(physical):
                            old_rx,old_tx=previous[key];new_rx,new_tx=physical[key]
                            if new_rx<old_rx or new_tx<old_tx:valid=False;break
                            rx=new_rx-old_rx;tx=new_tx-old_tx;rx_total+=rx;tx_total+=tx
                            rows.append(dict(index=key[0],type=key[2],rx_bytes=rx,tx_bytes=tx,rx_mbps=rx*8/elapsed/1_000_000,tx_mbps=tx*8/elapsed/1_000_000))
                        if valid:
                            rx_mbps=rx_total*8/elapsed/1_000_000;tx_mbps=tx_total*8/elapsed/1_000_000
                            record.update(interval_status="Measured",interval_seconds=elapsed,rx_mbps=rx_mbps,tx_mbps=tx_mbps,total_mbps=rx_mbps+tx_mbps,interfaces=rows,reason=None)
                        else:record["reason"]="COUNTER_RESET"
                    else:record["reason"]="SAMPLE_INTERVAL_OUT_OF_RANGE"
                else:record["reason"]="FIRST_SAMPLE_OR_INTERFACE_SET_CHANGED"
                self._previous=physical;self._previous_finished=finished
            else:
                self._previous=None;self._previous_finished=None;record["reason"]=raw.get("reason") or "SOURCE_COUNTERS_UNAVAILABLE"
            with self.condition:
                record["sample_index"]=len(self.samples)+1;self.samples.append(record);self.condition.notify_all()
            return record
    def start(self):
        if self.thread and self.thread.is_alive():return self
        self.stop_event.clear();self._capture()
        def loop():
            next_tick=self.clock()+self.interval
            while not self.stop_event.is_set():
                if self.stop_event.wait(max(0.0,next_tick-self.clock())):return
                self._capture();now=self.clock();next_tick+=self.interval
                if next_tick<=now:next_tick=now+self.interval
        self.thread=threading.Thread(target=loop,name="ano-load-sampler",daemon=True);self.thread.start();return self
    def current_state(self,max_age_seconds=2.5):
        with self.condition:rows=list(self.samples)
        if not rows:return dict(status="UNAVAILABLE",idle=False,reason="NO_SAMPLES",threshold_mbps=self.threshold_mbps,required_intervals=self.stable_intervals)
        latest=rows[-1];age=self.clock()-latest["finished"];window=rows[-self.stable_intervals:]
        if age<0 or age>max_age_seconds:return dict(status="UNAVAILABLE",idle=False,reason="LATEST_SAMPLE_STALE",sample_age_seconds=max(0,age),threshold_mbps=self.threshold_mbps,required_intervals=self.stable_intervals)
        if len(window)<self.stable_intervals or any(r["interval_status"]!="Measured" for r in window):
            return dict(status="UNAVAILABLE",idle=False,reason="INSUFFICIENT_CONTIGUOUS_SAMPLES",sample_age_seconds=age,threshold_mbps=self.threshold_mbps,required_intervals=self.stable_intervals)
        rates=[r["total_mbps"] for r in window];idle=all(v<=self.threshold_mbps for v in rates)
        rx=sorted(r["rx_mbps"] for r in window);tx=sorted(r["tx_mbps"] for r in window)
        return dict(status="IDLE" if idle else "BUSY",idle=idle,median_total_mbps=sorted(rates)[len(rates)//2],max_total_mbps=max(rates),min_total_mbps=min(rates),
            median_rx_mbps=rx[len(rx)//2],median_tx_mbps=tx[len(tx)//2],interval_count=len(window),sample_age_seconds=age,
            threshold_mbps=self.threshold_mbps,required_intervals=self.stable_intervals,start_sample_index=window[0]["sample_index"],
            end_sample_index=window[-1]["sample_index"],active_physical_interfaces=max(r["active_physical_interfaces"] for r in window),
            scope="物理网卡总收发速率；包含所有应用与协议，不进行进程归因。")
    def wait_for_idle(self,stop,timeout_seconds):
        started=self.clock();deadline=started+max(0.0,float(timeout_seconds))
        while True:
            if stop is not None and stop.is_set():return dict(status="CANCELLED",waited_seconds=max(0,self.clock()-started))
            state=self.current_state()
            if state.get("idle"):return dict(state,status="IDLE_WINDOW",waited_seconds=max(0,self.clock()-started))
            remaining=deadline-self.clock()
            if remaining<=0:
                status="BUSY_TIMEOUT" if state.get("status")=="BUSY" else "LOAD_UNAVAILABLE_TIMEOUT"
                return dict(state,status=status,waited_seconds=max(0,self.clock()-started))
            with self.condition:self.condition.wait(timeout=min(.25,remaining))
    def evidence(self):
        with self.condition:samples=[dict(r) for r in self.samples]
        return dict(status="Measured" if any(r["interval_status"]=="Measured" for r in samples) else "Unavailable",
            sample_interval_seconds=self.interval,idle_threshold_mbps=self.threshold_mbps,required_consecutive_intervals=self.stable_intervals,
            sample_count=len(samples),measured_intervals=sum(r["interval_status"]=="Measured" for r in samples),
            unavailable_intervals=sum(r["interval_status"]!="Measured" for r in samples),total_capture_seconds=sum(r["capture_seconds"] for r in samples),
            samples=samples,scope="仅物理网卡累计计数差分；不识别应用、进程、目的地址或流量来源。")
    def close(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=max(2.0,self.interval*2.5))
