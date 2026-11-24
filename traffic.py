"""Read-only native interface statistics. No packet or process inspection."""
import ctypes as c
import os
import time
U32=c.c_uint32;U64=c.c_uint64
class GUID(c.Structure):
    _fields_=[('a',U32),('b',c.c_uint16),('c',c.c_uint16),('d',c.c_ubyte*8)]
class IfRow(c.Structure):
    _fields_=[('luid',U64),('index',U32),('guid',GUID),('alias',c.c_uint16*257),
        ('description',c.c_uint16*257),('address_length',U32),('address',c.c_ubyte*32),
        ('permanent_address',c.c_ubyte*32)]+[(n,U32) for n in
        ('mtu','type','tunnel','media','physical_medium','access','direction')]+[
        ('flags',c.c_ubyte),('oper',U32),('admin',U32),('media_state',U32),
        ('network_guid',GUID),('connection',U32)]+[(n,U64) for n in
        ('tx_link','rx_link','in_octets','in_ucast','in_nucast','in_discards','in_errors','in_unknown',
        'in_ucast_octets','in_multicast_octets','in_broadcast_octets','out_octets','out_ucast','out_nucast',
        'out_discards','out_errors','out_ucast_octets','out_multicast_octets','out_broadcast_octets','out_queue')]
def sample(indices,clock=time.monotonic):
    started=clock()
    result=dict(status='Unavailable',interfaces=[],errors=[],started=started,finished=started)
    try:
        if os.name!='nt':result['reason']='WINDOWS_REQUIRED';return result
        if c.sizeof(IfRow)!=1352 or IfRow.in_octets.offset!=1208 or IfRow.out_octets.offset!=1280:
            result['reason']='ABI_LAYOUT_UNVERIFIED';return result
        api=c.WinDLL('iphlpapi.dll').GetIfEntry2
        api.argtypes=[c.POINTER(IfRow)];api.restype=U32
        for i in sorted(set(indices)):
            if not isinstance(i,int) or not 0<i<2**32:continue
            row=IfRow();row.index=i
            code=api(c.byref(row))
            if code or row.index!=i:
                result['errors'].append(dict(index=i,error=int(code)));continue
            result['interfaces'].append(dict(index=i,luid=int(row.luid),rx=int(row.in_octets),tx=int(row.out_octets),
                type=int(row.type),hardware=bool(row.flags&1),oper=int(row.oper),media_state=int(row.media_state)))
        result['status']='Measured' if result['interfaces'] and not result['errors'] else 'Partial' if result['interfaces'] else 'Unavailable'
        if not result['interfaces']:result['reason']='NO_COUNTERS'
    except (OSError,AttributeError,TypeError,ValueError,OverflowError):
        result['reason']='NATIVE_QUERY_FAILED';result['status']='Partial' if result['interfaces'] else 'Unavailable'
    finally:result['finished']=clock()
    return result

def delta(before,after,body_bytes=0):
    a={r['index']:r for r in before.get('interfaces',[])}
    b={r['index']:r for r in after.get('interfaces',[])}
    elapsed=after['finished']-before['started'];rows=[]
    for i in sorted(set(a)|set(b)):
        x,y=a.get(i),b.get(i);out=dict(index=i,status='Unavailable')
        if x is None or y is None:out['reason']='MISSING_ENDPOINT'
        elif x['luid']!=y['luid'] or x['type']!=y['type']:out['reason']='INTERFACE_IDENTITY_CHANGED'
        elif x['oper']!=y['oper'] or x['media_state']!=y['media_state']:out['reason']='INTERFACE_STATE_CHANGED'
        elif elapsed<=0 or y['rx']<x['rx'] or y['tx']<x['tx']:out['reason']='COUNTER_RESET_OR_INVALID_TIME'
        else:
            rx=y['rx']-x['rx'];tx=y['tx']-x['tx']
            out.update(status='Measured',rx_bytes=rx,tx_bytes=tx,rx_mbps=rx*8/elapsed/1e6,tx_mbps=tx*8/elapsed/1e6,
                       hardware=x['hardware'],type=x['type'],rx_to_test_body_ratio=rx/body_bytes if body_bytes>0 else None)
        rows.append(out)
    status='Measured' if rows and all(r['status']=='Measured' for r in rows) and before.get('status')==after.get('status')=='Measured' else 'Partial' if any(r['status']=='Measured' for r in rows) else 'Unavailable'
    return dict(status=status,interval_seconds=max(0,elapsed),capture_seconds=max(0,before['finished']-before['started'])+max(0,after['finished']-after['started']),
                test_body_bytes=body_bytes,interfaces=rows,before_status=before['status'],after_status=after['status'],
                before_errors=before.get('errors',[]),after_errors=after.get('errors',[]),before_reason=before.get('reason'),after_reason=after.get('reason'),
                scope='网卡累计流量差分，包括测速、其他应用、协议及代理开销；不跨网卡相加，不归因浏览器。')
