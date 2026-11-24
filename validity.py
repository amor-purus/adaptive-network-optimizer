"""Conservative DNS experiment validity gate; no network or configuration writes."""
import ipaddress
import json
import re

FAKE_RANGE = ipaddress.ip_network('198.18.0.0/15')
TUN_NAME = re.compile(r'clash|mihomo|sing[- ]?box|wireguard|wintun|tailscale|zerotier|openvpn|(?:^|[^a-z])(?:vpn|tun|tap)(?:[^a-z]|$)|anyconnect|globalprotect', re.I)
ROUTE_PREFIXES = {'0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1'}


def fake_ip(value):
    try:
        return ipaddress.ip_address(value) in FAKE_RANGE
    except (ValueError, TypeError):
        return False


def public_answer(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4 and ip.is_global and not ip.is_multicast and not ip.is_reserved and not ip.is_unspecified
    except (ValueError, TypeError):
        return False


def indicators(snap):
    found = set()
    active = {i.get('InterfaceIndex'): i.get('InterfaceAlias', '') for i in snap.get('interfaces', [])}
    for i, name in active.items():
        if TUN_NAME.search(str(name)):
            found.add('活动代理/VPN 网卡：' + str(name))
    for d in snap.get('dns', []):
        if d.get('InterfaceIndex') in active and any(fake_ip(a) for a in d.get('ServerAddresses') or []):
            found.add('活动网卡 DNS 使用 198.18.0.0/15：' + str(d.get('InterfaceAlias', '')))
    for route in snap.get('routes', []):
        if route.get('DestinationPrefix') not in ROUTE_PREFIXES:
            continue
        name = str(active.get(route.get('InterfaceIndex'), ''))
        if fake_ip(route.get('NextHop')) or TUN_NAME.search(name):
            found.add('默认/半默认路由指向疑似代理：' + name + ' ' + str(route.get('DestinationPrefix')))
    return sorted(found)


def signature(snap):
    # Compare only collected configuration, ignoring enumeration order.
    return tuple(tuple(sorted(json.dumps(x, sort_keys=True, ensure_ascii=False) for x in snap.get(k, []))) for k in ('interfaces','dns','routes'))


def assess(rows, before, after, current):
    before = before or {}; after = after or {}
    reasons = []
    signals = sorted(set(indicators(before) + indicators(after)))
    fake = []; nonpublic = []; missing = []
    for row in rows:
        if row.get('status') != 'OK':
            continue
        answers = row.get('answers') or []
        if not answers:
            missing.append(row)
        elif any(fake_ip(a) for a in answers):
            fake.append(row)
        elif any(not public_answer(a) for a in answers):
            nonpublic.append(row)
    if fake: reasons.append('FAKE_IP_RESPONSE')
    if nonpublic: reasons.append('NON_PUBLIC_RESPONSE')
    if missing: reasons.append('MISSING_ANSWER_EVIDENCE')
    if signals: reasons.append('PROXY_OR_TUN_INDICATOR')
    complete = all(isinstance(s.get(k), list) for s in (before, after) for k in ('interfaces','dns','routes')) and bool(before.get('interfaces')) and bool(after.get('interfaces'))
    if not complete: reasons.append('SNAPSHOT_UNAVAILABLE')
    elif signature(before) != signature(after): reasons.append('NETWORK_CONFIGURATION_CHANGED')
    if not current: reasons.append('NO_CURRENT_DNS_BASELINE')
    mode = 'proxy_or_tun_suspected' if signals or fake else ('environment_unverified' if not complete or 'NETWORK_CONFIGURATION_CHANGED' in reasons else 'no_known_proxy_indicators')
    messages = {
        'FAKE_IP_RESPONSE':'公开域名返回 198.18.0.0/15，可能是 Fake-IP 或透明 DNS 接管；不能比较公网解析器。',
        'NON_PUBLIC_RESPONSE':'公开域名返回非公网 A 地址，不能据此比较真实公网解析器。',
        'MISSING_ANSWER_EVIDENCE':'成功样本缺少 A 记录证据。',
        'PROXY_OR_TUN_INDICATOR':'发现代理/VPN/TUN 网卡、DNS 或路由迹象，无法确认候选请求未被接管。',
        'SNAPSHOT_UNAVAILABLE':'实验前后网络快照不完整。',
        'NETWORK_CONFIGURATION_CHANGED':'DNS 实验前后采集的网络配置不同，控制变量条件未满足。',
        'NO_CURRENT_DNS_BASELINE':'未取得当前 IPv4 DNS 基线。',
    }
    return {'environment':mode,'recommendation_allowed':not reasons,'reason_codes':reasons,'messages':[messages[x] for x in reasons],
            'proxy_indicators':signals,'fake_ip_samples':len(fake),'non_public_samples':len(nonpublic),'missing_answer_samples':len(missing),
            'fake_ip_servers':sorted({r['server'] for r in fake}),'fake_ip_domains':sorted({r.get('domain','') for r in fake}),
            'scope':'仅检查已知迹象，不证明直连或解析器身份；TCP/MTU 仅代表当前实际路径。'}
