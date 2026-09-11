"""Real conntrack layers for nested NAT and shared-address hairpin cases."""
import json

from scenarios import data, assert_direct


def stop_translator(r, node):
    process = r.nat_processes.pop(node)
    process.terminate()
    process.wait(timeout=5)
    assert process.returncode == 0
    r.ns(f'r{node}', 'nft', 'delete', 'table', 'inet', 'velvet_nat')


def forwarding(r, node):
    r.ns(node, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')


def prepare(r, node):
    family = 'ip' if r.args.underlay == 'ipv4' else 'ip6'
    if r.kind == 'nested-nat' and node == 2:
        inner = 'r100'
        r.routers.add(100)
        r.make_namespace(inner)
        # Moving a link between namespaces clears its L3 configuration; restore
        # the old client address as the inner translation's external address.
        r.ip(node, 'link', 'set', 'lan', 'netns', r.namespace(inner), 'name', 'wan')
        r.ip(inner, 'link', 'set', 'wan', 'up')
        r.ip(inner, 'addr', 'add', r.lan(2, 2) + ('/24' if family == 'ip' else '/64'), 'dev', 'wan')
        root, other = 'vin' + r.token, 'vic' + r.token
        r.run('ip', 'link', 'add', root, 'type', 'veth', 'peer', 'name', other)
        r.root_links.update((root, other))
        for owner, device in ((node, root), (inner, other)):
            r.run('ip', 'link', 'set', device, 'netns', r.namespace(owner), 'name', 'lan')
            r.root_links.discard(device)
            r.ip(owner, 'link', 'set', 'lan', 'up')
        client = '10.99.2.2' if family == 'ip' else 'fd42:99:2::2'
        gateway = '10.99.2.1' if family == 'ip' else 'fd42:99:2::1'
        width = '/24' if family == 'ip' else '/64'
        r.ip(node, 'addr', 'add', client + width, 'dev', 'lan')
        r.ip(inner, 'addr', 'add', gateway + width, 'dev', 'lan')
        flag = '-4' if family == 'ip' else '-6'
        r.ip(node, flag, 'route', 'replace', 'default', 'via', gateway)
        r.ip(inner, flag, 'route', 'add', 'default', 'via', r.lan(2, 1))
        forwarding(r, inner)
        r.ns(inner, 'nft', '-f', '-', input=f'''table {family} nested {{
 counter translated {{ }}
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
 oifname "wan" meta l4proto udp counter name translated snat to {r.lan(2, 2)}
 }}
 chain forward {{ type filter hook forward priority filter; policy accept; }}
}}''')
    if r.kind == 'shared-nat':
        # Disjoint local ephemeral pools let the hairpin forwarding rule be
        # explicit and deterministic; normal conntrack still does both SNATs.
        if node in (2, 3):
            r.ns(node, 'sysctl', '-qw', f'net.ipv4.ip_local_port_range={31000 if node == 2 else 31500} {31499 if node == 2 else 31999}')
        if node == 3:
            stop_translator(r, 2)
            stop_translator(r, 3)
            r.ip('r3', 'link', 'set', 'lan', 'netns', r.namespace('r2'), 'name', 'lan3')
            r.ip('r2', 'link', 'set', 'lan3', 'up')
            r.ip('r2', 'addr', 'add', r.lan(3, 1) + ('/24' if family == 'ip' else '/64'), 'dev', 'lan3')
            forwarding(r, 'r2')
            r.ns('r2', 'nft', '-f', '-', input=f'''table {family} shared {{
 counter translated {{ }}
 chain postrouting {{ type nat hook postrouting priority srcnat; policy accept;
 oifname "wan" meta l4proto udp counter name translated snat to {r.wan(2)}
 }}
 chain forward {{ type filter hook forward priority filter; policy accept; }}
 chain input {{ type filter hook input priority filter; policy accept; meta l4proto udp drop; }}
}}''')
            r.topology.extra_required.clear()


def exercise(r):
    r.verify()
    family = 'ip' if r.args.underlay == 'ipv4' else 'ip6'
    if r.kind == 'shared-nat':
        # The existing stable public-mediated path must work before hairpin is
        # enabled. Store its actual outcome rather than claiming all NATs forbid it.
        r.record('shared-wan-before-hairpin', pairs=r.coverage.state()['pairs'])
        data(r, label='shared-before-hairpin')
        r.ns('r2', 'nft', '-f', '-', input=f'''table {family} hairpin {{
 counter inward {{ }}
 counter outward {{ }}
 chain prerouting {{ type nat hook prerouting priority dstnat; policy accept;
 {family} daddr {r.wan(2)} udp dport 31000-31499 counter name inward dnat to {r.lan(2, 2)}
 {family} daddr {r.wan(2)} udp dport 31500-31999 counter name inward dnat to {r.lan(3, 2)}
 }}
 chain postrouting {{ type nat hook postrouting priority 90; policy accept;
 oifname {{ "lan", "lan3" }} ct status dnat counter name outward snat to {r.wan(2)}
 }}
}}''')
        r.topology.extra_required.update(((2, 3), (3, 2)))
        r.verify()
        assert_direct(r, 2, 3)
        counters = json.loads(r.ns('r2', 'nft', '-j', 'list', 'table', family, 'hairpin'))
        values = {e['counter']['name']: e['counter']['packets'] for e in counters['nftables'] if 'counter' in e}
        assert values['inward'] and values['outward'], 'hairpin translation not exercised'
        r.save('hairpin-counters.json', counters)
    else:
        counters = json.loads(r.ns('r100', 'nft', '-j', 'list', 'table', family, 'nested'))
        assert sum(e.get('counter', {}).get('packets', 0) for e in counters['nftables']) > 0
        status = json.loads((r.runtime / 'nat-2.json').read_text())
        assert status['created'] > 0 and status['in'] > 0, 'outer translation did not forward traffic'
        r.save('nested-counters.json', {'inner': counters, 'outer': status})
    data(r, label=r.kind)
