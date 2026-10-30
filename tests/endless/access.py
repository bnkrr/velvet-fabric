"""External WG Access clients and independent dual-stack return-path checks."""
import ipaddress
import json
import subprocess as sp

from model import NotConverged, is_retained_fallback, parse_wg, prefix as loopback_prefix
from underlay import families


def client(node, family):
    return f'10.100.{node}.2' if family == 4 else str(ipaddress.ip_address(f'fd30:100:{node:x}::2'))


def source_prefix(node, family):
    return f'10.100.{node}.0/24' if family == 4 else str(ipaddress.ip_network(f'fd30:100:{node:x}::/64'))


def service(node, family):
    return f'10.60.{node}.1' if family == 4 else str(ipaddress.ip_address(f'fd30:60:{node:x}::1'))


def service_prefix(node, family):
    return service(node, family) + ('/32' if family == 4 else '/128')


def configure(spec, node, size):
    spec['domains'] = {'access': {'source_table_id': 20001,
        'source_prefixes': [source_prefix(n, f) for f in (4, 6) for n in range(size)],
        'announcements': [source_prefix(node,f) for f in (4,6)] + [service_prefix(node, f) for f in (4, 6)]}}


def has_return_rule(rules, prefix):
    expected = ipaddress.ip_network(prefix)
    for rule in rules:
        dst = rule.get('dst', 'all')
        if dst == 'all':
            continue
        if '/' not in dst and 'dstlen' in rule:
            dst += '/' + str(rule['dstlen'])
        if (ipaddress.ip_network(dst, strict=False) == expected
                and str(rule.get('table')) == '20000'
                and str(rule.get('protocol')) == '201'):
            return True
    return False


def check_routes(routes, expected, label, retained=None):
    retained, expected, actual = retained or {}, set(expected), {}
    for route in routes:
        if route.get('type', 'unicast') != 'unicast':
            continue
        key = str(ipaddress.ip_network(route['dst'], strict=False))
        if route.get('dev') in retained:
            if not is_retained_fallback(route, retained):
                raise NotConverged(f'{label}: invalid route on retained Link: {route}')
            if key not in expected:
                continue  # A departed neighbor may keep its exact fallback.
        actual.setdefault(key, []).append(route)
    if set(actual) != expected:
        raise NotConverged(f'{label}: Access routes differ: {set(actual)} != {expected}')
    for key, options in actual.items():
        best = min(route.get('metric', 0) for route in options)
        if any(route.get('dev') in retained for route in options if route.get('metric', 0) == best):
            raise NotConverged(f'{label}: retained dead fallback is best path to {key}')


class Access:
    def __init__(self, runner):
        self.r = runner
        self.clients = set()
        self.public_keys = {}
        self.probes = 0

    def create(self, node):
        r, peer = self.r, f'a{node}'
        self.clients.add(node)
        r.make_namespace(peer)
        left, right = f'veg{r.token}{node:x}', f'vec{r.token}{node:x}'
        r.run('ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right)
        r.root_links.update((left, right))
        for owner, name, host in ((node, left, 1), (peer, right, 2)):
            r.run('ip', 'link', 'set', name, 'netns', r.namespace(owner), 'name', 'access-lan')
            r.root_links.discard(name)
            r.ip(owner, 'address', 'add', f'10.89.{node}.{host}/30', 'dev', 'access-lan')
            r.ip(owner, 'link', 'set', 'access-lan', 'up')
        keys = {}
        for role in ('gateway', 'client'):
            key = r.run('wg', 'genkey')
            path = r.runtime / f'access-{node}-{role}.key'
            path.write_text(key + '\n')
            keys[role] = path, r.run('wg', 'pubkey', input=key + '\n')
        self.public_keys[node] = {role: value[1] for role, value in keys.items()}
        for owner, role, remote, host in ((node, 'gateway', 'client', 1), (peer, 'client', 'gateway', 2)):
            r.ip(owner, 'link', 'add', 'access0', 'type', 'wireguard')
            allowed = ','.join(client(node, f) + ('/32' if f == 4 else '/128') for f in (4, 6)) if role == 'gateway' else '10.60.0.0/16,fd30:60::/32'
            r.ns(owner, 'wg', 'set', 'access0', 'private-key', str(keys[role][0]),
                 'listen-port', str(58000 + host), 'peer', keys[remote][1],
                 'allowed-ips', allowed, 'endpoint', f'10.89.{node}.{3-host}:{58000+3-host}',
                 'persistent-keepalive', '1')
            for f in (4, 6):
                addr = (f'10.100.{node}.{host}' if f == 4 else f'fd30:100:{node:x}::{host}')
                mask = ('/24' if f == 4 else '/64') if role == 'gateway' else ('/32' if f == 4 else '/128')
                r.ip(owner, f'-{f}', 'address', 'add', addr + mask, 'dev', 'access0')
            r.ip(owner, 'link', 'set', 'access0', 'up')
        for f, prefix in ((4, '10.60.0.0/16'), (6, 'fd30:60::/32')):
            r.ip(peer, f'-{f}', 'route', 'add', prefix, 'dev', 'access0')
        r.ip(node, 'link', 'add', 'service0', 'type', 'dummy')
        for f in (4, 6):
            r.ip(node, f'-{f}', 'address', 'add', service_prefix(node, f), 'dev', 'service0')
        r.ip(node, 'link', 'set', 'service0', 'up')
        r.ns(node, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
             'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0', 'net.ipv4.conf.access0.rp_filter=0')

    def remove(self, node):
        if node in self.clients:
            self.r.run('ip', 'netns', 'del', self.r.namespace(f'a{node}'))
            self.clients.remove(node)
            self.public_keys.pop(node, None)

    def observe(self, node, obs):
        r = self.r
        wg = obs['wg'].pop('access0', None)
        remote = parse_wg(r.ns(f'a{node}', 'wg', 'show', 'all', 'dump')).get('access0')
        keys = self.public_keys[node]
        for link, own, peer in ((wg, 'gateway', 'client'), (remote, 'client', 'gateway')):
            if (not link or link['public'] != keys[own] or len(link['peers']) != 1
                    or link['peers'][0]['public'] != keys[peer] or not link['peers'][0]['handshake']):
                raise NotConverged(f'node {node}: WG Access identity/handshake missing')
        expected = {client(node, f) + ('/32' if f == 4 else '/128') for f in (4, 6)}
        if set(wg['peers'][0]['allowed']) != expected or set(remote['peers'][0]['allowed']) != {'10.60.0.0/16', 'fd30:60::/32'}:
            raise AssertionError('WG Access AllowedIPs changed')
        if '%access0:6696' in obs['babel_sockets'] or '%access0]:6696' in obs['babel_sockets']:
            raise AssertionError('Babel attached to external Access')
        data = {'gateway': wg, 'client': remote, 'families': {}}
        for f in (4, 6):
            rules = json.loads(r.ip(node, f'-{f}', '-j', '-details', 'rule', 'show'))
            for n in range(r.topology.size):
                if not has_return_rule(rules, source_prefix(n, f)):
                    raise NotConverged(f'node {node}: missing managed Access return rule to {source_prefix(n, f)}')
            fabric = json.loads(r.ip(node, f'-{f}', '-j', 'route', 'show', 'table', '20000'))
            domain = json.loads(r.ip(node, f'-{f}', '-j', 'route', 'show', 'table', '20001'))
            known = {source_prefix(n, f) for n in range(r.topology.size)}
            access_routes = [x for x in fabric if x.get('dst') in known]
            reachable = r.topology.components()[node] - {node}
            check_routes(access_routes, [source_prefix(n, f) for n in reachable], f'node {node}/v{f} return')
            data['families'][f] = {'rules': rules, 'fabric': access_routes, 'domain': domain}
        # Both underlay families must stay outside the Domain selectors.
        for family in families(r.args.underlay):
            destination = '192.0.2.254' if family == 4 else '2001:db8:ee::fe'
            host_route = json.loads(r.ip(node, '-j', 'route', 'get', destination))[0]
            if str(host_route.get('table', 'main')) != 'main' or host_route.get('dev') not in ('wan', 'lan'):
                raise AssertionError('Access rules captured ordinary host traffic')
        obs['access'] = data
        known6 = {source_prefix(n, 6) for n in range(r.topology.size)}
        obs['fib'] = [x for x in obs['fib'] if x.get('dst') not in known6]

    def audit(self, observations):
        # Run after model.audit validates retained WG identity, commitment and
        # kernel incarnation. Domain views mirror the same neighbor fallbacks.
        components = self.r.topology.components()
        for node, obs in observations.items():
            reachable = components[node] - {node}
            for f in (4, 6):
                expected = [prefix(n, f) for n in reachable for prefix in (source_prefix, service_prefix)]
                if f == 6:
                    expected += [loopback_prefix(n) for n in reachable]
                check_routes(obs['access']['families'][f]['domain'], expected,
                             f'node {node}/v{f} domain', obs['retained_peers'])

    def probe(self, source, target):
        r = self.r
        for f in (4, 6):
            # Unsolicited service -> client traffic exercises return selectors,
            # independently of conntrack state from the client -> service ping.
            for owner, src, dst in ((target, service(target, f), client(source, f)),
                                    (f'a{source}', client(source, f), service(target, f))):
                result = sp.run(['ip', 'netns', 'exec', r.namespace(owner), 'ping', f'-{f}',
                    '-n', '-c', '1', '-W', '1', '-I', src, dst], capture_output=True, text=True, timeout=r.timeout(3))
                if result.returncode not in (0, 1, 2):
                    raise RuntimeError(f'Access ping tool failed: {result.stderr}')
                if result.returncode:
                    raise NotConverged(f'WG Access v{f} probe failed {src} -> {dst}: {result.stderr.strip()}')
                self.probes += 1
            route = json.loads(r.ip(target, f'-{f}', '-j', 'route', 'get', client(source, f), 'from', service(target, f)))[0]
            if str(route.get('table')) != '20000' or not route.get('dev', '').startswith(('vl-', 'vdl-')):
                raise NotConverged(f'WG Access v{f} return bypassed Fabric: {route}')
            route = json.loads(r.ip(source, f'-{f}', '-j', 'route', 'get', service(target, f),
                                   'from', client(source, f), 'iif', 'access0'))[0]
            if str(route.get('table')) != '20001' or not route.get('dev', '').startswith(('vl-', 'vdl-')):
                raise NotConverged(f'WG Access v{f} outbound bypassed Domain: {route}')
