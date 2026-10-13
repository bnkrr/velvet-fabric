#!/usr/bin/env python3
"""Isolated systemd + kernel acceptance test. Run as root on a disposable VM."""
import hashlib, json, os, pathlib, shutil, socket, subprocess as sp, time, uuid, sys, signal, tempfile
R = pathlib.Path(sys.argv[1]).resolve()
T = R / 'packaging/systemd'
DYNAMIC = 'dynamic' in sys.argv[2:]
P = 'vr' + uuid.uuid4().hex[:5]
nodes = 'abc'
configs = {}
created = []

def run(*args, check=True, **kw):
    p = sp.run(args, text=True, capture_output=True, timeout=25, **kw)
    if check and p.returncode:
        raise RuntimeError(f'{args}: {p.stderr} {p.stdout}')
    return p.stdout.strip()

def ns(n, *args, **kw):
    return run('ip', 'netns', 'exec', P + '-' + n, *args, **kw)

def log(s):
    print(s, flush=True)

def wait(fn, timeout=45):
    end = time.monotonic() + timeout
    error = None
    while time.monotonic() < end:
        try:
            if fn():
                return
        except Exception as e:
            error = e
        time.sleep(0.5)
    raise RuntimeError(f'timeout: {error}')

def unit(n):
    return f'{P}-{n}.service'

def bu(n):
    return 'velvet-babel@' + configs[n]['node']['uid']['uuid'] + '.service'

def ctl(n, command='status', babel=False):
    uid = configs[n]['node']['uid']['uuid']
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(3)
        path = f'/run/velvet-babel/{uid}/babel-rs.ctl' if babel else f'/run/velvet/{uid}/velvetd.ctl'
        s.connect(path)
        with s.makefile('rwb') as f:
            f.readline()
            f.write(json.dumps(dict(api_version=1, id=1, command=command, params={})).encode() + b'\n')
            f.flush()
            reply = json.loads(f.readline())
            if not reply['ok']:
                raise RuntimeError(reply)
            return reply['result']

def pid(u):
    return int(run('systemctl', 'show', u, '-p', 'MainPID', '--value'))

def ping(n, target):
    return ' 0% packet loss' in ns(n, 'ping', '-n', '-c', '2', '-W', '1', '-I', f'fd78:ac10::{nodes.index(n) + 1}' if ':' in target else f'10.88.0.{nodes.index(n) + 1}', target, check=False)

def links(n):
    return {x['ifname']: x['ifindex'] for x in json.loads(ns(n, 'ip', '-j', 'link')) if x.get('ifalias', '').startswith('velvet:link:')}

def install_unit(name, body):
    path = pathlib.Path('/etc/systemd/system') / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    created.append(path)

def setup():
    keys = {n: run('wg', 'genkey') for n in nodes}
    pubs = {n: run('wg', 'pubkey', input=keys[n] + '\n') for n in nodes}
    psk = run('wg', 'genpsk')
    run('ip', 'link', 'add', P + '-br', 'type', 'bridge')
    run('ip', 'link', 'set', P + '-br', 'up')
    ports = {(a, b): 52000 + i for i, (a, b) in enumerate(((a, b) for a in nodes for b in nodes if a != b), 1)}
    for n in nodes:
        i = nodes.index(n) + 1
        run('ip', 'netns', 'add', P + '-' + n)
        run('ip', 'link', 'add', P + n + 'h', 'type', 'veth', 'peer', 'name', P + n + 'w')
        run('ip', 'link', 'set', P + n + 'h', 'master', P + '-br')
        run('ip', 'link', 'set', P + n + 'h', 'up')
        run('ip', 'link', 'set', P + n + 'w', 'netns', P + '-' + n)
        ns(n, 'ip', 'link', 'set', P + n + 'w', 'name', 'wan')
        ns(n, 'ip', 'addr', 'add', f'192.0.2.{i}/24', 'dev', 'wan')
        ns(n, 'ip', 'link', 'set', 'wan', 'up')
        ns(n, 'ip', 'link', 'set', 'lo', 'up')
        ns(n, 'ip', 'addr', 'add', f'10.88.0.{i}/32', 'dev', 'lo')
        ns(n, 'sysctl', '-qw', 'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.default.rp_filter=0', 'net.ipv4.ip_unprivileged_port_start=1024')
        peers = [dict(name=b, public_key=pubs[b], listen_port=ports[n, b], endpoints=[f'192.0.2.{nodes.index(b) + 1}:{ports[b, n]}'], interface_name=f'vl-{n}-{b}') for b in nodes if b != n and (not DYNAMIC or n == 'c' or b == 'c')]
        cfg = dict(api_version='velvet.io/v1alpha1', kind='NodeSpec', fabric=dict(psk=psk, loopback_prefix_v6='fd78:ac10::/48', announcements=[f'10.88.0.{i}/32']), node=dict(uid=dict(uuid=str(uuid.uuid4()), name=n), private_key=keys[n], loopback_address_v6=f'fd78:ac10::{i}'), peers=peers, babel=dict(enabled=True, executable=str(R / 'babel-rs')), dynamic_links=dict(mode='active' if DYNAMIC and n != 'c' else 'off', allow_candidate_prefixes=['192.0.2.0/24'], recovery_timeout_seconds=60), domains=dict(business=dict(table_id=20001, source_prefixes=['10.88.0.0/24'])))
        if not DYNAMIC:
            # NodeSpec allows privileged VFP ports. Exercise the packaged
            # service's bind capability; the dynamic scenario uses the default.
            cfg['fabric']['vfp_port'] = 443
        configs[n] = cfg
        cp = R / f'{n}.json'
        cp.write_text(json.dumps(cfg))
        cp.chmod(384)
        body = (T / 'velvetd.service').read_text().replace('ProtectHome=true', 'ProtectHome=false').replace(' velvet-recovery.timer', '').replace('/usr/bin/velvetd', str(R / 'velvetd')).replace('/etc/velvet/node.json', str(cp)).replace('ReadWritePaths=/etc/velvet', '').replace('WatchdogSec=60s', 'WatchdogSec=12s').replace('[Service]', f'[Service]\nNetworkNamespacePath=/run/netns/{P}-{n}').replace('--babel-systemd', '--babel-systemd --reconcile-interval 2s --recovery-window 45s --recovery-stable 10s')
        install_unit(unit(n), body)
        b = (T / 'velvet-babel@.service').read_text().replace('ProtectHome=true', 'ProtectHome=false').replace('/usr/bin/velvetd', str(R / 'velvetd')).replace('[Service]', f'[Service]\nNetworkNamespacePath=/run/netns/{P}-{n}')
        install_unit(bu(n), b.replace('%i', cfg['node']['uid']['uuid']))
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', *[unit(n) for n in nodes])
    wait(lambda: all((ctl(n)['runtime']['established_links'] >= len(configs[n]['peers']) and ctl(n)['runtime'].get('babel', {}).get('state') == 'running' for n in nodes)))
    wait(lambda: ping('a', 'fd78:ac10::2') and ping('a', '10.88.0.2'))
    assert all(run('systemctl', 'is-enabled', bu(n)) == 'enabled' for n in nodes)
    assert all('recovering_routes' in ctl(n, babel=True)['export'] for n in nodes), 'requires Babel FIB recovery build'
    log('PASS: independent packaged systemd units, initial dual-stack traffic')

def dynamic_test():
    wait(lambda: all((ctl(n)['runtime']['dynamic_links'] >= 1 for n in 'ab')), 90)
    original = {n: links(n) for n in 'ab'}
    interface = next((k for k in original['a'] if k.startswith('vdl-')))
    bp = pid(bu('a'))
    run('systemctl', 'stop', unit('b'))
    start = time.monotonic()
    time.sleep(35)
    assert links('a') == original['a'] and links('b') == original['b']
    assert ping('a', 'fd78:ac10::2') and ping('a', '10.88.0.2')
    log('PASS: dynamic control loss retains WG and forwarding beyond short PONG timeout')
    run('systemctl', 'restart', unit('a'))
    assert links('a') == original['a'] and pid(bu('a')) == bp
    wait(lambda: interface not in links('a'), 35)
    elapsed = time.monotonic() - start
    assert elapsed < 70, f'restart extended dynamic deadline: {elapsed}'
    assert 'vl-a-c' in links('a') and 'vl-b-c' in links('b')
    wait(lambda: ping('a', 'fd78:ac10::2') and ping('a', '10.88.0.2'), 60)
    log(f'PASS: dynamic long timeout across restart ({elapsed:.1f}s), static retained, Babel multihop recovery')
    run('systemctl', 'start', unit('b'))
    wait(lambda: all((ctl(n)['runtime']['dynamic_links'] >= 1 for n in 'ab')), 90)
    log('PASS: dynamic Link regrows after peer Fabric returns')

def test():
    ns('a', 'nft', 'add', 'table', 'inet', 'fault')
    ns('a', 'nft', 'add', 'chain', 'inet', 'fault', 'out', '{ type filter hook output priority 0; policy accept; }')
    ns('a', 'nft', 'add', 'rule', 'inet', 'fault', 'out', 'ip', 'daddr', '192.0.2.2', 'drop')
    ns('a', 'nft', 'add', 'chain', 'inet', 'fault', 'in', '{ type filter hook input priority 0; policy accept; }')
    ns('a', 'nft', 'add', 'rule', 'inet', 'fault', 'in', 'ip', 'saddr', '192.0.2.2', 'drop')
    wait(lambda: 'dev vl-a-c' in ns('a', 'ip', '-6', 'route', 'get', 'fd78:ac10::2'), 70)
    wait(lambda: ping('a', 'fd78:ac10::2') and ping('a', '10.88.0.2'), 70)
    routes = ns('a', 'ip', '-6', 'route', 'show', 'table', '20000')
    assert 'metric 131008' in routes
    log('PASS: finite multihop Babel beats retained direct fallback, IPv4/IPv6 traffic')
    ns('a', 'ip', '-6', 'route', 'add', 'fd78:ac10::3/128', 'dev', 'vl-a-c', 'src', 'fd78:ac10::1', 'table', '20000', 'proto', '202', 'metric', '1024')
    wait(lambda: 'metric 1024' not in ns('a', 'ip', '-6', 'route', 'show', 'table', '20000', 'exact', 'fd78:ac10::3/128'))
    run('systemctl', 'stop', unit('a'))
    run('systemctl', 'stop', bu('a'))
    ns('a', 'ip', '-6', 'route', 'add', 'unreachable', 'fd78:ac10::3/128', 'table', '20000', 'proto', '203', 'metric', '131070')
    assert 'dev vl-a-c' in ns('a', 'ip', '-6', 'route', 'get', 'fd78:ac10::3')
    assert ping('a', 'fd78:ac10::3')
    ns('a', 'ip', '-6', 'route', 'del', 'unreachable', 'fd78:ac10::3/128', 'table', '20000', 'proto', '203', 'metric', '131070')
    run('systemctl', 'start', unit('a'))
    wait(lambda: ctl('a')['runtime'].get('babel', {}).get('state') == 'running')
    wait(lambda: ping('a', 'fd78:ac10::2'))
    log('PASS: old adjacency metric migration; fallback beats same-prefix unreachable and works without Babel')
    before = links('c')
    bp = pid(bu('c'))
    run('systemctl', 'stop', unit('c'))
    time.sleep(35)
    assert links('c') == before and pid(bu('c')) == bp
    assert ping('a', 'fd78:ac10::2') and ping('a', '10.88.0.2')
    assert all(('25' in ns('c', 'wg', 'show', name, 'persistent-keepalive') for name in before))
    log('PASS: stopped relay Fabric beyond PONG timeout preserves WG, Babel and dual-stack forwarding')
    run('systemctl', 'start', unit('c'))
    wait(lambda: ctl('c')['runtime']['established_links'] == 2)
    assert links('c') == before and pid(bu('c')) == bp
    cp = pid(unit('c'))
    run('systemctl', 'kill', '-s', 'SIGKILL', '--kill-whom=main', unit('c'))
    wait(lambda: pid(unit('c')) not in (0, cp) and ctl('c')['ready'])
    assert links('c') == before and pid(bu('c')) == bp
    log('PASS: normal restart and SIGKILL adoption preserve interface indices and Babel PID')
    cp = pid(unit('c'))
    run('systemctl', 'kill', '-s', 'SIGSTOP', '--kill-whom=main', unit('c'))
    wait(lambda: pid(unit('c')) not in (0, cp) and ctl('c')['ready'], 45)
    assert links('c') == before and pid(bu('c')) == bp
    log('PASS: watchdog recovers stopped Fabric while preserving independent Babel and WG')
    cp = pid(unit('c'))
    assert 'recovering_routes' in ctl('c', babel=True)['export'], 'requires Babel FIB recovery build'
    ns('c', 'nft', 'add', 'table', 'inet', 'fib_test')
    for chain, hook in [('in', 'input'), ('out', 'output')]:
        ns('c', 'nft', 'add', 'chain', 'inet', 'fib_test', chain,
           '{ type filter hook ' + hook + ' priority 0; policy accept; }')
        ns('c', 'nft', 'add', 'rule', 'inet', 'fib_test', chain, 'udp', 'dport', '6696', 'drop')
    run('systemctl', 'kill', '-s', 'SIGKILL', '--kill-whom=main', bu('c'))
    wait(lambda: pid(bu('c')) not in (0, bp))
    wait(lambda: ping('a', 'fd78:ac10::2'))
    assert pid(unit('c')) == cp
    wait(lambda: ctl('c', babel=True)['export']['recovering_routes'] > 0)
    assert ping('a', 'fd78:ac10::2') and ping('a', '10.88.0.2')
    ns('c', 'nft', 'delete', 'table', 'inet', 'fib_test')
    expected = {'fd78:ac10::1/128', 'fd78:ac10::2/128', '10.88.0.1/32', '10.88.0.2/32'}
    def recovered():
        fresh = {route['destination'] for route in ctl('c', 'routes', babel=True)['routes']
                 if route.get('metric', 65535) < 65535}
        return expected <= fresh and ctl('c', babel=True)['export']['recovering_routes'] == 0
    wait(recovered, 240)
    assert ping('a', 'fd78:ac10::2') and ping('a', '10.88.0.2')
    log('PASS: Babel crash retains dual-stack forwarding with routing traffic blocked; fresh routes take over')
    ns('c', str(R / 'velvetd'), '--config', str(R / 'c.json'), '--recovery-check')
    assert links('c') == before
    configs['c']['babel']['enabled'] = False
    (R / 'c.json').write_text(json.dumps(configs['c']))
    ctl('c', 'reload')
    wait(lambda: pid(bu('c')) == 0)
    assert links('c') == before
    configs['c']['babel']['enabled'] = True
    (R / 'c.json').write_text(json.dumps(configs['c']))
    ctl('c', 'reload')
    wait(lambda: pid(bu('c')) > 0)
    log('PASS: explicit Babel disable/re-enable and cleanup/startup mutual exclusion')
    install_unit(unit('c') + '.d/no-restart.conf', '[Service]\nRestart=no\n')
    body = (T / 'velvet-recovery.service').read_text().replace('ProtectHome=true', 'ProtectHome=false').replace('/usr/bin/velvetd', str(R / 'velvetd')).replace('/etc/velvet/node.json', str(R / 'c.json')).replace('[Service]', f'[Service]\nNetworkNamespacePath=/run/netns/{P}-c')
    install_unit(P + '-recovery.service', body)
    install_unit(P + '-recovery.timer', '[Unit]\nDescription=Temporary recovery test\n[Timer]\nOnActiveSec=1s\nOnUnitActiveSec=2s\nAccuracySec=1s\n')
    run('systemctl', 'daemon-reload')
    time.sleep(15)
    ns('c', 'ip', 'link', 'add', 'foreign-wg', 'type', 'wireguard')
    ns('c', 'ip', 'link', 'set', 'foreign-wg', 'alias', 'velvet:link:' + str(uuid.uuid4()) + ':foreign')
    ns('c', 'ip', 'route', 'add', 'blackhole', '198.51.100.0/24', 'table', '30000', 'proto', '201')
    run('systemctl', 'kill', '-s', 'SIGKILL', '--kill-whom=main', unit('c'))
    run('systemctl', 'kill', '-s', 'SIGKILL', '--kill-whom=main', bu('c'))
    (R / 'c.json').write_text('{invalid')
    run('systemctl', 'start', P + '-recovery.timer')
    wait(lambda: not any((name.startswith('vl-') for name in links('c'))), 65)
    assert pid(bu('c')) == 0
    assert 'foreign-wg' in ns('c', 'ip', 'link', 'show') and '198.51.100.0/24' in ns('c', 'ip', 'route', 'show', 'table', '30000')
    assert pathlib.Path('/var/lib/velvet', configs['c']['node']['uid']['uuid']).is_dir()
    log('PASS: independent deadline cleanup survives daemon deaths/invalid config; preserves foreign resources and persistent state')

def cleanup():
    errors = []
    def attempt(*args):
        try:
            run(*args, check=False)
        except (OSError, sp.TimeoutExpired) as error:
            errors.append(str(error))
    units = [P + '-recovery.timer', P + '-recovery.service'] + [unit(n) for n in nodes] + [bu(n) for n in configs]
    for name in units:
        attempt('systemctl', 'stop', name)
    for n in configs:
        attempt('systemctl', 'disable', '--now', bu(n))
    for path in reversed(created):
        path.unlink(missing_ok=True)
        if path.parent.name.endswith('.d'):
            path.parent.rmdir()
    attempt('systemctl', 'daemon-reload')
    for name in units:
        attempt('systemctl', 'reset-failed', name)
    for n in nodes:
        attempt('ip', 'netns', 'del', P + '-' + n)
    attempt('ip', 'link', 'del', P + '-br')
    for n, cfg in configs.items():
        uid = cfg['node']['uid']['uuid']
        shutil.rmtree('/var/lib/velvet/' + uid, ignore_errors=True)
        shutil.rmtree('/run/velvet/' + uid, ignore_errors=True)
        shutil.rmtree('/run/velvet-babel/' + uid, ignore_errors=True)
        path = pathlib.Path('/var/lib/velvet/recovery') / (hashlib.sha256(str(R / f'{n}.json').encode()).hexdigest()[:32] + '.json')
        path.unlink(missing_ok=True)
        pathlib.Path(str(path) + '.lock').unlink(missing_ok=True)
    remaining = run('ip', 'netns', 'list')
    assert not any(line.split()[0].startswith(P + '-') for line in remaining.splitlines()), remaining
    assert all(run('systemctl', 'show', name, '-p', 'MainPID', '--value', check=False) in ('', '0') for name in units), 'test service still running after cleanup'
    if errors:
        raise RuntimeError('cleanup errors: ' + '; '.join(errors))

def preflight():
    if os.geteuid() != 0:
        raise RuntimeError('resilience E2E requires root on a disposable systemd VM')
    if pathlib.Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise RuntimeError('resilience E2E requires systemd as PID 1; use netns for the other suites')
    for tool in ('ip', 'wg', 'nft', 'ping', 'systemctl', 'sysctl'):
        if not shutil.which(tool):
            raise RuntimeError(f'missing required tool: {tool}')
    for path in (R / 'velvetd', R / 'babel-rs'):
        if not os.access(path, os.X_OK):
            raise RuntimeError(f'missing executable: {path}')
    for name in ('velvetd.service', 'velvet-babel@.service', 'velvet-recovery.service'):
        if not (T / name).is_file():
            raise RuntimeError(f'missing packaged systemd unit: {name}')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml') as config:
        config.write('shutdown_policy = "retain"\nrestart_recovery_seconds = 1\n'
                     '[[interfaces]]\nmatch = ["absent*"]\n'
                     '[export]\n[[export.views]]\ntable = 201\n')
        config.flush()
        run(str(R / 'babel-rs'), 'check', '--config', config.name)


def interrupted(signum, _frame):
    raise KeyboardInterrupt(f'interrupted by signal {signum}')


# Invalid dependencies fail before any namespaces or services are created.
preflight()
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
try:
    setup()
    dynamic_test() if DYNAMIC else test()
except BaseException:
    for n in configs:
        log(ns(n, 'ip', '-6', 'route', 'show', 'table', '20000', check=False))
        log(ns(n, 'ip', 'route', 'show', 'table', '20001', check=False))
        log(run('journalctl', '-u', unit(n), '-u', bu(n), '-n', '25', '--no-pager', check=False))
    raise
finally:
    cleanup()
