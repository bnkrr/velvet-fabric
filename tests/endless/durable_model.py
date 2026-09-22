"""Cross-check saved agreements against host-owned identities and real WG state."""
import base64
import ipaddress
import time
import uuid

from model import NotConverged, prefix


def agreement(record):
    value = record['agreement_id']
    if not isinstance(value, str):
        raise AssertionError('durable agreement is not a UUID string')
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise AssertionError('durable agreement is not a canonical UUID') from exc
    if str(parsed) != value or parsed.version != 4:
        raise AssertionError('durable agreement is not a canonical UUIDv4')
    return value


def fixed(record, owner_uid):
    result = []
    endpoint = record['local'].get('recovery_endpoint')
    if endpoint:
        result.append((owner_uid, endpoint))
    endpoint = record['peer'].get('recovery_endpoint')
    if endpoint:
        result.append((record['peer']['uuid'], endpoint))
    return tuple(sorted(result))


def peer_key(record):
    value = record['peer']['public_key']
    if not isinstance(value, str):
        raise AssertionError('durable public key is not WireGuard Base64')
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise AssertionError('durable public key is not WireGuard Base64') from exc
    if len(decoded) != 32 or base64.b64encode(decoded).decode() != value:
        raise AssertionError('durable public key is not canonical WireGuard Base64')
    return value


class DurableAudit:
    def __init__(self, uids, pubs):
        self.uids, self.pubs = uids, pubs
        self.previous = {}
        self.recovering = {}

    def observe(self, topology, observations, now=None):
        now = time.monotonic() if now is None else now
        owners = {uid: node for node, uid in self.uids.items()}
        current = {}
        for node, obs in observations.items():
            records = obs.get('durable_records', [])
            by_peer = {}
            for record in records:
                uid = record['peer']['uuid']
                remote = owners.get(uid)
                if remote is None or remote == node or peer_key(record) != self.pubs[remote]:
                    raise AssertionError('durable store contains an unknown/mismatched peer')
                last_loopback = record['peer'].get('last_loopback')
                if (last_loopback and last_loopback != prefix(remote).split('/')[0]) or uid in by_peer:
                    raise AssertionError('durable store contains duplicate/wrong peer metadata')
                fields = fixed(record, self.uids[node])
                if not 1 <= len(fields) <= 2 or len({x[0] for x in fields}) != len(fields):
                    raise AssertionError('invalid durable recovery endpoint set')
                for owner, endpoint in fields:
                    host, port = endpoint.rsplit(':', 1)
                    ipaddress.ip_address(host.strip('[]'))
                    if owner not in (self.uids[node], uid) or not 1 <= int(port) <= 65535:
                        raise AssertionError('invalid durable endpoint owner/port')
                    if owner == self.uids[node] and int(port) != record['local']['listen_port']:
                        raise AssertionError('durable local recovery endpoint differs from saved port')
                key = (node, remote)
                value = agreement(record), fields
                old = self.previous.get(key)
                if old and old[0] == value[0] and old[1] != fields:
                    raise AssertionError('durable recovery endpoints mutated under the same agreement')
                current[key] = value
                by_peer[uid] = record
            runtime = obs['status']['runtime']
            reported = {item['peer']['uuid']: item for item in runtime.get('durable', [])}
            if (set(reported) != set(by_peer) or any(
                    reported[peer]['agreement_id'] != agreement(record)
                    or reported[peer]['confirmed'] != record['confirmed']
                    or fixed(reported[peer], self.uids[node]) != fixed(record, self.uids[node])
                    for peer, record in by_peer.items())):
                raise NotConverged(f'node {node}: durable status disagrees with disk')
            if runtime.get('durable_links', 0) != sum(bool(r['confirmed']) for r in records):
                raise NotConverged(f'node {node}: durable count disagrees with disk')
            if topology.modes[node] == 'off' and records:
                raise NotConverged(f'node {node}: off retained durable records')
            obs['durable_by_interface'], obs['durable_waiting'] = {}, []
            states = {link['interface']: link for link in runtime.get('links', [])}
            for name, link in obs['wg'].items():
                if not name.startswith('vdl-'):
                    continue
                matches = [r for r in records if any(p['public'] == peer_key(r) for p in link['peers'])]
                if not matches:
                    continue
                record = matches[0]
                if link['port'] != record['local']['listen_port']:
                    raise NotConverged(f'node {node}/{name}: WG port differs from durable store')
                obs['durable_by_interface'][name] = record
                if name in states and not states[name]['active']:
                    obs['durable_waiting'].append(name)
            choice = obs.get('automatic_ports', {})
            for name, link in obs['wg'].items():
                if not name.startswith('vdl-') or not link['port']:
                    continue
                span = choice.get('port_range')
                if span and not span['first'] <= link['port'] <= span['last']:
                    raise AssertionError('automatic WG listen port escaped configured range')
                if choice.get('listen_port', 0) and link['port'] != choice['listen_port']:
                    raise AssertionError('automatic WG listen port escaped fixed choice')
        for (node, remote), value in current.items():
            reverse = current.get((remote, node))
            if reverse is not None and reverse != value:
                raise NotConverged(f'durable agreement differs between {node} and {remote}')
        # Unlike fresh Dynamic discovery, saved endpoint validation may take the
        # production 30-minute failure window before returning to discovery.
        # Admit fallback only for matching, physically present saved receivers
        # at both live nodes. This is not permission to use an uncommitted Link.
        waiting = {}
        for node, obs in observations.items():
            obs['durable_recovery_peers'] = []
            for name in obs['durable_waiting']:
                record = obs['durable_by_interface'][name]
                remote = owners[record['peer']['uuid']]
                waiting[node, remote] = agreement(record)
        recovering = {}
        for (node, remote), identity in waiting.items():
            if remote not in topology.active or waiting.get((remote, node)) != identity:
                continue
            key = node, remote, identity
            since = self.recovering.get(key, now)
            if now - since > 1800 + 90:
                raise AssertionError('online durable recovery exceeded failure window and cleanup allowance')
            recovering[key] = since
            observations[node]['durable_recovery_peers'].append(remote)
        self.recovering = recovering
        self.previous.update(current)
