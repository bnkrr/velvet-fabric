"""Underlay address families and evidence from actual forwarding endpoints."""
import ipaddress

from model import NotConverged


def families(mode):
    return {'ipv4': (4,), 'ipv6': (6,), 'dual': (4, 6)}[mode]


def candidate_order(mode, slot, birth):
    if mode != 'dual':
        return families(mode)
    # Rotate independent input configurations, including single-family hints
    # on a dual-stack listener. The selected WG family remains an observation.
    return ((4,), (6,), (4, 6), (6, 4))[(slot + birth) % 4]


def prefix(family):
    return '192.0.2.0/24' if family == 4 else '2001:db8:ee::/64'


def endpoint_family(endpoint):
    return f"ipv{ipaddress.ip_address(endpoint.rsplit(':', 1)[0].strip('[]')).version}"


def sampled_family(before, after):
    # A successful payload is attributed only to an unchanged selected WG hop.
    # Endpoint changes or counter resets during the probe invalidate the sample.
    if any(before[key] != after[key] for key in ('dev', 'public', 'endpoint')):
        raise NotConverged('underlay path changed during payload probe')
    if not before['handshake'] or not after['handshake']:
        raise NotConverged('underlay payload path has no WireGuard handshake')
    # Babel may route the reply through a different interface. This sample
    # attributes the outgoing direction; every ordered pair is probed separately.
    if after['tx'] <= before['tx'] or after['rx'] < before['rx']:
        raise NotConverged('underlay payload path did not send WireGuard bytes or counters reset')
    return endpoint_family(after['endpoint'])
