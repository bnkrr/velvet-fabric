//go:build linux

package linux

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type endpointAttempt struct {
	index         int
	since         time.Time
	lastHandshake time.Time
}

func (b *Backend) applyBootstrapLink(client *wgctrl.Client, desired reconcile.LinkPlan) error {
	device, err := ensureOwnedWireGuardInterface(desired.InterfaceName, desired.OwnerAlias)
	if err != nil {
		return err
	}
	if err := reconcileBootstrapAddress(device, desired.BootstrapAddress); err != nil {
		return fmt.Errorf("assign bootstrap address: %w", err)
	}
	if err := netlink.LinkSetUp(device); err != nil {
		return fmt.Errorf("set interface up: %w", err)
	}
	current, err := client.Device(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("read current WireGuard device: %w", err)
	}
	peers := stalePeerRemovals(current.Peers, desired.PeerPublicKey)
	endpointIndex, changeEndpoint := b.endpointChoice(desired, current)
	var endpoint *net.UDPAddr
	if changeEndpoint {
		endpoint, err = net.ResolveUDPAddr("udp", desired.Endpoints[endpointIndex])
		if err != nil {
			return fmt.Errorf("resolve endpoint %q: %w", desired.Endpoints[endpointIndex], err)
		}
	}
	peer := wgtypes.PeerConfig{
		PublicKey: desired.PeerPublicKey, PresharedKey: &desired.PresharedKey, Endpoint: endpoint,
		ReplaceAllowedIPs: true, AllowedIPs: defaultAllowedIPs(), PersistentKeepaliveInterval: desired.Keepalive,
	}
	peers = append(peers, peer)
	privateKey, listenPort := desired.PrivateKey, desired.ListenPort
	config := wgtypes.Config{PrivateKey: &privateKey, ListenPort: &listenPort, Peers: peers}
	if err := client.ConfigureDevice(desired.InterfaceName, config); err != nil {
		return fmt.Errorf("configure WireGuard device: %w", err)
	}
	return nil
}

func stalePeerRemovals(peers []wgtypes.Peer, wanted wgtypes.Key) []wgtypes.PeerConfig {
	result := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		if peer.PublicKey != wanted {
			result = append(result, wgtypes.PeerConfig{PublicKey: peer.PublicKey, Remove: true})
		}
	}
	return result
}

func (b *Backend) endpointChoice(desired reconcile.LinkPlan, current *wgtypes.Device) (int, bool) {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	attempt, exists := b.attempts[desired.InterfaceName]
	var peer *wgtypes.Peer
	if len(current.Peers) == 1 && current.Peers[0].PublicKey == desired.PeerPublicKey {
		peer = &current.Peers[0]
	}
	changeEndpoint := peer == nil || peer.Endpoint == nil
	if !exists || attempt.index >= len(desired.Endpoints) {
		attempt = endpointAttempt{since: now}
		if peer != nil && peer.Endpoint != nil {
			matched := false
			for index, raw := range desired.Endpoints {
				resolved, err := net.ResolveUDPAddr("udp", raw)
				if err == nil && resolved.String() == peer.Endpoint.String() {
					attempt.index = index
					matched = true
					break
				}
			}
			// A fresh endpoint outside the configured list may be authenticated
			// WireGuard roaming. Preserve it across reconciliation.
			if !matched {
				changeEndpoint = endpointStale(peer.LastHandshakeTime, now, desired.Keepalive)
			}
		}
	}
	if peer != nil && peer.LastHandshakeTime.After(attempt.lastHandshake) {
		attempt.lastHandshake = peer.LastHandshakeTime
		attempt.since = now
	}
	if len(desired.Endpoints) > 1 && now.Sub(attempt.since) >= 15*time.Second && endpointStale(attempt.lastHandshake, now, desired.Keepalive) {
		attempt.index = (attempt.index + 1) % len(desired.Endpoints)
		attempt.since = now
		changeEndpoint = true
	}
	b.attempts[desired.InterfaceName] = attempt
	return attempt.index, changeEndpoint
}

func endpointStale(handshake, now time.Time, keepalive *time.Duration) bool {
	threshold := 3 * time.Minute
	if keepalive != nil && *keepalive*3 > threshold {
		threshold = *keepalive * 3
	}
	return handshake.IsZero() || now.Sub(handshake) >= threshold
}

func verifyBootstrapLink(client *wgctrl.Client, desired reconcile.LinkPlan) error {
	device, err := netlink.LinkByName(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("look up interface: %w", err)
	}
	if device.Type() != "wireguard" || device.Attrs().Alias != desired.OwnerAlias {
		return errors.New("interface type or ownership does not match")
	}
	if device.Attrs().Flags&net.FlagUp == 0 {
		return errors.New("interface is down")
	}
	addresses, err := netlink.AddrList(device, netlink.FAMILY_V6)
	if err != nil || !addressPresent(addresses, desired.BootstrapAddress) {
		return errors.New("bootstrap address is missing")
	}
	wgDevice, err := client.Device(desired.InterfaceName)
	if err != nil {
		return fmt.Errorf("read WireGuard device: %w", err)
	}
	if wgDevice.PublicKey != desired.PrivateKey.PublicKey() || wgDevice.ListenPort != desired.ListenPort {
		return errors.New("WireGuard local configuration does not match")
	}
	if len(wgDevice.Peers) != 1 || wgDevice.Peers[0].PublicKey != desired.PeerPublicKey || wgDevice.Peers[0].PresharedKey != desired.PresharedKey {
		return errors.New("WireGuard peer key material does not match")
	}
	if desired.Keepalive != nil && wgDevice.Peers[0].PersistentKeepaliveInterval != *desired.Keepalive {
		return errors.New("WireGuard persistent keepalive does not match")
	}
	return nil
}

func defaultAllowedIPs() []net.IPNet {
	return []net.IPNet{
		*prefixIPNet(netip.MustParsePrefix("0.0.0.0/0")),
		*prefixIPNet(netip.MustParsePrefix("::/0")),
	}
}
