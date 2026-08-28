package link

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"sort"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	minimumDerivedPort = 20000
	derivedPortSpan    = 40000
)

var lowerBootstrap = netip.MustParsePrefix("fe80::1/64")
var higherBootstrap = netip.MustParsePrefix("fe80::2/64")

type Bootstrap struct {
	InterfaceName string
	ListenPort    int
	LocalAddress  netip.Prefix
	PeerAddress   netip.Addr
	Dialer        bool
	PresharedKey  wgtypes.Key
}

type Proposal struct {
	V4 netip.Prefix
	V6 netip.Prefix
}

func (p Proposal) Empty() bool { return !p.V4.IsValid() && !p.V6.IsValid() }

func DeriveBootstrap(fabricPSK []byte, localPrivate, peerPublic wgtypes.Key, localUID spec.NodeUID, peer spec.Peer) (Bootstrap, error) {
	localPublic := localPrivate.PublicKey()
	if localPublic == peerPublic {
		return Bootstrap{}, fmt.Errorf("peer WireGuard public key equals local public key")
	}
	lower := bytes.Compare(localPublic[:], peerPublic[:]) < 0
	localAddress, peerAddress := higherBootstrap, lowerBootstrap.Addr()
	if lower {
		localAddress, peerAddress = lowerBootstrap, higherBootstrap.Addr()
	}
	portDigest := digest(fabricPSK, []byte("velvet-fabric/wg-listen-port/v1"), localPublic[:], peerPublic[:])
	result := Bootstrap{
		InterfaceName: spec.InterfaceName(localUID, peer.Name, peer.PublicKey),
		ListenPort:    minimumDerivedPort + int(binary.BigEndian.Uint16(portDigest[:2]))%derivedPortSpan,
		LocalAddress:  localAddress,
		PeerAddress:   peerAddress,
		Dialer:        lower,
	}
	if peer.InterfaceName != "" {
		result.InterfaceName = peer.InterfaceName
	}
	if peer.ListenPort != nil {
		result.ListenPort = *peer.ListenPort
	}
	key, err := deriveWGLinkPSK(fabricPSK, localPublic, peerPublic)
	if err != nil {
		return Bootstrap{}, err
	}
	result.PresharedKey = key
	return result, nil
}

func DeriveLoopbackV6(fabricPSK []byte, uid uuid.UUID, v6Pool netip.Prefix, overrideV6 string) (netip.Addr, error) {
	v6 := deriveHost(v6Pool, digest(fabricPSK, []byte("velvet-fabric/loopback/v6/v1"), uid[:]))
	var err error
	if overrideV6 != "" {
		v6, err = netip.ParseAddr(overrideV6)
		if err != nil {
			return netip.Addr{}, err
		}
	}
	return v6, nil
}

func DeriveProposal(fabricPSK []byte, local, remote uuid.UUID, v4Pool, v6Pool netip.Prefix, overrides []string, attempt uint32) (Proposal, error) {
	ids := [][]byte{local[:], remote[:]}
	if bytes.Compare(ids[0], ids[1]) > 0 {
		ids[0], ids[1] = ids[1], ids[0]
	}
	var attemptBytes [4]byte
	binary.BigEndian.PutUint32(attemptBytes[:], attempt)
	var result Proposal
	if v4Pool.IsValid() {
		result.V4 = deriveSubnet(v4Pool, 30, digest(fabricPSK, []byte("velvet-fabric/link-prefix/v4/v1"), ids[0], ids[1], attemptBytes[:]))
	}
	if v6Pool.IsValid() {
		result.V6 = deriveSubnet(v6Pool, 126, digest(fabricPSK, []byte("velvet-fabric/link-prefix/v6/v1"), ids[0], ids[1], attemptBytes[:]))
	}
	for _, raw := range overrides {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return Proposal{}, err
		}
		if prefix.Addr().Is4() {
			result.V4 = prefix.Masked()
		} else {
			result.V6 = prefix.Masked()
		}
	}
	return result, nil
}

func EndpointAddresses(proposal Proposal, local, remote uuid.UUID) (localPrefixes []netip.Prefix, peerAddresses []netip.Addr) {
	localLower := bytes.Compare(local[:], remote[:]) < 0
	for _, prefix := range []netip.Prefix{proposal.V4, proposal.V6} {
		if !prefix.IsValid() {
			continue
		}
		first, second := prefix.Addr().Next(), prefix.Addr().Next().Next()
		localAddr, peerAddr := second, first
		if localLower {
			localAddr, peerAddr = first, second
		}
		localPrefixes = append(localPrefixes, netip.PrefixFrom(localAddr, prefix.Bits()))
		peerAddresses = append(peerAddresses, peerAddr)
	}
	return
}

func MatchesOverrides(proposal Proposal, overrides []string) bool {
	for _, raw := range overrides {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return false
		}
		if prefix.Addr().Is4() && proposal.V4 != prefix.Masked() {
			return false
		}
		if prefix.Addr().Is6() && proposal.V6 != prefix.Masked() {
			return false
		}
	}
	return true
}

func deriveWGLinkPSK(fabricPSK []byte, a, b wgtypes.Key) (wgtypes.Key, error) {
	keys := [][]byte{a[:], b[:]}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	info := append([]byte("velvet-fabric/wg-link-psk/v1\x00"), keys[0]...)
	info = append(info, keys[1]...)
	reader := hkdf.New(sha256.New, fabricPSK, nil, info)
	var result wgtypes.Key
	if _, err := io.ReadFull(reader, result[:]); err != nil {
		return wgtypes.Key{}, err
	}
	return result, nil
}

func digest(key []byte, values ...[]byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	for _, value := range values {
		_, _ = mac.Write([]byte{0})
		_, _ = mac.Write(value)
	}
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func deriveSubnet(pool netip.Prefix, bits int, entropy [32]byte) netip.Prefix {
	return netip.PrefixFrom(fillBits(pool, bits, entropy), bits).Masked()
}

func deriveHost(pool netip.Prefix, entropy [32]byte) netip.Addr {
	addr := fillBits(pool, pool.Addr().BitLen(), entropy)
	if addr.Is4() && pool.Bits() <= 30 {
		masked := netip.PrefixFrom(addr, pool.Bits()).Masked().Addr()
		if addr == masked {
			addr = addr.Next()
		}
	}
	return addr
}

func fillBits(pool netip.Prefix, targetBits int, entropy [32]byte) netip.Addr {
	addressBytes := append([]byte(nil), pool.Addr().AsSlice()...)
	for addressBit := pool.Bits(); addressBit < targetBits; addressBit++ {
		entropyBit := addressBit - pool.Bits()
		// SHA-256 is enough for the supported v4/v6 address width.
		value := entropy[(entropyBit/8)%len(entropy)] & (1 << (7 - entropyBit%8))
		mask := byte(1 << (7 - addressBit%8))
		if value == 0 {
			addressBytes[addressBit/8] &^= mask
		} else {
			addressBytes[addressBit/8] |= mask
		}
	}
	if pool.Addr().Is4() {
		var value [4]byte
		copy(value[:], addressBytes)
		return netip.AddrFrom4(value)
	}
	var value [16]byte
	copy(value[:], addressBytes)
	return netip.AddrFrom16(value)
}
