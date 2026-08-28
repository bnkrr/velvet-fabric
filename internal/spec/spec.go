package spec

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	APIVersion     = "velvet.io/v1alpha1"
	Kind           = "NodeSpec"
	DefaultVFPPort = 58420
)

var uidNamePattern = regexp.MustCompile(`^[a-z0-9]{0,5}$`)
var peerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type NodeSpec struct {
	APIVersion string     `json:"api_version"`
	Kind       string     `json:"kind"`
	Fabric     FabricSpec `json:"fabric"`
	Node       Node       `json:"node"`
	Peers      []Peer     `json:"peers"`
}

type FabricSpec struct {
	PSK              string `json:"psk"`
	LinkPrefixV4     string `json:"link_prefix_v4,omitempty"`
	LinkPrefixV6     string `json:"link_prefix_v6,omitempty"`
	LoopbackPrefixV6 string `json:"loopback_prefix_v6"`
	VFPPort          *int   `json:"vfp_port,omitempty"`
}

type Node struct {
	UID               NodeUID `json:"uid"`
	PrivateKey        string  `json:"private_key"`
	LoopbackAddressV6 string  `json:"loopback_address_v6,omitempty"`
}

type NodeUID struct {
	Name string `json:"name,omitempty"`
	UUID string `json:"uuid,omitempty"`
}

type Peer struct {
	Name                       string   `json:"name"`
	PublicKey                  string   `json:"public_key"`
	Endpoints                  []string `json:"endpoints"`
	ListenPort                 *int     `json:"listen_port,omitempty"`
	LinkAddresses              []string `json:"link_addresses,omitempty"`
	PersistentKeepaliveSeconds *int     `json:"persistent_keepalive_seconds,omitempty"`
	InterfaceName              string   `json:"interface_name,omitempty"`
}

// Load reads and validates a NodeSpec. If node.uid.uuid is absent, Load creates
// a UUIDv4 and atomically writes the complete config back to the same path.
func Load(path string) (*NodeSpec, error) {
	contents, mode, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	nodeSpec, err := decode(contents)
	if err != nil {
		return nil, err
	}
	generated := false
	if nodeSpec.Node.UID.UUID == "" {
		nodeSpec.Node.UID.UUID = uuid.NewString()
		generated = true
	}
	if err := nodeSpec.Validate(); err != nil {
		return nil, err
	}
	if generated {
		if err := writeAtomic(path, mode, nodeSpec); err != nil {
			return nil, fmt.Errorf("persist generated node UUID: %w", err)
		}
	}
	return nodeSpec, nil
}

func (s *NodeSpec) Validate() error {
	var problems []string
	if s.APIVersion != APIVersion {
		problems = append(problems, fmt.Sprintf("api_version must be %q", APIVersion))
	}
	if s.Kind != Kind {
		problems = append(problems, fmt.Sprintf("kind must be %q", Kind))
	}
	if _, err := parseInlineKey(s.Fabric.PSK); err != nil {
		problems = append(problems, "fabric.psk must be an inline base64 32-byte key")
	}
	linkV4, linkV4Err := parseOptionalPool(s.Fabric.LinkPrefixV4, true, 30)
	linkV6, linkV6Err := parseOptionalPool(s.Fabric.LinkPrefixV6, false, 126)
	loopV6, loopV6Err := parsePool(s.Fabric.LoopbackPrefixV6, false, 128)
	appendPrefixProblem := func(name string, err error) {
		if err != nil {
			problems = append(problems, "fabric."+name+" "+err.Error())
		}
	}
	appendPrefixProblem("link_prefix_v4", linkV4Err)
	appendPrefixProblem("link_prefix_v6", linkV6Err)
	appendPrefixProblem("loopback_prefix_v6", loopV6Err)
	if s.Fabric.VFPPort != nil && (*s.Fabric.VFPPort < 1 || *s.Fabric.VFPPort > 65535) {
		problems = append(problems, "fabric.vfp_port must be between 1 and 65535")
	}
	if !uidNamePattern.MatchString(s.Node.UID.Name) {
		problems = append(problems, "node.uid.name must contain at most five lowercase letters or digits")
	}
	if parsed, err := uuid.Parse(s.Node.UID.UUID); err != nil || parsed == uuid.Nil {
		problems = append(problems, "node.uid.uuid must be a non-zero UUID")
	}
	privateKey, privateKeyErr := ParseKey(s.Node.PrivateKey)
	if privateKeyErr != nil {
		problems = append(problems, "node.private_key must be an inline base64 WireGuard key")
	}
	validateLoopback := func(name, raw string, pool netip.Prefix, poolErr error) {
		if raw == "" {
			return
		}
		addr, err := netip.ParseAddr(raw)
		if err != nil || !addr.Is6() || !validUnicast(addr) {
			problems = append(problems, "node."+name+" must be a valid unicast address")
			return
		}
		if poolErr == nil && !pool.Contains(addr) {
			problems = append(problems, "node."+name+" is outside its Fabric loopback prefix")
		}
	}
	validateLoopback("loopback_address_v6", s.Node.LoopbackAddressV6, loopV6, loopV6Err)
	if len(s.Peers) == 0 {
		problems = append(problems, "peers must not be empty")
	}

	names := map[string]struct{}{}
	interfaces := map[string]string{}
	ports := map[int]string{}
	for i, peer := range s.Peers {
		where := fmt.Sprintf("peers[%d]", i)
		if !peerNamePattern.MatchString(peer.Name) {
			problems = append(problems, where+".name is invalid")
		} else if _, ok := names[peer.Name]; ok {
			problems = append(problems, where+".name is duplicated")
		}
		names[peer.Name] = struct{}{}
		publicKey, err := ParseKey(peer.PublicKey)
		if err != nil {
			problems = append(problems, where+".public_key must be an inline base64 WireGuard key")
		} else if privateKeyErr == nil && publicKey == privateKey.PublicKey() {
			problems = append(problems, where+".public_key cannot equal the local WireGuard public key")
		}
		if len(peer.Endpoints) == 0 {
			problems = append(problems, where+".endpoints must not be empty")
		}
		seenEndpoints := map[string]struct{}{}
		for _, endpoint := range peer.Endpoints {
			if err := validateEndpoint(endpoint); err != nil {
				problems = append(problems, where+".endpoints: "+err.Error())
			} else if _, ok := seenEndpoints[endpoint]; ok {
				problems = append(problems, where+".endpoints contains a duplicate endpoint")
			}
			seenEndpoints[endpoint] = struct{}{}
		}
		if peer.ListenPort != nil {
			if *peer.ListenPort < 1 || *peer.ListenPort > 65535 {
				problems = append(problems, where+".listen_port must be between 1 and 65535")
			} else if other, ok := ports[*peer.ListenPort]; ok {
				problems = append(problems, fmt.Sprintf("%s.listen_port is already used by peer %q", where, other))
			}
			ports[*peer.ListenPort] = peer.Name
		}
		if peer.PersistentKeepaliveSeconds != nil && (*peer.PersistentKeepaliveSeconds < 0 || *peer.PersistentKeepaliveSeconds > 65535) {
			problems = append(problems, where+".persistent_keepalive_seconds must be between 0 and 65535")
		}
		name := peer.InterfaceName
		if name == "" {
			name = InterfaceName(s.Node.UID, peer.Name, peer.PublicKey)
		}
		if !validInterfaceName(name) {
			problems = append(problems, where+".interface_name is invalid")
		} else if other, ok := interfaces[name]; ok {
			problems = append(problems, fmt.Sprintf("%s resolves to interface %q already used by peer %q", where, name, other))
		}
		interfaces[name] = peer.Name
		seenFamily := map[bool]struct{}{}
		for _, raw := range peer.LinkAddresses {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix != prefix.Masked() || prefix.Bits() != linkBits(prefix.Addr()) {
				problems = append(problems, where+".link_addresses must contain canonical /30 IPv4 or /126 IPv6 prefixes")
				continue
			}
			family := prefix.Addr().Is4()
			if _, ok := seenFamily[family]; ok {
				problems = append(problems, where+".link_addresses contains the same family twice")
			}
			seenFamily[family] = struct{}{}
			if family && linkV4Err == nil && (!linkV4.IsValid() || !linkV4.Contains(prefix.Addr())) {
				problems = append(problems, where+".link_addresses IPv4 prefix requires and must be inside fabric.link_prefix_v4")
			}
			if !family && linkV6Err == nil && (!linkV6.IsValid() || !linkV6.Contains(prefix.Addr())) {
				problems = append(problems, where+".link_addresses IPv6 prefix requires and must be inside fabric.link_prefix_v6")
			}
		}
	}
	if len(problems) > 0 {
		return errors.New("invalid NodeSpec: " + strings.Join(problems, "; "))
	}
	return nil
}

func (s NodeSpec) ParsedUUID() uuid.UUID { return uuid.MustParse(s.Node.UID.UUID) }
func (f FabricSpec) EffectiveVFPPort() int {
	if f.VFPPort != nil {
		return *f.VFPPort
	}
	return DefaultVFPPort
}
func ParseKey(value string) (wgtypes.Key, error) { return wgtypes.ParseKey(strings.TrimSpace(value)) }
func ParsePSK(value string) ([]byte, error)      { return parseInlineKey(value) }

func ParseFabricPrefixes(f FabricSpec) (link4, link6, loop6 netip.Prefix, err error) {
	if link4, err = parseOptionalPool(f.LinkPrefixV4, true, 30); err != nil {
		return
	}
	if link6, err = parseOptionalPool(f.LinkPrefixV6, false, 126); err != nil {
		return
	}
	loop6, err = parsePool(f.LoopbackPrefixV6, false, 128)
	return
}

func InterfaceName(local NodeUID, peerName, peerPublicKey string) string {
	left := local.Name
	if left == "" {
		left = strings.ReplaceAll(local.UUID, "-", "")
		if len(left) < 5 {
			left = "node0"
		} else {
			left = left[:5]
		}
	}
	right := interfaceSlug(peerName)
	readable := "vl-" + left + "-" + right
	if len(readable) <= 15 {
		return readable
	}
	digest := deriveDigest([]byte("velvet/interface-name/v2"), local.UUID, peerName, peerPublicKey)
	return fmt.Sprintf("vl-%.3s-%.3s-%02x%02x", left, right, digest[0], digest[1])
}

func readConfig(path string) ([]byte, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("stat config: %w", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read config: %w", err)
	}
	return contents, info.Mode().Perm(), nil
}

func decode(contents []byte) (*NodeSpec, error) {
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	var result NodeSpec
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, err
	}
	return &result, nil
}

func writeAtomic(path string, mode os.FileMode, value any) (err error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".velvet-nodespec-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode trailing config data: %w", err)
	}
	return errors.New("config contains more than one JSON value")
}

func parseInlineKey(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("key must decode to 32 bytes")
	}
	return decoded, nil
}

func validateEndpoint(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("invalid endpoint %q", value)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid endpoint port in %q", value)
	}
	return nil
}

func validInterfaceName(value string) bool {
	return len(value) > 0 && len(value) <= 15 && value != "." && value != ".." && interfacePattern.MatchString(value)
}
func linkBits(addr netip.Addr) int {
	if addr.Is4() {
		return 30
	}
	return 126
}
func validUnicast(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast() && !addr.IsLinkLocalUnicast() && addr.String() != "255.255.255.255"
}

func parsePool(raw string, ipv4 bool, targetBits int) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix != prefix.Masked() {
		return netip.Prefix{}, errors.New("must be a canonical network prefix")
	}
	if prefix.Addr().Is4() != ipv4 {
		return netip.Prefix{}, errors.New("has the wrong address family")
	}
	if prefix.Bits() > targetBits {
		return netip.Prefix{}, fmt.Errorf("must be no longer than /%d", targetBits)
	}
	return prefix, nil
}

func parseOptionalPool(raw string, ipv4 bool, targetBits int) (netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return netip.Prefix{}, nil
	}
	return parsePool(raw, ipv4, targetBits)
}

func interfaceSlug(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "peer"
	}
	return b.String()
}
