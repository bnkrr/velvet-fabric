package spec

import (
	"errors"
	"time"
)

type PortRange struct {
	First int `json:"first"`
	Last  int `json:"last"`
}

// PortChoice is an effective choice: a zero Range means system/fixed mode.
type PortChoice struct {
	Port  int
	Range PortRange
}

func ValidatePorts(port *int, span *PortRange) error {
	if port != nil && span != nil {
		return errors.New("listen_port and port_range are mutually exclusive")
	}
	if port != nil && (*port < 0 || *port > 65535) {
		return errors.New("listen_port must be between 0 and 65535")
	}
	if span != nil && (span.First < 1 || span.Last > 65535 || span.First > span.Last) {
		return errors.New("port_range requires 1 <= first <= last <= 65535")
	}
	return nil
}

func ChoosePorts(port *int, span *PortRange) PortChoice {
	if port != nil {
		return PortChoice{Port: *port}
	}
	if span != nil {
		return PortChoice{Range: *span}
	}
	return PortChoice{}
}

func (p PortChoice) validateVFPPort(vfpPort int) error {
	if p.Port == vfpPort || (p.Range.First == vfpPort && p.Range.Last == vfpPort) {
		return errors.New("WireGuard port choice must leave a port other than fabric.vfp_port")
	}
	return nil
}

func (s *NodeSpec) PeerPorts(peer Peer) PortChoice {
	if peer.ListenPort != nil || peer.PortRange != nil {
		return ChoosePorts(peer.ListenPort, peer.PortRange)
	}
	return ChoosePorts(s.Node.ListenPort, s.Node.PortRange)
}

type DurableSpec struct {
	SoftLimit     *int `json:"soft_limit,omitempty"`
	StableSeconds *int `json:"stable_seconds,omitempty"`
}

type DurableSettings struct {
	SoftLimit int
	Stable    time.Duration
}

func (d *DurableSpec) Validate() error {
	if d.SoftLimit != nil && (*d.SoftLimit < 0 || *d.SoftLimit > 128) {
		return errors.New("durable.soft_limit must be between 0 and 128")
	}
	if d.StableSeconds != nil && (*d.StableSeconds < 1 || *d.StableSeconds > 86400*365) {
		return errors.New("durable.stable_seconds must be between 1 and 31536000")
	}
	return nil
}

func EffectiveDurable(d *DynamicLinksSpec) DurableSettings {
	s := DurableSettings{SoftLimit: 2, Stable: 30 * time.Minute}
	if d != nil && d.Durable != nil {
		if d.Durable.SoftLimit != nil {
			s.SoftLimit = *d.Durable.SoftLimit
		}
		if d.Durable.StableSeconds != nil {
			s.Stable = time.Duration(*d.Durable.StableSeconds) * time.Second
		}
	}
	return s
}
