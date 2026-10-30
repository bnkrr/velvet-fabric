package spec

import (
	"bytes"
	"encoding/json"
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

// ListenPorts accepts a single port (0 means system allocated) or an inclusive
// two-element range. Static and automatic Links each have their own choice.
type ListenPorts PortChoice

func (p *ListenPorts) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	var choice ListenPorts
	if len(data) > 0 && data[0] == '[' {
		var ports []int
		if err := json.Unmarshal(data, &ports); err != nil || len(ports) != 2 {
			return errors.New("listen_ports must be an integer or exactly two integers [first,last]")
		}
		choice.Range = PortRange{First: ports[0], Last: ports[1]}
		if ports[0] < 1 || ports[1] > 65535 || ports[0] > ports[1] {
			return errors.New("listen_ports range requires 1 <= first <= last <= 65535")
		}
	} else if err := json.Unmarshal(data, &choice.Port); err != nil {
		return errors.New("listen_ports must be an integer or exactly two integers [first,last]")
	}
	if err := choice.Validate(); err != nil {
		return err
	}
	*p = choice
	return nil
}

func (p ListenPorts) MarshalJSON() ([]byte, error) {
	if p.Range != (PortRange{}) {
		return json.Marshal([2]int{p.Range.First, p.Range.Last})
	}
	return json.Marshal(p.Port)
}

func (p *ListenPorts) Choice() PortChoice {
	if p == nil {
		return PortChoice{}
	}
	return PortChoice(*p)
}

func (p *ListenPorts) Validate() error {
	choice := p.Choice()
	if choice.Port < 0 || choice.Port > 65535 {
		return errors.New("listen_ports must be between 0 and 65535")
	}
	if choice.Range != (PortRange{}) && (choice.Port != 0 || choice.Range.First < 1 || choice.Range.Last > 65535 || choice.Range.First > choice.Range.Last) {
		return errors.New("listen_ports range requires 1 <= first <= last <= 65535")
	}
	return nil
}

func (p PortChoice) validateVFPPort(vfpPort int) error {
	if p.Port == vfpPort || (p.Range.First == vfpPort && p.Range.Last == vfpPort) {
		return errors.New("WireGuard port choice must leave a port other than fabric.vfp_port")
	}
	return nil
}

func (s *NodeSpec) PeerPorts(peer Peer) PortChoice {
	return peer.ListenPorts.Choice()
}

func (s *NodeSpec) DynamicPorts() PortChoice {
	if s.DynamicLinks == nil {
		return PortChoice{}
	}
	return s.DynamicLinks.ListenPorts.Choice()
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
