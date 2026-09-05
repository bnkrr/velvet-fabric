// Package inference derives WireGuard endpoint candidates from locally held
// endpoint evidence. It has no network or runtime-state side effects.
package inference

import (
	"errors"
	"net/netip"
)

// Evidence binds an observation to the local WireGuard socket that produced
// the observed NAT mapping. Link is the implementation's local Link identity.
type Evidence struct {
	Link             string
	LocalListenPort  uint16
	ObservedEndpoint netip.AddrPort
}

func (e Evidence) Valid() bool {
	return e.Link != "" && e.LocalListenPort != 0 && e.ObservedEndpoint.IsValid() && e.ObservedEndpoint.Port() != 0
}

func NewEvidence(link string, localListenPort int, observed netip.AddrPort) (Evidence, error) {
	if link == "" {
		return Evidence{}, errors.New("endpoint evidence has no Link identity")
	}
	if localListenPort < 1 || localListenPort > 65535 {
		return Evidence{}, errors.New("endpoint evidence has an invalid local listen port")
	}
	if !observed.IsValid() || observed.Port() == 0 {
		return Evidence{}, errors.New("endpoint evidence has an invalid observed endpoint")
	}
	return Evidence{
		Link:             link,
		LocalListenPort:  uint16(localListenPort),
		ObservedEndpoint: observed,
	}, nil
}

// Baseline implements VFP v1's single-Candidate inference profile: select the
// first Evidence in stable store order, retain its observed IP, and substitute
// the listen port reserved for the tentative Link.
func Baseline(evidence []Evidence, listenPort int) (netip.AddrPort, bool) {
	if len(evidence) == 0 || !evidence[0].Valid() || listenPort < 1 || listenPort > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(evidence[0].ObservedEndpoint.Addr(), uint16(listenPort)), true
}
