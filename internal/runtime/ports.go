package runtime

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/spec"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/probe"
)

// One reservation namespace covers wildcard IPv4/IPv6 WG and probe sockets.
// A lease is an identity, so delayed release cannot free a replacement owner.
type portPool struct {
	mu     sync.Mutex
	leases map[int]*portLease
}
type portLease struct {
	pool *portPool
	port int
}

func (l *portLease) release() {
	if l == nil {
		return
	}
	l.pool.mu.Lock()
	defer l.pool.mu.Unlock()
	if l.pool.leases[l.port] == l {
		delete(l.pool.leases, l.port)
	}
}

func (p *portPool) bind(choice spec.PortChoice, sticky int, bind func(int) (int, error)) (*portLease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.leases == nil {
		p.leases = map[int]*portLease{}
	}
	var candidates []int
	if choice.Range.First != 0 {
		if sticky >= choice.Range.First && sticky <= choice.Range.Last {
			candidates = append(candidates, sticky)
		}
		n := choice.Range.Last - choice.Range.First + 1
		start := rand.IntN(n)
		for i := range n {
			port := choice.Range.First + (start+i)%n
			if port != sticky {
				candidates = append(candidates, port)
			}
		}
	} else if choice.Port != 0 {
		candidates = []int{choice.Port}
	} else {
		if sticky != 0 {
			candidates = append(candidates, sticky)
		}
		// Kernel ephemeral choices may collide with a temporarily unbound WG
		// handoff reservation; retries remain bounded.
		candidates = append(candidates, make([]int, 16)...)
	}
	var last error
	for _, port := range candidates {
		if p.leases[port] != nil {
			continue
		}
		actual, err := bind(port)
		if err != nil {
			last = err
			continue
		}
		if (port != 0 && actual != port) || actual < 1 || actual > 65535 {
			return nil, errors.New("invalid allocated UDP port")
		}
		if p.leases[actual] != nil {
			last = errors.New("allocated port reserved by another Link")
			continue
		}
		lease := &portLease{pool: p, port: actual}
		p.leases[actual] = lease
		return lease, nil
	}
	return nil, fmt.Errorf("Link UDP ports unavailable: %w", errors.Join(errors.New("reservation exhausted"), last))
}

type leasedProbe struct {
	probeSocket
	lease  *portLease
	mu     sync.Mutex
	handed bool
}

func (s *leasedProbe) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.probeSocket.Close()
	if !s.handed {
		s.lease.release()
	}
	return err
}
func (s *leasedProbe) handoff() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handed = true
	_ = s.probeSocket.Close()
}

func (d *dynamicLinkEngine) reserveProbe(ctx context.Context, endpoint netip.AddrPort, receiver *probe.Receiver, receive func(probe.Received), choice spec.PortChoice) (probeSocket, error) {
	if endpoint.Port() != 0 {
		port := int(endpoint.Port())
		if choice.Range.First != 0 && (port < choice.Range.First || port > choice.Range.Last) {
			return nil, errors.New("probe port outside configured range")
		}
		if choice.Port != 0 && choice.Port != port {
			return nil, errors.New("probe port differs from fixed port")
		}
		choice = spec.PortChoice{Port: port}
	}
	var socket probeSocket
	lease, err := d.runner.ports.bind(choice, 0, func(port int) (int, error) {
		if socket != nil {
			_ = socket.Close()
			socket = nil
		}
		candidate, err := d.listenProbe(ctx, netip.AddrPortFrom(endpoint.Addr(), uint16(port)), receiver, receive)
		if err != nil {
			return 0, err
		}
		// A failed listener may return a typed nil inside probeSocket. Only
		// successfully created sockets belong to retry/error cleanup.
		socket = candidate
		return int(socket.Endpoint().Port()), nil
	})
	if err != nil {
		if socket != nil {
			socket.Close()
		}
		return nil, err
	}
	return &leasedProbe{probeSocket: socket, lease: lease}, nil
}

// Reserve static ports before any automatic work starts. Socket close releases
// the kernel binding, but the internal lease survives until runtime shutdown.
func (r *Runner) reserveStaticPorts(ctx context.Context) error {
	// Fixed reservations go first so system allocation cannot steal a later
	// configured port before its interface is provisioned.
	for _, fixed := range []bool{true, false} {
		for i := range r.Desired.Links {
			plan := &r.Desired.Links[i]
			if (plan.Ports.Port != 0) != fixed {
				continue
			}
			lease, err := r.reserveStaticPort(ctx, *plan)
			if err != nil {
				plan.WaitingPort = true
				r.log(Event{Event: "velvet-link-port", Status: "waiting", Interface: plan.InterfaceName, Error: err.Error()})
				continue
			}
			plan.ListenPort = lease.port
			r.links.own(*plan, lease)
		}
	}
	return nil
}

func (r *Runner) reserveStaticPort(ctx context.Context, plan reconcile.LinkPlan) (*portLease, error) {
	sticky, _ := r.Reconciler.ListenPort(ctx, plan.InterfaceName)
	var socket *net.UDPConn
	lease, err := r.ports.bind(plan.Ports, sticky, func(port int) (int, error) {
		if socket != nil {
			socket.Close()
			socket = nil
		}
		if port != 0 && port == sticky {
			return port, nil
		}
		var err error
		socket, err = net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			return 0, err
		}
		return socket.LocalAddr().(*net.UDPAddr).Port, nil
	})
	if socket != nil {
		socket.Close()
	}
	return lease, err
}
