package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/discovery"
)

func (r *Runner) runLink(ctx context.Context, desired reconcile.LinkPlan, established chan<- struct{}) {
	var establishedOnce sync.Once
	for ctx.Err() == nil {
		conn, err := r.discoverPeer(ctx, desired)
		if err == nil {
			err = r.serveSession(ctx, conn, desired, &establishedOnce, established)
		}
		if ctx.Err() != nil {
			return
		}
		r.log(Event{Event: "velvet-session", Status: "retrying", Peer: desired.PeerName, Interface: desired.InterfaceName, Error: errorText(err)})
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

type acceptedConnection struct {
	conn *net.TCPConn
	err  error
}

func (r *Runner) discoverPeer(ctx context.Context, desired reconcile.LinkPlan) (net.Conn, error) {
	localAddress := desired.BootstrapAddress.Addr()
	listenAddress := &net.TCPAddr{IP: net.IP(localAddress.AsSlice()), Port: r.Desired.VFPPort, Zone: desired.InterfaceName}
	listener, err := net.ListenTCP("tcp6", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for VFP: %w", err)
	}
	defer listener.Close()
	socket, err := discovery.Listen(desired.InterfaceName, localAddress, r.Desired.VFPPort)
	if err != nil {
		return nil, err
	}
	defer socket.Close()
	discoveryContext, cancel := context.WithCancel(ctx)
	defer cancel()

	accepted := acceptConnections(discoveryContext, listener)
	discovered, readErrors := readDiscovery(discoveryContext, socket)
	announceErrors := make(chan error, 1)
	go func() { announceErrors <- socket.Announce(discoveryContext) }()

	var remoteAddress netip.Addr
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case readErr := <-readErrors:
			if ctx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("receive discovery Hello: %w", readErr)
		case announceErr := <-announceErrors:
			if ctx.Err() != nil || errors.Is(announceErr, context.Canceled) || errors.Is(announceErr, net.ErrClosed) {
				return nil, ctx.Err()
			}
			return nil, announceErr
		case observation := <-discovered:
			remote := observation.Source
			if remote == localAddress {
				return nil, fmt.Errorf("discovery address collision on %s: %s", desired.InterfaceName, remote)
			}
			if observation.Type == discovery.Hello {
				if err := socket.SendAck(remote); err != nil {
					return nil, err
				}
			}
			if remote != remoteAddress {
				r.log(Event{Event: "velvet-discovery", Status: "peer-found", Peer: desired.PeerName, Interface: desired.InterfaceName, RemoteIP: remote.String()})
			}
			remoteAddress = remote
			if shouldDial(localAddress, remote) {
				conn, err := dialVFP(ctx, desired.InterfaceName, localAddress, remote, r.Desired.VFPPort)
				if err != nil {
					return nil, err
				}
				cancel()
				_ = listener.Close()
				return conn, nil
			}
		case result := <-accepted:
			if result.err != nil {
				if ctx.Err() != nil || errors.Is(result.err, net.ErrClosed) {
					return nil, ctx.Err()
				}
				return nil, fmt.Errorf("accept VFP: %w", result.err)
			}
			remote, ok := tcpRemoteAddress(result.conn)
			if !ok || !shouldAcceptDiscovered(localAddress, remote) {
				_ = result.conn.Close()
				continue
			}
			configureTCP(result.conn)
			cancel()
			return result.conn, nil
		}
	}
}

func acceptConnections(ctx context.Context, listener *net.TCPListener) <-chan acceptedConnection {
	result := make(chan acceptedConnection, 1)
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			select {
			case result <- acceptedConnection{conn: conn, err: err}:
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return result
}

func readDiscovery(ctx context.Context, socket *discovery.Socket) (<-chan discovery.Observation, <-chan error) {
	observations := make(chan discovery.Observation, 1)
	errCh := make(chan error, 1)
	go func() {
		for {
			observation, err := socket.ReadHello()
			if err != nil {
				select {
				case errCh <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case observations <- observation:
			case <-ctx.Done():
				return
			}
		}
	}()
	return observations, errCh
}

func dialVFP(ctx context.Context, interfaceName string, local, remote netip.Addr, port int) (*net.TCPConn, error) {
	localAddress := &net.TCPAddr{IP: net.IP(local.AsSlice()), Zone: interfaceName}
	remoteAddress := &net.TCPAddr{IP: net.IP(remote.AsSlice()), Port: port, Zone: interfaceName}
	conn, err := dialTCP(ctx, localAddress, remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("dial discovered VFP peer %s: %w", remoteAddress, err)
	}
	return conn, nil
}

func dialTCP(ctx context.Context, local, remote *net.TCPAddr) (*net.TCPConn, error) {
	conn, err := (&net.Dialer{LocalAddr: local, Timeout: 3 * time.Second}).DialContext(ctx, "tcp6", remote.String())
	if err != nil {
		return nil, err
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("TCP dial did not return a TCP connection")
	}
	configureTCP(tcp)
	return tcp, nil
}

func shouldDial(local, remote netip.Addr) bool { return local.Compare(remote) < 0 }

func shouldAcceptDiscovered(local, remote netip.Addr) bool {
	return remote.Is6() && remote.IsLinkLocalUnicast() && remote != local && !shouldDial(local, remote)
}

func tcpRemoteAddress(conn *net.TCPConn) (netip.Addr, bool) {
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	address, ok := netip.AddrFromSlice(remote.IP)
	return address.Unmap(), ok
}

func configureTCP(conn *net.TCPConn) {
	_ = conn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3})
}
