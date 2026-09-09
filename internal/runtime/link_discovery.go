package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/engine"
)

func (r *Runner) runLink(ctx context.Context, desired reconcile.LinkPlan, established chan<- struct{}) {
	var once sync.Once
	for ctx.Err() == nil {
		err := r.manageLink(ctx, desired, nil, func(engine.Result) { once.Do(func() { established <- struct{}{} }) })
		if ctx.Err() != nil {
			return
		}
		// A local supervisor failure (not TCP failure) must not leave an
		// unmonitored direct route indefinitely shadowing the Fabric fallback.
		for ctx.Err() == nil {
			if e := r.withdrawLinkAdjacency(ctx, desired); e == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
		r.log(Event{Event: "velvet-link-supervisor", Status: "retrying", Interface: desired.InterfaceName, Error: errorText(err)})
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

type acceptedConnection struct {
	conn *net.TCPConn
	err  error
}

func dialVFP(ctx context.Context, interfaceName string, local, remote netip.Addr, port int) (*net.TCPConn, error) {
	zone, err := linkZone(interfaceName)
	if err != nil {
		return nil, err
	}
	localAddress := &net.TCPAddr{IP: net.IP(local.AsSlice()), Zone: zone}
	remoteAddress := &net.TCPAddr{IP: net.IP(remote.AsSlice()), Port: port, Zone: zone}
	conn, err := dialTCP(ctx, localAddress, remoteAddress)
	if err != nil {
		return nil, fmt.Errorf("dial discovered VFP peer %s: %w", remoteAddress, err)
	}
	return conn, nil
}

// Do not use Go's cached name-to-zone mapping across same-name WG recreation.
func linkZone(interfaceName string) (string, error) {
	device, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", err
	}
	return strconv.Itoa(device.Index), nil
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
