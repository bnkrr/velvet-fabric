//go:build linux

package linux

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
	"github.com/vishvananda/netlink"
)

// RetireInstance runs only after the independent Babel service has stopped and
// while the caller owns the same namespace lock used by velvetd startup.
func RetireInstance(ctx context.Context, node string, tables []int) error {
	id, err := uuid.Parse(node)
	if err != nil || id == uuid.Nil || id.String() != node {
		return fmt.Errorf("invalid retirement identity %q", node)
	}
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, device := range links {
		if err := ctx.Err(); err != nil {
			return err
		}
		alias := device.Attrs().Alias
		if (device.Type() == "wireguard" && strings.HasPrefix(alias, "velvet:link:"+node+":")) || (device.Type() == "dummy" && alias == "velvet:loopback:"+node) {
			if err := netlink.LinkDel(device); err != nil {
				return err
			}
		}
	}
	ownedTables := map[int]bool{}
	for _, table := range tables {
		ownedTables[table] = true
	}
	for _, protocol := range []netlink.RouteProtocol{StaticProtocol, LinkProtocol, reconcile.BabelDynamicProtocol} {
		routes, err := routesByProtocol(protocol)
		if err != nil {
			return err
		}
		for i := range routes {
			if ownedTables[routes[i].Table] {
				if err := netlink.RouteDel(&routes[i]); err != nil {
					return err
				}
			}
		}
		rules, err := rulesByProtocol(uint8(protocol))
		if err != nil {
			return err
		}
		for i := range rules {
			if ownedTables[rules[i].Table] {
				if err := netlink.RuleDel(&rules[i]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
