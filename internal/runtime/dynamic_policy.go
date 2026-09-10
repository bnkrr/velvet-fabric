package runtime

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

const (
	dynamicRetryBase         = 10 * time.Second
	dynamicRetryMax          = 5 * time.Minute
	dynamicQueryInterval     = 5 * time.Minute
	dynamicUpdateInterval    = 5 * time.Second
	dynamicTargetRetention   = 30 * time.Minute
	maxDynamicDialsPerSecond = 4
	maxPolicySendsPerTick    = 16
)

func jitterDelay(base time.Duration) time.Duration {
	return base + time.Duration(rand.Int64N(int64(base/4)+1))
}
func retryDelay(failures uint8) time.Duration {
	shift := min(failures, uint8(6))
	if shift > 0 {
		shift--
	}
	return jitterDelay(min(dynamicRetryBase*time.Duration(1<<shift), dynamicRetryMax))
}

// All target state is guarded by d.mu. TTL eviction requires route absence,
// no active resources and expired budgets; incoming packets cannot erase backoff.
func (d *dynamicLinkEngine) targetLocked(addr netip.Addr, now time.Time) *dynamicTarget {
	if t := d.targets[addr]; t != nil {
		return t
	}
	if len(d.targets) >= maxDynamicTargets {
		return nil
	}
	t := &dynamicTarget{lastSeen: now}
	d.targets[addr] = t
	return t
}

func (d *dynamicLinkEngine) bindPolicyPeer(addr netip.Addr, id uuid.UUID) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	t := d.targetLocked(addr, time.Now())
	if t == nil {
		return errors.New("dynamic peer cache full")
	}
	if t.uid != uuid.Nil && t.uid != id {
		return errors.New("routed peer identity conflicts with cached binding")
	}
	for a, other := range d.targets {
		if a != addr && other.uid == id {
			return errors.New("routed UID already bound to another loopback")
		}
	}
	t.uid, t.bound, t.lastSeen = id, true, time.Now()
	return nil
}

func (d *dynamicLinkEngine) mergePolicyLocked(t *dynamicTarget, p *message.DynamicLinkPolicy) {
	if t == nil || p == nil || p.Revision == 0 {
		return
	}
	if t.policy != nil && p.Revision <= t.policy.Revision {
		return
	}
	changed := t.policy == nil || t.policy.Accept != p.Accept
	copy := *p
	t.policy = &copy
	t.pendingQuery = false
	// Receiving a decision never changes either sending budget.
	if changed {
		status := "denied"
		if p.Accept {
			status = "allowed"
		}
		d.runner.log(Event{Event: "velvet-dynamic-policy", Status: status, RemoteUID: t.uid.String()})
	}
}

func (d *dynamicLinkEngine) policyIngress(index int) bool {
	ifi, err := net.InterfaceByIndex(index)
	if err != nil {
		return false
	}
	for _, plan := range d.runner.Desired.Links {
		if plan.InterfaceName == ifi.Name {
			return true
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, attempt := range d.attempts {
		if attempt.plan.InterfaceName == ifi.Name && !attempt.plan.Probing {
			return true
		}
	}
	return false
}

func (d *dynamicLinkEngine) readPolicy(ctx context.Context) {
	for {
		source, m, err := d.policySocket.Read()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				d.reportError(err)
			}
			return
		}
		d.receivePolicy(source, m, time.Now())
	}
}

func (d *dynamicLinkEngine) receivePolicy(source netip.Addr, m message.Message, now time.Time) {
	if m.UID == nil || m.UID.UUID == uuid.Nil || m.UID.UUID == d.runner.Desired.UUID {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		return
	}
	t := d.targets[source]
	if t != nil && t.uid != uuid.Nil && t.uid != m.UID.UUID {
		return
	}
	for addr, other := range d.targets {
		if addr != source && other.uid == m.UID.UUID {
			return
		}
	}
	switch m.Type {
	case message.PolicyUpdate:
		if t == nil || !t.bound || t.uid != m.UID.UUID {
			return
		}
		d.mergePolicyLocked(t, m.Policy)
	case message.PolicyQuery:
		if !d.allowsInbound() {
			return
		}
		if t == nil {
			t = d.targetLocked(source, now)
		}
		if t == nil {
			return
		}
		t.uid = m.UID.UUID
		t.lastSeen = now
		t.reachable = true
		t.pendingUpdate = true
	}
}

// One worker owns sending. Round-robin traversal prevents a busy low-address
// peer from starving other queued updates under the node-wide rate budget.
func (d *dynamicLinkEngine) flushPolicy(now time.Time) {
	if d.policySocket == nil {
		return
	}
	type send struct {
		addr netip.Addr
		m    message.Message
	}
	var sends []send
	d.mu.Lock()
	keys := make([]netip.Addr, 0, len(d.targets))
	for addr := range d.targets {
		keys = append(keys, addr)
	}
	slices.SortFunc(keys, func(a, b netip.Addr) int { return a.Compare(b) })
	for visited := 0; visited < len(keys) && len(sends) < maxPolicySendsPerTick; visited++ {
		idx := d.policyCursor % len(keys)
		d.policyCursor = (idx + 1) % len(keys)
		addr := keys[idx]
		t := d.targets[addr]
		m := message.Message{UID: &message.UID{UUID: d.runner.Desired.UUID}}
		if t.pendingUpdate && t.reachable && !now.Before(t.nextUpdate) && d.policyRevision != 0 {
			m.Type = message.PolicyUpdate
			m.Policy = &message.DynamicLinkPolicy{Revision: d.policyRevision, Accept: d.allowsInbound()}
			t.pendingUpdate = false
			t.nextUpdate = now.Add(dynamicUpdateInterval)
		} else if t.pendingQuery && !now.Before(t.nextQuery) && t.bound && t.policy != nil && !t.policy.Accept {
			m.Type = message.PolicyQuery
			t.pendingQuery = false
			t.nextQuery = now.Add(jitterDelay(dynamicQueryInterval))
		} else {
			continue
		}
		sends = append(sends, send{addr, m})
	}
	d.mu.Unlock()
	for _, s := range sends {
		_ = d.policySocket.Send(s.addr, s.m)
	}
}

func (d *dynamicLinkEngine) targetForPeerLocked(id uuid.UUID) *dynamicTarget {
	for _, target := range d.targets {
		if target.uid == id {
			return target
		}
	}
	return nil
}
