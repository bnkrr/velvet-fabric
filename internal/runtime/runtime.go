package runtime

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/babel"
	"github.com/velvet-fabric/velvet-fabric/internal/reconcile"
)

type Event struct {
	Event     string `json:"event"`
	Status    string `json:"status,omitempty"`
	NodeUID   string `json:"node_uid,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Interface string `json:"interface,omitempty"`
	RemoteUID string `json:"remote_uid,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Runner struct {
	Desired    *reconcile.DesiredState
	Reconciler *reconcile.Reconciler
	Interval   time.Duration
	Log        func(Event)
	Ready      chan<- error

	mu      sync.RWMutex
	states  map[string]materializedState
	babel   *babel.Manager
	dynamic *dynamicRuntime
}

type Status struct {
	NodeUID          string        `json:"node_uid"`
	ConfiguredLinks  int           `json:"configured_links"`
	EstablishedLinks int           `json:"established_links"`
	DynamicLinks     int           `json:"dynamic_links"`
	Babel            *babel.Status `json:"babel,omitempty"`
}

type materializedState struct {
	desired reconcile.LinkPlan
	local   []netip.Prefix
	peers   []netip.Addr
	remote  uuid.UUID
	dynamic bool
}

func (r *Runner) Run(ctx context.Context, once bool) error {
	if err := r.Reconciler.Reconcile(ctx, r.Desired); err != nil {
		r.signalReady(err)
		return err
	}
	r.log(Event{Event: "velvet-reconcile", Status: "success", NodeUID: r.Desired.UUID.String()})

	ctx, cancel := context.WithCancel(ctx)
	babelDone := r.startBabel(ctx)
	defer func() {
		cancel()
		waitForBabel(babelDone)
	}()
	r.mu.Lock()
	r.states = make(map[string]materializedState)
	r.mu.Unlock()
	if err := r.waitBabelReady(ctx); err != nil {
		r.signalReady(err)
		return err
	}

	r.dynamic = newDynamicRuntime(r)
	if err := r.dynamic.start(ctx); err != nil {
		r.signalReady(err)
		return err
	}
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
		r.dynamic.stop()
	}()
	r.signalReady(nil)

	established := make(chan struct{}, len(r.Desired.Links))
	for _, plan := range r.Desired.Links {
		workers.Go(func() { r.runLink(ctx, plan, established) })
	}
	if once {
		return waitForLinks(ctx, established, len(r.Desired.Links))
	}
	if r.Interval > 0 {
		workers.Go(func() { r.maintain(ctx) })
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-r.dynamic.errors:
		return err
	}
}

func (r *Runner) startBabel(ctx context.Context) chan struct{} {
	if r.Desired.Babel == nil {
		return nil
	}
	r.babel = babel.New(r.Desired.Babel, func(event babel.Event) {
		r.log(Event{Event: "babel-rs", Status: event.Status, NodeUID: r.Desired.UUID.String(), Error: event.Error})
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.babel.Run(ctx)
	}()
	return done
}

func waitForBabel(done <-chan struct{}) {
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(6 * time.Second):
	}
}

func waitForLinks(ctx context.Context, established <-chan struct{}, count int) error {
	for range count {
		select {
		case <-established:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (r *Runner) waitBabelReady(ctx context.Context) error {
	if r.babel == nil {
		return nil
	}
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status := r.babel.Status()
		if status.State == "running" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("babel-rs did not attach all configured interfaces: %s", status.LastError)
		case <-ticker.C:
		}
	}
}

func (r *Runner) signalReady(err error) {
	if r.Ready == nil {
		return
	}
	select {
	case r.Ready <- err:
	default:
	}
}

func (r *Runner) Status() Status {
	r.mu.RLock()
	var established, dynamic int
	for _, state := range r.states {
		if state.dynamic {
			dynamic++
		} else {
			established++
		}
	}
	r.mu.RUnlock()
	status := Status{
		NodeUID: r.Desired.UUID.String(), ConfiguredLinks: len(r.Desired.Links),
		EstablishedLinks: established, DynamicLinks: dynamic,
	}
	if r.babel != nil {
		value := r.babel.Status()
		status.Babel = &value
	}
	return status
}

func (r *Runner) maintain(ctx context.Context) {
	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Reconciler.Maintain(ctx, r.Desired); err != nil {
				r.log(Event{Event: "velvet-reconcile", Status: "failed", NodeUID: r.Desired.UUID.String(), Error: err.Error()})
				continue
			}
			r.maintainMaterialized(ctx)
		}
	}
}

func (r *Runner) maintainMaterialized(ctx context.Context) {
	// A snapshot must not outlive Dynamic-Link deletion and interface reuse.
	r.dynamic.resourceMu.Lock()
	defer r.dynamic.resourceMu.Unlock()
	for _, state := range r.materializedStates() {
		if err := r.Reconciler.Materialize(ctx, r.Desired, state.desired, state.local, state.peers); err != nil {
			r.log(Event{Event: "velvet-reconcile", Status: "failed", Peer: state.desired.PeerName, Interface: state.desired.InterfaceName, Error: err.Error()})
		}
	}
}

func (r *Runner) materializedStates() []materializedState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]materializedState, 0, len(r.states))
	for _, state := range r.states {
		result = append(result, state)
	}
	return result
}

func (r *Runner) log(event Event) {
	if r.Log != nil {
		r.Log(event)
	}
}
