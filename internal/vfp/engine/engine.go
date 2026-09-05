package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/velvet-fabric/velvet-fabric/internal/link"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
)

const maxCounterproposals = 64

type Config struct {
	Context                  SessionContext
	LocalUID                 message.UID
	LocalLoopbackV6          netip.Addr
	ExpectedRemoteLoopbackV6 netip.Addr
	LinkPoolV4               netip.Prefix
	LinkPoolV6               netip.Prefix
	LoopbackPoolV6           netip.Prefix
	FabricPSK                []byte
	LinkOverrides            []string
	Accept                   func(message.UID, link.Proposal) bool
	Commit                   func(Result) error
	FrameError               func(error)
	Operational              func(*Session) error
	OperationalMessage       func(*Session, message.Message) error
	EstablishmentTimeout     time.Duration
}

type SessionContext uint8

const (
	LinkBoundSession SessionContext = iota
	RoutedSession
)

type Session struct {
	Context          context.Context
	Kind             SessionContext
	RemoteUID        message.UID
	RemoteLoopbackV6 netip.Addr
	send             func(message.Message) error
	close            func() error
}

func (s *Session) Send(value message.Message) error { return s.send(value) }
func (s *Session) Close() error                     { return s.close() }

type Result struct {
	RemoteUID        message.UID
	RemoteLoopbackV6 netip.Addr
	Proposal         link.Proposal
}

type Engine struct{ config Config }

func New(config Config) *Engine { return &Engine{config: config} }

type readEvent struct {
	message      message.Message
	err          error
	frameInvalid bool
}
type writeRequest struct {
	message message.Message
	done    chan error
}

// Run drives one VFP TCP session. All protocol state is owned by this event
// loop; the reader and writer goroutines only move framed messages.
func (e *Engine) Run(ctx context.Context, conn net.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	reads := make(chan readEvent)
	writes := make(chan writeRequest)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); readLoop(ctx, conn, reads) }()
	go func() { defer workers.Done(); writeLoop(ctx, conn, writes) }()
	defer func() {
		cancel()
		_ = conn.Close()
		workers.Wait()
	}()
	go func() { <-ctx.Done(); _ = conn.Close() }()

	send := func(value message.Message) error {
		done := make(chan error, 1)
		select {
		case writes <- writeRequest{message: value, done: done}:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	establishmentTimeout := e.config.EstablishmentTimeout
	if establishmentTimeout <= 0 {
		establishmentTimeout = 10 * time.Second
	}
	if err := conn.SetDeadline(time.Now().Add(establishmentTimeout)); err != nil {
		return fmt.Errorf("set VFP establishment deadline: %w", err)
	}
	establishmentTimer := time.NewTimer(establishmentTimeout)
	defer establishmentTimer.Stop()
	establishmentDeadline := establishmentTimer.C
	if err := send(message.Message{Type: message.Open, UID: &e.config.LocalUID}); err != nil {
		return err
	}

	fsm := sessionFSM{config: e.config}
	var operationalSession *Session
	operationalNotified := false
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-establishmentDeadline:
			return fmt.Errorf("VFP establishment timed out after %s", establishmentTimeout)
		case event := <-reads:
			if event.err != nil {
				if event.frameInvalid {
					if !fsm.opened {
						return fmt.Errorf("opening frame: %w", event.err)
					}
					if e.config.FrameError != nil {
						e.config.FrameError(event.err)
					}
					continue
				}
				return event.err
			}
			if fsm.operational {
				if !validOperationalMessage(e.config.Context, event.message.Type) {
					if e.config.FrameError != nil {
						e.config.FrameError(fmt.Errorf("message %d is invalid in operational session context", event.message.Type))
					}
					continue
				}
				if e.config.OperationalMessage != nil {
					if err := e.config.OperationalMessage(operationalSession, event.message); err != nil {
						return fmt.Errorf("process operational VFP message: %w", err)
					}
				}
				continue
			}
			outbound, disposition, err := fsm.handle(event.message)
			if err != nil {
				if disposition == discardFrame {
					if e.config.FrameError != nil {
						e.config.FrameError(err)
					}
					continue
				}
				return err
			}
			if outbound != nil {
				if err := send(*outbound); err != nil {
					return err
				}
			}
			if result := fsm.takeCommit(); result != nil {
				if e.config.Commit != nil {
					if err := e.config.Commit(*result); err != nil {
						return fmt.Errorf("commit negotiated link: %w", err)
					}
				}
				fsm.markEstablished()
				if err := conn.SetDeadline(time.Time{}); err != nil {
					return fmt.Errorf("clear VFP establishment deadline: %w", err)
				}
				if !establishmentTimer.Stop() {
					select {
					case <-establishmentTimer.C:
					default:
					}
				}
				establishmentDeadline = nil
			}
			if fsm.operational && !operationalNotified {
				operationalSession = &Session{
					Context: ctx, Kind: e.config.Context, RemoteUID: fsm.remoteUID,
					RemoteLoopbackV6: fsm.remoteLoopbackV6(), send: send, close: conn.Close,
				}
				operationalNotified = true
				if err := conn.SetDeadline(time.Time{}); err != nil {
					return fmt.Errorf("clear VFP establishment deadline: %w", err)
				}
				if !establishmentTimer.Stop() {
					select {
					case <-establishmentTimer.C:
					default:
					}
				}
				establishmentDeadline = nil
				if e.config.Operational != nil {
					if err := e.config.Operational(operationalSession); err != nil {
						return fmt.Errorf("enter operational VFP state: %w", err)
					}
				}
			}
		}
	}
}

func readLoop(ctx context.Context, conn net.Conn, output chan<- readEvent) {
	for {
		frame, err := message.Read(conn)
		if err != nil {
			deliverRead(ctx, output, readEvent{err: err})
			return
		}
		decoded, err := message.Decode(frame)
		if err != nil {
			if !deliverRead(ctx, output, readEvent{err: err, frameInvalid: true}) {
				return
			}
			continue
		}
		if !deliverRead(ctx, output, readEvent{message: decoded}) {
			return
		}
	}
}

func deliverRead(ctx context.Context, output chan<- readEvent, event readEvent) bool {
	select {
	case output <- event:
		return true
	case <-ctx.Done():
		return false
	}
}

func writeLoop(ctx context.Context, conn net.Conn, input <-chan writeRequest) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-input:
			err := message.Write(conn, request.message)
			request.done <- err
			if err != nil {
				return
			}
		}
	}
}

type disposition uint8

const (
	closeConnection disposition = iota
	discardFrame
)

type sessionFSM struct {
	config        Config
	opened        bool
	stateReceived bool
	remoteUID     message.UID
	remoteV6      netip.Addr
	link          *staticLinkFSM
	operational   bool
}

type staticLinkFSM struct {
	config                   Config
	remoteUID                message.UID
	remoteV6                 netip.Addr
	waitingForRemoteProposal bool
	waitingForResponse       bool
	outstanding              link.Proposal
	attempt                  uint32
	seen                     map[string]struct{}
	pendingCommit            *Result
	established              bool
}

func (s *sessionFSM) handle(in message.Message) (*message.Message, disposition, error) {
	if !s.opened {
		return s.handleOpen(in)
	}
	if !s.stateReceived {
		return s.handleNodeState(in)
	}
	return s.link.handle(in)
}

func (s *staticLinkFSM) handle(in message.Message) (*message.Message, disposition, error) {
	if s.waitingForRemoteProposal {
		if in.Type != message.LinkPropose {
			return nil, discardFrame, errors.New("expected LINK_PROPOSE")
		}
		return s.handleProposal(in)
	}
	if s.waitingForResponse {
		switch in.Type {
		case message.LinkAccept:
			result := s.result(s.outstanding)
			s.pendingCommit = &result
			s.waitingForResponse = false
			return nil, discardFrame, nil
		case message.LinkPropose:
			return s.handleProposal(in)
		default:
			return nil, discardFrame, errors.New("expected LINK_ACCEPT or counterproposal")
		}
	}
	return nil, discardFrame, errors.New("link FSM has no active transition")
}

func (s *sessionFSM) handleOpen(in message.Message) (*message.Message, disposition, error) {
	if in.Type != message.Open || in.UID == nil {
		return nil, closeConnection, errors.New("first message is not a valid OPEN")
	}
	if in.UID.UUID == s.config.LocalUID.UUID {
		return nil, closeConnection, errors.New("remote Node UUID equals local UUID")
	}
	s.remoteUID = *in.UID
	s.opened = true
	state := message.Message{Type: message.NodeState, LoopbackV6: s.config.LocalLoopbackV6}
	return &state, discardFrame, nil
}

func (s *sessionFSM) handleNodeState(in message.Message) (*message.Message, disposition, error) {
	if in.Type != message.NodeState {
		return nil, discardFrame, errors.New("expected NODE_STATE")
	}
	if !withinAddress(in.LoopbackV6, s.config.LoopbackPoolV6) {
		return nil, discardFrame, errors.New("remote loopback is outside Fabric prefix")
	}
	s.stateReceived = true
	s.remoteV6 = in.LoopbackV6
	if s.config.Context == RoutedSession {
		if s.config.ExpectedRemoteLoopbackV6.IsValid() && in.LoopbackV6 != s.config.ExpectedRemoteLoopbackV6 {
			return nil, closeConnection, errors.New("remote loopback does not match routed session target")
		}
		s.operational = true
		return nil, discardFrame, nil
	}
	s.link = &staticLinkFSM{
		config: s.config, remoteUID: s.remoteUID,
		remoteV6: in.LoopbackV6,
		seen:     map[string]struct{}{},
	}
	return s.link.start()
}

func (s *staticLinkFSM) start() (*message.Message, disposition, error) {
	if bytes.Compare(s.config.LocalUID.UUID[:], s.remoteUID.UUID[:]) < 0 {
		proposal, err := s.nextProposal()
		if err != nil {
			return nil, closeConnection, err
		}
		s.outstanding, s.waitingForResponse = proposal, true
		out := proposalMessage(proposal)
		return &out, discardFrame, nil
	}
	s.waitingForRemoteProposal = true
	return nil, discardFrame, nil
}

func (s *staticLinkFSM) handleProposal(in message.Message) (*message.Message, disposition, error) {
	proposal := link.Proposal{V4: in.LinkPrefixV4, V6: in.LinkPrefixV6}
	if !withinPrefix(proposal.V4, s.config.LinkPoolV4) || !withinPrefix(proposal.V6, s.config.LinkPoolV6) {
		return nil, discardFrame, errors.New("proposed Link prefix is outside Fabric prefix")
	}
	key := proposalKey(proposal)
	if _, repeated := s.seen[key]; repeated {
		return nil, closeConnection, errors.New("peer repeated a Link proposal")
	}
	s.seen[key] = struct{}{}
	acceptable := true
	if s.config.Accept != nil {
		acceptable = s.config.Accept(s.remoteUID, proposal)
	}
	if acceptable {
		result := s.result(proposal)
		s.pendingCommit = &result
		s.waitingForRemoteProposal, s.waitingForResponse = false, false
		accept := message.Message{Type: message.LinkAccept}
		return &accept, discardFrame, nil
	}
	counter, err := s.nextProposal()
	if err != nil {
		return nil, closeConnection, err
	}
	if proposalKey(counter) == key {
		return nil, closeConnection, errors.New("no distinct counterproposal available")
	}
	s.outstanding, s.waitingForRemoteProposal, s.waitingForResponse = counter, false, true
	out := proposalMessage(counter)
	return &out, discardFrame, nil
}

func (s *staticLinkFSM) nextProposal() (link.Proposal, error) {
	for s.attempt < maxCounterproposals {
		proposal, err := link.DeriveProposal(s.config.FabricPSK, s.config.LocalUID.UUID, s.remoteUID.UUID, s.config.LinkPoolV4, s.config.LinkPoolV6, s.config.LinkOverrides, s.attempt)
		s.attempt++
		if err != nil {
			return link.Proposal{}, err
		}
		key := proposalKey(proposal)
		if _, used := s.seen[key]; used {
			continue
		}
		if s.config.Accept != nil && !s.config.Accept(s.remoteUID, proposal) {
			continue
		}
		s.seen[key] = struct{}{}
		return proposal, nil
	}
	return link.Proposal{}, errors.New("no acceptable counterproposal available")
}

func (s *staticLinkFSM) result(proposal link.Proposal) Result {
	return Result{RemoteUID: s.remoteUID, RemoteLoopbackV6: s.remoteV6, Proposal: proposal}
}

func (s *sessionFSM) takeCommit() *Result {
	if s.link == nil || s.link.pendingCommit == nil {
		return nil
	}
	result := s.link.pendingCommit
	s.link.pendingCommit = nil
	return result
}

func (s *sessionFSM) markEstablished() {
	s.link.established = true
	s.operational = true
}

func (s *sessionFSM) remoteLoopbackV6() netip.Addr {
	return s.remoteV6
}

func validOperationalMessage(context SessionContext, kind message.Type) bool {
	if context == RoutedSession {
		return kind == message.DynamicLinkPropose || kind == message.DynamicLinkAccept || kind == message.DynamicLinkDecline
	}
	return kind == message.EndpointObservation
}

func proposalMessage(p link.Proposal) message.Message {
	return message.Message{Type: message.LinkPropose, LinkPrefixV4: p.V4, LinkPrefixV6: p.V6}
}
func proposalKey(p link.Proposal) string { return p.V4.String() + "|" + p.V6.String() }
func withinAddress(addr netip.Addr, pool netip.Prefix) bool {
	return !addr.IsValid() || pool.Contains(addr)
}
func withinPrefix(prefix, pool netip.Prefix) bool {
	return !prefix.IsValid() || (prefix.Bits() >= pool.Bits() && pool.Contains(prefix.Addr()))
}
