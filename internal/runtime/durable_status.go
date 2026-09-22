package runtime

import (
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
)

type DurableLocalStatus struct {
	ListenPort       int    `json:"listen_port"`
	RecoveryEndpoint string `json:"recovery_endpoint,omitempty"`
}

type DurablePeerStatus struct {
	UUID             string `json:"uuid"`
	Name             string `json:"name,omitempty"`
	PublicKey        string `json:"public_key"`
	LastLoopback     string `json:"last_loopback,omitempty"`
	RecoveryEndpoint string `json:"recovery_endpoint,omitempty"`
}

type DurableStatus struct {
	PeerReadyUntil *time.Time         `json:"peer_ready_until,omitempty"`
	FailedSince    *time.Time         `json:"failed_since,omitempty"`
	AgreementID    string             `json:"agreement_id"`
	Confirmed      bool               `json:"confirmed"`
	Local          DurableLocalStatus `json:"local"`
	Peer           DurablePeerStatus  `json:"peer"`
}

func (d *durableManager) status() []DurableStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	var result []DurableStatus
	for _, record := range d.records {
		var ready, failed *time.Time
		if check := d.checks[record.Peer.UUID]; check != nil {
			if !check.readyUntil.IsZero() {
				value := check.readyUntil
				ready = &value
			}
			if !check.failedSince.IsZero() {
				value := check.failedSince
				failed = &value
			}
		}
		value := DurableStatus{
			PeerReadyUntil: ready, FailedSince: failed,
			AgreementID: uuid.UUID(record.ID).String(), Confirmed: record.Confirmed,
			Local: DurableLocalStatus{ListenPort: record.LocalPort},
			Peer:  DurablePeerStatus{UUID: record.Peer.UUID.String(), Name: record.Peer.Name, PublicKey: record.PublicKey.String()},
		}
		if record.LastLoopback.IsValid() {
			value.Peer.LastLoopback = record.LastLoopback.String()
		}
		if endpoint := fixedFor(record, d.owner.UUID); endpoint.IsValid() {
			value.Local.RecoveryEndpoint = endpoint.String()
		}
		if endpoint := fixedFor(record, record.Peer.UUID); endpoint.IsValid() {
			value.Peer.RecoveryEndpoint = endpoint.String()
		}
		result = append(result, value)
	}
	slices.SortFunc(result, func(a, b DurableStatus) int {
		if a.Peer.UUID < b.Peer.UUID {
			return -1
		}
		if a.Peer.UUID > b.Peer.UUID {
			return 1
		}
		return 0
	})
	return result
}

func (r *Runner) DeleteDurable(raw string) error {
	peer, err := uuid.Parse(raw)
	if err != nil || peer == uuid.Nil {
		return errors.New("peer must be a nonzero UUID")
	}
	d := r.durable
	if d == nil {
		return errors.New("durable manager unavailable")
	}
	d.mu.Lock()
	if d.closed || r.dynamic.ctx.Err() != nil {
		d.mu.Unlock()
		return errors.New("runtime stopping")
	}
	record, exists := d.records[peer]
	err = d.deleteLocked(peer, "operator deletion")
	d.mu.Unlock()
	if err == nil && exists {
		d.removeFailed(record)
	}
	return err
}
