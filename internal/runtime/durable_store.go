package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
	"github.com/velvet-fabric/velvet-fabric/internal/vfp/message"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type durableRecord struct {
	ID             [16]byte
	Peer           message.UID
	LastLoopback   netip.Addr
	PublicKey      wgtypes.Key
	LocalPort      int
	FixedEndpoints []message.FixedEndpoint
	Confirmed      bool
}

type durableOwner struct {
	UUID      uuid.UUID
	PublicKey wgtypes.Key
}

type durableOwnerJSON struct {
	UUID      uuid.UUID `json:"uuid"`
	PublicKey string    `json:"public_key"`
}

type durableLocalJSON struct {
	ListenPort       int    `json:"listen_port"`
	RecoveryEndpoint string `json:"recovery_endpoint,omitempty"`
}

type durablePeerJSON struct {
	UUID             uuid.UUID `json:"uuid"`
	Name             string    `json:"name,omitempty"`
	PublicKey        string    `json:"public_key"`
	LastLoopback     string    `json:"last_loopback,omitempty"`
	RecoveryEndpoint string    `json:"recovery_endpoint,omitempty"`
}

type durableRecordJSON struct {
	AgreementID string           `json:"agreement_id"`
	Confirmed   bool             `json:"confirmed"`
	Local       durableLocalJSON `json:"local"`
	Peer        durablePeerJSON  `json:"peer"`
}

type durableFile struct {
	Version int                 `json:"version"`
	Owner   durableOwnerJSON    `json:"owner"`
	Records []durableRecordJSON `json:"records"`
}

func (r *Runner) durableOwner() durableOwner {
	return durableOwner{UUID: r.Desired.UUID, PublicKey: r.Desired.PrivateKey.PublicKey()}
}

func canonicalUUID(raw, field string) (uuid.UUID, error) {
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != raw {
		return uuid.Nil, fmt.Errorf("%s must be a canonical nonzero UUID", field)
	}
	return id, nil
}

func canonicalKey(raw, field string) (wgtypes.Key, error) {
	key, err := wgtypes.ParseKey(raw)
	if err != nil || key == (wgtypes.Key{}) || key.String() != raw {
		return wgtypes.Key{}, fmt.Errorf("%s must be a canonical WireGuard public key", field)
	}
	return key, nil
}

func parseRecoveryEndpoint(raw, field string) (netip.AddrPort, error) {
	if raw == "" {
		return netip.AddrPort{}, nil
	}
	endpoint, err := netip.ParseAddrPort(raw)
	if err != nil || !endpoint.IsValid() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s must be an IP endpoint with a nonzero port", field)
	}
	return endpoint, nil
}

func encodeDurableRecord(record durableRecord, local uuid.UUID) durableRecordJSON {
	value := durableRecordJSON{
		AgreementID: uuid.UUID(record.ID).String(), Confirmed: record.Confirmed,
		Local: durableLocalJSON{ListenPort: record.LocalPort},
		Peer:  durablePeerJSON{UUID: record.Peer.UUID, Name: record.Peer.Name, PublicKey: record.PublicKey.String()},
	}
	if record.LastLoopback.IsValid() {
		value.Peer.LastLoopback = record.LastLoopback.String()
	}
	if endpoint := fixedFor(record, local); endpoint.IsValid() {
		value.Local.RecoveryEndpoint = endpoint.String()
	}
	if endpoint := fixedFor(record, record.Peer.UUID); endpoint.IsValid() {
		value.Peer.RecoveryEndpoint = endpoint.String()
	}
	return value
}

func decodeDurableRecord(value durableRecordJSON, local uuid.UUID) (durableRecord, error) {
	agreement, err := canonicalUUID(value.AgreementID, "agreement_id")
	if err != nil {
		return durableRecord{}, err
	}
	if value.Peer.UUID == uuid.Nil || value.Peer.UUID == local {
		return durableRecord{}, errors.New("durable peer UUID must be nonzero and differ from owner")
	}
	key, err := canonicalKey(value.Peer.PublicKey, "peer.public_key")
	if err != nil {
		return durableRecord{}, err
	}
	if value.Local.ListenPort < 1 || value.Local.ListenPort > 65535 {
		return durableRecord{}, errors.New("local.listen_port must be between 1 and 65535")
	}
	localEndpoint, err := parseRecoveryEndpoint(value.Local.RecoveryEndpoint, "local.recovery_endpoint")
	if err != nil {
		return durableRecord{}, err
	}
	peerEndpoint, err := parseRecoveryEndpoint(value.Peer.RecoveryEndpoint, "peer.recovery_endpoint")
	if err != nil {
		return durableRecord{}, err
	}
	if !localEndpoint.IsValid() && !peerEndpoint.IsValid() {
		return durableRecord{}, errors.New("durable agreement requires at least one recovery endpoint")
	}
	if localEndpoint.IsValid() && int(localEndpoint.Port()) != value.Local.ListenPort {
		return durableRecord{}, errors.New("local recovery endpoint port differs from listen_port")
	}
	var lastLoopback netip.Addr
	if value.Peer.LastLoopback != "" {
		lastLoopback, err = netip.ParseAddr(value.Peer.LastLoopback)
		if err != nil || !lastLoopback.Is6() || lastLoopback.IsUnspecified() {
			return durableRecord{}, errors.New("peer.last_loopback must be a usable IPv6 address")
		}
	}
	fixed := make([]message.FixedEndpoint, 0, 2)
	if localEndpoint.IsValid() {
		fixed = append(fixed, message.FixedEndpoint{UID: message.UID{UUID: local}, Endpoint: localEndpoint})
	}
	if peerEndpoint.IsValid() {
		fixed = append(fixed, message.FixedEndpoint{UID: message.UID{UUID: value.Peer.UUID, Name: value.Peer.Name}, Endpoint: peerEndpoint})
	}
	slices.SortFunc(fixed, func(a, b message.FixedEndpoint) int { return bytes.Compare(a.UID.UUID[:], b.UID.UUID[:]) })
	record := durableRecord{
		ID: [16]byte(agreement), Peer: message.UID{UUID: value.Peer.UUID, Name: value.Peer.Name},
		LastLoopback: lastLoopback, PublicKey: key, LocalPort: value.Local.ListenPort,
		FixedEndpoints: fixed, Confirmed: value.Confirmed,
	}
	if _, err := message.Encode(message.Message{Type: message.DurablePropose, OperationID: record.ID, FixedEndpoints: fixed}); err != nil {
		return durableRecord{}, err
	}
	return record, nil
}

func loadDurable(path string, owner durableOwner) (map[uuid.UUID]durableRecord, error) {
	result := map[uuid.UUID]durableRecord{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	var f durableFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&f); err != nil {
		return nil, fmt.Errorf("invalid durable store: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF || f.Version != 1 {
		return nil, errors.New("unsupported or malformed durable store")
	}
	key, err := canonicalKey(f.Owner.PublicKey, "owner.public_key")
	if err != nil {
		return nil, err
	}
	if f.Owner.UUID != owner.UUID || key != owner.PublicKey {
		return nil, errors.New("durable store belongs to another node or WireGuard identity")
	}
	for _, value := range f.Records {
		record, err := decodeDurableRecord(value, owner.UUID)
		if err != nil {
			return nil, fmt.Errorf("invalid durable record: %w", err)
		}
		if record.PublicKey == owner.PublicKey {
			return nil, errors.New("durable peer public key equals owner public key")
		}
		if _, exists := result[record.Peer.UUID]; exists {
			return nil, errors.New("duplicate durable peer")
		}
		result[record.Peer.UUID] = record
	}
	return result, nil
}

type durableStoreIO struct {
	write  func(*os.File, []byte) (int, error)
	sync   func(*os.File) error
	rename func(string, string) error
}

// Success means both the file and its directory entry reached stable storage.
// A failed load never turns into an empty overwrite.
func saveDurable(path string, owner durableOwner, records map[uuid.UUID]durableRecord) error {
	return saveDurableWithIO(path, owner, records, durableStoreIO{(*os.File).Write, (*os.File).Sync, os.Rename})
}

// Per-call operations allow fault injection without mutable process-wide hooks.
func saveDurableWithIO(path string, owner durableOwner, records map[uuid.UUID]durableRecord, ops durableStoreIO) error {
	f := durableFile{Version: 1, Owner: durableOwnerJSON{UUID: owner.UUID, PublicKey: owner.PublicKey.String()}, Records: make([]durableRecordJSON, 0, len(records))}
	ordered := make([]durableRecord, 0, len(records))
	for _, record := range records {
		ordered = append(ordered, record)
	}
	slices.SortFunc(ordered, func(a, b durableRecord) int { return bytes.Compare(a.Peer.UUID[:], b.Peer.UUID[:]) })
	for _, record := range ordered {
		f.Records = append(f.Records, encodeDurableRecord(record, owner.UUID))
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = makePolicyDirectory(dir); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".durable-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = ops.write(tmp, append(data, '\n')); err == nil {
		err = ops.sync(tmp)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = ops.rename(tmp.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return ops.sync(directory)
}
