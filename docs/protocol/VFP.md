# Velvet Fabric Protocol (VFP)

## Version 1

Status: Version 1 protocol specification
Wire version: 1
Last updated: 2026-08-28

## Abstract

The Velvet Fabric Protocol (VFP) is the inter-node control protocol used by
`velvetd` instances belonging to one Fabric. It provides one extensible
protocol framework for the distributed control operations of the Fabric.

The first implementation phase only needs the information exchange required
after a statically configured WireGuard Link has been created. Later revisions
may add dynamic route exchange and dynamic Link establishment to the same
protocol. Those later functions do not justify separate top-level protocols,
but they also MUST NOT be predesigned as generic RPC calls or encoded before
their state machines are understood.

This document defines the agreed protocol boundary, framing and parsing model,
extension rules, error handling, and the initial static-Link message set.
Route exchange and dynamic-Link messages remain outside the current revision.

## 1. Status and Requirements Language

This document is the normative specification of VFP wire version 1. Informative
research notes under `refs/` record alternatives considered during design but
do not change the behavior specified here. Functions explicitly described as
future work are outside version 1.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** are to be interpreted as described by BCP 14 when, and only when,
they appear in all capitals.

All diagrams number bits from the most significant bit of the first octet.
Multi-octet integers use network byte order.

## 2. Scope

### 2.1 Protocol purpose

VFP carries distributed control information between `velvetd` nodes. Its
eventual scope may include:

- session establishment and peer identity;
- node resources, including a node loopback address;
- Link address negotiation and Link state changes;
- route announcement, withdrawal, and synchronization;
- control information required to establish a dynamic Link.

This is one protocol with multiple well-bounded exchanges. A Message Type
identifies a protocol action or state-machine event. TLVs carry the data needed
by that action.

### 2.2 Out of scope

VFP is not:

- the local NodeSpec format or the `velvetctl` API;
- a generic RPC protocol;
- a transport for logs, diagnostics, or arbitrary implementation objects;
- the WireGuard data plane;
- a serialization of kernel interface names or other local-only state;
- a routing algorithm by itself.

The dynamic routing algorithm has not been selected. In particular, this
document does not assume Babel.

### 2.3 Implementation phases

The intended delivery order is:

1. static Link establishment and direct neighbor reachability;
2. static routes;
3. dynamic routes;
4. dynamic Links.

Version 1 defines only phase 1 business messages while keeping the framing
usable by later phases.

## 3. Terminology

**Fabric**
: A set of nodes participating in one Velvet network.

**Node**
: One `velvetd` instance identified by a Node UID. A Node UID contains a
  persistent UUID and an optional short readable name.

**Peer**
: The remote node at the other end of a point-to-point Link or VFP session.

**Link**
: A point-to-point relationship between exactly two nodes. In the current
  implementation it is represented by a dedicated WireGuard interface with
  one peer.

**Session**
: A TCP connection on which VFP messages are exchanged.

**Frame**
: One complete VFP message, consisting of the common header and its TLV body.

**Message Type**
: The protocol action or state-machine event represented by a frame.

**TLV**
: A typed value carried in a frame body.

**Schema**
: The rules for a Message Type in a particular protocol state: which TLVs are
  understood, their cardinality, and how selected values are interpreted.

## 4. Architecture

### 4.1 Transport

VFP runs over TCP. TCP provides ordered, reliable octets; VFP framing provides
message boundaries.

The default VFP TCP port is 58420. A deployment MAY override this port through
out-of-band configuration. Both endpoints of a Link MUST agree on the effective
port; the port is not negotiated or carried in VFP.

In the static-Link phase, the TCP connection is made over the already
configured WireGuard Link using scoped link-local addresses. This allows VFP
to operate before any routed Fabric path exists.

A later dynamic-Link phase may signal over an existing routed Fabric path,
most likely using node loopback reachability. The exact transport selection and
fallback behavior for that phase are TBD.

### 4.2 Security context

In the static-Link phase, VFP runs inside a WireGuard Link whose peer public
key and optional Fabric PSK are already configured. VFP does not add a
certificate system, signing public key, or separate application handshake in
this phase.

The configured WireGuard public key identifies the peer endpoint of this
particular Link; it is not the Node UID and is not required to be globally
unique across the Fabric. The two endpoints of one WireGuard Link MUST use
different WireGuard public keys, as required for WireGuard to configure each
endpoint's remote peer. Reusing a public key on different dedicated Link
interfaces is outside VFP identity semantics.

Authentication for a future VFP session reached through a routed path is TBD
and MUST be designed together with the dynamic-Link threat model.

### 4.3 Protocol state

Protocol state is local state in the two peers' state machines. It is not
repeated as a field in every frame.

The meaning and validity of a frame are determined by:

1. the current local protocol state;
2. the frame's Message Type; and
3. the TLVs selected from its body.

No kernel or persistent control-plane state may be changed until the complete
frame has passed structural and semantic validation.

## 5. Common Wire Format

### 5.1 Frame header

Version 1 uses the following common frame header:

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |    Version    | Message Type  |        Message Length         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 ~                         TLV Body                              ~
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Version (8 bits)**
: The VFP wire version. A version-1 sender MUST encode this field as `1`.

**Message Type (8 bits)**
: The action or state-machine event represented by this frame.

**Message Length (16 bits)**
: Total frame length in octets, including the four-octet common header.

The minimum Message Length is 4. The version-1 maximum Message Length is 4096.
A sender MUST NOT emit a larger frame. A receiver MUST treat a larger declared
length as connection-invalid even though the 16-bit field can represent values
up to 65535.

The common header currently contains no magic value, flags, transaction ID,
session ID, source Node ID, or destination Node ID. Any such field requires a
concrete protocol need before inclusion.

### 5.2 TLV encoding

Every frame body is a sequence of TLVs. Message-specific fixed bodies are not
used.

The non-normative comparison that led to this choice is recorded in
[REF-FORMAT](refs/FORMAT.md).

Version 1 uses the following TLV layout:

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           TLV Type            |          Value Length         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 ~                         Value                                 ~
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**TLV Type (16 bits)**
: Identifies the value's syntax and general meaning.

**Value Length (16 bits)**
: Length of Value in octets; it does not include the four-octet TLV header.

TLVs are concatenated without alignment padding. An empty body is valid only
for a Message Type whose schema permits no required TLVs.

Encoding a value as a TLV does not make it semantically optional. Requiredness
is specified by the schema of the Message Type in the current state.

### 5.3 Frame extraction

A receiver MUST:

1. read the complete common header;
2. validate Message Length against the common-header size and hard receive
   limit;
3. read exactly the remaining `Message Length - header length` octets;
4. process no bytes from the following frame as part of the current frame.

An outer frame boundary that cannot be determined safely is a connection-level
error as specified in Section 9.

## 6. Generic TLV Processing

### 6.1 Two-stage processing

Frame processing has two distinct stages:

1. **Generic parse.** Walk the body from the first TLV to the frame boundary,
   checking only its structural bounds and collecting known values.
2. **Schema validation.** Apply the rules for the current state and Message
   Type, including requiredness, cardinality, value syntax, and business
   preconditions.

The generic parser does not choose a replacement value, infer intent, or
perform side effects.

### 6.2 Schema cardinality

For every known TLV used by a Message Type, its schema specifies two
cardinality values:

**min_occurs**
: The minimum number of occurrences the sender is required to emit and the
  receiver is required to select. It is a non-negative integer.

**max_occurs**
: The maximum number of occurrences the sender may emit and the receiver
  selects. It is either a positive integer or `unbounded`, and MUST be greater
  than or equal to `min_occurs`.

The notation `N` means `min_occurs = N, max_occurs = N`; `M..N` means the
inclusive range; and `M..*` means `min_occurs = M, max_occurs = unbounded`.

The receiver selects occurrences in wire order, up to `max_occurs`. Any later
occurrences are ignored. When `max_occurs` is `unbounded`, all occurrences are
selected, subject to the enclosing frame and protocol resource limits.

An unknown TLV, or a known TLV unused by the current Message Type, behaves as
`min_occurs = 0, max_occurs = 0`: its value is skipped using its declared
length.

If fewer than `min_occurs` occurrences are selected, the frame is invalid. If
a selected occurrence has an invalid value, the frame is invalid. The receiver
MUST NOT search an ignored later occurrence for a replacement value.

Example: a singleton field has cardinality `1`. The first occurrence is
authoritative for validation; subsequent occurrences are ignored and do not
override it.

### 6.3 Message schema

For each Message Type, its specification MUST define:

- in which protocol states it is valid;
- the allowed known TLVs;
- `min_occurs` and `max_occurs` for each allowed TLV;
- semantic validation and resulting state transition;
- whether processing is idempotent;
- the canonical sender form.

A known TLV that is not used by the current Message Type is ignored. This is a
field-level result, not a frame error.

### 6.4 Atomicity

The receiver MUST finish validation of all selected fields before changing
session state, route state, Link state, kernel networking, or persistent state.
An invalid frame therefore has no partial effect.

## 7. Sender Requirements

Receivers accept only the variations explicitly described by this document;
senders emit one canonical form.

A sender MUST:

- emit accurate, minimal lengths;
- emit each permitted TLV within the schema's `min_occurs..max_occurs` range;
- encode reserved bits or reserved values as zero when they are later defined;
- use the canonical TLV ordering defined for each Message Type;
- omit fields not permitted by the Message Type;
- validate its complete frame before sending it.

For the initial Message Types, canonical TLV order is ascending TLV Type. A
receiver MUST NOT depend on TLV order except when selecting the first
`max_occurs` occurrences of the same TLV Type.

## 8. Protocol Fields and Business Messages

This section defines the version-1 static-Link business messages and their
numeric code points.

### 8.1 Message Type registry

| Value | Name | Purpose |
|---:|---|---|
| `0x01` | `OPEN` | Open a VFP session and declare the sending Node UID |
| `0x02` | `NODE_STATE` | Publish the sending node's IPv6 loopback |
| `0x03` | `LINK_PROPOSE` | Propose a complete replacement Link-address set |
| `0x04` | `LINK_ACCEPT` | Accept the one currently outstanding Link proposal |

There is no `OPEN_ACK`, `LINK_REJECT`, generic result, or generic error Message
Type. A valid peer `OPEN` completes the opening exchange. A counterproposal
implicitly rejects and replaces the previous proposal. `LINK_ACCEPT` refers to
the single outstanding proposal held by session state.

### 8.2 TLV Type registry

| Value | Name | Value length | Purpose |
|---:|---|---:|---|
| `0x0001` | `NODE_UID` | 16..21 | Persistent Node UUID followed by an optional readable name |
| `0x0002` | Reserved | — | Not used by version 1 |
| `0x0003` | `LOOPBACK_V6` | 16 | Node-owned IPv6 loopback address; `/128` is implicit |
| `0x0004` | `LINK_PREFIX_V4` | 4 | Network address of a proposed point-to-point IPv4 `/30` |
| `0x0005` | `LINK_PREFIX_V6` | 16 | Network address of a proposed point-to-point IPv6 `/126` |

The following subsections define the complete value syntax. Addresses are
encoded as network-order octets without text, address-family, or prefix-length
fields.

#### 8.2.1 `NODE_UID`

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                                               |
 |                         UUID (16 octets)                      |
 |                                                               |
 |                                                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                 Name (0..5 ASCII octets)                     ...
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The first 16 octets are the binary representation of the Node's persistent
UUID. The all-zero UUID is invalid. UUID equality and ordering compare these
16 octets only, in unsigned lexicographic order.

The remaining zero to five octets are the Node's optional readable name. Each
octet MUST be a lowercase ASCII letter or decimal digit. The name is a display
and local-name-derivation hint; it is not required to be unique and does not
participate in UUID equality or ordering. Changing only the name does not
change Node identity.

A node normally generates and persists its own UUID. Peer configuration does
not contain an expected remote UUID. The remote UID is learned from `OPEN`
inside the already authenticated WireGuard Link.

#### 8.2.2 `LOOPBACK_V6`

The value is exactly 16 octets containing one IPv6 unicast address. The
address represents a node-owned `/128`; the `/128` length is not carried.

The address MUST be contained by the configured Fabric IPv6 loopback prefix
and MUST NOT be unspecified, multicast, or link-local. VFP control traffic may
use separate scoped Link-local addresses; those addresses are not Node
loopbacks and are never encoded by this TLV.

#### 8.2.3 `LINK_PREFIX_V4`

The value is exactly four octets containing the network address of an IPv4
`/30`. Bits outside the `/30` prefix MUST be zero.

After acceptance, the endpoint with the lexicographically smaller Node UUID
uses network address plus one, and the endpoint with the larger Node UUID uses
network address plus two. The prefix itself MUST be contained by the
configured Fabric IPv4 Link prefix. An endpoint with no configured IPv4 Link
prefix does not propose an automatically derived IPv4 prefix.

#### 8.2.4 `LINK_PREFIX_V6`

The value is exactly 16 octets containing the network address of an IPv6
`/126`. Bits outside the `/126` prefix MUST be zero.

After acceptance, the endpoint with the lexicographically smaller Node UUID
uses network address plus one, and the endpoint with the larger Node UUID uses
network address plus two. The prefix itself MUST be contained by the
configured Fabric IPv6 Link prefix. An endpoint with no configured IPv6 Link
prefix does not propose an automatically derived IPv6 prefix.

### 8.3 `OPEN`

`OPEN` is the first Message Type sent by each endpoint after TCP establishment.
Both endpoints send it; neither endpoint waits to receive `OPEN` before sending
its own.

| TLV | Cardinality | Meaning |
|---|---:|---|
| `NODE_UID` | `1` | UID of the sender |

The canonical body contains exactly one `NODE_UID`.

The first received frame MUST be `OPEN`. Once an endpoint has sent its own
`OPEN` and accepted the peer's `OPEN`, the opening exchange is complete. A
second `OPEN` on the same session is invalid in the current state.

`OPEN` is not idempotent within one TCP session. A replacement TCP session
starts a new opening exchange and sends a new `OPEN`.

If both endpoints declare the same UUID, the session is a self-identity or
cloned-identity conflict and is connection-invalid. The optional names may be
equal and do not affect this check.

### 8.4 `NODE_STATE`

`NODE_STATE` publishes the sender's node-owned IPv6 loopback for the current
session. It is sent after the opening exchange completes and before Link
address negotiation begins.

| TLV | Cardinality | Meaning |
|---|---:|---|
| `LOOPBACK_V6` | `1` | Sender's IPv6 node loopback |

The canonical body contains exactly one `LOOPBACK_V6`. Version 1 does not
publish an IPv4 node loopback and defines no loopback-collision exchange.

The initial static phase sends one `NODE_STATE` per session. A second
`NODE_STATE` is invalid in the current state; future live resource updates
require an explicitly specified state transition rather than treating this
message as an unconstrained update container.

`NODE_STATE` is not idempotent within one TCP session. A replacement TCP
session publishes the complete state again.

### 8.5 `LINK_PROPOSE`

`LINK_PROPOSE` carries one complete proposed set of routed Link addresses. It
is not a patch against an earlier proposal. Receiving a valid new proposal
implicitly rejects and replaces the previous outstanding proposal.

| TLV | Cardinality | Meaning |
|---|---:|---|
| `LINK_PREFIX_V4` | `0..1` | Proposed IPv4 `/30` for this Link |
| `LINK_PREFIX_V6` | `0..1` | Proposed IPv6 `/126` for this Link |

Canonical order is IPv4 followed by IPv6. The body MAY be empty. An empty
proposal means that the Link remains bootstrap-Link-local-only, with no routed
Link address. A local Fabric policy MAY refuse to accept an empty proposal and
counterpropose a non-empty set.

The version-1 product default is an unnumbered Link: when neither optional
Fabric Link prefix is configured, the initial proposal is empty. Numbered Link
addresses are optional resources and are not required for Velvet control-plane
or routed data-plane connectivity.

Exactly one proposal may be outstanding in a session. The endpoint with the
smaller Node UUID sends the initial proposal. Thereafter, proposal ownership
alternates:

1. the sender stores the complete proposal and waits;
2. the receiver either sends `LINK_ACCEPT`, or sends one complete
   `LINK_PROPOSE` counterproposal;
3. a counterproposal becomes the only outstanding proposal and reverses the
   sender and receiver roles.

Partial acceptance is represented by a counterproposal that retains accepted
families and replaces or omits unacceptable families. There is no per-family
acceptance state. For example, a receiver may replace only the IPv4 prefix
while copying the proposed IPv6 prefix unchanged.

A sender MUST NOT send another proposal while its own proposal is outstanding.
A proposal received outside the receiver's turn is invalid in the current
state. Implementations MUST bound counterproposal rounds and MUST NOT repeat a
complete proposal already sent in the same negotiation. `LINK_PROPOSE` is not
idempotent: every accepted occurrence creates or replaces the single
outstanding proposal and reverses whose turn it is.

If an endpoint cannot accept the outstanding proposal and has no proposal it
is willing to send, it closes the TCP session without a VFP error message.
This is a failed business negotiation, not a malformed frame and not a
`LINK_REJECT`. A later connection attempt is subject to local retry and
backoff policy.

### 8.6 `LINK_ACCEPT`

`LINK_ACCEPT` accepts the entire one outstanding `LINK_PROPOSE` most recently
sent by the peer.

| TLV | Cardinality | Meaning |
|---|---:|---|
| None | `0` | The accepted proposal is identified by session state |

The canonical `LINK_ACCEPT` has an empty body. It carries no prefix, address
family, transaction ID, status, or reason. It is valid only when the receiver
of `LINK_ACCEPT` has exactly one outstanding proposal and the sender of
`LINK_ACCEPT` is the endpoint whose turn was to evaluate it.

On a valid `LINK_ACCEPT`, both endpoints' desired Link state becomes the
complete accepted proposal. The acceptor reaches that state when it sends
`LINK_ACCEPT`; the proposer reaches it when it receives and validates
`LINK_ACCEPT`. If the TCP session fails between those events, normal
reconciliation on the next session MUST converge kernel state again; VFP does
not add a distributed commit exchange for this temporary failure window.

`LINK_ACCEPT` is not idempotent within one negotiation. After it is processed,
there is no outstanding proposal, so a second `LINK_ACCEPT` is invalid in the
current state.

### 8.7 Static-phase state machine

```text
TCP established
      |
      | both endpoints send OPEN
      v
OPEN exchange complete
      |
      | both endpoints send NODE_STATE
      v
NODE_STATE exchange complete
      |
      | smaller UUID sends LINK_PROPOSE
      v
proposal outstanding
      |\
      | \ LINK_PROPOSE: replace proposal and reverse turn
      |  `-----------------------------------------------.
      |                                                   |
      `---- LINK_ACCEPT ----------------------------------'
                              |
                              v
                    Link proposal accepted
```

The static-phase sequence is therefore:

1. Each endpoint is configured with its own WireGuard private key, the remote
   Link endpoint's WireGuard public key, the Fabric PSK, and any required
   endpoint candidates. A remote Node UUID is not configured.
2. Each endpoint creates its dedicated point-to-point WireGuard Link. The two
   endpoint public keys on that Link are different; no Fabric-wide public-key
   uniqueness is required by VFP.
3. Deterministic scoped Link-local addresses permit the peers to create a TCP
   connection without relying on any Fabric route.
4. Both endpoints exchange `OPEN`, learning each other's Node UID.
5. Both endpoints exchange `NODE_STATE`, learning each other's IPv6 node
   loopback.
6. The lower-UUID endpoint sends the initial complete `LINK_PROPOSE`.
7. The peers exchange counterproposals until one side sends `LINK_ACCEPT`.
8. Both sides reconcile any accepted Link addresses and the direct `/128`
   route to the adjacent peer's IPv6 loopback. An empty proposal adds no routed
   address to the Link.

No VFP field carries the Fabric PSK, WireGuard keys, endpoint candidates,
listen port, persistent keepalive, local Peer name, or local interface name.
Those values are already known or are local-only configuration.

### 8.8 Static routes

The first static-route phase does not require route announcements to propagate
through VFP. Static routes remain local configuration referring to a Peer.
Domain, plan, and dynamic route data are not part of the current protocol
schema.

## 9. Error Handling

VFP has exactly three generic error dispositions. There is no fourth generic
severity and no generic error-response message.

The non-normative error-handling survey is recorded in
[REF-ERROR](refs/ERROR_HANDLING.md).

### 9.1 Connection invalid — close TCP

The receiver closes the TCP connection when a trustworthy next frame boundary
or valid session cannot be maintained. Current cases are:

- Message Length is smaller than the common header;
- Message Length exceeds the version-1 limit of 4096 octets;
- TCP ends before the complete declared frame arrives;
- the first frame is not `OPEN`;
- the frame Version is unsupported;
- the first `OPEN` cannot pass its complete schema and semantic validation;
- the peer's `OPEN` declares the same Node UUID as the local node;
- Link negotiation cannot progress because a peer repeats a proposal or the
  local endpoint has no acceptable counterproposal.

Closing the connection is the entire wire-visible behavior. No VFP error frame
is sent.

### 9.2 Frame invalid — discard frame, keep session

If the outer frame boundary is trustworthy but the frame cannot be processed,
the receiver discards the entire frame, changes no protocol or networking
state, and continues the established session. Current cases are:

- a TLV header is incomplete;
- a TLV Value Length crosses the outer frame boundary;
- a TLV occurs fewer than its schema's `min_occurs`;
- a selected known TLV has an invalid length or value;
- the Message Type is invalid in the current state;
- the Message Type is unknown in an established session.

The receiver does not send a generic diagnostic or unsupported-message reply.

### 9.3 Field ignored — continue frame

The receiver skips the field and continues validating the frame when:

- the TLV Type is unknown;
- the TLV is known but unused by the current Message Type;
- an occurrence is beyond a field's finite `max_occurs`.

The field's declared length must still fit within the frame. Otherwise Section
9.2 applies.

### 9.4 Business rejection is not a parser error

A structurally valid proposal may be semantically unacceptable—for example, a
proposed Link prefix may conflict locally. The receiver sends a complete
counterproposal as specified in Section 8.5. This implicitly rejects the old
proposal and is not a fourth parser error category.

Likewise, route-specific recovery such as ignoring, replacing, or withdrawing
a route must be specified by the future route protocol semantics rather than by
this generic error framework.

Local logging is an implementation matter and has no wire semantics.

## 10. Extensibility and Versioning

### 10.1 Unknown elements

In an established session:

- an unknown TLV is ignored as specified in Section 9.3;
- an unknown Message Type is discarded as specified in Section 9.2.

An extension cannot make an unknown TLV mandatory for an old receiver and
still claim unchanged semantics.

### 10.2 Version changes

A new protocol version is required when an old implementation cannot safely
preserve the intended semantics by ignoring the new element. Examples include:

- making a previously unknown field required for an existing Message Type;
- changing the meaning or syntax of an existing field;
- changing framing or TLV boundary rules;
- changing an existing state transition incompatibly.

No capability-negotiation mechanism is defined yet. It should be added only
when a concrete independently negotiable feature requires it.

### 10.3 Reserved complexity

VFP currently defines no generic flags, transaction IDs, request IDs, generic
status values, or generic error messages. Each requires an observed protocol
need and a state-machine analysis before being added.

## 11. Robustness and Security Requirements

An implementation MUST:

- enforce frame and resource limits before allocating from peer-supplied
  lengths;
- validate TLV boundaries using overflow-safe arithmetic;
- avoid side effects until full-frame validation succeeds;
- treat peer values as untrusted even when the transport is WireGuard;
- ensure retries or duplicate delivery cannot create unintended kernel state;
- keep local configuration and kernel object names out of the wire format.

The protocol aims to be tolerant of explicitly ignorable extensions while
remaining strict about frame boundaries, selected field syntax, peer identity,
and state transitions. “Ignore unknown” does not mean “guess malformed input.”

## 12. References

### 12.1 Normative references

- [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), Key words for use in RFCs
  to Indicate Requirement Levels.
- [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174), Ambiguity of Uppercase vs
  Lowercase in RFC 2119 Key Words.

### 12.2 Informative references

- [REF-FORMAT](refs/FORMAT.md), wire-format and extensibility survey.
- [REF-ERROR](refs/ERROR_HANDLING.md), parsing and error-handling survey.

Informative references explain the alternatives that were considered. They do
not define VFP behavior; this document does.
