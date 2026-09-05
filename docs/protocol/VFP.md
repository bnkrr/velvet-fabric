# Velvet Fabric Protocol (VFP)

## Version 1

Status: Version 1 protocol specification
Wire version: 1
Last updated: 2026-09-05

## Abstract

The Velvet Fabric Protocol (VFP) is the inter-node control protocol used by
`velvetd` instances belonging to one Fabric. It provides one extensible
protocol framework for the distributed control operations of the Fabric.

Version 1 supports both the information exchange required after a statically
configured WireGuard Link has been created and the establishment of additional
Dynamic Links over an already routed Fabric. New functions MUST NOT be
predesigned as generic RPC calls or encoded before their state machines are
understood. Dynamic route exchange is deliberately separate: Velvet uses the
standard Babel protocol over the Link rather than defining VFP route messages.

This document defines the agreed protocol boundary, framing and parsing model,
extension rules, error handling, static-Link establishment, Endpoint
Observation, and Dynamic-Link establishment. Route exchange is outside VFP.

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

VFP carries distributed control information between `velvetd` nodes. Version
1 includes:

- session establishment and peer identity;
- node resources, including a node loopback address;
- Link address negotiation and Link state changes;
- control information required to establish a Dynamic Link.

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
- a routing algorithm or a transport for Babel packets.

Dynamic routing uses Babel as an independent standard UDP protocol. Babel
packets are not wrapped in VFP frames, and VFP does not duplicate Babel route,
neighbour, metric, or sequence-number state.

### 2.3 Implementation phases

The intended delivery order is:

1. static Link establishment and direct neighbor reachability;
2. static routes;
3. dynamic routes;
4. dynamic Links.

Version 1 defines phases 1 and 4 business messages. Phases 2 and 3 do not add
VFP route messages.

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

**Dynamic Link**
: A Link created at runtime by the Dynamic-Link procedure rather than declared
  as a static Peer in local configuration.

**Endpoint Evidence**
: Locally held information from which an Endpoint Candidate can be inferred.
  Evidence does not assert that the resulting endpoint is reachable.

**Endpoint Observation**
: Endpoint Evidence reported by a direct peer that observed the receiving
  node's WireGuard underlay endpoint on their existing Link.

**Endpoint Candidate**
: An underlay UDP endpoint proposed for one side of a Link Attempt.

**Link Attempt**
: One finite attempt by a pair of nodes to establish a Dynamic Link.

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
configured WireGuard Link using discovered scoped link-local addresses. This
allows VFP to operate before any routed Fabric path exists. Section 4.2
specifies the discovery exchange.

Dynamic-Link signalling uses a routed VFP session: TCP is opened from the local
node loopback to the target node loopback through an already working Fabric
path. A routed session uses the same effective VFP port and common framing as a
link-bound session. The transport context, rather than a wire field,
distinguishes the two session kinds.

### 4.2 Static-Link discovery

Before opening VFP/TCP, each endpoint derives and installs a local IPv6
link-local address. The derivation input is the local persistent Node UUID,
local effective interface name, and the Fabric PSK; it MUST NOT depend on the
remote Node UUID or a predicted remote address. Version 1 uses the first 64
bits of:

```text
HMAC-SHA-256(Fabric-PSK, 0x00 || "velvet-fabric/link-local/v1" ||
              0x00 || Node-UUID || 0x00 || UTF8(Interface-Name))
```

as the interface identifier under `fe80::/64`, clears the group bit of that
identifier, and substitutes identifier value 1 if all identifier bits are
zero. Every local Link MUST have a distinct effective interface name and
therefore independently derives its address. The two endpoints do not need to
use matching interface names.

Each endpoint opens its TCP listener and sends Discovery Hello datagrams to
`ff02::1` on the effective VFP port over the Link interface. UDP and TCP use
the same numeric port but remain separate transport namespaces. A sender MUST
use hop limit 1. A receiver MUST accept a Hello only when it was received on
the expected interface and its source is IPv6 link-local.

The Discovery version-1 Hello is exactly eight octets:

```text
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                 Magic = ASCII "VFPD"                         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Version = 1  | Message Type  |          Length = 8           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Message Type 1 is `HELLO`; Message Type 2 is `HELLO_ACK`. Unknown versions or
Message Types, incorrect lengths, invalid source addresses, and datagrams
received on another interface are silently ignored. The discovery datagram
carries no Node UID, WireGuard key, port, or resource. Node identity remains an
`OPEN` property after TCP is established.

A node sends one Hello immediately and repeats it with jittered exponential
backoff bounded at two seconds while the interface has no active TCP session.
Receiving a multicast `HELLO` triggers one unicast `HELLO_ACK` to its actual
source address on the effective discovery port. A receiver MUST NOT reply to
`HELLO_ACK`; consequently replies cannot form a loop or Fabric-wide flood.
Either valid type discovers the sender. Once a TCP session is chosen, both
Hello send and receive activity for the Link stop. Discovery restarts after
session failure or interface reactivation.

After learning the actual remote source address, both endpoints compare the
two IPv6 addresses as unsigned 128-bit integers. The endpoint with the lower
address initiates TCP and the endpoint with the higher address accepts. Both
endpoints listen before sending Hello. A node accepts TCP only when its source
is an IPv6 link-local address scoped to the expected Link and address ordering
assigns the remote endpoint the dialling role. Receipt of the peer's Hello need
not win a scheduling race with TCP accept: the scoped link-local source is
sufficient return-address evidence on this point-to-point Link. Equal
addresses are a collision and no VFP session is established. Address ordering
selects one TCP role only; it is never used to predict an address.

Discovery framing has its own version. Its version changes do not change the
VFP/TCP frame Version defined in Section 5.

### 4.3 Security context

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

Version 1 treats all Fabric nodes as mutually trusted. A routed VFP session is
protected hop by hop by the existing Fabric Links, but VFP adds no end-to-end
authentication, confidentiality, integrity, or replay protection. Matching the
peer's `NODE_STATE` loopback to the routed target is an internal consistency
check, not cryptographic authentication. Deployments that do not trust every
Fabric member MUST NOT enable version-1 Dynamic Links.

### 4.4 Protocol state

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

This section defines all version-1 business messages and their numeric code
points.

### 8.1 Message Type registry

| Value | Name | Purpose |
|---:|---|---|
| `0x01` | `OPEN` | Open a VFP session and declare the sending Node UID |
| `0x02` | `NODE_STATE` | Publish the sending node's IPv6 loopback |
| `0x03` | `LINK_PROPOSE` | Propose a complete replacement Link-address set |
| `0x04` | `LINK_ACCEPT` | Accept the one currently outstanding Link proposal |
| `0x05` | `ENDPOINT_OBSERVATION` | Report the receiving node's endpoint as observed on a direct Link |
| `0x06` | `DYNAMIC_LINK_PROPOSE` | Propose one Dynamic-Link operation and the initiator's parameters |
| `0x07` | `DYNAMIC_LINK_ACCEPT` | Accept an operation and return the acceptor's parameters |
| `0x08` | `DYNAMIC_LINK_DECLINE` | Decline participation in one Dynamic-Link operation |

There is no `OPEN_ACK`, `LINK_REJECT`, Dynamic-Link success/failure, generic
result, or generic error Message Type. A valid peer `OPEN` completes the
opening exchange. A static counterproposal implicitly rejects and replaces the
previous proposal. `LINK_ACCEPT` refers to the single outstanding static
proposal held by session state.

### 8.2 TLV Type registry

| Value | Name | Value length | Purpose |
|---:|---|---:|---|
| `0x0001` | `NODE_UID` | 16..21 | Persistent Node UUID followed by an optional readable name |
| `0x0002` | Reserved | — | Not used by version 1 |
| `0x0003` | `LOOPBACK_V6` | 16 | Node-owned IPv6 loopback address; `/128` is implicit |
| `0x0004` | `LINK_PREFIX_V4` | 4 | Network address of a proposed point-to-point IPv4 `/30` |
| `0x0005` | `LINK_PREFIX_V6` | 16 | Network address of a proposed point-to-point IPv6 `/126` |
| `0x0006` | `OPERATION_ID` | 16 | Opaque identifier correlating one operation's messages |
| `0x0007` | `WG_PUBLIC_KEY` | 32 | Sender's WireGuard public key for one Link Attempt |
| `0x0008` | `WG_ENDPOINT` | 8 or 20 | A WireGuard underlay endpoint whose role is defined by the Message Type |
| `0x0009` | Reserved | — | Not used by version 1 |

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
not contain an expected remote UUID. The remote UID is learned from `OPEN`.
On a link-bound session, the surrounding configured WireGuard Link provides
the security context. On a routed session, version 1 accepts the assertion
under the all-Fabric-members-trusted model in Section 4.3.

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

#### 8.2.5 `OPERATION_ID`

The value is exactly 16 opaque octets. It is not required to be a UUID and
carries no time, sequence, or operation-type semantics. An initiator MUST use a
value distinct from its other operations that may still be active. A responder
compares the value for equality and copies it unchanged into its response.

A Dynamic Link Attempt is identified by the initiator Node UID and
`OPERATION_ID`. The field is carried only by Message Types whose operation
requires correlation; it is not part of the common header.

#### 8.2.6 `WG_PUBLIC_KEY`

The value is exactly 32 octets containing a non-zero WireGuard Curve25519
public key. The sender MUST possess the corresponding private key. VFP does not
require whether the key pair is per-site, per-Link, or temporary. The field is
a parameter of the current Link Attempt, not Node identity.

The two public keys selected for one Link MUST differ. Equal keys cannot form a
WireGuard peer relationship and cause the Attempt to be declined or fail.

#### 8.2.7 `WG_ENDPOINT`

`WG_ENDPOINT` has this value syntax:

```text
Address Family (16 bits) | Port (16 bits) | Address (4 or 16 octets)
```

All integers use network byte order. Address Family uses IANA Address Family
Numbers: IPv4 is `1` and makes an eight-octet value; IPv6 is `2` and makes a
20-octet value. Port MUST be in `1..65535`. The address MUST be unicast and
MUST NOT be unspecified, multicast, IPv4-mapped IPv6, IPv4 limited broadcast,
or scoped IPv6 link-local. Private IPv4 and IPv6 ULA addresses remain valid.
The value contains no DNS name, scope identifier, priority, NAT type, or
inference metadata.

The enclosing Message Type defines the endpoint's role. In
`ENDPOINT_OBSERVATION`, it is the receiver endpoint observed by the sender. In
`DYNAMIC_LINK_PROPOSE` or `DYNAMIC_LINK_ACCEPT`, it is the sender's Candidate
that the receiver is asked to try for the current Attempt. Observation and
Candidate remain distinct protocol concepts but do not require distinct wire
types.

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
session. It is sent after the opening exchange completes. A link-bound session
then begins Link-address negotiation; a routed session becomes operational.

| TLV | Cardinality | Meaning |
|---|---:|---|
| `LOOPBACK_V6` | `1` | Sender's IPv6 node loopback |

The canonical body contains exactly one `LOOPBACK_V6`. Version 1 does not
publish an IPv4 node loopback and defines no loopback-collision exchange.

Version 1 sends one `NODE_STATE` per session. A second
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
3. Each endpoint derives only its local scoped link-local address, opens a TCP
   listener, and sends Discovery Hello over link-local multicast.
4. Each endpoint learns the actual remote source address. The lower-address
   endpoint initiates the single TCP connection; discovery then stops.
5. Both endpoints exchange `OPEN`, learning each other's Node UID.
6. Both endpoints exchange `NODE_STATE`, learning each other's IPv6 node
   loopback.
7. The lower-UUID endpoint sends the initial complete `LINK_PROPOSE`.
8. The peers exchange counterproposals until one side sends `LINK_ACCEPT`.
9. Both sides reconcile any accepted Link addresses and the direct `/128`
   route to the adjacent peer's IPv6 loopback. An empty proposal adds no routed
   address to the Link.

No VFP field carries the Fabric PSK, WireGuard keys, endpoint candidates,
listen port, persistent keepalive, local Peer name, or local interface name.
Those values are already known or are local-only configuration.

### 8.8 Static routes

The first static-route phase does not require route announcements to propagate
through VFP. Static routes remain local configuration referring to a Peer.
Domain and Plan configuration are local, while dynamic route exchange uses
Babel; none of these are VFP messages.

### 8.9 Session contexts and operational messages

Every VFP/TCP session first exchanges `OPEN` and `NODE_STATE`. The transport
path assigns one of two local contexts; no `SESSION_TYPE` field is sent:

- A **link-bound session** is established by Section 4.2 on a known direct
  WireGuard interface. It then performs Sections 8.5 through 8.7 and, after
  commit, accepts only `ENDPOINT_OBSERVATION` as an operational message.
- A **routed session** is opened from one node loopback to another through an
  already routed Fabric path. After `NODE_STATE`, it immediately becomes
  operational and accepts only `DYNAMIC_LINK_PROPOSE`,
  `DYNAMIC_LINK_ACCEPT`, and `DYNAMIC_LINK_DECLINE`.

The initiator of a routed session MUST require the peer's `LOOPBACK_V6` to
equal the destination loopback used for that TCP connection. Both session
contexts reject a remote loopback outside the configured Fabric loopback
prefix. These are consistency and scope checks, not cryptographic identity
proofs.

An operational routed session can carry Link Attempts as independent
operations correlated by `OPERATION_ID`; the session is not placed into one
monolithic per-Attempt state. Version 1 nevertheless permits at most one
active Link Attempt for a given Node pair.

### 8.10 `ENDPOINT_OBSERVATION`

`ENDPOINT_OBSERVATION` is valid only on an operational link-bound session. It
reports the WireGuard endpoint at which the sender currently observes the
receiver on the Link carrying that session.

| TLV | Cardinality | Meaning |
|---|---:|---|
| `WG_ENDPOINT` | `1` | Receiver endpoint observed by the sender |

The canonical body contains exactly one `WG_ENDPOINT`. The message does
not carry Node UID, Link ID, operation ID, timestamp, lease, or expiry: the
established session identifies both nodes and its carrying Link.

Upon entering operational state, each endpoint MUST read the carrying
WireGuard interface's current peer endpoint. If present, it MUST immediately
send one Observation. If absent, the initial sending obligation remains until
the endpoint first becomes available. While the session remains operational,
the sender MUST send a new Observation whenever the endpoint value changes and
MUST NOT periodically repeat an unchanged value. Every replacement
link-bound session creates a new initial sending obligation.

Observation has no acknowledgement or response Message. TCP supplies reliable
ordered delivery; a send failure fails the session, and its replacement sends
the current value again. A receiver synchronously replaces the Evidence entry
for the carrying Link before processing a later frame. An inability to retain
that fixed-size entry fails the session.

Evidence is keyed by the direct Link, not the transient TCP session. Each
entry associates the received Observation with the actual local WireGuard
listen port of that carrying Link at receipt time, forming the local mapping
`(Link, Local Listen Port, Observed Endpoint)`. The listen port is already
known locally and is not carried in the Observation. Session failure does not
expire Evidence; deleting the Link deletes it. A stale Observation is only an
input to inference, and direct connectivity validation remains authoritative.

### 8.11 Baseline discovery, selection, and inference

Dynamic Link is an optimization over an existing routed path. VFP neither
distributes nor computes loopback routes. Given a reachable node loopback `L`,
a node discovers its target by connecting TCP to `[L]:VFP_PORT`, exchanging
`OPEN` and `NODE_STATE`, and requiring the returned `LOOPBACK_V6` to equal `L`.
The resulting Node UID identifies the peer for the lifetime of that routed
session. A local cache MAY retain the binding as a hint, but MUST NOT replace
the session exchange and has no protocol lease.

Link selection is distributed. Local policy conceptually supplies
`want_link(peer)`, `allow_link_from(peer)`, and
`allow_candidate(candidate)`. Either endpoint MAY initiate. A receiver
participates when it wants the Link or permits inbound creation, accepts the
initiator's Candidate, has no existing direct Link to that Node, and can
reserve the required local resources.

Version 1's baseline Endpoint Inference algorithm chooses the first locally
available Endpoint Observation in stable Evidence-store order. Given
Observation `A:old_port` and the actual listen port `P` reserved for the new
WireGuard interface, it returns exactly one Candidate `A:P`. It preserves the
observed IP address and does not use either port from the Evidence mapping.
The complete mapping remains available to other inference profiles. With no
Evidence it cannot propose or accept an Attempt. The protocol carries no
Candidate priority, confidence, source, or NAT classification.

The current automatic profile is one-shot after Node UID binding: an active
node makes at most one Dynamic-Link decision for each reachable remote `/128`
in the Fabric loopback prefix per configuration generation, excluding itself
and existing direct peers. Establishing the routed VFP session used for UID
binding MAY use up to three total connection attempts to tolerate transient
route or TCP convergence; failure after that bound exhausts the target for the
generation.
Once that routed session reaches operational state, policy refusal, resource
failure, failed Proposal, or Decline retains the routed path but creates no
automatic retry in that generation. Passive nodes only respond; disabled nodes
still send Observations on their existing Links but neither propose nor accept
Dynamic Links.

### 8.12 Dynamic-Link messages

`DYNAMIC_LINK_PROPOSE` starts one Link Attempt on an operational routed
session. Before sending it, the initiator MUST reserve its tentative
WireGuard interface and actual listen port, freeze its local public key and
Candidate, and choose a fresh active-operation `OPERATION_ID`.

| TLV | Cardinality | Meaning |
|---|---:|---|
| `OPERATION_ID` | `1` | Identifier chosen by the initiator |
| `WG_PUBLIC_KEY` | `1` | Initiator's key for this Attempt |
| `WG_ENDPOINT` | `1` | Initiator Candidate to be tried by the acceptor |

`DYNAMIC_LINK_ACCEPT` accepts the complete Proposal and supplies the
acceptor's frozen parameters:

| TLV | Cardinality | Meaning |
|---|---:|---|
| `OPERATION_ID` | `1` | Exact value copied from the Proposal |
| `WG_PUBLIC_KEY` | `1` | Acceptor's key for this Attempt |
| `WG_ENDPOINT` | `1` | Acceptor Candidate to be tried by the initiator |

`DYNAMIC_LINK_DECLINE` states only that the receiver will not participate in
this Attempt:

| TLV | Cardinality | Meaning |
|---|---:|---|
| `OPERATION_ID` | `1` | Exact value copied from the declined Proposal |

Decline carries no reason, retry delay, policy detail, or NAT classification.
It ends the initiator's wait without closing a routed session that may carry
other operations. A receiver sends Decline if local participation or Candidate
policy rejects the Proposal, a direct Link already exists, resources or a
complete local Candidate are unavailable, or the two WireGuard keys are
equal. If an initiator rejects the Candidate returned in an otherwise valid
Accept, it locally fails the Attempt; version 1 defines no second response.

Accept and Decline MUST be sent on the routed session that carried the
Proposal. A response whose `OPERATION_ID` is unknown, ended, or belongs to a
different session is frame-invalid. Each Message's canonical encoding lists
its TLVs in ascending Type order.

### 8.13 Link Attempt procedure

After Accept is sent or received, each endpoint configures the peer public key
and Candidate on its tentative WireGuard interface. The Link PSK, if used, is
derived outside VFP from Fabric state and both public keys. Link-local address
derivation remains Section 4.2 and is not carried in Dynamic-Link messages.

The tentative Link then runs the standard link-bound procedure: Discovery,
TCP, `OPEN`, `NODE_STATE`, `LINK_PROPOSE`, and `LINK_ACCEPT`. The Attempt is
committed only when that new link-bound session reaches operational state and
its remote Node UID equals the routed-session target. This is both the
WireGuard connectivity test and the bidirectional VFP test; no additional
success Message is sent.

The initiator starts a ten-second Response Timeout after completely writing
Proposal. Receipt of its corresponding Accept or Decline stops that timer.
The acceptor starts a 30-second Connectivity Deadline after completely
writing Accept; the initiator starts the same deadline after validating
Accept. These values are version-1 constants, not negotiated configuration.

Before Accept completes, loss of the routed session fails the associated
Attempt. After Accept completes, routed-session lifetime no longer controls
it. If standard Link establishment becomes operational first, the endpoint
cancels its deadline and commits. If the deadline wins, it removes tentative
state and ignores a late completion. The existing routed path remains present
throughout and therefore needs no rollback or fallback Message.

Either node may initiate. If both initiate concurrently, both retain the
Attempt whose initiator Node UUID is lexicographically smaller; the larger
UUID node supersedes its own Attempt and participates in the smaller UUID
node's Attempt. The losing Proposal receives Decline. Implementations MUST
permit the winning Attempt to reuse already reserved local resources even when
Decline and the countervailing Proposal arrive in either order.

The minimal state progression is:

```text
IDLE -> PROPOSING -> ATTEMPTING -> UP -> RECOVERING -> UP
          |              |                 |
          +--------------+-----------------+-> IDLE
                                      (deadline, cleanup, routed path retained)
```

Loss of the operational link-bound session after commit moves the local
Attempt to `RECOVERING`; it does not create a new routed Proposal. The endpoint
reruns the standard link-bound establishment procedure over the committed
WireGuard interface with a fresh 30-second Connectivity Deadline. Reaching
operational state with the same remote Node UID returns to `UP`. If the
deadline wins, the endpoint removes the Dynamic Link and its materialized
routing state. This recovery is local behavior and adds no wire Message.

Version 1 sends no retransmitted Proposal on one session and defines no
cancel, success, failure, rollback, or generic error Message. A future
continuous `want_link` policy MAY apply bounded backoff locally, but it must
not alter these wire messages or cause a tight retry loop.

### 8.14 Dynamic-Link local resources

VFP does not encode interface names. A conforming implementation MUST ensure
that a tentative interface is not confused with another Node pair and that
cleanup of a superseded Attempt cannot delete resources already reused by the
winning Attempt. Dynamic Links are runtime state: preserving them across an
effectively unchanged local configuration is permitted, while a changed
configuration MAY cancel, remove, and relearn them from the surviving routed
Fabric.

Routing protocols may observe a tentative interface before VFP commit. Such a
protocol forms no useful adjacency until the Link carries packets and must
withdraw its state if the interface is removed. This does not change the VFP
success condition and does not put routing messages inside VFP.

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
- static Link negotiation cannot progress because a peer repeats a proposal or the
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
- the Message Type is unknown in an established session;
- a Dynamic-Link response references an unknown, ended, or different-session
  operation.

The receiver does not send a generic diagnostic or unsupported-message reply.

### 9.3 Field ignored — continue frame

The receiver skips the field and continues validating the frame when:

- the TLV Type is unknown;
- the TLV is known but unused by the current Message Type;
- an occurrence is beyond a field's finite `max_occurs`.

The field's declared length must still fit within the frame. Otherwise Section
9.2 applies.

### 9.4 Business rejection is not a parser error

A structurally valid proposal may be semantically unacceptable. A static Link
prefix conflict causes the receiver to send a complete counterproposal as
specified in Section 8.5. A Dynamic-Link policy or resource rejection causes
the receiver to send `DYNAMIC_LINK_DECLINE` as specified in Section 8.12.
Neither is a fourth parser error category.

Route-specific recovery such as ignoring, replacing, or withdrawing a route is
specified by the independent route protocol rather than by this generic error
framework.

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
- limit active Link Attempts and tentative interfaces per Node pair;
- validate every remote Candidate against local admission policy before using
  it as a WireGuard endpoint;
- enforce the Response Timeout and Connectivity Deadline so an unresponsive
  peer cannot retain tentative resources indefinitely;
- bind Dynamic-Link commit to the Node UID confirmed by the new link-bound
  session;
- keep local configuration and kernel object names out of the wire format.

The protocol aims to be tolerant of explicitly ignorable extensions while
remaining strict about frame boundaries, selected field syntax, peer identity,
and state transitions. “Ignore unknown” does not mean “guess malformed input.”

Version 1 routed VFP and its Dynamic-Link parameters are safe only within the
all-Fabric-members-trusted model of Section 4.3. Hop-by-hop WireGuard does not
prevent an on-path Fabric node from reading, changing, replaying, or
impersonating routed VFP traffic. Candidate allow-lists reduce accidental or
policy-forbidden endpoint use but are not Node authentication. An extension
that supports mutually untrusted Fabric members requires an authenticated
binding between Node UID and a long-term identity plus end-to-end integrity,
replay protection, and downgrade rules.

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
