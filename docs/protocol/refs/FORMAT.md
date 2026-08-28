# REF-FORMAT: Wire-Format and Extensibility Survey

Status: Informative research note; not part of the VFP specification.

## Question

How should a TCP-carried, stateful Fabric control protocol frame messages and
encode message-specific data without committing the implementation to a generic
RPC or object-serialization system?

## Compared designs

### BGP

BGP uses a fixed common message header containing a length and type, followed
by a body whose syntax is selected by the message type. Optional and extensible
data inside messages may use typed attributes or optional parameters. This
makes framing cheap and message boundaries unambiguous, but it leaves each
message family with its own parsing structure.

Sources:

- [RFC 4271: BGP-4](https://www.rfc-editor.org/rfc/rfc4271)
- [RFC 5492: Capabilities Advertisement with BGP-4](https://www.rfc-editor.org/rfc/rfc5492)

### DHCPv6

DHCPv6 uses a small message header and represents most message content as a
sequence of typed options. The message type determines which options are
required or permitted. An option's TLV encoding and its semantic optionality
are separate questions.

Source:

- [RFC 8415: DHCP for IPv6](https://www.rfc-editor.org/rfc/rfc8415)

### Babel

Babel uses a packet header followed by TLVs. Its TLV model demonstrates compact
extension and skipping of unknown fields, while its routing semantics and
datagram transport are not applicable automatically to VFP.

Source:

- [RFC 8966: The Babel Routing Protocol](https://www.rfc-editor.org/rfc/rfc8966)

### PCEP

PCEP is a stateful control protocol over TCP. It uses a common message header,
message types, and typed objects/TLVs. It demonstrates that a single protocol
can contain multiple bounded exchanges without becoming a generic RPC system.

Source:

- [RFC 5440: Path Computation Element Communication Protocol](https://www.rfc-editor.org/rfc/rfc5440)

### Tailscale DERP

DERP uses explicit binary frame types and lengths over a stream. Its framing is
simple and purpose-specific. Its relay role and message set are not a model for
VFP's Fabric control semantics.

Source:

- [Tailscale DERP protocol implementation](https://github.com/tailscale/tailscale/blob/main/derp/derp.go)

## Conclusions used by VFP

1. A length-delimited common frame is needed on TCP.
2. Message Type should represent a protocol action or state-machine event.
3. VFP can use a uniform TLV body without a message-specific fixed body.
4. The schema for the current state and Message Type must define requiredness,
   accepted fields, cardinality, and semantics.
5. Unknown fields can be skipped only when their outer and TLV boundaries are
   trustworthy.
6. Encoding all business values as TLVs does not require protobuf, generic RPC,
   reflection, or a generic status envelope.
7. Versioning and capability negotiation are distinct. Capability machinery
   should not be added until an independently negotiable feature exists.

The exact VFP header widths and code points are defined by the normative VFP
document, not by this survey.
