# REF-ERROR: Parsing and Error-Handling Survey

Status: Informative research note; not part of the VFP specification.

## Question

How should VFP tolerate extensions and recoverable message errors without
making malformed input ambiguous or expanding the protocol with diagnostic
messages and special recovery states?

## Compared guidance

### BGP base behavior and revised error handling

The original BGP specification closes the connection for many protocol errors.
RFC 7606 later reduces the scope of selected UPDATE errors so that one bad item
does not necessarily destroy otherwise useful session state. Its useful lesson
for VFP is error containment, not its route-specific recovery actions.

Sources:

- [RFC 4271: BGP-4](https://www.rfc-editor.org/rfc/rfc4271)
- [RFC 7606: Revised Error Handling for BGP UPDATE Messages](https://www.rfc-editor.org/rfc/rfc7606)

### BGPsec

BGPsec validation treats the complete security-relevant structure as a unit.
An implementation must not accept a partially validated structure. For VFP,
the applicable conclusion is to validate a complete selected message before
performing state or kernel changes.

Source:

- [RFC 8205: BGPsec Protocol Specification](https://www.rfc-editor.org/rfc/rfc8205)

### Robust-protocol guidance

Modern robustness guidance rejects unbounded guesses about malformed input.
Receiver tolerance should be explicit and deterministic, while senders produce
one canonical form.

Source:

- [RFC 9413: Maintaining Robust Protocols](https://www.rfc-editor.org/rfc/rfc9413)

### DHCPv6 and Babel unknown elements

Both option/TLV-oriented designs distinguish an unknown, well-bounded element
from a malformed enclosing message. This supports extension by skipping a
field without losing synchronization.

Sources:

- [RFC 8415: DHCP for IPv6](https://www.rfc-editor.org/rfc/rfc8415)
- [RFC 8966: The Babel Routing Protocol](https://www.rfc-editor.org/rfc/rfc8966)

## Conclusions used by VFP

1. If the next frame boundary cannot be trusted, the TCP connection must close.
2. If the outer frame is trustworthy but the frame is unusable, the frame can
   be discarded without changing state while the established session remains.
3. If one TLV is explicitly ignorable, it can be skipped while the rest of the
   frame continues.
4. These three dispositions are sufficient for the generic protocol layer.
   Route withdrawal, Link rejection, and similar outcomes belong to their
   business state machines.
5. VFP does not need a generic error response, unsupported-message response,
   diagnostic exchange, or extra error severity merely to implement these
   dispositions.
6. A selected malformed value invalidates the frame; a later duplicate is not
   searched as a replacement.
7. Complete semantic validation must precede all state and kernel mutations.

The normative mapping of concrete VFP conditions to these dispositions is
defined only by the VFP document.
