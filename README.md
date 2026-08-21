# SwornMail Protocol Specification

**Cryptographic IPv6 prefix attestation for SMTP.** A sending operator
attests, verifiably and at connection time, that a connecting IPv6 address
belongs to a declared prefix under one accountable domain — giving
receivers a stable reputation unit instead of an unusable 2^64 address
space. Fail-open by design: absence or failure of attestation leaves
treatment unchanged.

| File | Contents |
|---|---|
| `draft-kafedzhy-swornmail-01.md` | Internet-Draft source, current revision (kramdown-rfc) |
| `draft-kafedzhy-swornmail-00.md` | Previous revision, kept for history |
| `threat-model.md` | Assets, adversaries, analyzed attacks, residual risks |
| `test-vectors/v1.json` | Deterministic vectors for the -01 wire format: keys, record, verification cases with complete tokens (`v0.json` retained for history) |
| `SECURITY.md` | Vulnerability reporting (security@swornmail.dev) |

## Status

`-01`, pre-submission. Wire format v1 (COSE `kid` + content-type,
selector-in-QNAME records) is intended to be stable through the 0.x
implementations; remaining pre-v1 breaking changes will be called out in
the issues.

Build the draft: `gem install kramdown-rfc && kdrfc draft-kafedzhy-swornmail-01.md`

Implementations verifying against the shared vectors:
[swornmail-go](https://github.com/swornmail/swornmail-go) (Go) ·
[swornmail](https://github.com/swornmail/swornmail) (Rust, early).

## Intellectual property

A US provisional patent application (filed August 2026) covers the
mechanisms described here. It exists to keep the protocol open — to
prevent the mechanism from being patented out from under its implementers.
If it matures into a granted patent, the author intends to bind it with an
irrevocable royalty-free pledge for conforming implementations, in the
spirit of the Tesla and Red Hat patent pledges; it will not be asserted
against implementations of the protocol. The reference implementations are
Apache-2.0, which carries its own patent license grant.

## License

Repository content is Apache-2.0 (see `LICENSE`). Upon IETF datatracker
submission the draft text will additionally be subject to the standard
IETF Trust provisions (BCP 78/79).

Maintained by [PlatOps Security, LLC](https://platops.com). Copyright:
see `NOTICE`.
