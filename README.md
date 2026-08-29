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
| `threat-model.md` | Assets, adversaries, analyzed attacks, residual risks |
| `test-vectors/v1.json` | Deterministic vectors for the `-01` wire format: keys, records, verification cases with complete tokens, and policy-authorization cases |
| `SECURITY.md` | Vulnerability reporting (security@swornmail.dev) |

## Status

`-01`, pre-submission. Wire format v1 (COSE `kid` + content-type,
selector-in-QNAME records) is intended to be stable through the 0.x
implementations; remaining pre-v1 breaking changes will be called out in
the issues.

**Repo revisions vs IETF revisions.** The datatracker requires a first
submission to be version `-00`, so `draft-kafedzhy-swornmail-01.md` here is
submitted there as `draft-kafedzhy-swornmail-00`. The two numbering schemes
are independent: "the `-01` wire format", as named throughout the
implementations and `test-vectors/v1.json`, always means this repository's
`-01`.

The earlier `-00` source was removed, along with `test-vectors/v0.json`,
rather than kept alongside the current revision. Its security considerations
asserted properties this protocol does not have — that DNS spoofing without
DNSSEC could not impersonate an operator, that key theft alone was
non-exploitable, and that replay was confined to one reputation unit — and it
predated policy authorization entirely. A superseded revision sitting in a
public repository is a document someone implements from, and vectors for a
format no implementation targets are a trap for whoever finds them first.
Both remain in git history.

**Record acceptance tightened within `-01`.** Token bytes are unchanged and
`test-vectors/v1.json` still reproduces byte-identically for every case that
existed before it, so the wire format is unaffected and no published token
is invalidated. Three classes of *record* that earlier `-01` implementations
accepted are now malformed:

- a policy `u=` coarser than any prefix in the same record's `p=` — a
  reputation unit may not extend into space the operator did not attest
- `rua=` values outside a conservative ASCII `mailto:<dot-atom>@<domain>` —
  no quoted local parts, URI parameters, or additional recipients
- any octet outside printable US-ASCII (0x20–0x7E) anywhere in a record

These are corrections, not features: each one closed a way for two
conforming verifiers to read the same record differently. An operator
publishing a record in one of those shapes must fix it; `sworn genrecord`
will not emit one. The Rust crate ships the tightened rules from `0.2.0`;
`0.1.0` predates them.

Build the draft: `gem install kramdown-rfc && kdrfc draft-kafedzhy-swornmail-01.md`

Build the submission artifact (v3 XML, IETF-stream numbering):

```sh
mkdir -p submission
sed 's/^docname: draft-kafedzhy-swornmail-01$/docname: draft-kafedzhy-swornmail-00/' \
  draft-kafedzhy-swornmail-01.md |
  kramdown-rfc > submission/draft-kafedzhy-swornmail-00.xml
```

Rebuild it on the day you submit — the toolchain stamps the build date into
the document.

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

Maintained by Val Kafedzhy. Copyright:
see `NOTICE`.
