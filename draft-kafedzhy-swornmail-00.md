---
###
# SwornMail Protocol — Internet-Draft source (kramdown-rfc format)
# Build: kdrfc draft-kafedzhy-swornmail-00.md  (gem install kramdown-rfc)
# TODO before datatracker submission: complete test-vector appendix from
# conformance repo; confirm author email once sworn.email mailbox is live.
###
title: "SwornMail: Cryptographic IPv6 Prefix Attestation for SMTP"
abbrev: SwornMail
docname: draft-kafedzhy-swornmail-00
category: exp
ipr: trust200902
area: Applications
workgroup: Independent Submission
keyword: [SMTP, IPv6, reputation, attestation, email]
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - name: Val Kafedzhy
    organization: SwornMail Project
    email: val@sworn.email
normative:
  RFC2119:
  RFC4291:
  RFC5321:
  RFC8032:
  RFC8152:
  RFC8174:
  RFC8601:
informative:
  RFC5518:
  RFC6698:
  RFC7208:
  RFC7672:
  RFC8617:
  RFC9364:
---

--- abstract

Reputation systems for SMTP were designed for IPv4, where individual
addresses are scarce and accountable. The smallest standard IPv6
on-link allocation (a /64) contains 2^64 addresses, making per-address
reputation information-free and forcing receivers into coarse
heuristics that penalize IPv6 mail indiscriminately. SwornMail lets a
sending operator cryptographically attest that a connecting IPv6
address belongs to a declared prefix under a single accountable
administrative identity, and declares the granularity at which
receivers SHOULD aggregate reputation within that prefix. Attestation
is voluntary liability acceptance: the operator stakes its domain's
reputation on the attested prefix. The protocol has two deployment
modes: a DNS-only mode requiring no changes to mail software, and an
SMTP extension carrying a compact signed token verified statelessly at
connection time.

--- middle

# Introduction

## The Granularity Problem {#granularity}

IPv4 DNS blocklists operate per address. This fails on IPv6 for
arithmetic reasons: a single /64 (the SLAAC boundary defined in
{{RFC4291}}) contains 18,446,744,073,709,551,616 addresses. A sender
rotating source addresses per message never repeats an address;
per-address listings cannot converge, and per-address DNSBL queries
approach a 100% cache-miss rate, degrading blocklist infrastructure
itself. Aggregating listings at /64 causes collateral damage on
shared infrastructure; aggregating wider punishes entire providers.

No stable aggregation boundary exists because the administrative
allocation boundary — which addresses constitute one accountable
entity — is invisible to receivers. SwornMail makes that boundary
explicit, verifiable, and staked on a domain identity.

## Design Goals {#goals}

1. Fail-open: absence or failure of SwornMail MUST NOT make treatment
   worse than the receiver's existing default for unattested IPv6.
2. Deployment friction comparable to SPF {{RFC7208}}: the baseline
   mode requires publishing DNS records only.
3. Stateless verification at the receiver, O(1) per connection.
4. Key compromise alone MUST NOT enable off-prefix impersonation.
5. Cryptographic agility, including a registered migration path to
   post-quantum signature algorithms.
6. Attestation is accountability, not endorsement: receivers and
   reputation services decide trust.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

Operator:
: The administrative entity accountable for an attested prefix,
  identified by a DNS domain (the "operator domain").

Attested Prefix:
: An IPv6 prefix (RECOMMENDED length /48 to /64) the operator claims
  as a single administrative unit.

Reputation Unit:
: The prefix length within an attested prefix at which the operator
  requests receivers aggregate reputation (default 64).

# Operator Records {#records}

An operator publishes a key/policy record at the `_sworn` label of the
operator domain:

~~~
_sworn.mailer.example.com. IN TXT
    "v=SWORN1; k=ed25519; s=2026a; pk=<base64>; u=64;
     l=https://log.example/..."
~~~

Tag definitions: `v` (version, REQUIRED, "SWORN1"); `k` (algorithm
identifier from the registry in {{iana}}); `s` (key selector,
enabling multiple concurrent keys, DKIM-style); `pk` (public key,
base64); `u` (reputation unit, default 64); `l` (OPTIONAL transparency
log URL).

An OPTIONAL prefix enumeration record supports third-party audit:

~~~
_prefixes._sworn.mailer.example.com. IN TXT
    "v=SWORN1; p=2001:db8:f00::/48,2620:12a:8000::/48"
~~~

DNSSEC {{RFC9364}} is RECOMMENDED but NOT REQUIRED; see
{{security}} for why key substitution without prefix access is
non-exploitable.

TODO: full ABNF; record size guidance; multi-string TXT handling.

# Mode 1: DNS-Only Attestation {#mode1}

Discovery is decentralized by design; no SwornMail-specific
infrastructure is required on the normative path.

Normative discovery: for a connection from address A, the receiver
(1) resolves the PTR of A and forward-confirms the resulting
hostname per the iprev semantics of {{RFC8601}}; (2) derives the
candidate operator domain from the confirmed hostname (TODO: exact
domain-derivation algorithm, organizational-domain handling);
(3) confirms A is within a prefix published under
`_prefixes._sworn.<operator-domain>`. Misdirected PTR records are
inert: discovery succeeds only if the pointed-to domain itself
publishes a covering prefix. Operators who control their ip6.arpa
delegation MAY additionally publish a `_sworn` pointer record in the
reverse tree (TODO: record form) as a PTR-independent path.

Non-normative accelerator: receivers MAY consult a transparency log's
prefix-to-operator map (bulk or query interface) as a cache in front
of normative discovery. Log unavailability MUST NOT change
verification outcomes, only latency.

The result is one additional cached DNS resolution chain on the
connection path; no changes to sending software; no per-connection
cryptography.

Mode 1 provides prefix-to-operator binding with weaker source
authenticity than Mode 2 (see BGP considerations, {{security}}).
Receivers SHOULD weight Mode 2 above Mode 1.

# Mode 2: Connection Token (SMTP Extension) {#mode2}

## EHLO Keyword

A receiver advertising `SWORN` in its EHLO response accepts tokens
via the `XSWORN` command prior to MAIL FROM:

~~~
C: EHLO mail.mailer.example.com
S: 250-SWORN
C: XSWORN <base64url(COSE_Sign1)>
S: 250 SWORN OK unit=2001:db8:f00::/64
~~~

## Token Structure

The token is a COSE_Sign1 {{RFC8152}} object over a CBOR map:

| Key | Field | Notes |
|-----|-------|-------|
| 1 | operator domain | key-lookup handle |
| 2 | attested prefix | binary address + length |
| 3 | unit | integer, default 64 |
| 4 | iat | issuance time |
| 5 | exp | MUST be <= iat + 86400 |
| 6 | role | "mta" / "esp-tenant" / "forwarder" |

Signature algorithm: Ed25519 {{RFC8032}} for `k=ed25519`. Token size
with classical signatures SHOULD NOT exceed 512 octets; this bound is
advisory and explicitly not a wire-format invariant, to accommodate
post-quantum algorithms ({{pq}}).

## Verification

Stateless, in order: (1) parse; (2) fetch/cache operator key from
`_sworn` record via selector; (3) verify signature; (4) verify
current time within [iat, exp]; (5) verify the connecting source
address is within the attested prefix. All five MUST pass. Replay of
a captured token is only possible from within the same attested
prefix, which is the same reputation unit; receivers therefore need
no anti-replay state.

## Result Reporting

Receivers stamp results with the `sworn` Authentication-Results
{{RFC8601}} method:

~~~
Authentication-Results: mx.example;
    sworn=pass op=mailer.example.com unit=2001:db8:f00::/64
~~~

Result values: pass / fail / temperror / permerror / none, with
machine-readable reason codes (TODO: full taxonomy table).

# Receiver Reputation Semantics {#semantics}

On `sworn=pass`, receivers SHOULD key reputation on the tuple
(operator domain, containing unit prefix). Abusive traffic from an
attested prefix SHOULD affect the reputation of the entire attested
prefix and MAY affect the operator domain across all its attested
prefixes. Absence of attestation MUST NOT worsen treatment relative
to the receiver's existing unattested-IPv6 policy ({{goals}}).

# Routing Origin Considerations {#rpki}

Attested prefixes SHOULD be covered by RPKI Route Origin
Authorizations. Transparency logs SHOULD record ROA coverage status.
Receivers MAY weight attestations from ROA-covered prefixes and
Mode 2 tokens above Mode 1 assertions from uncovered prefixes. This
bounds the impact of BGP origin hijacks against attested space.

# Cryptographic Agility and Post-Quantum Migration {#pq}

The `k=` registry ({{iana}}) is the agility mechanism. Initial
entries: `ed25519` (REQUIRED to implement). Planned entries:
`fn-dsa-512` (Falcon; compact PQ signatures) and composite
`ed25519+ml-dsa-44` for transition-period dual signing. SwornMail
carries no confidential payloads; the quantum threat is live forgery
only, not retrospective decryption, and forged tokens still fail
source-prefix verification. Transparency logs are Merkle structures
over SHA-256, which remain adequate under Grover-bounded adversaries.

# Security Considerations {#security}

Summarized from the project threat model (full analysis published
alongside this draft):

- Key theft alone is non-exploitable off-prefix: verification binds
  the token to the connecting address's membership in the attested
  prefix (goal 4).
- BGP hijack of an attested prefix defeats Mode 1 and enables replay
  against Mode 2 from within the hijacked space for up to the token
  lifetime; {{rpki}} bounds this. Exposure is not worse than any
  existing IP-reputation mechanism under identical hijack.
- Disposable-domain attestation cycles are visible in transparency
  logs as cross-domain re-attestation of the same space; reputation
  services SHOULD propagate prefix history across operator changes.
- EHLO keyword stripping downgrades to the fail-open baseline and
  confers no advantage beyond non-participation.
- `_sworn` record spoofing without DNSSEC enables at most denial of
  verification (fail-to-neutral), not impersonation.

# Privacy Considerations

Attestation records and logs disclose prefix-to-operator mappings.
Comparable information is generally already public via SPF records
and rDNS. Operators SHOULD publish enumeration records at /48
coarseness or omit them where topology disclosure is a concern.

# IANA Considerations {#iana}

TODO: (1) `sworn` method registration in the Email Authentication
Methods registry; (2) SMTP service extension keyword `SWORN`;
(3) creation of the SwornMail Algorithm Registry (`k=` values) with
initial entry ed25519 and registration policy Specification Required.

--- back

# Test Vectors

TODO: generated by the conformance suite (swornmail/conformance);
covers record parsing, token round-trip, prefix-membership edge
cases (::, prefix boundaries, embedded IPv4), expiry boundaries,
and negative cases (bad sig, off-prefix, expired, malformed CBOR).

# Acknowledgments

Prior art that informed this design: CSV/CSA, VBR {{RFC5518}},
DANE {{RFC6698}} {{RFC7672}}, ARC {{RFC8617}}, and the RPKI.
