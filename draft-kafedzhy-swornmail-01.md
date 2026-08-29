---
###
# SwornMail Protocol — Internet-Draft source (kramdown-rfc format)
# Build: kdrfc draft-kafedzhy-swornmail-01.md  (gem install kramdown-rfc)
# Datatracker submission: a first submission must be version -00, so build
# the submission artifact with docname draft-kafedzhy-swornmail-00. That is
# IETF-stream numbering; it does not renumber the -01 wire format, which is
# frozen and named as such in both implementations and the v1 vectors.
# Before submitting: the author email must be a live mailbox. The two
# remaining TODOs below (full ABNF, aggregate-report JSON schema) are
# ordinary work-items for an individual -00 and do not block submission.
###
title: "SwornMail: Cryptographic IPv6 Prefix Attestation for SMTP"
abbrev: SwornMail
docname: draft-kafedzhy-swornmail-01
category: exp
ipr: trust200902
submissiontype: IETF
area: Applications
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
  RFC4648:
  RFC5321:
  RFC8032:
  RFC8174:
  RFC8552:
  RFC8601:
  RFC8949:
  RFC9052:
informative:
  RFC3463:
  RFC5518:
  RFC6698:
  RFC6838:
  RFC6648:
  RFC7208:
  RFC7489:
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
receivers aggregate reputation within that prefix. Attestation is
voluntary liability acceptance: the operator stakes its domain's
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
3. Stateless verification at the receiver, O(1) per connection, with
   no verifier-initiated fetch to attacker-named endpoints beyond DNS.
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
: An IPv6 prefix (RECOMMENDED length /48 to /64; permitted range
  {{canon}}) the operator claims as a single administrative unit.

Reputation Unit:
: The prefix length within an attested prefix at which the operator
  requests receivers aggregate reputation (default 64).

Selector:
: A label, chosen by the operator, naming one of possibly several
  concurrent signing keys (DKIM-style key rotation).

## Address and Prefix Constraints {#canon}

All prefixes carried in records, tokens, and logs MUST be in masked
canonical form: every bit beyond the prefix length is zero. Signers
MUST NOT emit, and verifiers MUST reject as `permerror`, non-canonical
prefixes.

An attested prefix MUST fall within the global unicast range
`2000::/3`, MUST have a length of at least 32 bits and at most 64 bits,
and MUST NOT overlap the Teredo (`2001::/32`) or 6to4 (`2002::/16`)
ranges. Verifiers MUST reject tokens and enumeration records violating
any of these (`permerror`). The lower length bound prevents a single
attestation from covering unrelated networks; the `2000::/3` bound
keeps attestations out of special-purpose space.

A verifier MUST reject any connecting source address that is not an
ordinary global-unicast IPv6 address as `permerror` (reason
`ineligible_source`). In particular, source addresses that are
IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::/96`), NAT64
(`64:ff9b::/96`, `64:ff9b:1::/48`), Teredo (`2001::/32`), or 6to4
(`2002::/16`), and any address outside `2000::/3` (including link-local,
ULA, and multicast), MUST NOT be treated as within any attested
prefix. This closes the cross-family confusion where one IPv4 address
deterministically maps into an IPv6 range.

# Operator Records {#records}

An operator publishes two kinds of DNS record: one **key record** per
selector, and one **policy record** covering the operator.

## Key Record {#keyrecord}

Published at a QNAME that carries the selector, so each fetch returns
exactly one key and rotation never bloats a response:

~~~
2026a._sworn.mailer.example.com. IN TXT "v=SWORN1; k=ed25519; pk=<base64>"
~~~

Tags: `v` (version, REQUIRED, "SWORN1", MUST be first); `k` (algorithm
identifier from the registry in {{iana}}, REQUIRED); `pk` (public key,
base64 per {{RFC4648}} Section 4 with padding, REQUIRED). The selector
appears only in the QNAME; there is no `s=` tag.

Keys published in `_sworn` records MUST be dedicated to SwornMail and
MUST NOT be reused for any other protocol; the token's content-type
binding ({{token}}) additionally domain-separates signatures.

## Policy Record {#policyrecord}

Published once per operator, carrying prefix enumeration (for Mode 1
and third-party audit) and operator-wide policy tags:

~~~
_prefixes._sworn.mailer.example.com. IN TXT
    "v=SWORN1; p=2001:db8:f00::/48,2620:12a:8000::/48; u=64"
~~~

Tags: `v` (REQUIRED, first); `p` (comma-separated attested prefixes,
each meeting {{canon}}); `u` (reputation unit, default 64; MUST be no
shorter than every listed prefix and no longer than 64 — a value
outside that range makes the record malformed, so the publishing
operator sees the error rather than having it silently adjusted); `t`
(OPTIONAL flags, {{testing}}); `rua` (OPTIONAL aggregate report
destination, {{reports}}). Publishers MUST include at most 64 prefixes;
verifiers process only the first 64. The `p` enumeration authorizes
prefixes in both deployment modes, and `u`, `t`, and `rua` apply to
both modes. A policy with no `p` value authorizes no Mode-2 token.

## Record Tag Parsing {#tagparse}

Tag names are case-sensitive lowercase. The `v` tag MUST be first. A
record containing the same tag name more than once MUST be treated as
malformed.

A record MUST consist entirely of printable US-ASCII, octets 0x20
through 0x7E, together with HTAB (0x09); a record containing any other
octet is malformed. This excludes CR, LF, NUL, DEL and every other C0
control. Whitespace therefore means SP and HTAB and nothing else.
Leading and trailing whitespace around a tag name or value is stripped
before the value is interpreted; whitespace remaining inside a tag
value after stripping makes the record malformed.

Both rules are stated as octet ranges deliberately. "Whitespace" is
where independent implementations diverge without noticing — some
runtimes treat U+00A0 or U+3000 as whitespace, some treat VT as
whitespace and some do not — and a record that one verifier rejects
while another trims it into an apparently safe value is a parser
differential in a security decision. Restricting the record to
printable ASCII costs nothing, because every value this document
defines is ASCII by construction, and HTAB is admitted only because a
hand-edited zone file legitimately carries one between tags. Multiple
character-strings within a single TXT RR are concatenated in order
without separators. If more than one TXT RR at a QNAME begins with
`v=SWORN1`, the record set is in error and MUST yield `permerror`;
verifiers MUST NOT select one arbitrarily. TXT RRs not beginning with
`v=SWORN1` MUST be ignored.

A record whose `k=` names an algorithm the verifier does not implement
MUST yield `sworn=none`, never `sworn=fail`, so that publishing a
future-algorithm selector alongside a current one never penalizes an
operator with older verifiers.

## Delegated Record Management {#cname}

CNAME records are permitted at `<selector>._sworn` and `_prefixes._sworn`
labels, enabling delegation of key or prefix management to a third
party (ESP-style). Delegation via CNAME transfers to the target's
operator the ability to sign attestations, or enumerate prefixes,
binding the delegating domain's reputation. Operators MUST remove the
CNAME when a delegation ends; a dangling CNAME whose target zone is
later registered by another party constitutes takeover of the
operator's attestation identity. Transparency logs SHOULD record the
resolved CNAME chain so monitors can detect target changes.

DNSSEC {{RFC9364}} is RECOMMENDED. Prefix authorization prevents a
stolen signing key by itself from attesting unrelated space, but it
does not protect an unsigned DNS lookup: an active DNS attacker that
can replace both the policy and key records can impersonate an
operator. Verifiers capable of obtaining a validated DNSSEC status
SHOULD expose it to local policy, and security-sensitive deployments
SHOULD require validated answers. Every link in a delegated CNAME
chain is part of this DNS trust path.

TODO: full ABNF; record size guidance table.

# Mode 1: DNS-Only Attestation {#mode1}

Discovery is decentralized by design; no SwornMail-specific
infrastructure is required on the normative path.

Publishing a prefix in a `_prefixes._sworn` policy record is an
unconditional acceptance of accountability for every address within
it, including sub-allocations whose reverse DNS or PTR records the
operator does not control. Operators that delegate reverse DNS or PTR
authority for any part of an enumerated prefix SHOULD enumerate only
the sub-prefixes they operate directly, or use Mode 2, where each
token is individually signed and consent is explicit per prefix.

## Discovery {#mode1-discovery}

For a connection from address A, the receiver proceeds. Total DNS work
for one connection's Mode-1 discovery — reverse-tree queries, candidate
queries, and CNAME chain resolution combined — MUST NOT exceed 10 DNS
queries; a receiver that would exceed the budget MUST stop and return
`temperror`.

1. Reverse-tree pointer (preferred where present): query
   `_sworn.<nibbles>.ip6.arpa` at exactly two names — the enclosing
   /64 (16 reversed nibbles) and the enclosing /48 (12 reversed
   nibbles). The `_sworn` label is leftmost, so the name falls inside
   the operator's own reverse-DNS delegation. The record form is
   `"v=SWORN1; d=<operator domain>"`, where `d` MUST satisfy the
   operator-domain syntax of {{token}}. Receivers MUST prefer the
   longest (more specific) matching record and MUST NOT query at other
   prefix lengths. The domain named in `d` is subject to the same
   step-3 confirmation as a PTR-derived candidate; a `d` domain that
   does not confirm causes the receiver to fall through to step 2. This
   path serves operators holding /48 or longer; holders of shorter
   prefixes use step 2 or Mode 2. (Worked example: for
   `2001:db8:f00:1234::a:1`, the /64 name is
   `_sworn.4.3.2.1.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa` and the /48 name
   is `_sworn.0.0.f.0.8.b.d.0.1.0.0.2.ip6.arpa`.)
2. Otherwise, PTR-derived candidates: resolve the PTR of A and
   forward-confirm the resulting hostname per the iprev semantics of
   {{RFC8601}}. Receivers MUST consider at most one PTR name and MUST
   follow at most 3 CNAME links. Candidate 1 is the confirmed hostname
   itself. Candidates 2 through 5 are formed by stripping one leading
   label at a time. Receivers MUST evaluate candidates in order, MUST
   stop at the first confirmation, and MUST NOT evaluate more than 5
   candidates. Receivers MUST NOT query a name that is a public suffix
   (per a current public suffix list, https://publicsuffix.org/) or an
   ancestor of one; receivers without a public suffix list MUST NOT
   evaluate candidates with fewer than 3 labels.
3. Candidate confirmation: a candidate domain is confirmed if A is
   within a prefix published under `_prefixes._sworn.<candidate>`.

Misdirected PTR records are inert: confirmation requires the
pointed-to domain to publish a covering prefix, so pointing at a
domain that publishes none confirms nothing.

Non-normative accelerator: receivers MAY consult a transparency log's
prefix-to-operator map as a cache in front of normative discovery. Log
unavailability MUST NOT change verification outcomes, only latency.

Mode 1 provides prefix-to-operator binding with weaker source
authenticity than Mode 2 (see BGP considerations, {{security}}).
Receivers SHOULD weight Mode 2 above Mode 1. This revision specifies
Mode 1 as experimental; receivers deploying it SHOULD assign it low
reputation weight until operational experience accrues.

# Mode 2: Connection Token (SMTP Extension) {#mode2}

## EHLO Keyword and Session Semantics {#xsworn}

A receiver advertising `SWORN` in its EHLO response accepts one token
via the `SWORN` command:

~~~
C: EHLO mail.mailer.example.com
S: 250-SWORN
C: SWORN <base64url(COSE_Sign1)>
S: 250 2.7.0 SWORN pass unit=2001:db8:f00::/64
~~~

The command argument is the token encoded with base64url ({{RFC4648}}
Section 5) without padding; verifiers MUST reject an argument
containing '=' or any character outside the base64url alphabet
(`501 5.5.2`).

(Pre-registration implementations used the verb `XSWORN`; servers MAY
accept it as a deprecated alias.)

Session rules:

- Servers advertising `SWORN` MUST accept a command line of at least
  4096 octets for the SWORN command, extending the {{RFC5321}}
  Section 4.5.3.1.4 limit for this verb. Clients MUST NOT send a SWORN
  line exceeding 4096 octets.
- A server MUST accept at most one SWORN command per EHLO session, and
  it MUST precede the first MAIL FROM. A second SWORN before MAIL
  FROM, a SWORN after a transaction has begun, a SWORN before a
  successful EHLO, or a SWORN when the server did not advertise the
  keyword, MUST be answered `503 5.5.1` without verification and MUST
  NOT displace an earlier result.
- A server MUST discard any SwornMail result upon receiving a
  subsequent EHLO. After STARTTLS the client issues a new EHLO
  ({{RFC5321}}), so a client wishing attestation to apply MUST
  re-issue SWORN after the post-TLS EHLO, and SHOULD send SWORN only
  after STARTTLS where offered.
- With PIPELINING, SWORN MAY be sent in a pipelined group ahead of
  MAIL FROM; the server replies per command in order. Because the
  protocol is fail-open, a client MAY proceed without awaiting the
  reply; the result affects reputation treatment, never message
  acceptance by itself.
- Verification failure is reported in the reply (code 250, enhanced
  status 2.7.x, with a reason token) and in Authentication-Results; it
  MUST NOT by itself cause connection or message rejection ({{goals}}).
- A `role=forwarder` token attests the forwarder's own prefix; each
  hop attests independently and speaks only for its own connection.

## Token Structure {#token}

The token MUST be a tagged COSE_Sign1 object ({{RFC9052}}; CBOR tag
18, `COSE_Sign1_Tagged`). Verifiers MUST reject untagged COSE_Sign1
structures (`permerror`).

The protected header MUST contain, and verifiers MUST source
exclusively from the protected header:

- `alg` (label 1): the COSE algorithm. The verifier MUST determine the
  expected algorithm from the key record's `k=` tag and MUST reject a
  token whose `alg` does not correspond to it; the token's `alg` MUST
  NOT be used to select the verification algorithm.
- `content type` (label 3): the text string
  `application/sworn-token+cbor`. Verifiers MUST reject tokens whose
  content type is absent or different (`permerror`).
- `kid` (label 4): the selector as a byte string. The `kid` MUST be a
  single DNS label: 1 to 63 octets from ALPHA / DIGIT / "-", not
  beginning or ending with "-". Selector comparison is
  case-insensitive ASCII. The verifier uses `kid` to select the
  `<kid>._sworn.<operator domain>` key record.

A verifier MUST reject a token whose unprotected header contains label
1, 3, or 4, or any label also present in the protected header
(`permerror`). Tokens MUST NOT include the `crit` header (label 2);
verifiers MUST reject tokens containing it. Verifiers MUST ignore
protected header labels other than 1, 2, 3, and 4. The COSE
`external_aad` MUST be a zero-length byte string.

The payload is a CBOR map with integer keys, using deterministic
encoding ({{RFC8949}} Section 4.2.1):

| Key | Field | Req | Notes |
|-----|-------|-----|-------|
| 1 | operator domain | REQUIRED | text string, A-label form, <= 253 octets, each label <= 63 |
| 2 | attested prefix | REQUIRED | byte string, 16-byte address + 1 length byte, canonical and in range ({{canon}}) |
| 3 | unit | OPTIONAL | integer; absent means 64; MUST be >= prefix length and <= 64 |
| 4 | iat | REQUIRED | issuance time, integer Unix seconds |
| 5 | exp | REQUIRED | expiry; MUST be > iat and <= iat + 86400 |
| 6 | role | REQUIRED | text string, one of "mta" / "esp-tenant" / "forwarder" |

Signers MUST emit the operator domain in lowercase A-label form.
Verifiers accept ASCII letter case for interoperability but MUST
lowercase the domain before constructing DNS names, reporting a result,
or keying reputation. Domain-name comparison is case-insensitive.

CDDL:

~~~
sworn-payload = {
  1 => tstr,              ; operator domain, A-label form
  2 => bstr .size 17,     ; 16-octet address + 1-octet length
  ? 3 => uint,            ; unit; absent = 64
  4 => uint,              ; iat
  5 => uint,              ; exp
  6 => tstr,              ; role
  * int => any            ; unknown integer keys ignored
}
~~~

Signers MUST use deterministic encoding; because the signature binds
the exact payload octets, verifiers are NOT required to reject a
well-formed but non-deterministic encoding (indefinite-length,
non-minimal integers, unsorted keys), and the reference implementations
accept them. Map keys MUST be integers; a payload containing a
non-integer key MUST be rejected (`permerror`). Verifiers MUST reject a token missing any
REQUIRED key, with a duplicate map key, or with a `role` outside the
three values in the payload table (`permerror`). Unknown additional
integer keys MUST be ignored (forward compatibility). For
`role=esp-tenant`, `unit` MUST equal the prefix length, so the
reputation unit cannot be finer than the accountable prefix; this does
not make the prefix exclusive, and operators MUST NOT rely on token
possession as tenant authentication (see {{security}}). Per-tenant
accountability therefore requires a dedicated prefix (e.g. a /64) per
tenant.

Signature algorithm: Ed25519 {{RFC8032}} for `k=ed25519`. Token size
with classical signatures SHOULD NOT exceed 512 octets. Senders SHOULD
issue tokens with lifetimes of one hour or less; the 86400-second cap
is a hard limit, not a target. Short lifetimes bound the replay window
available to an attacker who temporarily controls routing for the
attested prefix ({{security}}).

## Verification {#verification}

Stateless. All of the following checks MUST pass for `sworn=pass`
(subject to the `t=y` reporting override in {{testing}}):

1. Parse: tagged COSE_Sign1; protected-header requirements ({{token}});
   payload key requirements and CDDL; prefix canonicality and range,
   and source-address eligibility ({{canon}}).
2. All remaining local checks: validity bounds on the raw payload
   values (`exp > iat` and `exp - iat <= 86400`); current time within
   `[iat - 300s, exp + 300s]`; unit bounds; and source membership.
   Verifiers MUST NOT apply a skew tolerance greater than 300 seconds.
   The cap in check 2 is evaluated on the unmodified `iat` and `exp`.
   `unit` MUST be at least the token prefix length and at most 64
   (absent = 64). The connecting source MUST be within the attested
   prefix after the {{canon}} eligibility checks.
3. Obtain the policy record from
   `_prefixes._sworn.<operator domain>`. The token prefix MUST be the
   same as or a subnet of at least one of the first 64 policy prefixes,
   and the token `unit` MUST equal the policy `u` value (including its
   default). More precisely, policy prefix Q authorizes token prefix P
   when `length(P) >= length(Q)` and Q contains P's canonical network
   address. No policy record yields `none`; a malformed policy,
   unauthorized prefix, or unit mismatch yields `permerror`.

   Because `u` is published once per operator, every token an operator
   issues shares one unit. An operator using `role=esp-tenant`, whose
   unit MUST equal its token prefix length ({{token}}), therefore
   issues tenant tokens at a single prefix length. This is deliberate:
   the aggregation an operator asks receivers to use is a property of
   the operator, published in DNS where it can be audited, rather than
   something each token restates. Operators needing several tenant
   granularities use a separate operator domain per granularity.
4. Obtain the operator key from the `<kid>._sworn.<operator domain>`
   record. An unimplemented `k=` yields `none` as specified in
   {{tagparse}}.
5. Verify the signature with the record key and the record's `k=`
   algorithm.

Checks 1 and 2 MUST complete before either DNS lookup. If a local check
fails, the verifier MUST report that failure and MUST NOT fetch the
policy or key. After a successful policy lookup, check 3 MUST complete
before the key lookup, so a syntactically valid but unauthorized token
cannot trigger a key query. Verifiers MUST reject a non-conforming
`kid` or operator domain before any DNS query. The outcome does not
otherwise depend on ordering; reason codes are advisory diagnostics,
not a canonical ordering.

Replay of a captured token is limited to connections originating
inside the signed prefix. It is not necessarily limited to one
declared reputation unit: a finer `unit` can differ across source
addresses inside a broader signed prefix. Receivers need no mandatory
anti-replay state because every successful replay remains attributable
to the same claimant domain and an observed source inside the signed
prefix. Reputation consequences remain subject to the prefix-control
rules in {{semantics}}. Deployments that attach privileges beyond
reputation MAY additionally maintain a bounded replay cache; `role`
alone is not evidence of a distinct sender.

## Result Reporting {#reporting}

Receivers stamp results with the `sworn` Authentication-Results
{{RFC8601}} method, with properties in `ptype.property=pvalue` form.
A pvalue containing `:` or `/` (an RFC 2045 tspecial) MUST be emitted
as a quoted-string:

~~~
Authentication-Results: mx.example;
    sworn=pass policy.op=mailer.example.com
    policy.unit="2001:db8:f00::/64"
    policy.observed="2001:db8:f00::/64" policy.mode=token
~~~

The `policy.mode` property is `token` for Mode 2 and `dns` for Mode 1.

`policy.unit` is the aggregation the operator asked for: a claim.
`policy.observed` is the observed unit ({{semantics}}) — the source
address masked to /64, which is what this connection actually
corroborated. Verifiers MUST emit both on every `pass` and on every
`t=y` observe-only result; consumers that stake reputation MUST use
`policy.observed` unless they hold independent evidence of control
over the whole attested prefix. The two are equal whenever the
operator declares the default `u=64`.

Result values and their causes:

| Result | Cause |
|--------|-------|
| none | no `v=SWORN1` policy/key record, NXDOMAIN, unimplemented `k=`, or (Mode 1) no confirming operator found |
| pass | all verification checks passed |
| fail | signature failure, off-prefix, expired, or not-yet-valid |
| permerror | malformed token/record, unauthorized token prefix, policy/token unit mismatch, bad headers, non-canonical or out-of-range prefix, ineligible source, bad unit, bad validity (`exp <= iat`), lifetime over cap, bad role, non-conforming kid or operator domain, missing REQUIRED key, duplicate key, `crit` present, or untagged COSE |
| temperror | DNS timeout or SERVFAIL, or (Mode 1) discovery query budget exhausted |

All `fail` and `permerror` causes identify no accountable party
({{semantics}}). Per {{RFC8601}} Section 5, an ADMD border MTA MUST
delete or rename any preexisting `Authentication-Results` field
claiming its own authserv-id; inbound `sworn=` results are trivially
spoofable and MUST NOT survive the trust boundary unexamined.

# Receiver Reputation Semantics {#semantics}

On `sworn=pass`, receivers SHOULD key reputation on the tuple
(operator domain, observed unit), where the observed unit is defined
below. Source membership proves
that the current connection originated somewhere inside the signed
prefix; it does not prove that the claimant exclusively controls every
address in that prefix. A shared-hosting tenant can therefore publish
a policy covering its provider's aggregate, but that self-claim MUST
NOT cause reputation consequences for the provider's domain, another
operator domain, an unobserved unit, or the aggregate as an IP-only
identity.

Absent independent evidence of control over the whole signed prefix
(for example, a reverse-DNS delegation rooted at the claimed boundary,
a provider authorization, or an applicable authenticated routing
attestation), receivers MUST scope positive and negative reputation to
the claimant domain and the connecting source's /64, or a finer
receiver-chosen prefix. This is the *observed unit*: the connecting
source address masked to /64. It is derived from the connection, never
from the token or the policy record, so a claimant's broader `u` value
cannot widen it. Because `u` is itself capped at 64 ({{records}}), the
observed unit is always the source /64.

Verifiers MUST make the observed unit available to their consumers
alongside the declared unit, and MUST report it as `policy.observed`
in Authentication-Results ({{reporting}}). A consumer reading only the
Authentication-Results field would otherwise have no way to tell the
claim apart from the corroborated boundary, which would leave this
requirement unenforceable in the one artifact that crosses the trust
boundary.

With independent control evidence, receivers
MAY instead use the declared unit up to the verified control boundary;
abusive traffic MAY then affect the claimant domain across its
attested prefixes and MAY be rolled up to that boundary. A signed
broad claim alone is never that evidence.

Receivers MUST NOT treat a `sworn=fail`, `sworn=temperror`, or
`sworn=permerror` result as worse than `sworn=none` for reputation or
delivery purposes (design goal 1). A failed verification identifies no
accountable party: receivers and reputation services MUST NOT
attribute a failed result to the operator domain named in the token.
Absence of attestation MUST NOT worsen treatment relative to the
receiver's existing unattested-IPv6 policy.

Where multiple valid attestations cover the same source, the most
specific (longest-prefix) attestation takes precedence for reputation
keying. Overlapping attestations under different operator domains are
legitimate in provider/tenant arrangements but SHOULD be surfaced by
transparency-log monitors. The declared unit is advisory to receivers,
which key reputation at whatever granularity they choose within the
attested prefix, subject to the observed-unit and independently verified
control boundary above. Cross-domain prefix history is an abuse-reset
signal for investigation, not authority to transfer reputation from
one claimant domain to another.

`role` is a self-assertion carrying no cryptographic weight beyond the
operator's accountability for the prefix. Receivers MUST NOT grant
more favourable treatment on the basis of `role` alone.

# Testing Mode {#testing}

The `t=` policy tag is a colon-separated list of flags; `y` means
testing. Unknown flags MUST be ignored. When every verification check
would otherwise pass under `t=y`, receivers MUST instead report
`sworn=none policy.testing=y policy.wouldbe=pass` and MUST NOT apply
liability-staking reputation semantics ({{semantics}}) — neither
credit nor blame accrues. A token that fails another check is reported
normally and MUST NOT carry operator properties, because a failed
signature identifies no accountable party. Reporting a successful
test as `none` keeps consumers that key on `sworn=pass` from mistaking
an observe-only deployment for a committed one.

This provides an observe-only on-ramp: operators validate their
records, tokens, and coverage in production traffic before accepting
consequences. Receivers MAY stop processing stale testing deployments
as attestations, but MUST NOT convert `t=y` into `sworn=pass` or apply
reputation consequences merely because testing has lasted a long time.

# Aggregate Feedback Reports {#reports}

The `rua=mailto:<address>` policy tag requests aggregate feedback, in
the spirit of DMARC {{RFC7489}} aggregate reports. Only an ASCII
`mailto:<dot-atom>@<A-label-domain>` value is defined; quoted local
parts, whitespace, control characters, URI parameters, commas, and
additional recipients are invalid. Before sending any report, a
receiver MUST confirm
consent when the rua mailbox domain is not the operator domain or a
subdomain of it: query
`<operator-domain>._report._sworn.<rua-domain>` for a TXT record
containing `v=SWORN1`, and MUST NOT send absent that record. This is
the DMARC external-destination check ({{RFC7489}} Section 7.1),
without which receivers become an attacker-directed mail cannon.

Receivers that honor `rua` SHOULD send at most one report per day per
(receiver, operator) pair, summarizing counts of sworn=pass/fail/none
connections per attested prefix and unit, the reason-code
distribution for failures, and any receiver-applied unit clamp. Report
format: JSON, schema to be published as an appendix in a future
revision (TODO). Reports carry counts only, never per-message or
per-recipient data.

# Routing Origin Considerations {#rpki}

Attested prefixes SHOULD be covered by RPKI Route Origin
Authorizations. Transparency logs SHOULD record ROA coverage status.
Receivers MAY weight attestations from ROA-covered prefixes and Mode 2
tokens above Mode 1 assertions from uncovered prefixes. This bounds
the impact of BGP origin hijacks against attested space.

# Cryptographic Agility and Post-Quantum Migration {#pq}

The `k=` registry ({{iana}}) is the agility mechanism. Initial entry:
`ed25519` (REQUIRED to implement). ML-DSA is standardized in NIST FIPS
204 and is the current basis for a future transition entry. FN-DSA
(Falcon) remains under NIST standardization as FIPS 206 at the time of
this revision and MUST NOT be registered here until its final encoding
and validation requirements are stable.

A transition-period composite such as `ed25519+ml-dsa-44` is a design
candidate, not an entry defined by this revision. Any future composite
definition MUST bind both signatures to the same protected headers and
payload, and verification MUST require both components; falling back to
whichever component verifies would enable downgrade. ML-DSA public keys
do not fit comfortably in the current DNS TXT key record and composite
tokens require an explicit COSE encoding, so the first post-quantum
registration will also define a companion key-distribution mechanism,
size limits, test vectors, and downgrade behavior. No implementation
should infer those details from this draft.

SwornMail carries no confidential payloads; the quantum threat is live
forgery only, not retrospective decryption. Even a forged token still
requires a covering operator policy and a connection from the
authorized prefix. Transparency logs are Merkle structures over
SHA-256, which remain adequate under Grover-bounded adversaries.

# Security Considerations {#security}

Summarized from the project threat model (published alongside this
draft):

- Key theft alone is non-exploitable outside the operator policy:
  verification requires both a covering policy prefix and source
  membership in the signed prefix (goal 4). A stolen key can forge
  tokens only for subnets the separately published policy already
  authorizes.
- A failed result attributes to no one ({{semantics}}), so an attacker
  replaying a captured token off-prefix produces `sworn=fail` that
  cannot be charged against the victim operator, and cannot be treated
  as worse than non-participation.
- BGP hijack of an attested prefix defeats Mode 1 and enables replay
  against Mode 2 from within the hijacked space for up to the token
  lifetime; short lifetimes ({{token}}) shrink this window and
  {{rpki}} bounds it. Exposure is not worse than any existing
  IP-reputation mechanism under identical hijack.
- `role=esp-tenant` shares a prefix among tenants, so within that
  prefix token possession is not tenant authentication: replay
  indifference holds only at the granularity of the attested prefix.
  Requiring `unit` to equal the prefix length for this role keeps the
  reputation unit aligned with the accountable prefix.
- Attestation squatting earns no benefit: reputation services MUST
  bind reputation only to attestations corroborated by verified
  traffic from the source /64 (or finer) inside the attested prefix. A connection
  from one shared-hosting address does not prove control of its
  provider's aggregate; absent independent control evidence, receivers
  MUST NOT honor a broader claimant-declared unit, spread reputation
  to another /64 or another domain. The observed unit ({{semantics}})
  makes this checkable rather than advisory: it is computed from the
  connection and reported as `policy.observed`, so a consumer never has
  to reconstruct it from a value the claimant chose.
  Logs SHOULD require or record proof of prefix control and distinguish
  uncorroborated claims.
- Mode-1 delegation: enumerating a prefix accepts accountability for
  delegated sub-allocations ({{mode1}}); operators that delegate
  reverse DNS SHOULD enumerate only what they operate.
- Disposable-domain cycles are visible in logs as cross-domain
  re-attestation. Reputation services SHOULD use that history as a
  reset-evasion signal, but MUST NOT automatically transfer reputation
  between claimant domains without independent evidence that both
  controlled the relevant prefix boundary; automatic transfer would
  let a cheap domain poison shared-provider space.
- EHLO keyword stripping downgrades to the fail-open baseline;
  post-STARTTLS re-issue ({{xsworn}}) keeps attestation inside TLS.
- `_sworn` record spoofing without DNSSEC can impersonate an operator
  if an active attacker replaces both the policy and key answers.
  DNSSEC validation or an equivalently authenticated DNS channel is
  required to exclude that attacker; without it, SwornMail has the
  same DNS-rooted residual risk as DKIM.
- Verifiers are DNS query generators. The `kid`/domain syntax checks
  before any query ({{token}}), cheap-checks-first ordering
  ({{verification}}), the 10-query Mode-1 budget ({{mode1-discovery}}),
  negative caching, and per-source rate limits on SWORN verifications
  and key fetches bound receiver-paid load toward attacker-named
  targets; implementations SHOULD apply all of these.

# Privacy Considerations

Attestation records and logs disclose prefix-to-operator mappings.
Comparable information is generally already public via SPF records and
rDNS. Operators SHOULD publish authorization at /48 coarseness where
that is sufficient; omitting a prefix disables attestation for it in
both modes. Aggregate reports ({{reports}}) carry counts only.

# IANA Considerations {#iana}

This document requests:

1. Registration of the `sworn` method in the Email Authentication
   Methods registry ({{RFC8601}}), with property names `policy.op`,
   `policy.unit`, `policy.observed`, `policy.mode`, `policy.testing`,
   and `policy.wouldbe`, and the result values of {{reporting}}. Reason
   tokens are advisory diagnostics and are not registered.
2. Registration of the SMTP service extension keyword `SWORN` and the
   `SWORN` command ({{RFC5321}}).
3. Creation of the SwornMail Algorithm Registry (`k=` values), initial
   entry `ed25519`, policy Specification Required.
4. Registration of the media type `application/sworn-token+cbor`
   ({{RFC6838}}, with the `+cbor` structured-syntax suffix).
5. Registration of the underscored node name `_sworn` in the
   "Underscored and Globally Scoped DNS Node Names" registry
   ({{RFC8552}}), RR type TXT.

--- back

# Test Vectors

Deterministic cross-implementation vectors are published in the
specification repository (`test-vectors/v1.json`): fixed keys and
timestamps; key and policy record examples; and verification cases —
positive, boundary (skew edges, prefix first/last address, exact
validity bounds), and negative (untagged COSE, header confusion, wrong
content type, missing/empty kid, non-canonical and out-of-range
prefixes, ineligible sources, unit/validity/lifetime/role violations,
non-integer and duplicate map keys, operator-domain injection,
off-prefix, tampered signature). Each token is given in base64url
(the wire encoding), base64-standard, and hex. Each case carries a
`spec_section` field; cases whose reason-code order the document leaves
unspecified carry `expect_any` (a set of conforming reasons) rather
than a single `expect`. The Go reference implementation verifies
against this file; a Rust verifier is in progress and is intended to
verify against the same file, which is the cross-implementation freeze
gate.

# Changes from -00 {#changes}

Wire-format changes (test vectors regenerated as v1):

- Selector moved into the key-record QNAME (`<selector>._sworn.<domain>`);
  `s=` tag removed. Operator policy tags (`u`, `t`, `rua`) moved to the
  `_prefixes._sworn` policy record so both modes have a policy home.
- Token MUST be a tagged COSE_Sign1 with REQUIRED protected `kid`,
  content type `application/sworn-token+cbor`, and record-derived
  `alg`; unprotected-bucket and `crit` header rules added; payload
  keys typed by CDDL with REQUIRED/OPTIONAL marking and duplicate-key
  rejection.
- Attested prefixes constrained to `2000::/3`, length 32–64, canonical;
  ineligible source ranges (v4-mapped/compat, NAT64, Teredo, 6to4)
  rejected. `unit` capped at 64 and clamped by receivers.
- Validity evaluated with a fixed 300-second skew; `exp > iat` required.
- Command verb renamed `XSWORN` → `SWORN` (X-prefix removed per
  {{RFC6648}}); one-command-per-session, 4096-octet line, and
  base64url-unpadded rules added.

Additions: reverse-tree pointer record and deterministic bounded
Mode-1 walk with a 10-query budget; delegated-tenant accountability
rule; CNAME delegation and takeover note; longest-prefix precedence,
mandatory unit clamping, and AR trust-boundary stripping;
attestation-squatting, DNS-oracle, and fail-attribution analysis;
testing mode (`t=y`) with safe `sworn=none` reporting; aggregate
reports (`rua=`) with DMARC-style external-destination verification;
result/reason taxonomy; expanded IANA registrations. COSE reference
updated RFC 8152 → RFC 9052.

Removed: the `hk=`/`ku=` retrieve-key-by-reference mechanism, deferred
to the future draft that registers a post-quantum algorithm ({{pq}}).

# Acknowledgments

Prior art that informed this design: CSV/CSA, VBR {{RFC5518}}, DANE
{{RFC6698}} {{RFC7672}}, ARC {{RFC8617}}, DMARC {{RFC7489}}, and the
RPKI. This document incorporates an adversarial design review.
