# SwornMail Threat Model

Companion to `draft-kafedzhy-swornmail-01`. Technical scope only; published
so implementers and reviewers can check our assumptions rather than trust
our claims.

## Assets & adversaries

**Assets:** integrity of the (operator, prefix) binding; receivers'
reputation ledgers keyed on attested units; operator signing keys;
transparency-log consistency.

**Adversaries:** spammers exploiting IPv6 rotation; attackers holding stolen
operator keys; on-path/routing attackers (BGP hijack); malicious or
compromised log operators; abusive attestors (protocol-compliant attackers).

## Design invariants

1. **Fail-open**: absent/failed attestation yields the receiver's existing
   unattested-IPv6 treatment. The protocol can only add signal, never new
   failure modes for non-participants.
2. **Policy and IP binding**: a valid signature is necessary but not
   sufficient — the token prefix must be covered by the operator's separate
   policy record, and the connection must originate inside the token prefix.
   Key theft alone cannot authorize unrelated space (contrast DKIM).
3. **Replay indifference** (Mode 2): tokens expire ≤24h and replay is only
   possible from inside the signed prefix. Every replay therefore remains
   attributable to the same claimant domain and to an observed unit — the
   source /64 the connection actually came from — so verifiers need no
   mandatory anti-replay state for reputation use. Replay does **not** license
   widening: rolling abuse up from the observed unit to the whole signed
   prefix requires the independent control evidence of invariant 4, because a
   replay from a neighbouring /64 inside a shared aggregate is not evidence
   the claimant operates that /64. `role` is self-asserted, token possession
   is not tenant authentication, and per-tenant accountability requires a
   dedicated prefix (e.g. /64).
4. **Claim/evidence separation**: an attestation states what an operator
   claims; the observed unit states what a connection proved. Reputation
   attaches to the observed unit and the claimant domain. Widening to the
   signed prefix is permitted only on independent evidence of control over
   that boundary (reverse-DNS delegation rooted at it, provider
   authorization, or applicable authenticated routing attestation). A signed
   broad claim is never that evidence.

## Analyzed attacks & outcomes

| Attack | Outcome |
|---|---|
| Disposable-domain attestation cycles | Attestation grants accountability, not positive trust; transparency logs make re-attestation under fresh domains linkable. History is a reset-evasion signal, not permission to transfer reputation automatically: doing so would let a $1 domain poison shared-provider space |
| Operator key theft | Cannot attest outside the separately published policy enumeration; inside an authorized prefix, the operator has already accepted accountability |
| BGP origin hijack of attested prefix | Defeats Mode 1 membership checks; Mode 2 limited to token replay within lifetime. Mitigations: RPKI ROAs SHOULD cover attested prefixes; logs record ROA status; receivers MAY weight Mode 2 + ROA-covered higher. Residual risk shared with all IP-based reputation |
| EHLO keyword stripping | Downgrade-to-baseline only (invariant 1); attest within STARTTLS; Mode 1 unstrippable |
| `_sworn` record spoofing (no DNSSEC) | Replacing only one record normally causes neutral verification failure, but replacing both policy and key records can impersonate the operator. DNSSEC validation (or an equivalently authenticated DNS channel) is required to exclude an active DNS attacker |
| Log flooding / equivocation / recon | Submission requires DNS proof of control; CT-style signed tree heads + gossip + independent monitors; publication at /48 coarseness limits topology disclosure (comparable data already public via SPF/rDNS) |
| Shared-hosting tenant claims the provider aggregate | A pass proves only that this connection came from inside the signed prefix, not that the claimant controls all of it. Without independent prefix-control evidence, receivers MUST clamp consequences to the claimant domain and source /64 (or finer), regardless of a broader `u=`; they MUST NOT poison the provider domain, neighboring /64s, or an IP-only aggregate |
| Attestation squatting (attesting space one doesn't control) | No reputation benefit by construction: receivers bind reputation only to verified traffic from the source /64 (or finer) and the claimant domain. Logs SHOULD require/record proof of broader prefix control (reverse-tree challenge, provider authorization, or applicable routing evidence) and flag uncorroborated claims |
| Overlapping attestations (provider /48 vs tenant /56) | Longest-prefix precedence when selecting which attestation applies — not a licence to key reputation above the observed unit. Cross-domain overlap legitimate but surfaced by log monitors. A policy unit must be at least as specific as every enumerated prefix and no longer than /64 |
| Mode-1 reputation laundering by a delegated tenant | A provider enumerating a broad prefix accepts accountability for every address within it, including reverse-DNS-delegated sub-allocations. Mitigation: operators delegating reverse DNS SHOULD enumerate only sub-prefixes they operate, or use Mode 2 (per-prefix signed consent). Mode 1 is experimental and SHOULD be weighted low |
| Verifier as DNS oracle (attacker tokens naming arbitrary domains) | All local checks run before DNS; policy authorization runs before the key fetch; negative caching and per-source/per-domain limits bound the remaining policy lookups |
| Spoofed inbound `sworn=` Authentication-Results | Border MTAs MUST strip/rename AR fields claiming their own authserv-id (RFC 8601 §5) — standard AR trust-boundary rule, restated because reputation feeds consume these headers |
| Signature cross-protocol confusion | Keys are protocol-dedicated; COSE protected content-type `application/sworn-token+cbor` is signed, domain-separating tokens from any other COSE use of the key |

## Residual risks (documented, accepted for v1)

1. Cloud-prefix recycling lets determined attackers churn attested space at
   provider scale; long-term answer is provider-role attestation.
2. Mode 1 inherits BGP's weaknesses; bounded by RPKI synergy, not eliminated.
3. Without DNSSEC validation, an active DNS attacker that can replace both
   SwornMail records can forge the DNS root of trust.
4. The base protocol proves source membership, not exclusive prefix ownership.
   Safe broad-prefix roll-up depends on independently authenticated provider,
   reverse-DNS, or routing evidence; without it, only claimant-domain plus
   source-/64-or-finer reputation is safe. The protocol makes the safe
   boundary explicit (the observed unit, reported as `policy.observed`) but
   cannot itself supply the control evidence needed to exceed it.

## Post-quantum posture

Signature-only protocol: no confidentiality, so harvest-now-decrypt-later
does not apply; the quantum threat is live forgery. Records are
algorithm-agile (`k=` registry, selectors). ML-DSA (FIPS 204) is the
standardized baseline for a future composite transition; FN-DSA is not used
until FIPS 206 is final. Any composite must require both classical and
post-quantum signatures over one claim, with no single-component fallback.
Algorithm removal and migration planning tracks NIST's transition guidance,
including its 2035 target for removing quantum-vulnerable algorithms. A
successful quantum forgery still needs a covering policy and traffic from
the authorized prefix.
