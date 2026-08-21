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
2. **IP-binding redundancy**: a valid signature is necessary but not
   sufficient — the connection must originate inside the attested prefix.
   Key theft alone is non-exploitable off-prefix (contrast DKIM).
3. **Replay indifference** (Mode 2): tokens expire ≤24h and replay is only
   possible from inside the same prefix = same reputation unit; verifiers
   need no anti-replay state. Holds for `role=mta`. For `role=esp-tenant`,
   where one prefix is shared among tenants, it holds only at the
   granularity of the attested prefix — token possession is not tenant
   authentication, and per-tenant accountability requires a dedicated
   prefix (e.g. /64) per tenant.

## Analyzed attacks & outcomes

| Attack | Outcome |
|---|---|
| Disposable-domain attestation cycles | Attestation grants accountability, not positive trust; transparency logs make re-attestation of the same space under fresh domains linkable; reputation services SHOULD propagate prefix history across operator changes |
| Operator key theft | Non-exploitable off-prefix (invariant 2); on-prefix attacker is inside the operator's own network |
| BGP origin hijack of attested prefix | Defeats Mode 1 membership checks; Mode 2 limited to token replay within lifetime. Mitigations: RPKI ROAs SHOULD cover attested prefixes; logs record ROA status; receivers MAY weight Mode 2 + ROA-covered higher. Residual risk shared with all IP-based reputation |
| EHLO keyword stripping | Downgrade-to-baseline only (invariant 1); attest within STARTTLS; Mode 1 unstrippable |
| `_sworn` record spoofing (no DNSSEC) | Verification DoS at worst (fail-to-neutral); substituted keys still fail invariant 2. DNSSEC recommended |
| Log flooding / equivocation / recon | Submission requires DNS proof of control; CT-style signed tree heads + gossip + independent monitors; publication at /48 coarseness limits topology disclosure (comparable data already public via SPF/rDNS) |
| Attestation squatting (attesting space one doesn't control) | No reputation benefit by construction: feeds MUST bind reputation only to traffic-corroborated attestations; logs SHOULD require/record proof of prefix control (reverse-tree challenge or ROA correspondence) and flag uncorroborated claims |
| Overlapping attestations (provider /48 vs tenant /56) | Longest-prefix precedence for reputation keying; cross-domain overlap legitimate but surfaced by log monitors. Declared unit is capped 1–64 and verifiers MUST clamp a larger policy-record `u=` to 64 |
| Mode-1 reputation laundering by a delegated tenant | A provider enumerating a broad prefix accepts accountability for every address within it, including reverse-DNS-delegated sub-allocations. Mitigation: operators delegating reverse DNS SHOULD enumerate only sub-prefixes they operate, or use Mode 2 (per-prefix signed consent). Mode 1 is experimental and SHOULD be weighted low |
| Verifier as DNS oracle (attacker tokens naming arbitrary domains) | Cheap-checks-first ordering (time + membership before key fetch), negative caching, per-domain rate limits on key fetches |
| Spoofed inbound `sworn=` Authentication-Results | Border MTAs MUST strip/rename AR fields claiming their own authserv-id (RFC 8601 §5) — standard AR trust-boundary rule, restated because reputation feeds consume these headers |
| Signature cross-protocol confusion | Keys are protocol-dedicated; COSE protected content-type `application/sworn-token+cbor` is signed, domain-separating tokens from any other COSE use of the key |

## Residual risks (documented, accepted for v1)

1. Cloud-prefix recycling lets determined attackers churn attested space at
   provider scale; long-term answer is provider-role attestation.
2. Mode 1 inherits BGP's weaknesses; bounded by RPKI synergy, not eliminated.

## Post-quantum posture

Signature-only protocol: no confidentiality, so harvest-now-decrypt-later
does not apply; the quantum threat is live forgery. Records are
algorithm-agile (`k=` registry, selectors); planned migration: FN-DSA
(Falcon-512) tokens, SLH-DSA log tree heads, composite dual-signing during
transition, aligned to the NIST 2030/2035 timeline. A successful quantum
forgery still fails invariant 2 without routing control.
