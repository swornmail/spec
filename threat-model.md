# SwornMail Threat Model

Companion to `draft-swornmail-protocol-00`. Technical scope only; published
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
   need no anti-replay state.

## Analyzed attacks & outcomes

| Attack | Outcome |
|---|---|
| Disposable-domain attestation cycles | Attestation grants accountability, not positive trust; transparency logs make re-attestation of the same space under fresh domains linkable; reputation services SHOULD propagate prefix history across operator changes |
| Operator key theft | Non-exploitable off-prefix (invariant 2); on-prefix attacker is inside the operator's own network |
| BGP origin hijack of attested prefix | Defeats Mode 1 membership checks; Mode 2 limited to token replay within lifetime. Mitigations: RPKI ROAs SHOULD cover attested prefixes; logs record ROA status; receivers MAY weight Mode 2 + ROA-covered higher. Residual risk shared with all IP-based reputation |
| EHLO keyword stripping | Downgrade-to-baseline only (invariant 1); attest within STARTTLS; Mode 1 unstrippable |
| `_sworn` record spoofing (no DNSSEC) | Verification DoS at worst (fail-to-neutral); substituted keys still fail invariant 2. DNSSEC recommended |
| Log flooding / equivocation / recon | Submission requires DNS proof of control; CT-style signed tree heads + gossip + independent monitors; publication at /48 coarseness limits topology disclosure (comparable data already public via SPF/rDNS) |

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
