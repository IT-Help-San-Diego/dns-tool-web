# DNS Tool — Zone Health Golden Rules

**Version:** 26.33.65
**Last Updated:** 2026-03-03
**Copyright:** (c) 2024-2026 IT Help San Diego Inc.
**License:** BUSL-1.1

---

## Purpose

This document specifies the golden rules governing DNS Tool's Zone Health advisory logic. These rules are RFC-mandated behaviors locked by automated tests in `health_test.go`. If a golden rule test fails, the code change is wrong — not the test.

The golden rules define:
- Which policy signals are emitted (and suppressed) for each zone profile
- How the structural score is computed (and what it excludes)
- How the Drift Engine compares zone files against live DNS
- The decision protocols governing advisory output

---

## Zone Profile Classification

Every uploaded zone file is classified into one of five profiles. Profile classification determines which policy signals are emitted.

| Profile | Detection Logic | SPF/DMARC Flagged? |
|---------|----------------|-------------------|
| **Delegation-Only** | SOA+NS+DS only, no A/AAAA/MX/email records; OR SOA+NS with no address/email/DS | No (suppressed) |
| **Full-Service** | Has A/AAAA AND has MX/SPF/DMARC/DKIM | Yes |
| **Web-Only** | Has A/AAAA, no email records | Yes |
| **Email-Only** | Has MX/SPF/DMARC/DKIM, no A/AAAA | Yes |
| **Minimal** | Fallback (e.g., CNAME-only) | Yes |

---

## Golden Rules

### GR-001: SPF Absence Always Flagged for Non-Delegation Zones

**RFC:** RFC 7208 Section 2.1
**Severity:** Critical
**Test:** `TestGoldenRuleSPFAlwaysFlaggedNonDelegation`

**Rule:** When a zone file lacks an SPF record (TXT containing `v=spf1`), it MUST be flagged as `missing` for ALL zone profiles EXCEPT Delegation-Only.

**Rationale:** Attackers send FROM a domain — they do not need the domain to receive mail. A domain without SPF allows any server on the internet to send email claiming to be from that domain. This applies to parked domains, web-only domains, and domains with zero email infrastructure.

**Signal:** `SPF | missing | "No SPF record — any server can claim to send email as this domain (RFC 7208)"`

**Tested profiles:** Full-Service (MX present), Web-Only (no MX), Minimal (CNAME only), Parked domain (SOA+NS+A, zero email)

---

### GR-002: DMARC Absence Always Flagged for Non-Delegation Zones

**RFC:** RFC 7489 Section 4
**Severity:** Critical
**Test:** `TestGoldenRuleDMARCAlwaysFlaggedNonDelegation`

**Rule:** When a zone file lacks a DMARC record (`_dmarc.*` TXT containing `v=DMARC1`), it MUST be flagged as `missing` for ALL zone profiles EXCEPT Delegation-Only.

**Rationale:** Without a DMARC policy, receiving mail servers have no enforcement instructions for spoofed email. Even domains that never send email need `v=DMARC1; p=reject` to protect against impersonation.

**Signal:** `DMARC | missing | "No DMARC policy — receiving servers have no spoofing policy to enforce (RFC 7489)"`

**Tested profiles:** Full-Service (MX present), Web-Only (no email at all), Minimal (bare domain)

---

### GR-003: Delegation-Only Suppresses SPF/DMARC Signals

**RFC:** RFC 7208, RFC 7489
**Severity:** Critical
**Test:** `TestGoldenRuleDelegationOnlySuppressesSPFDMARC`

**Rule:** TLD and delegation-only zones MUST NOT flag SPF or DMARC as missing. SPF/DMARC policies do not apply at the TLD level.

**Rationale:** TLD zones (.com, .net) delegate to child zones. They do not send or receive email. Flagging SPF/DMARC for a TLD zone is a false positive.

---

### GR-004: DANE/TLSA Absence Never Flagged

**RFC:** RFC 6698
**Severity:** Critical
**Test:** `TestGoldenRuleDANENeverFlaggedMissing`

**Rule:** DANE/TLSA absence MUST NEVER be flagged as `missing` for ANY zone profile, including Full-Service zones with MX records.

**Rationale:** TLSA records are per-service (`_443._tcp.host`, `_25._tcp.mail`) and typically managed by service operators or automation, not zone administrators. Flagging absence would produce false positives for the vast majority of zones.

**Tested profiles:** Full-Service with MX, Web-Only, Delegation-Only

---

### GR-005: DANE/TLSA Presence Detected

**RFC:** RFC 6698
**Test:** `TestGoldenRuleDANEPresentIsDetected`

**Rule:** When TLSA records are present in the zone file, a `detected` signal MUST be emitted with label `TLSA/DANE`.

---

### GR-006: Policy Signals Never Affect Structural Score

**Severity:** Critical
**Test:** `TestGoldenRulePolicySignalsNeverAffectStructuralScore`

**Rule:** The structural score MUST NOT change based on the presence or absence of SPF, DMARC, MX, CAA, or TLSA records. A zone with SOA+NS+A must score identically with or without policy records.

**Rationale:** Structural score measures zone file correctness per RFC 1035 (SOA, NS, address records, TTL consistency, duplicates). Policy records are operational concerns. Mixing structural and operational scoring conflates two distinct quality dimensions.

---

### GR-007: SPF Present Is Detected

**RFC:** RFC 7208
**Test:** `TestGoldenRuleSPFPresentIsDetected`

**Rule:** When a TXT record containing `v=spf1` is present, a `detected` signal MUST be emitted with label `SPF`.

---

### GR-008: DMARC Present Is Detected

**RFC:** RFC 7489
**Test:** `TestGoldenRuleDMARCPresentIsDetected`

**Rule:** When a TXT record at `_dmarc.*` is present, a `detected` signal MUST be emitted with label `DMARC`.

---

### GR-009: Missing SPF Signal Must Include Risk Explanation

**RFC:** RFC 7208
**Test:** `TestGoldenRuleMissingSPFMessage`

**Rule:** When SPF is flagged as `missing`, the Detail field MUST be non-empty and explain the spoofability risk. A bare `missing` label without context is not actionable.

---

## Advisory Decision Protocols

These protocols describe how DNS Tool decides whether and how to advise on each signal.

### AP-001: Profile-First Gating

Zone profile classification is the first gate. All signal emission decisions start by checking Delegation-Only status. If the zone is Delegation-Only, SPF and DMARC signals are suppressed entirely.

### AP-002: Universal SPF/DMARC Warning

SPF and DMARC absence warnings apply to ALL non-delegation zones regardless of email infrastructure. The presence of MX records does NOT gate SPF/DMARC warnings.

**Why:** Attackers spoof the FROM address. They do not need the victim domain to have MX records or any email infrastructure. RFC 7208 Section 2.1 states SPF applies to the envelope sender. RFC 7489 Section 4 states DMARC applies to the header From.

### AP-003: Email Intent Gates DKIM Info Only

DKIM absence is flagged as `info` (not `missing`) and ONLY when email intent is detected (MX, SPF, DMARC, or DKIM records present). DKIM selectors are rarely in zone files — providers manage them externally.

### AP-004: Web Intent Gates CAA Info Only

CAA absence is flagged as `info` (not `missing`) and ONLY when web intent is detected (A or AAAA records present). CAA restricts which CAs issue certificates — relevant only for addressable domains.

### AP-005: DANE/TLSA Is Detect-Only

DANE/TLSA is per-service (`_443._tcp`, `_25._tcp`). Absence is never flagged. Only presence is acknowledged as `detected`.

### AP-006: Structural vs Operational Separation

Structural score measures zone correctness (SOA, NS, addresses, TTL, duplicates). Policy signals (SPF, DMARC, DKIM, CAA, DANE) are reported in a separate dimension and never affect the structural score.

### AP-007: Signal Status Taxonomy

Every PolicySignal has exactly one status:
- **detected** — Record found in zone
- **missing** — Record absent, absence is a security concern per RFC
- **info** — Record absent, absence is informational (not a direct security risk)

---

## Structural Scoring

The structural score (0-100) is computed from RFC compliance checks. Policy records are excluded.

| Check | RFC | Severity | Weight |
|-------|-----|----------|--------|
| SOA record present | RFC 1035 Section 5.2.1 | Critical | 25 |
| NS records at apex | RFC 1035 Section 5.2.1 | Critical | 25 |
| NS redundancy (2+ nameservers) | RFC 2182 Section 4 | Warning | 15 |
| Address records (A/AAAA) | RFC 1035 Section 3.2.1 | Info | 10 |
| SOA timers RFC-compliant | RFC 1912 Section 2.2 | Warning | 15 |
| TTL consistency | RFC 2308 Section 4 | Warning | 15 |
| No duplicate RRsets | RFC 2181 Section 5.2 | Warning | 15 |

**Score formula:** (sum of passing check weights) / (sum of all weights) x 100

| Score Range | Verdict |
|-------------|---------|
| 90-100 | Well-Formed |
| 70-89 | Adequate |
| 50-69 | Needs Attention |
| 30-49 | Deficient |
| 0-29 | Minimal |

---

## Drift Engine

The Drift Engine compares an operator's zone file (declared state) against live DNS query results (actual deployed state).

**Terminology:** "Configuration drift" is the industry-standard term for actual-vs-declared state divergence, used by Terraform, CloudFormation, Ansible, Puppet, and formalized by NIST SP 800-128 (configuration baseline deviation).

### Drift Categories

| Category | Description |
|----------|-------------|
| **added** | Record in zone file, not observed in live DNS |
| **missing** | Record in live DNS, not in zone file |
| **changed** | Record in both, RDATA values differ |
| **ttl_only** | Record in both, identical RDATA, TTL differs |

### Known False-Positive Edges

| Edge Case | Description | Mitigation |
|-----------|-------------|------------|
| CNAME flattening | Providers synthesize A/AAAA from CNAME at apex | Documented as known provider behavior |
| DNSSEC records | RRSIG/NSEC/NSEC3 generated by signing process | Comparison limited to basic types (A, AAAA, NS, CNAME, MX, TXT, SOA, CAA) |
| Resolver TTL caching | Live TTL reflects remaining cache, not authoritative TTL | Reported as `ttl_only` — a distinct, lower-severity category |

### Comparison Scope

Apex-level basic record types only: A, AAAA, NS, CNAME, MX, TXT, SOA, CAA. Subdomain records and DNSSEC types are excluded.

---

## SOA Timer Validation

SOA timers are validated against RFC 1912 Section 2.2.

| Field | Threshold | Severity | RFC Basis |
|-------|-----------|----------|-----------|
| Refresh | < 1200s | Warning | RFC 1912: 1200-43200s recommended |
| Retry | < 120s | Warning | RFC 1912: 120-10800s recommended |
| Retry vs Refresh | retry >= refresh | Warning | RFC 1912: retry < refresh |
| Expire | < 1209600s (2 weeks) | Info | RFC 1912: 2-4 weeks recommended |
| Expire vs Refresh | expire <= refresh | Warning | RFC 1912: expire > refresh |
| Minimum (neg cache) | > 86400s (1 day) | Info | RFC 2308 Section 5: 1-3 hours |
| Serial | = 0 | Info | YYYYMMDDNN format recommended |

---

## Test Coverage Summary

- **9 golden rule test functions** with **15 sub-tests** across all zone profiles
- Additional non-golden tests: empty zone, basic zone detection, DNSSEC detection, structural scoring, SOA timer analysis, duplicate detection, zone profile classification, policy signal correctness, TTL spread detection
- **Total test functions in health_test.go:** 22+
