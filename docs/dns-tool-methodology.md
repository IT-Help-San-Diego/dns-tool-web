# DNS Tool: Confidence-Scored Analysis of Domain Security Infrastructure

**Carey James Balboa**
ORCID: [0009-0000-5237-9065](https://orcid.org/0009-0000-5237-9065)

Version 26.33.83
DOI: [10.5281/zenodo.18854899](https://doi.org/10.5281/zenodo.18854899)

---

## Abstract

DNS Tool is an open-source OSINT platform designed to analyze domain security posture using RFC-compliant signals from DNS and email authentication infrastructure. The system collects DNS records, evaluates configuration compliance with relevant RFC standards, and applies a confidence-scored interpretation model to produce structured security intelligence outputs.

Unlike traditional scanners that report raw DNS results, DNS Tool emphasizes confidence scoring and reproducibility, enabling analysts to distinguish between verified security signals, ambiguous observations, and unsupported conclusions.

The platform focuses on five major areas of domain security infrastructure:

- Email authentication (SPF, DKIM, DMARC)
- Transport security (MTA-STS, DANE)
- DNS integrity (DNSSEC validation)
- Brand protection indicators (BIMI)
- Domain configuration analysis (CAA, TLS-RPT)

This document describes the methodology used by DNS Tool to transform raw DNS observations into structured intelligence outputs.

---

## 1. Problem Statement

Modern domain security analysis is fragmented across multiple DNS-based mechanisms defined by different RFC specifications.

Examples include:

- SPF (RFC 7208)
- DKIM (RFC 6376)
- DMARC (RFC 7489)
- DNSSEC (RFC 4033–4035)
- MTA-STS (RFC 8461)
- DANE for SMTP (RFC 7672)
- BIMI (RFC 9495)
- TLS-RPT (RFC 8460)
- CAA (RFC 8659)

Most existing tools present raw DNS data without distinguishing between valid security signals, partial configurations, ambiguous results, and misconfigurations.

This creates a common problem for analysts: interpretation uncertainty.

DNS Tool was developed to address this problem by introducing a structured evaluation process that:

1. Collects DNS evidence
2. Verifies RFC compliance
3. Applies a confidence model to interpretation

---

## 2. Methodology

The DNS Tool analysis pipeline consists of four stages:

1. Data acquisition
2. RFC compliance evaluation
3. Signal classification
4. Confidence scoring

These stages transform DNS observations into structured intelligence outputs.

### 2.1 Data Acquisition

DNS Tool collects domain infrastructure signals using DNS queries and validation checks.

Typical collected records include:

- TXT records (SPF, DMARC, BIMI)
- DKIM selector records
- MX records
- TLSA records
- DNSSEC chain data
- MTA-STS policy indicators
- CAA records
- TLS-RPT records

Data collection emphasizes direct DNS observation rather than third-party interpretation. This ensures results are reproducible by independent analysts.

### 2.2 RFC Compliance Evaluation

Each observed record is evaluated against its relevant specification.

Examples include:

**SPF evaluation:**
- Syntax validation
- Mechanism parsing
- Policy completeness

**DMARC evaluation:**
- Policy presence
- Alignment settings
- Enforcement state

**DNSSEC evaluation:**
- Chain integrity
- Delegation signatures
- Validation status

**BIMI evaluation (RFC 9495):**
- SVG format enforcement
- VMC certificate validation
- DNS record structure

Records that fail specification requirements are classified as non-compliant signals rather than silently ignored.

### 2.3 Signal Classification

After validation, signals are categorized into three groups:

**Verified signals:** Signals that meet RFC requirements and can be interpreted confidently.

**Ambiguous signals:** Signals that exist but cannot support strong conclusions.

**Invalid signals:** Configurations that violate specification rules.

This classification prevents over-interpretation of incomplete configurations.

### 2.4 Confidence Scoring

DNS Tool assigns a confidence score to each interpreted signal.

The scoring model reflects how strongly the DNS evidence supports the resulting claim.

Confidence levels may represent:

**High confidence:** Evidence strongly supports the interpretation.

**Moderate confidence:** Evidence suggests the interpretation but contains uncertainty.

**Low confidence:** Evidence exists but cannot support a strong claim.

Confidence scoring is intended to mirror analytical practices used in intelligence analysis frameworks such as ICD-203 analytic standards.

---

## 3. Implementation Architecture

The DNS Tool system consists of three major components:

**Web interface:** Provides interactive domain analysis and visualization.

**Analysis engine:** Processes DNS records and performs RFC validation.

**Supporting intelligence modules:** Generate structured intelligence outputs from analysis results.

The implementation is written primarily in Go for the analysis engine with a web-based interface for user interaction. The system is designed to allow independent verification of DNS observations.

Core research logic and internal analysis pipelines are maintained in private repositories for security and intellectual property protection.

---

## 4. Limitations

DNS Tool operates exclusively on publicly available DNS information.

As a result, it cannot evaluate:

- Internal email infrastructure
- Private key security
- Server-side enforcement mechanisms

The tool therefore focuses on observable infrastructure posture rather than complete operational security evaluation.

Additionally, DNS observations may change over time, meaning results represent the configuration state at the time of analysis.

---

## 5. Reproducibility

All DNS signals used by DNS Tool are publicly observable and can be independently verified using standard DNS queries.

This design supports reproducibility and transparency in security analysis.

Source code and methodology are available at: https://github.com/careyjames/dns-tool-web

---

## 6. Citation

If DNS Tool contributes to research or analysis, please cite:

```bibtex
@software{balboa2026dnstool,
  author = {Balboa, Carey James},
  title = {DNS Tool: Domain Security Audit Platform},
  year = {2026},
  version = {26.33.82},
  doi = {10.5281/zenodo.18854899},
  url = {https://dnstool.it-help.tech},
  license = {BSL-1.1}
}
```

---

*DNS Tool v26.33.82 · IT Help San Diego Inc. · Licensed under BSL-1.1*
*DOI: 10.5281/zenodo.18854899*
