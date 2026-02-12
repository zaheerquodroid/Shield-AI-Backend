# Coco TestAI — Security & Compliance Certification Roadmap

**Date:** February 5, 2026
**Companion Document:** [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md)
**Context:** Roadmap for achieving security and compliance certifications for Coco TestAI, sorted from least expensive/time-consuming to most. Costs are estimates based on 2025-2026 industry data for a small-to-mid SaaS company (10-50 employees).

---

## Table of Contents

1. [Overview](#overview)
2. [Pre-Certification: Code Fixes Required](#pre-certification-code-fixes-required)
3. [Tier 1: Low Cost, Quick Wins](#tier-1-low-cost-quick-wins)
   - [1. security.txt + Vulnerability Disclosure Policy](#1-securitytxt--vulnerability-disclosure-policy)
   - [2. CSA STAR Level 1 (Self-Assessment)](#2-csa-star-level-1-self-assessment)
   - [3. OWASP Top 10 / ASVS Penetration Test](#3-owasp-top-10--asvs-penetration-test)
4. [Tier 2: Moderate Cost, Foundational Certifications](#tier-2-moderate-cost-foundational-certifications)
   - [4. SOC 2 Type I](#4-soc-2-type-i)
   - [5. GDPR Compliance](#5-gdpr-compliance)
   - [6. ISO 27001](#6-iso-27001)
5. [Tier 3: Higher Cost, Extended Certifications](#tier-3-higher-cost-extended-certifications)
   - [7. SOC 2 Type II](#7-soc-2-type-ii)
   - [8. CSA STAR Level 2](#8-csa-star-level-2-third-party-certification)
6. [Tier 4: Industry-Specific](#tier-4-industry-specific-if-applicable)
   - [9. HIPAA Compliance](#9-hipaa-compliance-healthcare-customers)
   - [10. PCI DSS](#10-pci-dss-payment-card-data)
7. [Recommended Certification Sequence](#recommended-certification-sequence)
8. [Compliance Automation Platform Comparison](#compliance-automation-platform-comparison)
9. [Cost Summary](#cost-summary)
10. [Sources](#sources)

---

## Overview

The following certifications are listed in order from least to most expensive. Each entry includes what the certification is, its cost, timeline, and — critically — what gaps from the [Security Audit Report](./SECURITY_AUDIT_REPORT.md) must be fixed before pursuing it.

| # | Certification | Cost Range | Timeline | Prerequisite |
|---|---------------|-----------|----------|--------------|
| 1 | security.txt + Disclosure Policy | $0 | 1 day | None |
| 2 | CSA STAR Level 1 | $0 – $2K | 1-3 weeks | None |
| 3 | OWASP Pen Test | $2.5K – $15K | 2-4 weeks | Code fixes |
| 4 | SOC 2 Type I | $20K – $50K | 2-4 months | Code fixes + policies |
| 5 | GDPR Compliance | $10K – $30K | 1-3 months | DPO + policies |
| 6 | ISO 27001 | $15K – $50K | 3-9 months | ISMS + policies |
| 7 | SOC 2 Type II | $30K – $80K/yr | 6-12 months after Type I | SOC 2 Type I |
| 8 | CSA STAR Level 2 | $15K – $40K | 2-4 months after ISO | ISO 27001 |
| 9 | HIPAA | $50K – $150K | 6-12 months | SOC 2 Type II (recommended) |
| 10 | PCI DSS | $15K – $200K+ | 3-12 months | Only if handling card data |

---

## Pre-Certification: Code Fixes Required

Before pursuing any certification, these code-level issues identified in the [Security Audit Report](./SECURITY_AUDIT_REPORT.md) must be addressed. They are prerequisites for every certification.

### Critical (Must Fix First)

| # | Fix | Codebase | File / Location | Affects |
|---|-----|----------|----------------|---------|
| 1 | Remove hardcoded fallback `SECRET_KEY`; fail if unset | Backend | `settings.py:36` | All certifications |
| 2 | Change `DEBUG` default to `False` | Backend | `settings.py:39` | All certifications |
| 3 | Change `ALLOWED_HOSTS` default to `[]` (empty) | Backend | `settings.py:41` | All certifications |

### High Priority

| # | Fix | Codebase | Effort | Affects |
|---|-----|----------|--------|---------|
| 4 | Replace 44+ `str(e)` responses with generic error messages | Backend | Medium | SOC 2, ISO, OWASP |
| 5 | Add security headers (HSTS, CSP, Referrer-Policy, Permissions-Policy, SSL redirect) | Backend | Medium | All certifications |
| 6 | Implement rate limiting on auth endpoints (login, signup, password reset) | Backend | Medium | SOC 2, ISO, OWASP |
| 7 | Add CI/CD security scanning pipeline (SAST, SCA, secret scanning) | All repos | Medium | SOC 2, ISO |
| 8 | Sanitize user input before LLM prompt interpolation | Backend | Medium | OWASP, SOC 2 |
| 9 | Add static analysis (AST inspection) for AI-generated code before execution | Backend | Medium | OWASP, SOC 2 |
| 10 | Chrome extension: add sender validation to `onMessage` listener | Extension | Medium | SOC 2, OWASP |

### Medium Priority

| # | Fix | Codebase | Effort | Affects |
|---|-----|----------|--------|---------|
| 11 | Implement structured audit logging with retention policy | Backend | Large | SOC 2 Type II, ISO, HIPAA |
| 12 | Implement database-level row-level security (PostgreSQL RLS) | Backend | Large | SOC 2, HIPAA |
| 13 | Add Kubernetes `NetworkPolicy` for container network isolation | Backend | Medium | SOC 2, ISO |
| 14 | Chrome extension: encrypt auth data in `chrome.storage.local` | Extension | Medium | SOC 2, OWASP |

### For HIPAA / Advanced Certifications

| # | Fix | Codebase | Effort | Affects |
|---|-----|----------|--------|---------|
| 15 | Upgrade encryption to AES-256-GCM with AWS KMS | Backend | Large | HIPAA, ISO |
| 16 | Write security policies (InfoSec, IR, Access Control, Data Classification, Vendor Mgmt) | Documentation | Large | All certifications |

---

## Tier 1: Low Cost, Quick Wins

These can be achieved with internal effort and minimal external spend. They build the foundation for all later certifications.

---

### 1. security.txt + Vulnerability Disclosure Policy

| | Details |
|---|---|
| **What it is** | RFC 9116 standard file at `/.well-known/security.txt` declaring how security researchers can report vulnerabilities. Expected by enterprise customers and auditors. |
| **Cost** | $0 (internal effort) |
| **Timeline** | 1 day |
| **Validity** | Keep updated; review annually |

**Checklist:**
- [ ] Create `/.well-known/security.txt` with:
  - Contact email/URL for reporting
  - Encryption key (PGP public key)
  - Preferred languages
  - Policy URL
  - Expiry date
- [ ] Publish a responsible disclosure policy on your website
- [ ] Set up a security@cocoframework.com email alias

**Example `security.txt`:**
```
Contact: mailto:security@cocoframework.com
Encryption: https://cocoframework.com/.well-known/pgp-key.txt
Preferred-Languages: en
Policy: https://cocoframework.com/security-policy
Expires: 2027-02-05T00:00:00.000Z
```

---

### 2. CSA STAR Level 1 (Self-Assessment)

| | Details |
|---|---|
| **What it is** | Free self-assessment questionnaire (CAIQ v4) published to the [CSA STAR Registry](https://cloudsecurityalliance.org/star/). Demonstrates cloud security posture to customers. Your published security page already claims CSA STAR Level 1 alignment. |
| **Cost** | $0 – $2,000 (internal time only; CSA membership optional at ~$500/yr for discounts on Level 2) |
| **Timeline** | 1 – 3 weeks |
| **Validity** | 1 year (must renew annually) |

**Checklist:**
- [ ] Download [CAIQ v4 questionnaire](https://cloudsecurityalliance.org/star/) (~300 questions)
- [ ] Answer questions mapping to existing controls:
  - RBAC (implemented)
  - MFA (implemented)
  - Encryption at rest/in transit (implemented, document current state)
  - Session management (implemented)
  - Tenant isolation (implemented at application layer)
- [ ] Document controls for areas currently missing:
  - Incident response plan
  - Data retention policy
  - Vulnerability management process
  - Business continuity / disaster recovery plan
- [ ] Submit completed CAIQ to CSA STAR Registry
- [ ] Update your security page with STAR Registry link

---

### 3. OWASP Top 10 / ASVS Penetration Test

| | Details |
|---|---|
| **What it is** | Third-party penetration test verifying your app against OWASP Top 10 (2025) or the ASVS (Application Security Verification Standard) Level 1/2. Not a formal "certification" but a recognized security attestation you can share with customers. |
| **Cost** | $2,500 – $15,000 (one-time per assessment) |
| **Timeline** | 2 – 4 weeks |
| **Validity** | Point-in-time; recommend annually or after major releases |

**Pre-requisite code fixes (from audit):**
- [ ] Fix all 44+ error information leakage instances (`str(e)` → generic messages)
- [ ] Add missing security headers (HSTS, CSP, Referrer-Policy, etc.)
- [ ] Implement rate limiting on auth endpoints
- [ ] Remove hardcoded `SECRET_KEY` fallback
- [ ] Change `DEBUG` default to `False`, `ALLOWED_HOSTS` default to `[]`
- [ ] Fix bare `except:` clause in `artifacts.py:2599`

**After code fixes:**
- [ ] Engage a penetration testing firm
  - Budget option: [Cobalt](https://cobalt.io), [Bugcrowd](https://bugcrowd.com) (~$2.5K – $8K)
  - Comprehensive: [HackerOne](https://hackerone.com), [NCC Group](https://nccgroup.com), [Bishop Fox](https://bishopfox.com) (~$10K – $42K)
- [ ] Request OWASP Top 10 2025 + ASVS Level 1 scope
- [ ] Remediate findings
- [ ] Obtain attestation letter / report

**Pen testing firms by price range:**

| Firm | Cost | Scope |
|------|------|-------|
| Cobalt | $2.5K – $8K | Crowdsourced pen test, OWASP Top 10 |
| Bugcrowd | $3K – $10K | Managed bug bounty / pen test |
| HackerOne | $5K – $15K | Pen test + bug bounty hybrid |
| Software Secured | $10K – $25K | Manual pen test with ASVS mapping |
| NCC Group / Bishop Fox | $15K – $42K+ | Full ASVS Level 2 audit with report |

---

## Tier 2: Moderate Cost, Foundational Certifications

These are the certifications enterprise customers and B2B SaaS buyers ask for most frequently.

---

### 4. SOC 2 Type I

| | Details |
|---|---|
| **What it is** | Point-in-time audit by a CPA firm verifying your security controls are designed correctly. The de facto standard for B2B SaaS in the US. Type I proves controls exist but doesn't test if they work over time. |
| **Cost** | $20,000 – $50,000 total (first year) |
| | — Compliance platform: $4,000 – $10,000/yr |
| | — Auditor fees: $10,000 – $30,000 |
| | — Internal effort: 100 – 200 hours |
| **Timeline** | 2 – 4 months (with compliance platform) |
| **Validity** | Point-in-time report |

**What you need to do (mapped to audit findings):**

| SOC 2 Trust Service Criteria | Current Gap | Required Fix |
|------------------------------|-------------|--------------|
| **CC6.1 — Logical Access** | RBAC exists but no DB-level RLS | Acceptable for Type I; document application-layer controls |
| **CC6.6 — Encryption** | Fernet not AES-256-GCM | Document current encryption; plan upgrade path |
| **CC6.7 — Transmission Security** | No HSTS, no SSL redirect | Add HSTS and `SECURE_SSL_REDIRECT` |
| **CC7.2 — Monitoring** | Text-file logging, no alerting | Implement structured logging + alerting (CloudWatch/Datadog) |
| **CC7.3 — Incident Response** | No IR plan documented | Write incident response plan and runbook |
| **CC8.1 — Change Management** | No CI/CD security scanning | Add basic CI/CD pipeline with security checks |
| **CC3.2 — Risk Assessment** | No documented risk assessment | Conduct and document a formal risk assessment |
| **CC1.4 — Policies** | No security policies documented | Write: InfoSec policy, acceptable use, access control, data classification, incident response, vendor management |

**Policy documents you need to write:**

| Policy | Purpose | Pages (approx.) |
|--------|---------|-----------------|
| Information Security Policy | Overall security framework and responsibilities | 5-10 |
| Access Control Policy | Who gets access to what and how | 3-5 |
| Data Classification Policy | How data is categorized and handled | 3-5 |
| Incident Response Plan | Steps to detect, respond to, and recover from incidents | 8-15 |
| Acceptable Use Policy | Employee/user acceptable behavior | 3-5 |
| Change Management Policy | How code and infra changes are reviewed and deployed | 3-5 |
| Vendor Management Policy | How third-party vendors are assessed | 3-5 |
| Risk Assessment Report | Formal identification and scoring of risks | 10-20 |
| Business Continuity / DR Plan | Recovery procedures for outages | 5-10 |

**Recommended compliance platforms:**

| Platform | Starting Cost | Best For | Key Integrations |
|----------|--------------|----------|------------------|
| [Sprinto](https://sprinto.com) | ~$4,000/yr | Budget-conscious startups | AWS, GitHub, Slack, Jira |
| [Vanta](https://vanta.com) | ~$7,500/yr | Quick setup, startup-friendly | AWS, GitHub, Google Workspace, Okta |
| [Drata](https://drata.com) | ~$15,000/yr | Engineering-heavy teams | AWS, GitHub, CI/CD, Datadog |

---

### 5. GDPR Compliance

| | Details |
|---|---|
| **What it is** | Compliance with the EU General Data Protection Regulation. Not a formal "certification" but a legal requirement if you serve EU customers. Your published security page claims GDPR compliance. |
| **Cost** | $10,000 – $30,000 (first year for a small SaaS) |
| | — Privacy management tool: $5,000 – $15,000/yr |
| | — DPO (external): $5,000 – $15,000/yr |
| | — Legal review: $3,000 – $10,000 |
| **Timeline** | 1 – 3 months |
| **Validity** | Ongoing obligation |

**What you need to do (mapped to audit findings):**

| GDPR Article | Current Gap | Required Fix |
|--------------|-------------|--------------|
| **Art. 15 — Right of Access** | No user data export API | Build data export endpoint |
| **Art. 17 — Right to Erasure** | Account deletion exists (partial) | Verify cascade deletion covers all user data (logs, conversations, test data, AI interaction history) |
| **Art. 25 — Data Protection by Design** | Encryption uses Fernet, not AES-256 | Upgrade encryption; document DPbD measures |
| **Art. 30 — Records of Processing** | No processing activity records | Document what data you collect, why, how long you keep it |
| **Art. 32 — Security of Processing** | Multiple gaps from audit | Address security headers, rate limiting, error handling |
| **Art. 33 — Breach Notification** | No incident response plan | Write IR plan with 72-hour notification procedure |
| **Art. 35 — DPIA** | No Data Protection Impact Assessment | Conduct DPIA for AI/LLM processing of user data |
| **Art. 37 — DPO** | No Data Protection Officer | Appoint internal or external DPO |
| **Consent & Privacy** | Not audited | Review/create privacy policy, cookie consent, DPAs |

**GDPR-specific deliverables:**

| Deliverable | Description |
|-------------|-------------|
| Privacy Policy | Public-facing policy describing data collection and use |
| Data Processing Agreement (DPA) | Template for customers who are data controllers |
| Records of Processing Activities (ROPA) | Internal register of all processing activities |
| Data Protection Impact Assessment (DPIA) | Risk assessment for AI/LLM data processing |
| Data Subject Request (DSR) Process | Documented process for handling access/deletion requests |
| Cookie Consent | Mechanism for website cookie consent |
| Sub-processor List | Published list of third-party processors (AWS, Anthropic, etc.) |
| Data Retention Schedule | Defined retention periods for each data category |

---

### 6. ISO 27001

| | Details |
|---|---|
| **What it is** | International standard for Information Security Management Systems (ISMS). Required by many European and global enterprise customers. Complementary to SOC 2 (~60-70% control overlap). |
| **Cost** | $15,000 – $50,000 (first year for small SaaS) |
| | — Compliance platform: included if already using Vanta/Drata/Sprinto |
| | — Certification body audit: $10,000 – $25,000 |
| | — Internal effort: 200 – 400 hours |
| **Timeline** | 3 – 9 months |
| **Validity** | 3 years (with annual surveillance audits at ~$5,000 – $10,000/yr) |

**What you need to do (beyond SOC 2 overlap):**

| ISO 27001 Annex A Control | Current Gap | Required Fix |
|---------------------------|-------------|--------------|
| **A.5 — Information Security Policies** | No documented policies | Write ISMS policy suite |
| **A.8 — Asset Management** | No asset inventory | Create and maintain asset inventory (data, systems, people) |
| **A.8.10 — Information Deletion** | Partial (account deletion exists) | Document data retention and deletion schedules |
| **A.8.24 — Use of Cryptography** | Fernet, no KMS | Document cryptographic controls; plan AES-256-GCM upgrade |
| **A.5.23 — Supplier Relationships** | No vendor security assessments | Establish vendor management process (AWS, Anthropic, etc.) |
| **A.8.8 — Vulnerability Management** | No scanning pipeline | Implement SAST/DAST/SCA in CI/CD |
| **A.5.24 — Incident Management** | No IR plan | Write and test incident response plan |
| **A.5.35 — Independent Review** | No security audits | Schedule annual pen tests and internal audits |
| **A.8.16 — Monitoring** | Text-file logging only | Implement centralized monitoring and alerting |

**ISO 27001 certification process:**
```
1. Gap Analysis          → Identify what's missing (2-4 weeks)
2. ISMS Implementation   → Build policies, controls, procedures (2-3 months)
3. Internal Audit        → Self-assess readiness (1-2 weeks)
4. Management Review     → Leadership sign-off (1 day)
5. Stage 1 Audit         → Documentation review by certification body (1-2 days)
6. Stage 2 Audit         → On-site/remote evidence review (2-5 days)
7. Certification         → Certificate issued (valid 3 years)
8. Surveillance Audits   → Annual checks by certification body
```

---

## Tier 3: Higher Cost, Extended Certifications

These build on top of Tier 2 and are typically pursued after SOC 2 Type I and/or ISO 27001 are in place.

---

### 7. SOC 2 Type II

| | Details |
|---|---|
| **What it is** | Audit proving your controls have been operating effectively over a period (typically 6-12 months). The "gold standard" for US B2B SaaS. Your published security page claims SOC 2 Type II. |
| **Cost** | $30,000 – $80,000/yr (ongoing) |
| | — Auditor fees: $15,000 – $50,000 |
| | — Compliance platform: $4,000 – $15,000/yr (ongoing) |
| | — Internal effort: 150 – 300 hours/yr |
| **Timeline** | 6 – 12 month observation period after Type I |
| **Validity** | Annual audit required |
| **Prerequisite** | SOC 2 Type I completed; controls operating for 6+ months |

**Checklist:**
- [ ] Complete SOC 2 Type I first
- [ ] Operate all controls consistently for 6-12 months
- [ ] Maintain evidence collection via compliance platform (automated)
- [ ] Address all findings from Type I report
- [ ] Ensure structured audit logging is operational (currently missing — see audit report)
- [ ] Ensure monitoring and alerting is active (currently missing — see audit report)
- [ ] Conduct periodic access reviews (quarterly)
- [ ] Complete employee security awareness training
- [ ] Document and track all security incidents during observation period

**Type I → Type II timeline:**
```
Month 0:     SOC 2 Type I completed
Months 1-6:  Observation period (controls operating, evidence collected)
Month 6:     Earliest Type II audit window opens
Month 7-8:   Type II audit conducted
Month 9:     Type II report issued
Month 12:    Annual renewal cycle begins
```

---

### 8. CSA STAR Level 2 (Third-Party Certification)

| | Details |
|---|---|
| **What it is** | Third-party audit of cloud security controls based on the Cloud Controls Matrix (CCM). Builds on ISO 27001 — requires ISO 27001 as a prerequisite. |
| **Cost** | $15,000 – $40,000 (on top of ISO 27001 costs) |
| **Timeline** | 2 – 4 months (after ISO 27001 is achieved) |
| **Validity** | 3 years |
| **Prerequisite** | ISO 27001 certification |

**Checklist:**
- [ ] Achieve ISO 27001 first
- [ ] Map ISO 27001 controls to CCM v4
- [ ] Address cloud-specific controls:
  - Container isolation (add K8s `NetworkPolicy`)
  - Multi-tenancy (implement DB-level RLS)
  - Encryption key management (upgrade to KMS)
  - Data residency (multi-region deployment if needed)
- [ ] Engage CSA-approved certification body
- [ ] Publish Level 2 certification on CSA STAR Registry

---

## Tier 4: Industry-Specific (If Applicable)

These are only needed if your customer base or data types require them.

---

### 9. HIPAA Compliance (Healthcare Customers)

| | Details |
|---|---|
| **What it is** | US regulation for protecting health information (PHI). Required if healthcare customers use Coco TestAI with PHI-containing test data. Your published security page mentions HIPAA-eligible infrastructure. |
| **Cost** | $50,000 – $150,000 (first year) |
| | — Compliance program: $15,000 – $30,000 |
| | — Risk assessment: $10,000 – $25,000 |
| | — Legal/BAA: $5,000 – $15,000 |
| | — Technical controls: $20,000 – $80,000 |
| **Timeline** | 6 – 12 months |
| **Validity** | Ongoing; annual risk assessments required |
| **Prerequisite** | SOC 2 Type II (recommended, not required) |

**What you need to do (major items from audit):**

| HIPAA Requirement | Current Gap | Required Fix |
|-------------------|-------------|--------------|
| **Encryption (§164.312(a)(2)(iv))** | Fernet, not AES-256 | Upgrade to AES-256-GCM with KMS |
| **Audit Controls (§164.312(b))** | Text-file logging | Implement immutable, structured audit logs |
| **Access Controls (§164.312(a)(1))** | App-layer RBAC only | Add DB-level RLS, enforce least privilege |
| **Transmission Security (§164.312(e)(1))** | No HSTS, no SSL redirect | Enforce TLS everywhere |
| **BAA** | No Business Associate Agreements | Execute BAAs with all subprocessors (AWS, Anthropic) |
| **Risk Analysis (§164.308(a)(1))** | No documented risk assessment | Conduct formal risk analysis |
| **Contingency Plan (§164.308(a)(7))** | No disaster recovery plan | Create and test DR/backup procedures |
| **Workforce Training (§164.308(a)(5))** | No security training program | Implement annual HIPAA training |

---

### 10. PCI DSS (Payment Card Data)

| | Details |
|---|---|
| **What it is** | Required if you process, store, or transmit credit card data. Most SaaS companies avoid PCI scope by using Stripe/payment processors. |
| **Cost** | $15,000 – $200,000+ depending on scope |
| | — SAQ-A (simplest): $15,000 – $25,000 |
| | — SAQ-D (complex): $30,000 – $50,000 |
| | — Full QSA audit: $50,000 – $200,000+ |
| **Timeline** | 3 – 12 months |
| **Validity** | Annual revalidation |

**Assessment:** If Coco TestAI does not directly handle payment card data (uses Stripe, etc.), PCI DSS scope can be minimized to SAQ-A (simplest level) or potentially avoided entirely. This should be the lowest priority unless you plan to handle card data directly.

**Decision tree:**
```
Do you store, process, or transmit card data?
├── No → Use Stripe/similar → SAQ-A (~$15K) or not needed
├── Redirect only → SAQ-A ($15K - $25K)
├── Embedded form (Stripe Elements) → SAQ-A-EP ($20K - $35K)
└── Direct card handling → Full PCI DSS ($50K - $200K+)
```

---

## Recommended Certification Sequence

Based on the current codebase state, published security claims, and typical B2B SaaS customer requirements:

```
Phase 1 (Months 1-2): Foundation                        Budget: $5K – $20K
├── Fix critical code issues from audit (items 1-10)
├── security.txt + Vulnerability Disclosure Policy
├── CSA STAR Level 1 (self-assessment)
└── OWASP Penetration Test

Phase 2 (Months 2-5): Core Certifications               Budget: $30K – $60K
├── Select compliance platform (Sprinto / Vanta / Drata)
├── Write security policies (9 documents)
├── SOC 2 Type I
└── GDPR compliance program

Phase 3 (Months 5-12): Observation + International       Budget: $30K – $70K
├── SOC 2 Type II observation period begins
├── ISO 27001 implementation + certification
└── CSA STAR Level 2 (after ISO 27001)

Phase 4 (Months 12+): Industry-Specific (if needed)      Budget: $30K – $150K+
├── SOC 2 Type II audit
├── HIPAA (if healthcare customers)
└── PCI DSS (if handling card data)
```

**Visual timeline:**

```
Month:  1    2    3    4    5    6    7    8    9    10   11   12
        ├────┤
        Code Fixes + security.txt + CSA STAR L1 + Pen Test
             ├──────────────────┤
             SOC 2 Type I
             ├──────────┤
             GDPR Compliance
                              ├────────────────────────────────┤
                              SOC 2 Type II Observation Period
                                   ├──────────────────────┤
                                   ISO 27001
                                                          ├────┤
                                                          CSA STAR L2
```

---

## Compliance Automation Platform Comparison

A compliance platform dramatically reduces the effort needed for SOC 2, ISO 27001, and other certifications by automating evidence collection, monitoring controls, and managing auditor workflows.

| Platform | Annual Cost | Best For | Frameworks | Key Integrations |
|----------|------------|----------|------------|------------------|
| [Sprinto](https://sprinto.com) | ~$4,000+ | Budget-conscious startups | SOC 2, ISO 27001, GDPR, HIPAA, PCI DSS | AWS, GitHub, Slack, Jira, Google Workspace |
| [Vanta](https://vanta.com) | ~$7,500+ | Quick setup, startup-friendly | SOC 2, ISO 27001, GDPR, HIPAA, PCI DSS, CSA STAR | AWS, GitHub, Google Workspace, Okta, Datadog |
| [Drata](https://drata.com) | ~$15,000+ | Engineering-heavy teams, CI/CD | SOC 2, ISO 27001, GDPR, HIPAA, PCI DSS, CSA STAR | AWS, GitHub, CI/CD pipelines, Datadog, Jira |
| [ComplyJet](https://complyjet.com) | Custom | Multi-framework efficiency | SOC 2, ISO 27001, GDPR | AWS, various |

**Recommendation for Coco TestAI:** Start with **Sprinto** or **Vanta** for cost efficiency. Both support all the frameworks you need and can automate evidence collection from AWS, GitHub, and your Django backend. Upgrade to Drata if you need deeper CI/CD integration later.

### What compliance platforms automate

| Manual Task | Automated By Platform |
|-------------|----------------------|
| Collecting evidence (screenshots, configs) | Continuous monitoring via API integrations |
| Tracking employee onboarding/offboarding | HR system integration |
| Monitoring access reviews | Automatic access inventory |
| Vulnerability scanning | Integration with Snyk, Dependabot |
| Policy version control | Built-in policy editor with versioning |
| Auditor communication | Built-in auditor portal |
| Control gap tracking | Dashboard with real-time status |

---

## Cost Summary

### By Phase

| Phase | Timeline | Cost Range |
|-------|----------|-----------|
| Phase 1: Foundation | Months 1-2 | $5,000 – $20,000 |
| Phase 2: Core Certifications | Months 2-5 | $30,000 – $60,000 |
| Phase 3: Observation + International | Months 5-12 | $30,000 – $70,000 |
| **Phases 1-3 Total** | **12 months** | **$65,000 – $150,000** |
| Phase 4: Industry-Specific | Months 12+ | $30,000 – $150,000+ |

### Annual Recurring Costs (After Year 1)

| Item | Annual Cost |
|------|------------|
| Compliance platform | $4,000 – $15,000 |
| SOC 2 Type II audit | $15,000 – $50,000 |
| ISO 27001 surveillance audit | $5,000 – $10,000 |
| Penetration testing | $5,000 – $15,000 |
| External DPO (GDPR) | $5,000 – $15,000 |
| **Total recurring** | **$34,000 – $105,000/yr** |

### Internal Resource Requirements

| Phase | Hours | Key Roles |
|-------|-------|-----------|
| Code fixes | 80 – 160 hours | Engineering |
| Policy writing | 60 – 120 hours | Security lead, Legal |
| SOC 2 Type I prep | 100 – 200 hours | Engineering, Security, Ops |
| GDPR implementation | 80 – 150 hours | Legal, Engineering, Product |
| ISO 27001 ISMS | 200 – 400 hours | Security lead, Engineering, Management |
| **Total (Year 1)** | **520 – 1,030 hours** | Cross-functional |

---

## Sources

- [SOC 2 Certification Cost 2026 — Bright Defense](https://www.brightdefense.com/resources/soc-2-certification-cost/)
- [SOC 2 Compliance Cost 2025 — Sprinto](https://sprinto.com/blog/soc-2-compliance-cost/)
- [SOC 2 Audit Cost — Thoropass](https://www.thoropass.com/blog/soc-2-audit-cost-a-guide)
- [ISO 27001 Certification Cost 2025 — Sprinto](https://sprinto.com/blog/iso-27001-certification-cost/)
- [ISO 27001 Certification Cost 2026 — Scytale](https://scytale.ai/resources/iso-27001-certification-costs/)
- [GDPR Compliance Cost 2025 — Sprinto](https://sprinto.com/blog/gdpr-compliance-cost/)
- [GDPR Compliance Checklist for B2B SaaS — ComplyDog](https://complydog.com/blog/gdpr-compliance-checklist-complete-guide-b2b-saas-companies)
- [CSA STAR Program — Cloud Security Alliance](https://cloudsecurityalliance.org/star/)
- [Penetration Testing Cost 2025 — Software Secured](https://www.softwaresecured.com/post/penetration-testing-cost)
- [SaaS Security Certifications 2025 — Neumetric](https://www.neumetric.com/journal/saas-security-certifications-for-organizations/)
- [Vanta Pricing — Sprinto](https://sprinto.com/blog/vanta-pricing/)
- [Drata Pricing 2025 — Spendflo](https://www.spendflo.com/blog/drata-pricing-the-ultimate-guide-to-costs-and-savings)
- [SOC 2 vs ISO 27001 — Secureframe](https://secureframe.com/blog/soc-2-vs-iso-27001)
- [OWASP ASVS — OWASP Foundation](https://owasp.org/www-project-application-security-verification-standard/)
- [CISA SBOM Guidance 2025](https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom)

---

*Document generated on February 5, 2026. Costs and timelines are estimates based on industry data and should be validated with vendors for your specific scope.*
