# Vendor Management Policy

**Organization:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Last Reviewed:** {{REVIEW_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Contact:** {{SECURITY_CONTACT}}
**Classification:** Internal

---

## 1. Purpose

This policy establishes the requirements for assessing, onboarding, and managing third-party vendors at {{COMPANY_NAME}}. It ensures that vendors handling {{COMPANY_NAME}} data or integrating with its systems meet appropriate security standards.

## 2. Scope

This policy applies to all third-party relationships where the vendor:

- Accesses, processes, stores, or transmits {{COMPANY_NAME}} or customer data
- Integrates with {{COMPANY_NAME}} systems or infrastructure
- Provides software, platform, or infrastructure services
- Has physical access to {{COMPANY_NAME}} facilities

## 3. Vendor Classification

### 3.1 Risk Tiers

| Tier | Criteria | Assessment Frequency |
|------|----------|---------------------|
| Critical | Access to Restricted/Confidential data, system admin access, single-source dependency | Annually + continuous monitoring |
| High | Access to Internal data, API integrations, cloud infrastructure | Annually |
| Medium | Limited data access, non-critical tools | Every 2 years |
| Low | No data access, no system integration | At onboarding only |

### 3.2 Classification Criteria

- Volume and sensitivity of data accessed
- Level of system access and integration depth
- Business criticality and replaceability
- Regulatory implications (GDPR sub-processor, etc.)

## 4. Vendor Assessment

### 4.1 Pre-Engagement Assessment

Before onboarding a Critical or High tier vendor:

1. **Security Questionnaire:** Complete vendor security assessment questionnaire
2. **Compliance Evidence:** Review SOC 2 Type II report, ISO 27001 certificate, or equivalent
3. **Penetration Test Results:** Review most recent penetration test summary
4. **Privacy Assessment:** Data processing agreement (DPA) review for GDPR compliance
5. **Business Continuity:** Review vendor BCP/DR capabilities
6. **Insurance:** Verify cyber liability insurance coverage

### 4.2 Assessment Criteria

| Domain | Requirements |
|--------|-------------|
| Access Control | MFA, RBAC, privileged access management |
| Encryption | Data encrypted at rest and in transit |
| Incident Response | Documented IR plan, notification SLA |
| Data Handling | Classification, retention, and disposal procedures |
| Personnel Security | Background checks, security training |
| Vulnerability Management | Regular scanning, patch management SLA |
| Business Continuity | DR plan, RTO/RPO defined, tested annually |

### 4.3 Risk Acceptance

- Identified risks documented in vendor risk register
- Compensating controls defined for unmet requirements
- Risk acceptance by {{POLICY_OWNER}} for Critical/High vendors
- Risk acceptance by department manager for Medium vendors

## 5. Contractual Requirements

### 5.1 Required Agreements

- Non-disclosure agreement (NDA)
- Data processing agreement (DPA) when processing personal data
- Service level agreement (SLA) with uptime and response commitments
- Right-to-audit clause for Critical and High tier vendors
- Security incident notification requirements (24-hour maximum for Critical vendors)

### 5.2 Security Clauses

All vendor contracts must include:

- Data handling and protection obligations
- Encryption requirements for data at rest and in transit
- Access control requirements (MFA, least privilege)
- Security incident notification timeline
- Data return and secure deletion upon contract termination
- Compliance with applicable regulations (GDPR, SOC 2, etc.)
- Subcontractor notification and approval requirements
- Liability and indemnification for security breaches

## 6. Ongoing Monitoring

### 6.1 Periodic Review

- Critical vendors: annual comprehensive review
- High vendors: annual review
- Medium vendors: biennial review
- All vendors: review upon significant changes (acquisition, breach, etc.)

### 6.2 Continuous Monitoring

For Critical vendors:

- Monitor vendor security advisories and breach notifications
- Track vendor compliance status (SOC 2 report renewal)
- Review vendor access logs quarterly
- Monitor vendor financial stability indicators

### 6.3 Performance Monitoring

- Track SLA compliance monthly
- Document and escalate recurring performance issues
- Review vendor incident response effectiveness
- Assess vendor responsiveness to security concerns

## 7. Vendor Access Management

- Dedicated vendor accounts (no shared credentials)
- Time-limited access with automatic expiration
- MFA required for all vendor remote access
- Access scoped to minimum necessary systems and data
- All vendor access logged and monitored
- VPN or secure access gateway for remote vendor access
- Access revoked within 24 hours of engagement end

## 8. Incident Management

### 8.1 Vendor Breach Notification

Vendors must notify {{COMPANY_NAME}} of security incidents:

| Vendor Tier | Notification Deadline |
|-------------|----------------------|
| Critical | Within 24 hours |
| High | Within 48 hours |
| Medium | Within 72 hours |

### 8.2 {{COMPANY_NAME}} Response

- Assess impact on {{COMPANY_NAME}} data and systems
- Coordinate incident response with vendor
- Determine regulatory notification obligations
- Document incident and vendor response quality

## 9. Vendor Offboarding

Upon contract termination or expiration:

1. Revoke all system access and credentials within 24 hours
2. Request confirmation of data deletion or return
3. Obtain certificate of data destruction for Confidential/Restricted data
4. Remove vendor integrations and API connections
5. Update vendor inventory and risk register
6. Conduct exit review for Critical vendors

## 10. Vendor Inventory

Maintain a current inventory of all vendors including:

- Vendor name, tier classification, and primary contact
- Services provided and data accessed
- Contract dates and renewal schedule
- Last assessment date and results
- Responsible {{COMPANY_NAME}} business owner

## 11. Review

This policy shall be reviewed at least annually. Next scheduled review: {{REVIEW_DATE}}.

---

*Approved by: {{POLICY_OWNER}}*
*Date: {{EFFECTIVE_DATE}}*
