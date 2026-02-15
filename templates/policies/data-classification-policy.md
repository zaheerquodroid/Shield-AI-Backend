# Data Classification Policy

**Organization:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Last Reviewed:** {{REVIEW_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Contact:** {{SECURITY_CONTACT}}
**Classification:** Internal

---

## 1. Purpose

This policy establishes a data classification framework for {{COMPANY_NAME}} to ensure information is protected according to its sensitivity and value. Proper classification enables appropriate handling, storage, and disposal of data throughout its lifecycle.

## 2. Scope

This policy applies to all data created, collected, processed, stored, or transmitted by {{COMPANY_NAME}}, regardless of format (digital, paper, verbal) or location (on-premises, cloud, third-party).

## 3. Classification Levels

### 3.1 Public

**Definition:** Information intended for public disclosure or whose release would cause no harm to {{COMPANY_NAME}}.

**Examples:**
- Marketing materials and press releases
- Published product documentation
- Public job postings
- Open-source code contributions

**Handling Requirements:**
- No special handling required
- May be shared freely
- No encryption requirement for storage or transit

### 3.2 Internal

**Definition:** Information intended for use within {{COMPANY_NAME}} that is not meant for public disclosure.

**Examples:**
- Internal policies and procedures
- Meeting notes and project plans
- Internal communications
- Non-sensitive business reports

**Handling Requirements:**
- Access limited to {{COMPANY_NAME}} personnel
- Encryption in transit required (TLS 1.2+)
- Standard access controls applied
- Secure disposal when no longer needed

### 3.3 Confidential

**Definition:** Sensitive business information whose unauthorized disclosure could cause significant harm to {{COMPANY_NAME}} or its customers.

**Examples:**
- Customer data and contracts
- Financial records and forecasts
- Source code and proprietary algorithms
- Security configurations and architecture documents
- Employee personal information

**Handling Requirements:**
- Access restricted to authorized individuals with business need
- Encryption at rest and in transit required
- Multi-factor authentication for access
- Logging of all access events
- Secure deletion with verification
- No storage on personal devices without approval

### 3.4 Restricted

**Definition:** Highly sensitive information whose unauthorized disclosure could cause severe harm, legal liability, or regulatory violation.

**Examples:**
- Credentials, API keys, and cryptographic keys
- Customer payment card data (PCI DSS scope)
- Protected health information (PHI)
- Personally identifiable information (PII) subject to GDPR
- Security incident details and vulnerability reports
- Penetration test results

**Handling Requirements:**
- Access on strict need-to-know basis with explicit authorization
- Encryption at rest (AES-256) and in transit (TLS 1.3)
- MFA and privileged access management required
- All access logged and monitored in real-time
- No storage in email, chat, or unencrypted media
- Cryptographic deletion or physical destruction
- Data residency requirements enforced

## 4. Classification Responsibilities

### 4.1 Data Owners

- Assign classification level at data creation
- Review classifications annually
- Approve access requests for Confidential and Restricted data
- Ensure downstream recipients understand handling requirements

### 4.2 Data Custodians

- Implement technical controls matching classification level
- Monitor access and report anomalies
- Ensure backup and recovery procedures match classification
- Apply secure disposal procedures

### 4.3 All Personnel

- Handle data according to its classification label
- Report misclassified or improperly handled data to {{SECURITY_CONTACT}}
- Do not downgrade classification without Data Owner approval
- Apply the highest classification when data sources are combined

## 5. Labeling Requirements

| Classification | Digital Labeling | Physical Labeling |
|---------------|------------------|-------------------|
| Public | None required | None required |
| Internal | Header or metadata tag | "INTERNAL" stamp |
| Confidential | Header, metadata, and file properties | "CONFIDENTIAL" stamp on each page |
| Restricted | Header, metadata, DRM where feasible | "RESTRICTED" stamp, numbered copies |

## 6. Data Handling Matrix

| Action | Public | Internal | Confidential | Restricted |
|--------|--------|----------|--------------|------------|
| Email (internal) | Allowed | Allowed | Encrypted | Prohibited |
| Email (external) | Allowed | With caution | Encrypted + approved | Prohibited |
| Cloud storage | Allowed | Approved services | Approved + encrypted | Approved + encrypted + DLP |
| Printing | Allowed | Allowed | Supervised | Prohibited without approval |
| Mobile devices | Allowed | MDM required | MDM + encryption | Prohibited |
| Removable media | Allowed | Encrypted | Encrypted + approved | Prohibited |
| Verbal discussion | Allowed | Private setting | Private setting + NDA | Secure room only |

## 7. Data Lifecycle

### 7.1 Creation

- Classify data at time of creation
- Apply appropriate labels and controls
- Register in data inventory if Confidential or Restricted

### 7.2 Storage

- Use approved storage locations matching classification
- Encrypt according to classification requirements
- Maintain access controls and audit logs

### 7.3 Transmission

- Use encrypted channels appropriate to classification
- Verify recipient authorization before sharing
- Use secure file transfer mechanisms for Confidential and Restricted data

### 7.4 Disposal

- Follow data retention schedule for retention periods
- Use secure deletion methods appropriate to classification
- Document disposal of Confidential and Restricted data
- Obtain Data Owner approval before disposal

## 8. Exceptions

Exceptions require written approval from {{POLICY_OWNER}} with documented justification and compensating controls.

## 9. Review

This policy shall be reviewed at least annually. Next scheduled review: {{REVIEW_DATE}}.

---

*Approved by: {{POLICY_OWNER}}*
*Date: {{EFFECTIVE_DATE}}*
