# Data Retention Schedule

**Organization:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Last Reviewed:** {{REVIEW_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Contact:** {{SECURITY_CONTACT}}
**Classification:** Internal

---

## 1. Purpose

This schedule defines the retention periods for data categories at {{COMPANY_NAME}}. It ensures compliance with regulatory requirements, supports business operations, and minimizes risk by disposing of data that is no longer needed.

## 2. Scope

This schedule applies to all data created, collected, processed, or stored by {{COMPANY_NAME}}, regardless of format or storage location.

## 3. Retention Principles

- **Minimize:** Retain only what is necessary for business or legal purposes
- **Classify:** Apply retention based on data classification and regulatory requirements
- **Automate:** Use automated deletion where feasible
- **Document:** Record disposal actions for Confidential and Restricted data
- **Legal Hold:** Suspend deletion when litigation or investigation is anticipated

## 4. Retention Schedule

### 4.1 Business Records

| Data Category | Retention Period | Legal Basis | Disposal Method |
|--------------|-----------------|-------------|-----------------|
| Financial records and tax documents | 7 years | Tax regulations | Secure deletion |
| Contracts and agreements | Duration + 6 years | Statute of limitations | Secure deletion |
| Corporate governance records | Permanent | Corporate law | N/A |
| Insurance policies | Duration + 7 years | Claims period | Secure deletion |
| Business correspondence | 3 years | Business need | Standard deletion |

### 4.2 Customer Data

| Data Category | Retention Period | Legal Basis | Disposal Method |
|--------------|-----------------|-------------|-----------------|
| Customer account data | Duration of service + 1 year | Contract | Cryptographic deletion |
| Customer transaction logs | 3 years | SOC 2 / business need | Secure deletion |
| Customer support records | 2 years | Business need | Standard deletion |
| Customer PII (GDPR scope) | Duration of consent/contract | GDPR Art. 5(1)(e) | Cryptographic deletion |
| Payment card data | Per PCI DSS requirements | PCI DSS | Cryptographic deletion |

### 4.3 Security and Audit Data

| Data Category | Retention Period | Legal Basis | Disposal Method |
|--------------|-----------------|-------------|-----------------|
| Security audit logs | 1 year (minimum) | SOC 2 / ISO 27001 | Automated deletion |
| Access control logs | 1 year | SOC 2 CC6.1 | Automated deletion |
| Incident response records | 3 years | Compliance / legal | Secure deletion |
| Vulnerability scan results | 1 year | SOC 2 CC7.1 | Secure deletion |
| Penetration test reports | 3 years | Compliance | Secure deletion |
| SIEM data | 90 days (hot) + 1 year (cold) | Operational | Automated deletion |

### 4.4 Employee Data

| Data Category | Retention Period | Legal Basis | Disposal Method |
|--------------|-----------------|-------------|-----------------|
| Employment records | Duration + 7 years | Employment law | Secure deletion |
| Payroll records | 7 years | Tax regulations | Secure deletion |
| Background check results | Duration of employment | Business need | Secure deletion |
| Training records | Duration + 3 years | Compliance | Standard deletion |
| Recruitment records (hired) | Duration + 1 year | Employment law | Standard deletion |
| Recruitment records (not hired) | 6 months | GDPR / EEOC | Secure deletion |

### 4.5 Technical Data

| Data Category | Retention Period | Legal Basis | Disposal Method |
|--------------|-----------------|-------------|-----------------|
| Application logs | 90 days | Operational | Automated deletion |
| Infrastructure metrics | 13 months | Operational | Automated deletion |
| Backup data | 30 days (incremental) / 1 year (monthly) | Business continuity | Automated rotation |
| Source code | Permanent (in VCS) | Business asset | N/A |
| Configuration data | Permanent (in VCS) | Business continuity | N/A |
| CI/CD build artifacts | 90 days | Operational | Automated deletion |
| SBOM records | 3 years | Supply chain compliance | Secure deletion |

## 5. Disposal Methods

### 5.1 Standard Deletion

- File system deletion with overwrite
- Suitable for Public and Internal classified data
- No verification required

### 5.2 Secure Deletion

- Multi-pass overwrite (NIST 800-88 compliant) or cryptographic erasure
- Suitable for Confidential data
- Disposal documented in disposal log

### 5.3 Cryptographic Deletion

- Destruction of encryption keys rendering data irrecoverable
- Required for Restricted data and GDPR erasure requests
- Certificate of destruction generated
- Disposal documented and retained for 3 years

### 5.4 Physical Destruction

- Shredding (NAID AAA certified) for physical media
- Degaussing for magnetic media
- Certificate of destruction required
- Witnessed destruction for Restricted data

## 6. Legal Hold

### 6.1 Hold Process

When litigation, investigation, or regulatory action is anticipated:

1. Legal counsel issues written legal hold notice
2. Automated deletion suspended for in-scope data
3. Data owners notified of preservation obligations
4. Hold tracked in legal hold register
5. Hold released only by written authorization from legal counsel

### 6.2 Hold Scope

Legal holds override all retention schedules. Data subject to hold must be preserved regardless of normal retention period expiration.

## 7. Data Subject Rights (GDPR)

### 7.1 Right to Erasure

- Erasure requests processed within 30 days
- Data deleted from all systems including backups (within backup rotation cycle)
- Erasure confirmed in writing to data subject
- Exceptions: legal obligation, public interest, legal claims

### 7.2 Data Portability

- Export of personal data provided in machine-readable format
- Processed within 30 days of request

## 8. Responsibilities

### 8.1 Data Owners

- Ensure data within their domain follows this retention schedule
- Authorize disposal of Confidential and Restricted data
- Report data that may require legal hold

### 8.2 IT/Security Team ({{SECURITY_CONTACT}})

- Implement automated retention and deletion mechanisms
- Maintain disposal logs and certificates of destruction
- Monitor compliance with retention schedules

### 8.3 {{POLICY_OWNER}}

- Approve exceptions to retention schedule
- Coordinate with legal counsel on hold requirements
- Ensure regulatory changes reflected in schedule

## 9. Compliance

This schedule supports compliance with:

- SOC 2 CC6.5 (Data Disposal)
- ISO 27001 A.8.3 (Media Handling)
- GDPR Article 5(1)(e) (Storage Limitation)
- GDPR Article 17 (Right to Erasure)

## 10. Review

This schedule shall be reviewed at least annually or when regulatory requirements change. Next scheduled review: {{REVIEW_DATE}}.

---

*Approved by: {{POLICY_OWNER}}*
*Date: {{EFFECTIVE_DATE}}*
