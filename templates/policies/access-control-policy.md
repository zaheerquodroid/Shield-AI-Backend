# Access Control Policy

**Organization:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Last Reviewed:** {{REVIEW_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Contact:** {{SECURITY_CONTACT}}
**Classification:** Internal

---

## 1. Purpose

This policy defines the access control requirements for {{COMPANY_NAME}} information systems and data. It establishes standards for authentication, authorization, and account management to ensure only authorized individuals can access resources.

## 2. Scope

This policy applies to all information systems, applications, databases, and infrastructure components managed by {{COMPANY_NAME}}, and to all personnel who require access to these resources.

## 3. Access Control Principles

### 3.1 Least Privilege

Users shall be granted the minimum level of access necessary to perform their job functions. Excessive permissions shall be promptly removed.

### 3.2 Separation of Duties

Critical functions shall be divided among multiple individuals to prevent fraud and error. No single person shall control all aspects of a critical process.

### 3.3 Need-to-Know

Access to information shall be restricted to individuals who require it for legitimate business purposes.

## 4. Authentication Requirements

### 4.1 Password Standards

- Minimum 14 characters
- Complexity requirements: uppercase, lowercase, numbers, and special characters
- Password history: last 12 passwords may not be reused
- Maximum password age: 90 days for standard accounts
- Account lockout after 5 failed attempts for 30 minutes

### 4.2 Multi-Factor Authentication (MFA)

MFA is required for:

- All production system access
- VPN and remote access connections
- Administrative and privileged accounts
- Cloud management consoles
- Source code repositories
- Email and collaboration platforms

Acceptable MFA methods:

- Hardware security keys (FIDO2/WebAuthn) — preferred
- Time-based one-time passwords (TOTP) via authenticator apps
- Push notifications from approved authenticator apps

SMS-based MFA is not permitted for privileged accounts.

### 4.3 Service Accounts

- Service accounts shall use API keys, certificates, or OAuth tokens
- Shared passwords for service accounts are prohibited
- Service account credentials shall be rotated at least every 90 days
- Service accounts shall be scoped to minimum required permissions

## 5. Authorization and Role Definitions

### 5.1 Role-Based Access Control (RBAC)

Access shall be granted through predefined roles aligned with job functions:

| Role | Description | Approval Required |
|------|-------------|-------------------|
| Read-Only | View access to non-sensitive data | Manager |
| Standard User | Day-to-day operational access | Manager |
| Power User | Extended access for technical roles | Manager + Security |
| Administrator | Full system administration | Director + Security |
| Super Admin | Infrastructure and security controls | CISO or {{POLICY_OWNER}} |

### 5.2 Privileged Access Management

- Privileged access granted through just-in-time (JIT) provisioning
- Maximum session duration of 8 hours for privileged sessions
- All privileged actions logged and monitored
- Privileged access reviewed monthly

## 6. Account Lifecycle Management

### 6.1 Provisioning

- Access requests submitted through approved ticketing system
- Approval required from direct manager and resource owner
- Identity verification completed before account creation
- Access provisioned within 2 business days of approval

### 6.2 Modification

- Role changes require new access request and approval
- Job transfers trigger access review within 5 business days
- Temporary elevated access requires documented justification and expiration date

### 6.3 Deprovisioning

- Access disabled within 4 hours of termination notification
- Account fully removed within 30 days of termination
- Voluntary departures: access disabled on last working day
- Involuntary departures: access disabled immediately upon notification
- All access tokens and credentials revoked upon deprovisioning

## 7. Access Reviews

### 7.1 Periodic Reviews

- Standard access: reviewed quarterly
- Privileged access: reviewed monthly
- Service accounts: reviewed quarterly
- Third-party access: reviewed monthly

### 7.2 Review Process

- Resource owners validate continued need for access
- Identified excess permissions removed within 5 business days
- Review completion documented and retained for audit

## 8. Remote Access

- Remote access requires VPN or zero-trust network access
- Company-managed devices required for accessing sensitive systems
- Split-tunneling prohibited on VPN connections to production networks
- Session timeouts enforced: 15 minutes inactivity for sensitive systems

## 9. Third-Party Access

- Third-party access requires signed NDA and security assessment
- Access scoped to specific systems and time-limited
- Dedicated accounts for each third-party individual (no shared accounts)
- Third-party access monitored and logged separately

## 10. Compliance and Monitoring

- Access control events logged to centralized SIEM
- Failed authentication attempts monitored and alerted
- Anomalous access patterns investigated by security team
- Compliance reports generated monthly for {{POLICY_OWNER}}

## 11. Exceptions

Exceptions to this policy require written approval from {{POLICY_OWNER}} with documented business justification, compensating controls, and expiration date. All exceptions are reviewed quarterly.

## 12. Review

This policy shall be reviewed at least annually. Next scheduled review: {{REVIEW_DATE}}.

---

*Approved by: {{POLICY_OWNER}}*
*Date: {{EFFECTIVE_DATE}}*
