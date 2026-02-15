# Incident Response Plan

**Organization:** {{COMPANY_NAME}}
**Effective Date:** {{EFFECTIVE_DATE}}
**Last Reviewed:** {{REVIEW_DATE}}
**Policy Owner:** {{POLICY_OWNER}}
**Contact:** {{SECURITY_CONTACT}}
**Classification:** Internal

---

## 1. Purpose

This plan establishes procedures for detecting, responding to, and recovering from security incidents at {{COMPANY_NAME}}. It defines roles, communication protocols, and escalation procedures to minimize the impact of security events.

## 2. Scope

This plan covers all security incidents affecting {{COMPANY_NAME}} information systems, data, personnel, and facilities, including but not limited to:

- Unauthorized access or data breaches
- Malware infections and ransomware
- Denial of service attacks
- Insider threats
- Physical security breaches
- Supply chain compromises

## 3. Incident Severity Levels

| Level | Description | Response Time | Example |
|-------|-------------|---------------|---------|
| Critical (P1) | Active data breach, ransomware, complete service outage | 15 minutes | Confirmed exfiltration of customer data |
| High (P2) | Compromised credentials, targeted attack, partial outage | 1 hour | Privileged account compromise |
| Medium (P3) | Malware detection, policy violation, vulnerability exploitation | 4 hours | Malware on single endpoint |
| Low (P4) | Suspicious activity, failed attacks, minor policy violation | 24 hours | Brute-force login attempts |

## 4. Incident Response Team

### 4.1 Core Team

| Role | Responsibility |
|------|---------------|
| Incident Commander | Coordinates response, makes decisions, manages communications |
| Security Lead ({{SECURITY_CONTACT}}) | Technical analysis, containment, and eradication |
| Communications Lead | Internal and external communications, regulatory notification |
| Legal Counsel | Legal obligations, regulatory compliance, law enforcement liaison |
| {{POLICY_OWNER}} | Executive oversight, resource authorization, stakeholder management |

### 4.2 Extended Team (as needed)

- Infrastructure engineers for system containment and recovery
- Application developers for code-level analysis
- HR for insider threat incidents
- External forensics firm (pre-contracted)
- Public relations for media management

## 5. Incident Response Phases

### 5.1 Phase 1: Detection and Identification

**Sources of Detection:**

- SIEM alerts and correlation rules
- Endpoint detection and response (EDR) alerts
- Intrusion detection/prevention system (IDS/IPS) alerts
- Employee reports via {{SECURITY_CONTACT}}
- Threat intelligence feeds
- Customer reports
- Automated vulnerability scanning

**Initial Triage:**

1. Verify the alert is a true positive
2. Assign severity level (P1-P4)
3. Document initial findings in incident tracking system
4. Notify Incident Commander if P1 or P2
5. Begin evidence preservation

### 5.2 Phase 2: Containment

**Short-Term Containment (immediate):**

- Isolate affected systems from network
- Block malicious IP addresses and domains
- Disable compromised accounts
- Implement emergency firewall rules
- Preserve forensic evidence before any changes

**Long-Term Containment (hours to days):**

- Deploy temporary fixes to prevent spread
- Redirect traffic through additional monitoring
- Implement enhanced logging on related systems
- Coordinate with cloud providers if applicable

### 5.3 Phase 3: Eradication

- Remove malware and attacker tooling
- Patch exploited vulnerabilities
- Reset compromised credentials and tokens
- Review and remediate configuration weaknesses
- Verify attacker persistence mechanisms are eliminated
- Scan related systems for indicators of compromise (IOCs)

### 5.4 Phase 4: Recovery

- Restore systems from verified clean backups
- Gradually reintroduce systems to production
- Monitor recovered systems for signs of reinfection
- Validate data integrity
- Confirm normal service operation
- Remove temporary containment measures

### 5.5 Phase 5: Post-Incident Review

- Conduct post-incident review within 5 business days
- Document timeline, root cause, and actions taken
- Identify lessons learned and improvement opportunities
- Update runbooks and detection rules
- Track remediation actions to completion

## 6. Communication Procedures

### 6.1 Internal Communication

- Incident channel created in secure messaging platform
- Status updates every 2 hours during active P1/P2 incidents
- Daily updates during P3 incidents
- All communications marked with appropriate classification

### 6.2 External Communication

- **Customers:** Notified within 72 hours of confirmed data breach (GDPR Article 33)
- **Regulators:** Supervisory authority notified within 72 hours if personal data involved
- **Law enforcement:** Contacted when criminal activity suspected (after legal review)
- **Media:** All media inquiries directed to Communications Lead

### 6.3 Regulatory Notification Requirements

| Regulation | Notification Deadline | Authority |
|------------|----------------------|-----------|
| GDPR | 72 hours | Supervisory Authority |
| SOC 2 | Per client contract | Clients and auditors |
| State breach laws | Varies (30-90 days) | State Attorney General |

## 7. Evidence Handling

- Chain of custody documented for all evidence
- Forensic images created before system modification
- Evidence stored in encrypted, access-controlled storage
- Logs preserved beyond normal retention during investigation
- Write-blockers used for physical media analysis

## 8. Incident Classification and Reporting

### 8.1 Metrics Tracked

- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Mean time to contain (MTTC)
- Number of incidents by severity and type
- Root cause categories

### 8.2 Reporting

- Monthly incident summary to {{POLICY_OWNER}}
- Quarterly trend analysis to executive leadership
- Annual incident response maturity assessment

## 9. Training and Exercises

- Tabletop exercises conducted quarterly
- Full simulation exercises conducted annually
- New team members trained within 30 days of joining
- Plan reviewed and updated after every P1/P2 incident

## 10. Review

This plan shall be reviewed at least annually or after any P1/P2 incident. Next scheduled review: {{REVIEW_DATE}}.

---

*Approved by: {{POLICY_OWNER}}*
*Date: {{EFFECTIVE_DATE}}*
