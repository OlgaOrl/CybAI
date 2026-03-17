# Cyber Standards & Compliance

## Applicable Laws and Standards for CybAI

---

## 1. KüTS — Küberturvalisuse seadus (Estonian Cybersecurity Act)

**Source:** https://www.riigiteataja.ee/akt/KüTS

### Key Definitions
- **Cybersecurity** — capacity to withstand events threatening network/information system security while maintaining availability, authenticity, integrity, and confidentiality
- **Cyberincident** — any event in a network/information system that threatens or damages system security
- **Critical Impact Incident** — incident affecting service continuity beyond maximum permitted downtime or causing significant harm

### Mandatory Requirements (§ 7)
- Implement continuous, appropriate, and proportionate **technical, operational, and organizational** security measures
- Manage risks threatening system security in service delivery
- Prevent or minimize incident impact on service recipients
- Prevent, detect, and resolve cyberincidents
- Measures must consider current **European/international standards** and implementation costs

### Incident Reporting (§ 8)
| Deadline | Action |
|----------|--------|
| 24 hours | Initial notification of significant incident |
| 72 hours | Detailed incident report |
| 1 month  | Final report after resolution |

### Board Responsibilities (§ 61)
- Approve and monitor security measure implementation
- Accept accountability for compliance
- Obtain regular training on risk management

### Penalties
| Entity Type | Max Fine |
|-------------|----------|
| Critical Infrastructure | €10,000,000 or 2% global revenue |
| Essential Service Providers | €4,000,000 or 1% global revenue |
| Other | €3,200,000 (legal entities) |

### Developer Checklist (KüTS)
- [ ] Risk analysis documented for all system components
- [ ] 24-hour incident detection and reporting capability implemented
- [ ] Security controls aligned with European/international standards
- [ ] Logging sufficient for incident investigation
- [ ] Responsibility chains documented for outsourced components
- [ ] Voluntary vulnerability reporting mechanism in place

---

## 2. E-ITS — Eesti Infoturbestandard (Estonian Information Security Standard)

**Source:** https://www.ria.ee/kuberturvalisus/riigi-infoturbe-meetmete-haldus/eesti-infoturbestandard-e-its
**Portal:** https://eits.ria.ee/

### Overview
- Estonia's localized information security framework aligned with **ISO/IEC 27001**
- Based on German **BSI IT-Grundschutz** system
- Mandatory for all organizations performing public tasks
- Available for private companies seeking security improvements

### Core Components
1. **Etalonturve (Benchmark Protection)** — baseline security implementations, standard modules
2. **Tugirakendus (Support Application)** — web-based tool for protection requirements and implementation plans

### Key Principles
- Systematic, comprehensive threat coverage
- Cost-effective implementation through standardized approaches
- Regular annual updates (autumn)
- Maps protected objects/processes to standard security modules

### Developer Checklist (E-ITS)
- [ ] Assets (services, systems, components, data) catalogued and assigned criticality
- [ ] Business processes documented with stakeholders, inputs, outputs, systems
- [ ] Risk scenarios created from assets and vulnerabilities
- [ ] Security controls documented with objectives, scope, responsibility
- [ ] Evidence collection for audits implemented
- [ ] Role-based access controlling visibility and authority

---

## 3. Current Threat Landscape (RIA Weekly Report, Week 10/2026)

**Source:** https://www.ria.ee/blogi/olulisemad-turvanorkused-2026-aasta-10-nadalal-android-chrome-cisco-jt

### Critical Vulnerabilities to Track

| CVE | Product | CVSS | Type |
|-----|---------|------|------|
| CVE-2026-20131 | Cisco Secure Firewall | 10.0 | Remote Code Execution |
| CVE-2026-27944 | Nginx | 9.8 | Unauthenticated backup download |
| D-Link DIR-513 (3x) | D-Link Router | 9.8 | Stack buffer overflow |
| CVE-2026-28536 | Huawei | 9.6 | Authentication bypass |
| CVE-2026-3537/3538/3539 | Chrome | 8.8 | Memory corruption |
| CVE-2026-21385 | Android/Qualcomm | 7.8 | Memory corruption zero-day |

### CISA Actively Exploited
- 7 vulnerabilities added to Known Exploited Vulnerabilities catalog (Apple, Rockwell, Hikvision)

### Relevance to CybAI
- Scanner module must detect these vulnerability types (open ports, outdated firmware, missing patches)
- CVSS scoring in analyzer must align with NVD/CISA data
- Threat intelligence feed integration should be considered

---

## 4. CybSIS — Reference Architecture for ISMS Platform

**Source:** https://raulwalter.com/service/cybsis/

### Architecture Components (reference for CybAI)
1. **Asset Management** — centralized inventory with criticality and relationships
2. **Business Process Mapping** — workflows connected to infrastructure
3. **Risk Management** — E-ITS risk analysis methodology, dynamic risk register
4. **Security Controls** — documented controls with verification schedules
5. **IMR (Implementation Roadmap)** — time-bound action plan for controls
6. **Audit View** — real-time compliance dashboard, gap identification
7. **Documentation & Evidence** — centralized, version-controlled, linked to controls

### Integrations (reference)
- Estonian ID-Card authentication
- Active Directory sync
- Jira Cloud for task management

### Relevance to CybAI
- CybAI scanner results should map to E-ITS security modules
- Risk analysis output should support audit evidence requirements
- Dashboard should show compliance status aligned with E-ITS requirements

---

## 5. Cross-Cutting Requirements for CybAI Development

### Data Protection
- No PII in logs (KüTS, GDPR)
- All scan results and vulnerability data encrypted at rest and in transit
- Access control on all API endpoints
- Audit trail for all security-relevant actions

### API Security
- Input validation on all endpoints (OWASP Top 10)
- Parameterized queries (SQL injection prevention)
- CORS restricted to known origins
- Rate limiting on scan endpoints
- Authentication required for all non-public endpoints

### Vulnerability Scanning Compliance
- CVSS scoring must follow CVSS v3.1/v4.0 specification
- CVE identifiers must reference official NVD database
- Scan results must include: id, type, title, description, severity, location, found_at
- Results must be reproducible and auditable

### Incident Response
- System must support 24-hour incident detection (KüTS § 8)
- Critical findings must trigger automated notifications
- All incidents must be loggable with structured JSON format
- trace_id for request tracing across services

### AI-Specific (EU AI Act considerations)
- AI risk analysis must be transparent (explainable recommendations)
- Demo mode must be clearly distinguishable from real analysis
- AI outputs must include confidence indicators
- Human oversight required for critical security decisions
