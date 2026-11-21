# Security Incident Case Management System (SICMS Sentinel)
**Enterprise SOC & Digital Forensics Incident Response (DFIR) Platform**

> Developed for SOC Analysts, Incident Responders, SecOps Engineers, and Compliance Auditors to coordinate, investigate, contain, remediate, and audit reported security incidents with end-to-end traceability and accountability.

---

## 1. Project Overview & Architectural Pillars

**Theme:** Enterprise Security Incident Case Management  
**Core Purpose:** Centralize security event triage, investigation, evidence collection, and playbook remediation with cryptographic accountability.  
**Real-World Problem Solved:** Eliminates fragmented communications, unverified evidence handling, and missing audit trails across SOC teams by providing a centralized command console with verifiable ownership, tamper-evident audit logs, and automated containment actions.

### Traceability & Accountability Guarantee
Every security event registered in the platform enforces:
- **Unique Incident Identifiers:** Structured IDs (`INC-1001`, `INC-1002`, ...) linked across all forensic artifacts.
- **Explicit Accountability & Ownership:** Every incident, remediation task, note, and evidence file is explicitly owned by a verified analyst with active shift availability status.
- **Tamper-Resistant Audit Trail:** A blockchain-style SHA-256 cryptographic hash-chained audit ledger that links every state change (`prev_hash` → `curr_hash`) to mathematically detect unauthorized modification or tampering.
- **Digital Chain of Custody:** Legal-grade evidence logging tracking who acquired, uploaded, accessed, verified, or exported forensic files, signed with digital HMAC/SHA-256 fingerprints.

---

## 2. Technical Stack & Implementation Architecture

| Layer | Technology | Description |
|---|---|---|
| **Frontend UI/UX** | **React / Modern SPA + Tailwind CSS** | Enterprise dark cybersecurity palette (`#070d1e` / `#0c1427` / `#111c35`), glowing telemetry badges, responsive layouts, glassmorphism card surfaces. |
| **Visual Analytics** | **Pure Vector SVG Chart Engine** | Zero-dependency high-DPI responsive vector charts: 6-month ingestion velocity, severity donut, attack vector bars, status funnel, and analyst workload matrix. |
| **Backend Server** | **Node.js (v24 native)** | Lightweight REST API server implementing routing, JWT-signed tokens, multipart evidence processing, and security middleware. |
| **Database Storage** | **SQLite (`node:sqlite` DatabaseSync)** | ACID-compliant relational storage storing 8 interrelated tables with foreign key constraints, pre-seeded realistic enterprise incidents, and audit logs. |
| **Integrity Engine** | **Cryptographic SHA-256 Hashing** | Native cryptographic hashing for bit-stream evidence verification and immutable audit block chaining. |
| **Resilience & Fallback** | **Dual-Engine Architecture** | Automatically connects to REST API server on `http://localhost:3000`; if running offline or sandboxed, seamlessly proxies to an in-memory client engine. |

---

## 3. Incident Lifecycle Workflow

The system strictly enforces the standard 7-stage incident response lifecycle with an interactive visual stepper:

```
[1. Reported] ──> [2. Assigned] ──> [3. Under Investigation] ──> [4. Containment] ──> [5. Remediation] ──> [6. Resolved] ──> [7. Closed]
```

1. **Reported:** Initial telemetry alert ingested from SIEM, EDR, Firewall, or employee phishing submission.
2. **Assigned:** Incident assigned to a designated security investigator based on specialty and availability.
3. **Under Investigation:** Analyst conducts forensic triage, queries IOCs, and logs timestamped findings.
4. **Containment:** Urgent automated or manual actions executed to limit blast radius (host isolation, IP blocking, token revocation).
5. **Remediation:** Threat actor persistence eliminated, malware quarantined, credentials rotated, and vulnerabilities patched.
6. **Resolved:** Systems restored to operational state; verification checks confirm normal baseline telemetry.
7. **Closed:** Executive review signed off, post-incident report compiled, and case formally sealed.

---

## 4. Key Pages and Feature Breakdown

### A. Authentication & Role-Based Access Control (RBAC)
- **Visual Design:** Cybersecurity grid with neon shield branding and defense status indicators.
- **Demo Personas & Credentials:**
  - **Sarah Connor** (`sarah.connor@cybersec.corp`) — **Security Administrator** (Full SecOps configuration, case creation, deletion, team management).
  - **Alex Mercer** (`alex.mercer@cybersec.corp`) — **Security Analyst** (Investigation, IOC logging, evidence collection, triage).
  - **Marcus Vance** (`marcus.vance@cybersec.corp`) — **Incident Responder** (Host isolation, firewall block deployment, remediation execution).
  - **Elena Rostova** (`elena.rostova@cybersec.corp`) — **Read-Only Auditor** (Compliance view, audit verification, read-only mode).
- **Interactive Role Switcher:** Switch between personas in 1-click from the top navigation menu to experience live RBAC restrictions.

### B. Command Dashboard
- **6 Real-Time KPI Cards:** Total Incidents, Open Queue, Critical Alerts (pulsing red alert), Under Investigation, Resolved Cases, and Overdue SLA Cases.
- **Interactive Visual Charts:**
  1. *Monthly Threat Ingestion Trends* (6-month comparative bar chart).
  2. *Threat Severity Distribution* (interactive donut chart with percentages).
  3. *Attack Category Breakdown* (frequency bars by threat type).
  4. *Incident Lifecycle Funnel* (distribution across the 7 stages).
  5. *Analyst Workload Matrix* (active cases and critical assignments per analyst).
- **Real-Time Activity Stream:** Live chronological feed of events across all incidents.

### C. Incident Management Table
- **Multi-Criteria Filter Toolbar:** Instant search across Incident ID, Title, Impacted Assets, and Descriptions. Filter by Status, Severity, Category, and Assigned Analyst.
- **Incident Table Fields:** Incident ID, Title, Category, Severity Badge, Priority Level, Status Pill, Assigned Analyst with avatar, Ingestion Timestamp, SLA Deadline with overdue alerts, and Actions.
- **Register New Incident Modal:** Form validation covering the 8 official incident categories, automated SLA countdown calculation, asset tagging, and detection source.

### D. Case Investigation Room (Dedicated Case Details)
- **Case Header & Breadcrumbs:** Direct navigation, severity pills, SLA timer, and investigator reassign button.
- **7-Stage Interactive Stepper:** Clickable nodes showing completed, current, and upcoming stages with transition justification prompts.
- **6 Structured Case Tabs:**
  1. *Overview & Telemetry:* Detailed narrative, impacted endpoints/accounts with 1-click quick isolation buttons, and SLA timeline.
  2. *Chronological Timeline:* Complete history of every event, performer, and timestamp.
  3. *Investigation Notes:* Timestamped notes categorized by General Finding, Threat Intelligence, Indicators of Compromise (IOC), and Containment Action.
  4. *Evidence Vault:* File records, formatted sizes, SHA-256 fingerprints, and integrity status badges.
  5. *Remediation Tasks:* Response action checklist, completion percentages, and execution logs.
  6. *Case Audit Ledger:* Immutable event ledger specific to the case.

### E. Evidence Management & Digital Chain of Custody
- **Forensic File Storage:** Records evidence name, classification (Memory Dump, PCAP, Disk Image, Auth Log, Binary), formatted size, and acquisition uploader.
- **Real-Time SHA-256 Verification:** Recalculates cryptographic checksum on demand and displays bit-for-bit pristine match verification.
- **Chain of Custody Drawer:** Full chronological custody transfer history detailing who acquired, uploaded, accessed, analyzed, or exported evidence with digital HMAC/SHA-256 signatures.

### F. Response & Remediation Command Hub
- **Dual View Modes:** **Kanban Board** (Pending, In Progress, Completed columns) and **List Table View**.
- **1-Click Automated Response Playbooks:**
  - 🔒 *Isolate Host via EDR* (cuts network communications to infected endpoints).
  - 🚫 *Block IP at Perimeter Firewall* (pushes drop rule to perimeter edge).
  - 👤 *Suspend Compromised User* (terminates Azure AD / Okta sessions).
  - 🔑 *Rotate Secrets & Credentials* (triggers credential rotation in secrets manager).
  - 🧹 *Purge Malicious Files* (quarantines persistence registry keys and droppers).
  - 🛡️ *Deploy Emergency Patch* (deploys zero-day security hotfix).

### G. Team Operations & RBAC Permissions Matrix
- **Analyst Roster:** Displays team member profile, role, department, contact, active case count, and shift availability (On Duty, Investigating, On Call, Offline).
- **Interactive RBAC Permissions Matrix:** Explicit table detailing allowed/denied permissions across all 4 roles.

### H. Tamper-Resistant Audit Trail Ledger
- **Cryptographic Hash Chaining:** Every log entry calculates `curr_hash = SHA256(prev_hash + timestamp + user + action + incident + values)`.
- **Run Cryptographic Verification:** Button that validates the entire block chain from genesis `0000...` to the latest block, mathematically certifying zero tampering.

### I. Executive Reports & Analytics
- **SOC Benchmarks:** Mean Time to Acknowledge (MTTA: 18.4m), Mean Time to Resolve (MTTR: 4.2h), SLA Compliance Rate (94.6%).
- **Export Options:**
  - *Download CSV Report:* RFC 4180 compliant CSV export containing all incident records.
  - *Executive PDF / Print Report:* Formatted printable summary briefing with executive KPI cards, critical cases table, and compliance sign-off.

---

## 5. Sample Enterprise Incidents Pre-Seeded

| Incident ID | Incident Title | Category | Severity | Status | Investigator |
|---|---|---|---|---|---|
| **INC-1001** | Suspicious Login from Unknown Location (Tor Exit Node) | Unauthorized Access | High | Containment | Alex Mercer |
| **INC-1002** | Phishing Email Campaign with Macro-Enabled Invoice Payload | Phishing Attack | Medium | Remediation | Marcus Vance |
| **INC-1003** | Ransomware Execution Detected on Production File Server | Ransomware | Critical | Under Investigation | Alex Mercer |
| **INC-1004** | Unauthorized Database Exfiltration Pattern on Customer DB | Data Breach | Critical | Under Investigation | Sarah Connor |
| **INC-1005** | Malware Infection (Vidar Stealer) on Engineering Laptop | Malware Infection | High | Assigned | Marcus Vance |
| **INC-1006** | Distributed Denial of Service (DDoS) on API Gateway | Denial of Service | High | Resolved | Marcus Vance |
| **INC-1007** | Potential Insider Threat: Mass Cloud Storage Download | Insider Threat | Critical | Reported | Unassigned |
| **INC-1008** | Suspicious DNS Tunneling & Cobalt Strike C2 Traffic | Suspicious Network Activity | Low | Closed | Alex Mercer |

---

## 6. How to Run the Application

### Option 1: Standalone Browser Artifact (Zero Setup)
Open the generated artifact directly in the Antigravity IDE or your browser:
```
C:\Users\malul\.gemini\antigravity\brain\98af1b7c-10ad-494a-b3bd-7f13ae1457c7\sicms-app.html
```

### Option 2: Run with Full-Stack Node.js REST API Server
Open PowerShell in the project directory:
```powershell
cd C:\Users\malul\.gemini\antigravity\scratch\security-incident-system
node server.js
```
The server will initialize the SQLite database `sicms.db`, verify the cryptographic audit chain, and start serving on:
```
http://localhost:3000
```
Open `http://localhost:3000` in any web browser to access the full-stack system.
