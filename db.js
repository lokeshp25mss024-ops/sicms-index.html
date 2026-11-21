// db.js - SQLite Database Layer for Security Incident Case Management System (SICMS)
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');

const DB_PATH = path.join(__dirname, 'sicms.db');
const db = new DatabaseSync(DB_PATH);

// Helper for cryptographic hashing
function sha256(data) {
  return crypto.createHash('sha256').update(typeof data === 'string' ? data : JSON.stringify(data)).digest('hex');
}

function initDatabase() {
  // Enable foreign keys and WAL mode if needed
  db.exec('PRAGMA foreign_keys = ON;');

  // 1. Users Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      department TEXT NOT NULL,
      avatar TEXT,
      availability TEXT DEFAULT 'On Duty',
      phone TEXT,
      created_at TEXT NOT NULL
    );
  `);

  // 2. Incidents Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      category TEXT NOT NULL,
      severity TEXT NOT NULL,
      priority TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Reported',
      assigned_to TEXT,
      assigned_name TEXT,
      reported_by TEXT NOT NULL,
      detection_source TEXT NOT NULL,
      affected_assets TEXT NOT NULL,
      sla_deadline TEXT NOT NULL,
      resolved_at TEXT,
      closed_at TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
  `);

  // 3. Investigation Timeline Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS timeline (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      performed_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
  `);

  // 4. Investigation Notes Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS investigation_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id TEXT NOT NULL,
      author_id TEXT NOT NULL,
      author_name TEXT NOT NULL,
      author_role TEXT NOT NULL,
      note_type TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
  `);

  // 5. Evidence Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY,
      incident_id TEXT NOT NULL,
      name TEXT NOT NULL,
      file_type TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      file_size_formatted TEXT NOT NULL,
      file_path TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      uploaded_by TEXT NOT NULL,
      uploader_role TEXT NOT NULL,
      description TEXT NOT NULL,
      integrity_status TEXT DEFAULT 'Verified Pristine',
      created_at TEXT NOT NULL,
      FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
  `);

  // 6. Chain of Custody Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS chain_of_custody (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      evidence_id TEXT NOT NULL,
      incident_id TEXT NOT NULL,
      action TEXT NOT NULL,
      performed_by TEXT NOT NULL,
      role TEXT NOT NULL,
      details TEXT NOT NULL,
      ip_address TEXT DEFAULT '10.240.4.15',
      signature TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
    );
  `);

  // 7. Remediation Tasks Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS remediation_tasks (
      id TEXT PRIMARY KEY,
      incident_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      action_type TEXT NOT NULL,
      priority TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending',
      assigned_to TEXT NOT NULL,
      assigned_role TEXT NOT NULL,
      deadline TEXT NOT NULL,
      comments TEXT DEFAULT '',
      completed_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
    );
  `);

  // 8. Audit Logs Table (with SHA-256 Tamper-Evident Hash Chaining)
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      user_name TEXT NOT NULL,
      user_role TEXT NOT NULL,
      action TEXT NOT NULL,
      incident_id TEXT,
      entity_type TEXT NOT NULL,
      entity_id TEXT,
      previous_value TEXT,
      new_value TEXT,
      ip_address TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      curr_hash TEXT NOT NULL,
      timestamp TEXT NOT NULL
    );
  `);

  // 9. Settings Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);

  // Check if seed data exists
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount === 0) {
    seedDatabase();
  }
}

// Helper to build canonical hash payload for an audit entry
function buildAuditPayload(prevHash, timestamp, userId, action, incidentId, entityType, entityId, previousValue, newValue) {
  const pVal = previousValue || '';
  const nVal = newValue || '';
  return `${prevHash}|${timestamp}|${userId}|${action}|${incidentId || ''}|${entityType}|${entityId || ''}|${pVal}|${nVal}`;
}

// Tamper-resistant Audit Logging Helper
function addAuditLog({ userId, userName, userRole, action, incidentId, entityType, entityId, previousValue, newValue, ipAddress = '10.240.4.15' }) {
  const timestamp = new Date().toISOString();
  
  // Fetch previous hash for cryptographic chaining
  const lastLog = db.prepare('SELECT curr_hash FROM audit_logs ORDER BY id DESC LIMIT 1').get();
  const prevHash = lastLog ? lastLog.curr_hash : '0000000000000000000000000000000000000000000000000000000000000000';
  
  const prevValStr = previousValue ? (typeof previousValue === 'string' ? previousValue : JSON.stringify(previousValue)) : '';
  const newValStr = newValue ? (typeof newValue === 'string' ? newValue : JSON.stringify(newValue)) : '';

  const payloadToHash = buildAuditPayload(prevHash, timestamp, userId, action, incidentId, entityType, entityId, prevValStr, newValStr);
  const currHash = sha256(payloadToHash);

  const stmt = db.prepare(`
    INSERT INTO audit_logs (
      user_id, user_name, user_role, action, incident_id, entity_type, entity_id,
      previous_value, new_value, ip_address, prev_hash, curr_hash, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    userId, userName, userRole, action, incidentId || null, entityType, entityId || null,
    prevValStr || null, newValStr || null, ipAddress, prevHash, currHash, timestamp
  );

  return { id: result.lastInsertRowid, currHash, timestamp };
}

// Verification function for tamper resistance
function verifyAuditChain() {
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY id ASC').all();
  let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
  const violations = [];

  for (const log of logs) {
    if (log.prev_hash !== expectedPrevHash) {
      violations.push({
        id: log.id,
        reason: `Broken chain link at log #${log.id}. Expected prev_hash ${expectedPrevHash}, found ${log.prev_hash}`
      });
    }

    const payloadToHash = buildAuditPayload(
      log.prev_hash,
      log.timestamp,
      log.user_id,
      log.action,
      log.incident_id,
      log.entity_type,
      log.entity_id,
      log.previous_value,
      log.new_value
    );
    const calculatedHash = sha256(payloadToHash);

    if (calculatedHash !== log.curr_hash) {
      violations.push({
        id: log.id,
        reason: `Cryptographic tamper detected at log #${log.id}! Stored hash: ${log.curr_hash}, Calculated: ${calculatedHash}`
      });
    }

    expectedPrevHash = log.curr_hash;
  }

  return {
    verified: violations.length === 0,
    totalLogs: logs.length,
    violations
  };
}

// Add Chain of Custody entry
function addChainOfCustody({ evidenceId, incidentId, action, performedBy, role, details, ipAddress = '10.240.4.15' }) {
  const timestamp = new Date().toISOString();
  const signature = sha256(`CUSTODY|${evidenceId}|${action}|${performedBy}|${timestamp}|${details}`);

  const stmt = db.prepare(`
    INSERT INTO chain_of_custody (
      evidence_id, incident_id, action, performed_by, role, details, ip_address, signature, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const res = stmt.run(evidenceId, incidentId, action, performedBy, role, details, ipAddress, signature, timestamp);
  return { id: res.lastInsertRowid, signature, timestamp };
}

// Seed realistic enterprise dataset
function seedDatabase() {
  console.log('Seeding SICMS database with enterprise security incidents and team members...');
  
  // Default password hash for "CyberSec2026!"
  const defaultPw = sha256('CyberSec2026!');

  // Users
  const users = [
    {
      id: 'USR-001',
      name: 'Sarah Connor',
      email: 'sarah.connor@cybersec.corp',
      password_hash: defaultPw,
      role: 'Security Administrator',
      department: 'SOC Leadership & SecOps',
      avatar: 'SC',
      availability: 'On Duty',
      phone: '+1 (555) 019-2831'
    },
    {
      id: 'USR-002',
      name: 'Alex Mercer',
      email: 'alex.mercer@cybersec.corp',
      password_hash: defaultPw,
      role: 'Security Analyst',
      department: 'Threat Triage & Intelligence',
      avatar: 'AM',
      availability: 'Investigating',
      phone: '+1 (555) 014-8842'
    },
    {
      id: 'USR-003',
      name: 'Marcus Vance',
      email: 'marcus.vance@cybersec.corp',
      password_hash: defaultPw,
      role: 'Incident Responder',
      department: 'DFIR & Remediation',
      avatar: 'MV',
      availability: 'On Call',
      phone: '+1 (555) 017-9921'
    },
    {
      id: 'USR-004',
      name: 'Elena Rostova',
      email: 'elena.rostova@cybersec.corp',
      password_hash: defaultPw,
      role: 'Read-Only Auditor',
      department: 'Compliance, Risk & GRC',
      avatar: 'ER',
      availability: 'On Duty',
      phone: '+1 (555) 018-3310'
    }
  ];

  const insertUser = db.prepare(`
    INSERT INTO users (id, name, email, password_hash, role, department, avatar, availability, phone, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const u of users) {
    insertUser.run(u.id, u.name, u.email, u.password_hash, u.role, u.department, u.avatar, u.availability, u.phone, '2026-01-10T08:00:00Z');
  }

  // Incidents
  const now = new Date();
  const hoursAgo = (h) => new Date(now.getTime() - h * 3600 * 1000).toISOString();
  const daysAgo = (d) => new Date(now.getTime() - d * 86400 * 1000).toISOString();
  const hoursFromNow = (h) => new Date(now.getTime() + h * 3600 * 1000).toISOString();

  const incidents = [
    {
      id: 'INC-1001',
      title: 'Suspicious Login from Unknown Location (Tor Exit Node)',
      description: 'Multiple anomalous authentication attempts detected on VP of Finance account from an identified Tor exit node (185.220.101.5) bypassing conditional access geolocation policies via MFA fatigue attack.',
      category: 'Unauthorized Access',
      severity: 'High',
      priority: 'P2 - High',
      status: 'Containment',
      assigned_to: 'USR-002',
      assigned_name: 'Alex Mercer',
      reported_by: 'Azure AD Identity Protection Alert',
      detection_source: 'Cloud SIEM / Azure Sentinel',
      affected_assets: 'usr:c.hargrove@cybersec.corp, host:vpn-gw-us-east.cybersec.corp',
      sla_deadline: hoursFromNow(2),
      resolved_at: null,
      closed_at: null,
      created_at: hoursAgo(6),
      updated_at: hoursAgo(1)
    },
    {
      id: 'INC-1002',
      title: 'Phishing Email Campaign with Macro-Enabled Invoice Payload',
      description: 'Spear-phishing email masquerading as Q4 Vendor Invoice distributed to 14 finance employees containing malicious XLSM attachment designed to download Cobalt Strike beacon.',
      category: 'Phishing Attack',
      severity: 'Medium',
      priority: 'P3 - Normal',
      status: 'Remediation',
      assigned_to: 'USR-003',
      assigned_name: 'Marcus Vance',
      reported_by: 'PhishAlarm Employee Submission',
      detection_source: 'Proofpoint Email Gateway',
      affected_assets: 'mail:finance-dept@cybersec.corp, mail-srv-02',
      sla_deadline: hoursFromNow(8),
      resolved_at: null,
      closed_at: null,
      created_at: hoursAgo(14),
      updated_at: hoursAgo(2)
    },
    {
      id: 'INC-1003',
      title: 'Ransomware Execution Detected on Production File Server',
      description: 'CrowdStrike Falcon alerted on rapid mass file encryption pattern matching LockBit 3.0 on file server fs-prod-04. Volume Shadow Copies deletion command executed via vssadmin.',
      category: 'Ransomware',
      severity: 'Critical',
      priority: 'P1 - Immediate',
      status: 'Under Investigation',
      assigned_to: 'USR-002',
      assigned_name: 'Alex Mercer',
      reported_by: 'CrowdStrike Falcon EDR',
      detection_source: 'EDR Falcon Sensor v7.14',
      affected_assets: 'host:fs-prod-04.internal.lan, volume:D:\\SharedData',
      sla_deadline: hoursFromNow(1),
      resolved_at: null,
      closed_at: null,
      created_at: hoursAgo(3),
      updated_at: hoursAgo(0.5)
    },
    {
      id: 'INC-1004',
      title: 'Unauthorized Database Exfiltration Pattern on Customer DB',
      description: 'DLP sensor identified large-scale SQL query dumping 45,000 credit records outside business hours through compromised service account svc_analytics_prod.',
      category: 'Data Breach',
      severity: 'Critical',
      priority: 'P1 - Immediate',
      status: 'Under Investigation',
      assigned_to: 'USR-001',
      assigned_name: 'Sarah Connor',
      reported_by: 'Imperva Database Security',
      detection_source: 'Database Activity Monitoring (DAM)',
      affected_assets: 'db:cust-prod-db-cluster-01, svc:svc_analytics_prod',
      sla_deadline: hoursAgo(0.5), // overdue for demo!
      resolved_at: null,
      closed_at: null,
      created_at: hoursAgo(5),
      updated_at: hoursAgo(1)
    },
    {
      id: 'INC-1005',
      title: 'Malware Infection (Vidar Stealer) on Engineering Laptop',
      description: 'Infostealer Trojan downloaded via trojanized open-source utility installer. Browser credentials, crypto wallet files, and SSH keys in ~/.ssh targeted for harvesting.',
      category: 'Malware Infection',
      severity: 'High',
      priority: 'P2 - High',
      status: 'Assigned',
      assigned_to: 'USR-003',
      assigned_name: 'Marcus Vance',
      reported_by: 'Windows Defender for Endpoint',
      detection_source: 'Microsoft Defender ATP',
      affected_assets: 'host:ws-dev-eng-89.cybersec.corp',
      sla_deadline: hoursFromNow(5),
      resolved_at: null,
      closed_at: null,
      created_at: hoursAgo(2),
      updated_at: hoursAgo(1.5)
    },
    {
      id: 'INC-1006',
      title: 'Distributed Denial of Service (DDoS) on API Gateway',
      description: 'Volumetric SYN flood and HTTP GET flood targeting /api/v1/checkout reaching 42 Gbps peak throughput causing 45% HTTP 504 timeouts.',
      category: 'Denial of Service',
      severity: 'High',
      priority: 'P2 - High',
      status: 'Resolved',
      assigned_to: 'USR-003',
      assigned_name: 'Marcus Vance',
      reported_by: 'Cloudflare WAF Automated Alert',
      detection_source: 'Edge WAF / Cloudflare Magic Transit',
      affected_assets: 'gw:api-edge-proxy-01, edge-ip:198.51.100.44',
      sla_deadline: daysAgo(1),
      resolved_at: hoursAgo(8),
      closed_at: null,
      created_at: daysAgo(2),
      updated_at: hoursAgo(8)
    },
    {
      id: 'INC-1007',
      title: 'Potential Insider Threat: Mass Cloud Storage Download by Terminated Staff',
      description: 'Employee submitted 2-week notice and downloaded 18.4 GB of source code repositories and customer contracts to personal Google Drive and encrypted USB.',
      category: 'Insider Threat',
      severity: 'Critical',
      priority: 'P1 - Immediate',
      status: 'Reported',
      assigned_to: null,
      assigned_name: 'Unassigned',
      reported_by: 'Netskope Cloud CASB',
      detection_source: 'CASB / DLP Engine',
      affected_assets: 'usr:b.kowalski@cybersec.corp, drive:Internal-R&D-Vault',
      sla_deadline: hoursFromNow(3),
      resolved_at: null,
      closed_at: null,
      created_at: hoursAgo(1),
      updated_at: hoursAgo(1)
    },
    {
      id: 'INC-1008',
      title: 'Suspicious DNS Tunneling & Cobalt Strike C2 Traffic',
      description: 'Unusual high-frequency base64-encoded subdomains queried to dynamic domain ns1.update-microsoft-check[.]org indicating active DNS tunneling beacon.',
      category: 'Suspicious Network Activity',
      severity: 'Low',
      priority: 'P4 - Low',
      status: 'Closed',
      assigned_to: 'USR-002',
      assigned_name: 'Alex Mercer',
      reported_by: 'Cisco Umbrella DNS Analytics',
      detection_source: 'DNS Threat Defense',
      affected_assets: 'host:srv-build-worker-03',
      sla_deadline: daysAgo(5),
      resolved_at: daysAgo(4),
      closed_at: daysAgo(3),
      created_at: daysAgo(6),
      updated_at: daysAgo(3)
    }
  ];

  const insertInc = db.prepare(`
    INSERT INTO incidents (
      id, title, description, category, severity, priority, status,
      assigned_to, assigned_name, reported_by, detection_source, affected_assets,
      sla_deadline, resolved_at, closed_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const inc of incidents) {
    insertInc.run(
      inc.id, inc.title, inc.description, inc.category, inc.severity, inc.priority, inc.status,
      inc.assigned_to, inc.assigned_name, inc.reported_by, inc.detection_source, inc.affected_assets,
      inc.sla_deadline, inc.resolved_at, inc.closed_at, inc.created_at, inc.updated_at
    );
  }

  // Timeline entries
  const timelines = [
    { incId: 'INC-1001', type: 'created', title: 'Incident Registered', desc: 'Azure AD alert ingested via automated SIEM webhook.', by: 'System SIEM', time: hoursAgo(6) },
    { incId: 'INC-1001', type: 'assigned', title: 'Analyst Assigned', desc: 'Assigned to Alex Mercer for investigation.', by: 'Sarah Connor', time: hoursAgo(5.5) },
    { incId: 'INC-1001', type: 'status_changed', title: 'Status -> Under Investigation', desc: 'Analyst acknowledged case and began IP and token log analysis.', by: 'Alex Mercer', time: hoursAgo(5) },
    { incId: 'INC-1001', type: 'evidence_uploaded', title: 'Evidence Uploaded', desc: 'Uploaded Okta authentication audit log JSON dump.', by: 'Alex Mercer', time: hoursAgo(4) },
    { incId: 'INC-1001', type: 'status_changed', title: 'Status -> Containment', desc: 'Invoked conditional access revocation and session termination.', by: 'Marcus Vance', time: hoursAgo(2) },

    { incId: 'INC-1003', type: 'created', title: 'Critical Alert Triaged', desc: 'EDR blocked encryption threads and quarantined initial droppers.', by: 'CrowdStrike Alert', time: hoursAgo(3) },
    { incId: 'INC-1003', type: 'assigned', title: 'Assigned to Lead DFIR', desc: 'Assigned to Alex Mercer.', by: 'Sarah Connor', time: hoursAgo(2.8) },
    { incId: 'INC-1003', type: 'status_changed', title: 'Status -> Under Investigation', desc: 'Initiated forensic memory triage and host network isolation.', by: 'Alex Mercer', time: hoursAgo(2.5) },
    { incId: 'INC-1003', type: 'evidence_uploaded', title: 'Memory Dump Secured', desc: 'Forensic volatile memory dump acquired via winpmem.', by: 'Alex Mercer', time: hoursAgo(1.5) },

    { incId: 'INC-1006', type: 'created', title: 'DDoS Event Detected', desc: 'Automated mitigation rule engaged on edge proxy.', by: 'Cloudflare SIEM', time: daysAgo(2) },
    { incId: 'INC-1006', type: 'status_changed', title: 'Status -> Remediation', desc: 'Border BGP rate-limiting applied with ISP upstream scrubbing.', by: 'Marcus Vance', time: daysAgo(1.5) },
    { incId: 'INC-1006', type: 'resolved', title: 'Incident Resolved', desc: 'Attack ceased; all upstream traffic normalized. Zero payload impact.', by: 'Marcus Vance', time: hoursAgo(8) }
  ];

  const insertTimeline = db.prepare(`
    INSERT INTO timeline (incident_id, event_type, title, description, performed_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  for (const t of timelines) {
    insertTimeline.run(t.incId, t.type, t.title, t.desc, t.by, t.time);
  }

  // Investigation Notes
  const notes = [
    {
      incId: 'INC-1001',
      authorId: 'USR-002',
      authorName: 'Alex Mercer',
      authorRole: 'Security Analyst',
      type: 'Threat Intelligence',
      content: 'The source IP 185.220.101.5 is an active Tor exit node listed on Shodan with multiple malicious abuse reports in the last 48 hours targeting corporate SSO portals.',
      time: hoursAgo(4.5)
    },
    {
      incId: 'INC-1001',
      authorId: 'USR-002',
      authorName: 'Alex Mercer',
      authorRole: 'Security Analyst',
      type: 'General Finding',
      content: 'User was prompted with 18 push notifications within 3 minutes at 02:45 UTC. Fatigue triggered accidental approval on the 19th prompt. Refresh token was minted.',
      time: hoursAgo(3.8)
    },
    {
      incId: 'INC-1001',
      authorId: 'USR-003',
      authorName: 'Marcus Vance',
      authorRole: 'Incident Responder',
      type: 'Containment Action',
      content: 'Terminated all active Azure AD and Okta OAuth sessions. Reset primary password and transferred user to FIDO2 hardware security key requirement.',
      time: hoursAgo(1.8)
    },
    {
      incId: 'INC-1003',
      authorId: 'USR-002',
      authorName: 'Alex Mercer',
      authorRole: 'Security Analyst',
      type: 'Indicators of Compromise (IOC)',
      content: `SHA-256 Hashes identified:
- LockBit Encryptor: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
- Persistence Registry Key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost_updater.exe
- Ransom Note: RESTORE_MY_FILES.txt`,
      time: hoursAgo(2)
    }
  ];

  const insertNote = db.prepare(`
    INSERT INTO investigation_notes (incident_id, author_id, author_name, author_role, note_type, content, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const n of notes) {
    insertNote.run(n.incId, n.authorId, n.authorName, n.authorRole, n.type, n.content, n.time);
  }

  // Evidence Records
  const evidenceList = [
    {
      id: 'EVD-5001',
      incident_id: 'INC-1001',
      name: 'vpn_authentication_audit_log.json',
      file_type: 'Authentication Logs (.json)',
      file_size: 489240,
      file_size_formatted: '477.8 KB',
      file_path: 'uploads/INC-1001/vpn_authentication_audit_log.json',
      sha256_hash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      uploaded_by: 'Alex Mercer',
      uploader_role: 'Security Analyst',
      description: 'Extracted Palo Alto GlobalProtect VPN logs detailing external IP handshake, TLS cipher suite, and MFA verification failure bursts.',
      created_at: hoursAgo(4)
    },
    {
      id: 'EVD-5002',
      incident_id: 'INC-1001',
      name: 'azure_ad_token_revocation_receipt.pdf',
      file_type: 'Forensic Report (.pdf)',
      file_size: 184500,
      file_size_formatted: '180.2 KB',
      file_path: 'uploads/INC-1001/azure_ad_token_revocation_receipt.pdf',
      sha256_hash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      uploaded_by: 'Marcus Vance',
      uploader_role: 'Incident Responder',
      description: 'Cryptographic confirmation receipt from Microsoft Graph API confirming token invalidation across all federated apps.',
      created_at: hoursAgo(2)
    },
    {
      id: 'EVD-5003',
      incident_id: 'INC-1003',
      name: 'fs04_volatile_memory_dump.raw',
      file_type: 'Memory Dump (.raw)',
      file_size: 8589934592,
      file_size_formatted: '8.00 GB',
      file_path: 'uploads/INC-1003/fs04_volatile_memory_dump.raw',
      sha256_hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
      uploaded_by: 'Alex Mercer',
      uploader_role: 'Security Analyst',
      description: 'Bit-stream RAM capture of infected server fs-prod-04 collected using WinPmem v4.0. Contains in-memory decryption keys and Cobalt Strike payload.',
      created_at: hoursAgo(1.5)
    },
    {
      id: 'EVD-5004',
      incident_id: 'INC-1003',
      name: 'pcap_lateral_movement_smb.pcapng',
      file_type: 'Network Packet Capture (.pcap)',
      file_size: 154823000,
      file_size_formatted: '147.6 MB',
      file_path: 'uploads/INC-1003/pcap_lateral_movement_smb.pcapng',
      sha256_hash: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
      uploaded_by: 'Alex Mercer',
      uploader_role: 'Security Analyst',
      description: 'Network packet capture displaying SMBv2 remote execution attempts and PsExec staging traffic from 10.240.4.88.',
      created_at: hoursAgo(1.2)
    },
    {
      id: 'EVD-5005',
      incident_id: 'INC-1004',
      name: 'db_exfiltration_session_dump.sql',
      file_type: 'Database Query Log (.sql)',
      file_size: 3840220,
      file_size_formatted: '3.66 MB',
      file_path: 'uploads/INC-1004/db_exfiltration_session_dump.sql',
      sha256_hash: 'ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d',
      uploaded_by: 'Sarah Connor',
      uploader_role: 'Security Administrator',
      description: 'Audit trace of malicious queries targeting `tbl_customer_pii` and `tbl_payment_tokens` via compromised service account.',
      created_at: hoursAgo(2)
    }
  ];

  const insertEvd = db.prepare(`
    INSERT INTO evidence (
      id, incident_id, name, file_type, file_size, file_size_formatted, file_path,
      sha256_hash, uploaded_by, uploader_role, description, integrity_status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const e of evidenceList) {
    insertEvd.run(
      e.id, e.incident_id, e.name, e.file_type, e.file_size, e.file_size_formatted,
      e.file_path, e.sha256_hash, e.uploaded_by, e.uploader_role, e.description,
      e.integrity_status || 'Verified Pristine', e.created_at
    );

    // Initial chain-of-custody entry
    addChainOfCustody({
      evidenceId: e.id,
      incidentId: e.incident_id,
      action: 'Collected & Uploaded',
      performedBy: e.uploaded_by,
      role: e.uploader_role,
      details: `Forensic acquisition completed. Initial SHA-256 fingerprint calculated: ${e.sha256_hash.substring(0, 16)}...`
    });

    addChainOfCustody({
      evidenceId: e.id,
      incidentId: e.incident_id,
      action: 'Hash Integrity Verified',
      performedBy: 'Elena Rostova',
      role: 'Read-Only Auditor',
      details: 'Automated DFIR integrity validator confirmed hash match against original digital signature.'
    });
  }

  // Remediation Tasks
  const tasks = [
    {
      id: 'TSK-2001',
      incident_id: 'INC-1001',
      title: 'Revoke active refresh tokens and OAuth sessions for c.hargrove',
      description: 'Run automated PowerShell script on Azure AD to terminate all user sessions and revoke active OAuth grants.',
      action_type: 'Account Suspension',
      priority: 'Critical',
      status: 'Completed',
      assigned_to: 'Marcus Vance',
      assigned_role: 'Incident Responder',
      deadline: hoursAgo(1),
      comments: 'Executed successfully via Graph API cmdlet. All active sessions invalidated across 3 devices.',
      completed_at: hoursAgo(2),
      created_at: hoursAgo(5)
    },
    {
      id: 'TSK-2002',
      incident_id: 'INC-1001',
      title: 'Block Tor Exit Node 185.220.101.5 on Edge Firewalls',
      description: 'Push firewall drop rule to Palo Alto perimeter cluster to prevent further ingress attempts.',
      action_type: 'IP Firewall Block',
      priority: 'High',
      status: 'Completed',
      assigned_to: 'Marcus Vance',
      assigned_role: 'Incident Responder',
      deadline: hoursAgo(2),
      comments: 'Rule deployed to edge cluster. Verified 0 packets passed since 04:12 UTC.',
      completed_at: hoursAgo(3),
      created_at: hoursAgo(5)
    },
    {
      id: 'TSK-2003',
      incident_id: 'INC-1001',
      title: 'Enforce Number-Matching MFA and FIDO2 Token Enrollment',
      description: 'Upgrade user account conditional access policy to strictly enforce FIDO2 WebAuthn keys and disable SMS/voice fallback.',
      action_type: 'Policy Update',
      priority: 'Medium',
      status: 'In Progress',
      assigned_to: 'Sarah Connor',
      assigned_role: 'Security Administrator',
      deadline: hoursFromNow(12),
      comments: 'YubiKey provisioned. Awaiting employee hardware registration appointment at 16:00.',
      completed_at: null,
      created_at: hoursAgo(2)
    },
    {
      id: 'TSK-2004',
      incident_id: 'INC-1003',
      title: 'Isolate host fs-prod-04 from corporate network via EDR',
      description: 'Use CrowdStrike Falcon API network containment to cut network communications while preserving forensic channel.',
      action_type: 'Host Isolation',
      priority: 'Critical',
      status: 'Completed',
      assigned_to: 'Marcus Vance',
      assigned_role: 'Incident Responder',
      deadline: hoursAgo(2),
      comments: 'Host network contained immediately. Only sensor connection to Falcon Cloud maintained.',
      completed_at: hoursAgo(2.5),
      created_at: hoursAgo(3)
    },
    {
      id: 'TSK-2005',
      incident_id: 'INC-1003',
      title: 'Mount immutable offline tape backups to restore affected shares',
      description: 'Verify volume shadow copy integrity and initiate restore from AWS S3 Glacier Object Lock immutable bucket.',
      action_type: 'System Restoration',
      priority: 'Critical',
      status: 'In Progress',
      assigned_to: 'Marcus Vance',
      assigned_role: 'Incident Responder',
      deadline: hoursFromNow(4),
      comments: 'S3 Object Lock bucket integrity checked. 840 GB restoring at 120 MB/s.',
      completed_at: null,
      created_at: hoursAgo(1)
    },
    {
      id: 'TSK-2006',
      incident_id: 'INC-1004',
      title: 'Rotate compromised database service account credentials',
      description: 'Rotate password and secret keys for svc_analytics_prod in AWS Secrets Manager and recycle DB connection pool.',
      action_type: 'Credential Reset',
      priority: 'Critical',
      status: 'Pending',
      assigned_to: 'Sarah Connor',
      assigned_role: 'Security Administrator',
      deadline: hoursFromNow(1),
      comments: 'Coordinating with Analytics engineering team to schedule zero-downtime key rotation.',
      completed_at: null,
      created_at: hoursAgo(3)
    },
    {
      id: 'TSK-2007',
      incident_id: 'INC-1002',
      title: 'Purge malicious phishing email from all Microsoft 365 inboxes',
      description: 'Execute Microsoft Defender O365 hard delete for message with subject "URGENT: Q4 Overdue Vendor Payment".',
      action_type: 'Malware Purge',
      priority: 'High',
      status: 'Completed',
      assigned_to: 'Marcus Vance',
      assigned_role: 'Incident Responder',
      deadline: hoursAgo(4),
      comments: 'Purged 14 messages from inboxes. 0 users opened attachment prior to quarantine.',
      completed_at: hoursAgo(5),
      created_at: hoursAgo(12)
    }
  ];

  const insertTask = db.prepare(`
    INSERT INTO remediation_tasks (
      id, incident_id, title, description, action_type, priority, status,
      assigned_to, assigned_role, deadline, comments, completed_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const t of tasks) {
    insertTask.run(
      t.id, t.incident_id, t.title, t.description, t.action_type, t.priority, t.status,
      t.assigned_to, t.assigned_role, t.deadline, t.comments, t.completed_at, t.created_at
    );
  }

  // Pre-seed Audit Logs (with valid SHA-256 blockchain chain)
  const auditEntries = [
    {
      userId: 'USR-001',
      userName: 'Sarah Connor',
      userRole: 'Security Administrator',
      action: 'SYSTEM_INITIALIZATION',
      incidentId: null,
      entityType: 'System',
      entityId: 'SYS-CORE',
      previousValue: null,
      newValue: { status: 'SEC_SYSTEM_READY', version: '2.5.0', engine: 'SICMS-Enterprise' }
    },
    {
      userId: 'USR-001',
      userName: 'Sarah Connor',
      userRole: 'Security Administrator',
      action: 'CREATE_INCIDENT',
      incidentId: 'INC-1001',
      entityType: 'Incident',
      entityId: 'INC-1001',
      previousValue: null,
      newValue: { title: 'Suspicious Login from Unknown Location', severity: 'High', status: 'Reported' }
    },
    {
      userId: 'USR-001',
      userName: 'Sarah Connor',
      userRole: 'Security Administrator',
      action: 'ASSIGN_ANALYST',
      incidentId: 'INC-1001',
      entityType: 'Incident',
      entityId: 'INC-1001',
      previousValue: { assigned_to: null, assigned_name: 'Unassigned' },
      newValue: { assigned_to: 'USR-002', assigned_name: 'Alex Mercer' }
    },
    {
      userId: 'USR-002',
      userName: 'Alex Mercer',
      userRole: 'Security Analyst',
      action: 'UPDATE_STATUS',
      incidentId: 'INC-1001',
      entityType: 'Incident',
      entityId: 'INC-1001',
      previousValue: { status: 'Assigned' },
      newValue: { status: 'Under Investigation' }
    },
    {
      userId: 'USR-002',
      userName: 'Alex Mercer',
      userRole: 'Security Analyst',
      action: 'UPLOAD_EVIDENCE',
      incidentId: 'INC-1001',
      entityType: 'Evidence',
      entityId: 'EVD-5001',
      previousValue: null,
      newValue: { name: 'vpn_authentication_audit_log.json', sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' }
    },
    {
      userId: 'USR-003',
      userName: 'Marcus Vance',
      userRole: 'Incident Responder',
      action: 'UPDATE_STATUS',
      incidentId: 'INC-1001',
      entityType: 'Incident',
      entityId: 'INC-1001',
      previousValue: { status: 'Under Investigation' },
      newValue: { status: 'Containment' }
    },
    {
      userId: 'USR-003',
      userName: 'Marcus Vance',
      userRole: 'Incident Responder',
      action: 'COMPLETE_REMEDIATION_TASK',
      incidentId: 'INC-1001',
      entityType: 'RemediationTask',
      entityId: 'TSK-2001',
      previousValue: { status: 'In Progress' },
      newValue: { status: 'Completed', completed_at: hoursAgo(2) }
    },
    {
      userId: 'USR-004',
      userName: 'Elena Rostova',
      userRole: 'Read-Only Auditor',
      action: 'VERIFY_EVIDENCE_INTEGRITY',
      incidentId: 'INC-1001',
      entityType: 'Evidence',
      entityId: 'EVD-5001',
      previousValue: { status: 'Pending Verification' },
      newValue: { status: 'Verified Pristine', verified_hash_match: true }
    }
  ];

  for (const a of auditEntries) {
    addAuditLog(a);
  }

  // Settings
  const defaultSettings = [
    { key: 'sla_critical_hours', value: '1' },
    { key: 'sla_high_hours', value: '4' },
    { key: 'sla_medium_hours', value: '12' },
    { key: 'sla_low_hours', value: '48' },
    { key: 'siem_webhook_url', value: 'https://siem-collector.internal.lan/api/v1/incidents' },
    { key: 'auto_isolate_critical', value: 'true' },
    { key: 'evidence_retention_days', value: '365' },
    { key: 'mfa_enforced', value: 'true' },
    { key: 'audit_tamper_seal', value: 'ENABLED' }
  ];

  const insertSetting = db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
  for (const s of defaultSettings) {
    insertSetting.run(s.key, s.value);
  }

  console.log('Database initialization & seeding completed successfully.');
}

module.exports = {
  db,
  sha256,
  initDatabase,
  addAuditLog,
  verifyAuditChain,
  addChainOfCustody
};
