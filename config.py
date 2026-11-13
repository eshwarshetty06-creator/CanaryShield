"""
config.py - Centralized Configuration for Anti-Ransomware Canary Tripwire System
"""

import os
import sys
import io
import zipfile
import sqlite3
import tempfile
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
SANDBOX_DIR = BASE_DIR / "sandbox"
LOGS_DIR = BASE_DIR / "logs"
QUARANTINE_DIR = BASE_DIR / "quarantine"
AGENT_PID_FILE = BASE_DIR / "canary_edr.pid"
PROTECTED_CONFIG_FILE = BASE_DIR / "protected_directories.json"

# Ensure directories exist
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# Backward Compatible Canary Names
CANARY_FILENAME = "!_canary_financial_records.txt"
CANARY_FILEPATH = SANDBOX_DIR / CANARY_FILENAME
REVERSE_CANARY_FILENAME = "zz_canary_archive_backup.txt"

# Multi-Extension Canary Matrix & Tar-Pit Delays
# Deploys high-value decoys (.txt, .xlsx, .db, .docx, .zip, .bak), Tar-Pit delay, and Stealth Anti-Evasion Decoys
CANARY_FLEET = [
    # --- Standard Classic Canaries ---
    {
        "filename": "!_canary_customer_vault.db",
        "type": "sqlite",
        "description": "Forward A-Z Tripwire: SQLite Master Customer Database Vault",
        "traversal": "FORWARD",
        "stealth": False
    },
    {
        "filename": "!_canary_executive_payroll.xlsx",
        "type": "xlsx",
        "description": "Forward A-Z Tripwire: Executive Compensation & Bonus Worksheet",
        "traversal": "FORWARD",
        "stealth": False
    },
    {
        "filename": "!_canary_financial_records.txt",
        "type": "text",
        "description": "Forward A-Z Tripwire: Confidential Corporate Treasury Ledger",
        "traversal": "FORWARD",
        "stealth": False
    },
    {
        "filename": "!_canary_legal_contract.docx",
        "type": "docx",
        "description": "Forward A-Z Tripwire: Mutual Non-Disclosure Legal Agreement",
        "traversal": "FORWARD",
        "stealth": False
    },
    {
        "filename": "!_canary_tarpit_master_ledger.dat",
        "type": "tarpit",
        "description": "Forward Tar-Pit Decoy: 2.5MB Structured Ledger (Forces I/O Crawl Delay)",
        "traversal": "FORWARD",
        "stealth": False
    },
    # --- Stealth Anti-Evasion Decoys (Defeats 'canary' name skipping filters) ---
    {
        "filename": "!_accounting_customer_vault.db",
        "type": "sqlite",
        "description": "Stealth Forward Tripwire: Enterprise Customer Account Vault",
        "traversal": "FORWARD",
        "stealth": True
    },
    {
        "filename": "!_executive_payroll_records.xlsx",
        "type": "xlsx",
        "description": "Stealth Forward Tripwire: Executive Salary & Bonus Worksheet",
        "traversal": "FORWARD",
        "stealth": True
    },
    # --- Reverse Z-A Canaries & Stealth Decoys ---
    {
        "filename": "zz_canary_archive_backup.txt",
        "type": "text",
        "description": "Reverse Z-A Tripwire: Offline Backup Catalog & Manifest",
        "traversal": "REVERSE",
        "stealth": False
    },
    {
        "filename": "zz_canary_archive_backup.zip",
        "type": "zip",
        "description": "Reverse Z-A Tripwire: Disaster Recovery Infrastructure Catalog Archive",
        "traversal": "REVERSE",
        "stealth": False
    },
    {
        "filename": "zz_canary_cold_storage.bak",
        "type": "bak",
        "description": "Reverse Z-A Tripwire: Database Cold Storage Backup Manifest",
        "traversal": "REVERSE",
        "stealth": False
    },
    {
        "filename": "zz_cold_storage_manifest.bak",
        "type": "bak",
        "description": "Stealth Reverse Tripwire: Cold Storage Disaster Backup",
        "traversal": "REVERSE",
        "stealth": True
    }
]

# Set of all active canary filenames for instantaneous lookup
CANARY_NAMES_SET = {item["filename"] for item in CANARY_FLEET}

# Detection Thresholds
SHANNON_ENTROPY_THRESHOLD = 7.0
FALLBACK_POLL_INTERVAL = 0.5

# Defensive Actions & EDR Controls
AUTO_NEUTRALIZE = True              # Instantly terminate offending process on tripwire breach
KILL_PROCESS_TREE = True            # Terminate child processes spawned by the threat
AUTO_QUARANTINE_PAYLOAD = True      # Isolate script/binary & strip execution rights
AUTO_QUARANTINE_BINARY = True       # Backward-compatible alias
AUTO_RESTORE_CANARY = True          # Self-healing: instantly redeploy fresh unencrypted canary

# Real Windows Firewall Containment & Isolation
ENABLE_FIREWALL_CONTAINMENT = True  # Automatically cuts off outbound C2 traffic via Windows Firewall
FIREWALL_RULE_NAME = "CanaryShield_Emergency_Containment"
SIMULATE_NETWORK_ISOLATION = True   # Fallback simulation if not elevated

# Volume Shadow Copy (VSS) Guardian
ENABLE_VSS_GUARDIAN = True          # Monitor & block attempts to delete Volume Shadow Copies or disable recovery
VSS_TAMPER_PATTERNS = [
    ("vssadmin", "delete", "shadows"),
    ("wmic", "shadowcopy", "delete"),
    ("wbadmin", "delete", "catalog"),
    ("bcdedit", "recoveryenabled", "no"),
    ("bcdedit", "bootstatuspolicy", "ignoreallfailures"),
    ("powershell", "win32_shadowcopy", "delete"),
]

# Windows Service / Task Scheduler Identifier
SERVICE_TASK_NAME = "CanaryShieldEDRAgent"

# MITRE ATT&CK Mappings for Forensic Reporting
MITRE_ATTACK_MAPPINGS = {
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversary encrypts data on target systems with high entropy to disrupt access.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversary uses script interpreters (e.g. Python, PowerShell) to execute malicious encryption logic.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversary enumerates files and folders in directory order to find targets to encrypt.",
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactic": "Defense Evasion",
        "description": "Adversary alters or destroys original file contents during in-place encryption.",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "description": "Adversary attempts to delete Volume Shadow Copies or disable recovery options to prevent restoration.",
    },
    "T1046": {
        "name": "Network Service Discovery / C2 Exfiltration",
        "tactic": "Discovery / Exfiltration",
        "description": "Adversary attempts to communicate with Command & Control infrastructure for encryption key exchange.",
    }
}

# Baseline Canary Content (Plaintext realistic corporate financial ledger)
DEFAULT_CANARY_CONTENT = """================================================================================
CONFIDENTIAL: CORPORATE TREASURY & FINANCIAL LEDGER (FY2026 - Q3)
CLASSIFICATION: RESTRICTED / INTERNAL EYES ONLY
================================================================================

1. EXECUTIVE CASH RESERVES & LIQUIDITY
   - Primary Operating Account (JPMorgan Chase): $14,850,230.12
   - Secondary Escrow Reserve (Silicon Valley Bank): $4,200,000.00
   - Automated Clearing House (ACH) Routing: 021000021 / Account: 8492019482
   - Swift BIC: CHASEUS33XXX

2. PAYROLL & COMPENSATION DISBURSEMENT (SEPTEMBER 2026)
   - Executive Leadership Team: $425,000.00 (Disbursed Sep 15)
   - Core Engineering & Platform Operations: $1,180,450.00 (Disbursed Sep 28)
   - Security Operations & Threat Research: $390,200.00 (Disbursed Sep 28)
   - Tax Withholdings (Federal/State IRS): $612,980.50

3. VENDOR & INFRASTRUCTURE EXPENDITURES
   - AWS GovCloud Infrastructure (Compute & S3): $184,320.18
   - Cloudflare DDoS Mitigation & Zero Trust Gateway: $24,500.00
   - CrowdStrike Falcon Complete Managed EDR: $48,000.00

4. WIRE TRANSFER AUTHORIZATION KEY CODES
   - Wire Reference #TX-98402: Authorized by Chief Financial Officer
   - Dual-Control Token Checksum: A7F2-99B1-884C-109D

[CONFIDENTIAL NOTICE: Unauthorized disclosure or modification is strictly prohibited.]
"""

# Reverse Traversal Canary Content
REVERSE_CANARY_CONTENT = """================================================================================
OFFLINE BACKUP CATALOG & DISASTER RECOVERY ARCHIVE MANIFEST
SYSTEM ID: PROD-EAST-DR-CATALOG-2026
================================================================================

1. DATABASE SNAPSHOT ARCHIVES (COLD STORAGE)
   - Snapshot-PostgreSQL-Cluster-Full-2026-09-30.tar.gz : 412.5 GB (Checksum: 8fa7b12)
   - Snapshot-Redis-Cache-State-2026-09-30.rdb         : 18.2 GB  (Checksum: c9901ef)
   - Encrypted-Customer-PII-Master-Vault.bak          : 94.8 GB  (Checksum: 334ab7c)

2. DEPLOYMENT CREDENTIAL BACKUPS
   - Kubernetes Cluster Admin Kubeconfig Backup        : Archived to Glacier Vault 9
   - TLS Wildcard Certificate Private Keys (*.corp)    : Hardware Security Module (HSM-1)

3. RESTORATION VALIDATION POLICY
   - Recovery Time Objective (RTO): < 45 minutes
   - Recovery Point Objective (RPO): < 15 minutes
   - Disaster Recovery Drill Authorization: VP of Infrastructure

[SECURE ARCHIVE STATUS: VERIFIED READ-ONLY INTEGRITY]
"""

# Default Mock User Files for Sandbox
DEFAULT_USER_FILES = {
    "assignment.txt": """CS 401: Advanced Operating Systems - Assignment 3
Student Name: Alex Mercer
Topic: Virtual Memory Page Replacement Algorithms

Summary:
In this assignment, we implement and benchmark three virtual memory page replacement
algorithms: Least Recently Used (LRU), First-In First-Out (FIFO), and the Second-Chance
(Clock) algorithm.

Observations:
1. Under heavy sequential scanning, LRU suffers from cache thrashing.
2. FIFO exhibits Belady's Anomaly where increasing frames results in more page faults.
3. The Second-Chance algorithm strikes an effective balance between overhead and accuracy.
""",
    "photos_info.txt": """Camera Trip Metadata - Pacific Northwest Expedition 2026
Camera Body: Sony A7 IV
Primary Lens: FE 24-70mm f/2.8 GM II

Photo Log:
- DSC04921.ARW: Sunrise over Mount Rainier (f/8, 1/250s, ISO 100)
- DSC04922.ARW: Olympic National Park Rainforest canopy (f/4, 1/60s, ISO 400)
- DSC04923.ARW: Cannon Beach sunset over Haystack Rock (f/11, 2.5s, ISO 50, ND filter)
- DSC04924.ARW: Multnomah Falls upper bridge cascade (f/16, 1.0s, ISO 64)

GPS Coordinates:
- Mt Rainier Camp: 46.8523° N, 121.7603° W
- Olympic Trailhead: 47.8021° N, 123.6044° W
""",
    "resume.txt": """Alex Mercer
Principal Systems Security Engineer | Cloud Infrastructure Architect
Email: alex.mercer@cyberdefense.internal | Location: Seattle, WA

PROFESSIONAL SUMMARY
Systems security engineer with 8+ years specializing in low-level kernel telemetry,
ransomware behavioral mitigation, and automated threat hunting pipelines.

TECHNICAL SKILLS
- Languages: Python, C/C++, Rust, Go, Bash, PowerShell
- Systems: Linux eBPF, Windows API, Kernel Driver Telemetry, Sysmon, Psutil
- Security: MITRE ATT&CK, YARA, Reverse Engineering, EDR Architecture

EXPERIENCE
Lead Detection Engineer - CyberShield Labs (2022 - Present)
- Architected tripwire deception systems protecting 50,000+ endpoints.
- Reduced mean time to detect (MTTD) and neutralize ransomware from minutes to <100ms.
"""
}


def generate_canary_file(filename: str, target_path: Path):
    """
    Generates realistic, low-entropy baseline files for each format in the canary fleet.
    Ensures correct binary structure, valid headers, and authentic payload semantics.
    Supports both classic and stealth anti-evasion filenames.
    """
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fname_lower = filename.lower()

    if fname_lower.endswith(".db") or "vault" in fname_lower:
        tf = tempfile.NamedTemporaryFile(delete=False)
        tmp_name = tf.name
        tf.close()
        try:
            with sqlite3.connect(tmp_name) as conn:
                conn.execute("CREATE TABLE customer_vault (id INT PRIMARY KEY, name TEXT, balance REAL, ach_routing TEXT);")
                for i in range(1, 51):
                    conn.execute("INSERT INTO customer_vault VALUES (?, ?, ?, ?)", (i, f"Enterprise_Client_{i:03d}", 250000.0 + (i * 1543.20), f"021000{i:03d}"))
                conn.commit()
            with open(tmp_name, "rb") as rf:
                target_path.write_bytes(rf.read())
        finally:
            if os.path.exists(tmp_name):
                try:
                    os.unlink(tmp_name)
                except Exception:
                    pass

    elif fname_lower.endswith(".xlsx") or "payroll" in fname_lower:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
            z.writestr("xl/workbook.xml", '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="Executive_Payroll_FY26" sheetId="1"/></sheets></workbook>')
            rows = "".join(f'<row r="{i}"><c r="A{i}" t="inlineStr"><is><t>Employee_{i:03d} | Salary: ${140000 + i*1500} | Bonus: ${25000 + i*250}</t></is></c></row>' for i in range(1, 40))
            z.writestr("xl/worksheets/sheet1.xml", f'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>{rows}</sheetData></worksheet>')
        target_path.write_bytes(buf.getvalue())

    elif fname_lower.endswith(".docx") or "contract" in fname_lower:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
            z.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>RESTRICTED MUTUAL NON-DISCLOSURE AND INTELLECTUAL PROPERTY ESCROW AGREEMENT (CONFIDENTIAL - 2026)</w:t></w:r></w:p></w:body></w:document>')
        target_path.write_bytes(buf.getvalue())

    elif fname_lower.endswith(".dat") or "tarpit" in fname_lower:
        header = "================================================================================\nCANARYSHIELD DISTRIBUTED ENTERPRISE LEDGER & TRANSACTION AUDIT ARCHIVE (TAR-PIT)\n================================================================================\n"
        record_block = ("[AUDIT-RECORD] TIMESTAMP=2026-09-30T12:00:00Z | TXN_ID=" + "FEDCBA9876543210" * 2 + " | TRANSFER=$100,000.00 TO SETTLEMENT ACCOUNT | STATUS=VERIFIED\n") * 100
        content = header + (record_block * 150)
        target_path.write_text(content, encoding="utf-8")

    elif fname_lower.endswith(".zip") or "archive" in fname_lower:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("backup_manifest.txt", REVERSE_CANARY_CONTENT)
            z.writestr("system_catalog.json", '{"dr_site": "East-US-Vault-9", "recovery_objective_mins": 15, "status": "PRISTINE"}')
        target_path.write_bytes(buf.getvalue())

    elif fname_lower.endswith(".bak") or "cold_storage" in fname_lower or "manifest" in fname_lower:
        target_path.write_text(REVERSE_CANARY_CONTENT, encoding="utf-8")

    elif "zz_" in fname_lower:
        target_path.write_text(REVERSE_CANARY_CONTENT, encoding="utf-8")

    else:
        # Fallback corporate financial records text
        target_path.write_text(DEFAULT_CANARY_CONTENT, encoding="utf-8")


def boost_process_priority() -> bool:
    """
    Sets process execution priority to HIGH_PRIORITY_CLASS on Windows.
    Guarantees OS kernel scheduling preemption against aggressive multithreaded ransomware crawlers.
    """
    if sys.platform == "win32":
        try:
            import psutil
            p = psutil.Process()
            p.nice(psutil.HIGH_PRIORITY_CLASS)
            return True
        except Exception:
            return False
    return False


def set_file_hidden(filepath: Path, hide: bool = True) -> bool:
    """
    Applies or removes the Windows FILE_ATTRIBUTE_HIDDEN attribute to prevent accidental human tampering.
    Ransomware crawlers using FindFirstFile/FindNextFile still enumerate hidden files, keeping traps active.
    """
    if sys.platform == "win32" and filepath.exists():
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_NORMAL = 0x80
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
            if attrs == -1:
                return False
            if hide:
                new_attrs = attrs | FILE_ATTRIBUTE_HIDDEN
            else:
                new_attrs = attrs & ~FILE_ATTRIBUTE_HIDDEN
            return bool(ctypes.windll.kernel32.SetFileAttributesW(str(filepath), new_attrs))
        except Exception:
            return False
    return False
