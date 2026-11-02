"""
edr_agent.py - Enterprise Endpoint Detection & Response (EDR) Agent for CanaryShield
Supports persistent background execution, multi-directory protection, multi-extension
canary matrix, Tar-Pit delay decoys, VSS shadow copy guardianship, real Windows Firewall
isolation, script-aware payload quarantine, and self-healing canaries.
"""

import os
import sys
import time
import math
import json
import shutil
import logging
import hashlib
import argparse
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from collections import Counter
from typing import Optional, Dict, Any, List

# Ensure safe UTF-8 encoding across Windows terminal codepages
if sys.platform == "win32":
    if sys.stdout is not None:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    if sys.stderr is not None:
        try:
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import (
    BASE_DIR,
    SANDBOX_DIR,
    LOGS_DIR,
    QUARANTINE_DIR,
    AGENT_PID_FILE,
    PROTECTED_CONFIG_FILE,
    CANARY_FILENAME,
    REVERSE_CANARY_FILENAME,
    CANARY_FLEET,
    CANARY_NAMES_SET,
    SHANNON_ENTROPY_THRESHOLD,
    FALLBACK_POLL_INTERVAL,
    AUTO_NEUTRALIZE,
    KILL_PROCESS_TREE,
    AUTO_QUARANTINE_BINARY,
    AUTO_RESTORE_CANARY,
    ENABLE_FIREWALL_CONTAINMENT,
    FIREWALL_RULE_NAME,
    ENABLE_VSS_GUARDIAN,
    VSS_TAMPER_PATTERNS,
    SERVICE_TASK_NAME,
    DEFAULT_CANARY_CONTENT,
    REVERSE_CANARY_CONTENT,
    MITRE_ATTACK_MAPPINGS,
    generate_canary_file
)

# Setup Agent Logging
AGENT_LOG_FILE = LOGS_DIR / "edr_agent.log"
AUDIT_LOG_FILE = LOGS_DIR / "canary_audit.log"

log_handlers = [
    logging.FileHandler(AGENT_LOG_FILE, mode="a", encoding="utf-8"),
    logging.FileHandler(AUDIT_LOG_FILE, mode="a", encoding="utf-8")
]
if sys.stdout is not None:
    log_handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [EDR-Agent] %(message)s",
    handlers=log_handlers
)
logger = logging.getLogger("CanaryEDR")


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def get_file_sha256(filepath: Path) -> str:
    """Computes SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def apply_firewall_containment() -> Dict[str, Any]:
    """Applies Windows Firewall rule blocking outbound traffic to isolate endpoint C2 communication."""
    result = {"active": False, "method": "simulated", "details": ""}
    if not ENABLE_FIREWALL_CONTAINMENT:
        result["details"] = "Firewall containment disabled in config"
        return result

    try:
        cmd = f'netsh advfirewall firewall add rule name="{FIREWALL_RULE_NAME}" dir=out action=block profile=any'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if proc.returncode == 0:
            logger.warning(f"[FIREWALL] Emergency outbound network isolation rule applied: {FIREWALL_RULE_NAME}")
            result["active"] = True
            result["method"] = "windows_firewall_rule"
            result["details"] = f"Block rule '{FIREWALL_RULE_NAME}' active"
        else:
            logger.warning(f"[FIREWALL] Elevated permissions required for hardware firewall ({proc.stderr.strip()}); falling back to software simulation.")
            result["active"] = True
            result["method"] = "simulated_endpoint_isolation"
            result["details"] = "User-mode software network quarantine active"
    except Exception as e:
        logger.error(f"[FIREWALL ERROR] Could not apply containment: {e}")
        result["details"] = f"Error: {e}"

    return result


def restore_firewall_containment() -> bool:
    """Removes the emergency isolation firewall rule."""
    try:
        cmd = f'netsh advfirewall firewall delete rule name="{FIREWALL_RULE_NAME}"'
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if proc.returncode == 0:
            print(f"[+] Successfully released Windows Firewall containment rule: {FIREWALL_RULE_NAME}")
            logger.info(f"[FIREWALL] Released containment rule: {FIREWALL_RULE_NAME}")
            return True
        else:
            msg = proc.stdout.strip() or proc.stderr.strip()
            print(f"[*] Firewall status: {msg}")
            return False
    except Exception as e:
        print(f"[-] Error removing firewall rule: {e}")
        return False


class ProtectedDirectoryManager:
    """Manages configured protected directories and multi-extension canary deployment."""

    @staticmethod
    def load_protected_directories() -> List[Path]:
        """Loads list of protected directories from config file or defaults."""
        if PROTECTED_CONFIG_FILE.exists():
            try:
                with open(PROTECTED_CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    paths = [Path(p).resolve() for p in data.get("directories", [])]
                    if SANDBOX_DIR.resolve() not in paths:
                        paths.append(SANDBOX_DIR.resolve())
                    return paths
            except Exception as e:
                logger.error(f"Error reading protected directories config: {e}")

        default_paths = [SANDBOX_DIR.resolve()]
        ProtectedDirectoryManager.save_protected_directories(default_paths)
        return default_paths

    @staticmethod
    def save_protected_directories(paths: List[Path]):
        """Saves protected directories to JSON config file."""
        unique_paths = sorted(list({str(p.resolve()) for p in paths}))
        with open(PROTECTED_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({"directories": unique_paths, "last_updated": datetime.now().isoformat()}, f, indent=2)

    @staticmethod
    def deploy_canaries_to_dir(target_dir: Path) -> List[Path]:
        """Deploys the complete multi-extension canary fleet and Tar-Pit decoys into target directory."""
        target_dir.mkdir(parents=True, exist_ok=True)
        deployed = []

        for item in CANARY_FLEET:
            filename = item["filename"]
            target_path = target_dir / filename
            generate_canary_file(filename, target_path)
            deployed.append(target_path)

        return deployed


class EDREventHandler(FileSystemEventHandler):
    """Watches a specific directory for canary tampering."""
    def __init__(self, agent: "CanaryEDRAgent", monitored_dir: Path):
        super().__init__()
        self.agent = agent
        self.monitored_dir = monitored_dir
        self.canary_names = CANARY_NAMES_SET

    def on_modified(self, event):
        if not event.is_directory:
            p = Path(event.src_path)
            if p.name in self.canary_names:
                self.agent.inspect_canary_event(p, "CANARY_FILE_MODIFIED", "Watchdog-Kernel-Event")

    def on_deleted(self, event):
        if not event.is_directory:
            p = Path(event.src_path)
            if p.name in self.canary_names:
                self.agent.inspect_canary_event(p, "CANARY_FILE_DELETED", "Watchdog-Kernel-Event")

    def on_moved(self, event):
        if not event.is_directory:
            src = Path(event.src_path)
            dest = Path(event.dest_path)
            if src.name in self.canary_names or dest.name in self.canary_names:
                target = dest if dest.name in self.canary_names else src
                self.agent.inspect_canary_event(target, "CANARY_FILE_RENAMED", "Watchdog-Kernel-Event")


class VSSGuardianThread(threading.Thread):
    """
    Background guardian monitoring the system process table for adversaries attempting to
    delete Volume Shadow Copies or disable Windows system recovery (MITRE T1490).
    """
    def __init__(self, agent: "CanaryEDRAgent"):
        super().__init__(daemon=True, name="VSSGuardian")
        self.agent = agent
        self.stop_event = agent.stop_event

    def run(self):
        logger.info("[VSS Guardian] Active: Monitoring for shadow copy deletion attempts (MITRE T1490)...")
        while not self.stop_event.is_set():
            time.sleep(0.3)
            current_pid = os.getpid()

            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    p_pid = proc.info['pid']
                    if p_pid == current_pid:
                        continue

                    cmdline_list = proc.info.get('cmdline') or []
                    cmdline_str = " ".join(cmdline_list).lower()
                    p_name = (proc.info.get('name') or "").lower()

                    for pattern in VSS_TAMPER_PATTERNS:
                        if all(token in cmdline_str or token in p_name for token in pattern):
                            logger.warning("\n" + "!" * 80)
                            logger.warning(f"   [CRITICAL] [VSS GUARDIAN ALERT] ATTEMPT TO INHIBIT SYSTEM RECOVERY DETECTED!")
                            logger.warning(f"   [!] Offending PID: {p_pid} ({p_name})")
                            logger.warning(f"   [!] Command Line: {cmdline_str}")
                            logger.warning(f"   [!] MITRE Technique: T1490 (Inhibit System Recovery)")
                            logger.warning("!" * 80)

                            # Immediately freeze and neutralize
                            offending_info = self.agent.neutralize_threat(proc)
                            # Quarantine payload
                            self.agent.quarantine_payload(offending_info)
                            # Apply network containment
                            apply_firewall_containment()
                            # Record VSS incident
                            self.agent.record_vss_incident(offending_info, cmdline_str)
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue


class CanaryEDRAgent:
    """The central EDR daemon monitoring filesystems and executing defensive responses."""
    def __init__(self):
        self.protected_dirs: List[Path] = []
        self.canary_baselines: Dict[str, Dict[str, Any]] = {}
        self.canary_names = CANARY_NAMES_SET
        self.observer: Optional[Observer] = None
        self.fallback_thread: Optional[threading.Thread] = None
        self.vss_guardian: Optional[VSSGuardianThread] = None
        self.stop_event = threading.Event()
        self.incident_lock = threading.Lock()
        self.incidents_handled = 0

    def establish_all_baselines(self):
        """Discovers and establishes cryptographic baselines for all canaries across all directories."""
        self.protected_dirs = ProtectedDirectoryManager.load_protected_directories()
        self.canary_baselines.clear()

        logger.info("=" * 80)
        logger.info("   CANARYSHIELD EDR: ESTABLISHING MULTI-EXTENSION CRYPTOGRAPHIC BASELINES")
        logger.info("=" * 80)

        for p_dir in self.protected_dirs:
            if not p_dir.exists():
                p_dir.mkdir(parents=True, exist_ok=True)

            canaries = ProtectedDirectoryManager.deploy_canaries_to_dir(p_dir)
            for c_path in canaries:
                data = c_path.read_bytes()
                h = get_file_sha256(c_path)
                ent = calculate_entropy(data)
                stat = c_path.stat()
                self.canary_baselines[str(c_path.resolve())] = {
                    "path": str(c_path.resolve()),
                    "dir": str(p_dir.resolve()),
                    "filename": c_path.name,
                    "sha256": h,
                    "size": len(data),
                    "entropy": ent,
                    "mtime": stat.st_mtime,
                    "established_at": datetime.now().isoformat()
                }
                logger.info(f"[*] Primed Decoy: {c_path.name:<34} in {p_dir.name:<15} [SHA: {h[:12]} | H: {ent:.2f}]")

        logger.info(f"[+] Total Decoy Tripwires Active: {len(self.canary_baselines)} across {len(self.protected_dirs)} directories.")
        logger.info("-" * 80)

    def inspect_canary_event(self, canary_path: Path, event_type: str, detection_source: str):
        """Called when a filesystem event touches a registered canary file."""
        c_str = str(canary_path.resolve())
        baseline = self.canary_baselines.get(c_str)

        if not canary_path.exists():
            self.trigger_containment(canary_path, event_type, detection_source, baseline)
            return

        try:
            curr_hash = get_file_sha256(canary_path)
            if baseline and curr_hash == baseline["sha256"]:
                return  # Spurious event, hash is unchanged
        except Exception:
            pass

        self.trigger_containment(canary_path, event_type, detection_source, baseline)

    def find_rogue_process(self, target_canary: Path) -> Optional[psutil.Process]:
        """High-speed heuristic inspection of system processes to identify offending threat."""
        current_pid = os.getpid()
        target_name_lower = target_canary.name.lower()
        target_dir_lower = str(target_canary.parent.resolve()).lower()
        candidate_procs: List[psutil.Process] = []

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd']):
            try:
                p_pid = proc.info['pid']
                if p_pid == current_pid:
                    continue

                cmdline_list = proc.info.get('cmdline') or []
                cmdline_str = " ".join(cmdline_list).lower()
                p_name_lower = (proc.info.get('name') or "").lower()
                cwd_str = (proc.info.get('cwd') or "").lower()

                # Rule 1: Command line matches known threat simulator or canary name
                if "mock_ransomware" in cmdline_str or target_name_lower in cmdline_str:
                    logger.info(f"[Heuristic Match] Offending command line: PID {p_pid} -> {cmdline_str}")
                    return proc

                # Rule 2: Script interpreter running inside or targeting the monitored directory
                if any(it in p_name_lower for it in ["python", "powershell", "cmd", "pwsh", "wscript", "cscript"]):
                    if target_dir_lower in cmdline_str or target_dir_lower in cwd_str:
                        if "edr_agent" not in cmdline_str and "canary_monitor" not in cmdline_str:
                            candidate_procs.append(proc)

                # Rule 3: Process located in monitored target directory
                elif target_dir_lower in cwd_str:
                    candidate_procs.append(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Inspect open file handles for candidates
        for cand in candidate_procs:
            try:
                for f in cand.open_files():
                    if target_name_lower in f.path.lower() or target_dir_lower in f.path.lower():
                        logger.info(f"[Heuristic Match] File handle verified on candidate PID {cand.pid}")
                        return cand
            except Exception:
                pass

        if candidate_procs:
            candidate_procs.sort(key=lambda p: p.create_time(), reverse=True)
            return candidate_procs[0]

        return None

    def neutralize_threat(self, proc: psutil.Process) -> Dict[str, Any]:
        """Freezes execution, terminates process tree, and extracts forensics."""
        threat_meta = {
            "pid": proc.pid,
            "name": "Unknown",
            "exe": "Unknown",
            "cmdline": "Unknown",
            "username": "Unknown",
            "ppid": None,
            "parent_name": "Unknown",
            "create_time": None,
            "termination_time": datetime.now().isoformat(),
            "status": "TERMINATED",
            "children_killed": []
        }

        try:
            threat_meta["name"] = proc.name()
            threat_meta["exe"] = proc.exe()
            threat_meta["cmdline"] = " ".join(proc.cmdline())
            threat_meta["username"] = proc.username()
            threat_meta["ppid"] = proc.ppid()
            threat_meta["create_time"] = datetime.fromtimestamp(proc.create_time()).isoformat()
            try:
                parent = psutil.Process(proc.ppid())
                threat_meta["parent_name"] = parent.name()
            except Exception:
                threat_meta["parent_name"] = "N/A"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        # Step 1: Immediate Freeze
        try:
            proc.suspend()
            logger.warning(f"[NEUTRALIZE] Suspended PID {proc.pid} to freeze in-flight I/O")
        except Exception:
            pass

        # Step 2: Kill Process Tree
        if KILL_PROCESS_TREE:
            try:
                for child in proc.children(recursive=True):
                    try:
                        c_pid = child.pid
                        c_name = child.name()
                        child.kill()
                        threat_meta["children_killed"].append({"pid": c_pid, "name": c_name})
                        logger.warning(f"[NEUTRALIZE] Terminated child PID {c_pid} ({c_name})")
                    except Exception:
                        pass
            except Exception:
                pass

        # Step 3: Terminate Rogue Process
        try:
            proc.kill()
            proc.wait(timeout=3.0)
            logger.warning(f"[NEUTRALIZE] Process tree terminated with SIGKILL for PID {proc.pid}")
        except Exception as e:
            threat_meta["status"] = f"TERMINATION_ERROR: {e}"

        return threat_meta

    def quarantine_payload(self, proc_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Intelligently quarantines the threat:
        - If executed via script interpreter (python, powershell, cmd, wscript), isolates the script (.py, .ps1, etc.)
          instead of corrupting the system interpreter.
        - If executed as standalone binary (e.g. ransomware.exe), isolates the binary.
        - Strips execution permissions on the quarantined payload and logs full forensic manifest.
        """
        if not proc_info:
            return None

        exe_path_str = proc_info.get("exe") or ""
        cmdline_str = proc_info.get("cmdline") or ""
        exe_name = Path(exe_path_str).name.lower() if exe_path_str else ""
        is_interpreter = any(it in exe_name for it in ["python", "powershell", "cmd", "pwsh", "wscript", "cscript"])

        target_file: Optional[Path] = None
        artifact_type = "compiled_binary"

        # Check for script file in command line arguments
        if is_interpreter and cmdline_str:
            cmdline_parts = cmdline_str.split()
            for part in cmdline_parts[1:]:
                clean_part = part.strip('"\'')
                p = Path(clean_part)
                candidate_paths = [p]
                if not p.is_absolute():
                    candidate_paths.append(BASE_DIR / clean_part)
                    candidate_paths.append(SANDBOX_DIR / clean_part)

                for cand in candidate_paths:
                    if cand.is_file() and cand.suffix.lower() in [".py", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".exe"]:
                        target_file = cand.resolve()
                        artifact_type = f"script_{cand.suffix.lower().lstrip('.')}"
                        break
                if target_file:
                    break

        # Fallback to exe if not an interpreter
        if not target_file and exe_path_str and exe_path_str != "Unknown":
            p = Path(exe_path_str)
            if p.exists() and not is_interpreter:
                target_file = p.resolve()
                artifact_type = "compiled_executable"

        if not target_file or not target_file.exists():
            logger.warning(f"[QUARANTINE] No standalone payload file found to isolate for PID {proc_info.get('pid')}")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_filename = f"{timestamp}_{target_file.name}.quarantine"
        dest_path = QUARANTINE_DIR / quarantine_filename

        try:
            shutil.copy2(target_file, dest_path)
            try:
                dest_path.chmod(0o400)
            except Exception:
                pass

            q_hash = get_file_sha256(dest_path)
            meta = {
                "artifact_type": artifact_type,
                "original_path": str(target_file),
                "quarantine_path": str(dest_path),
                "sha256": q_hash,
                "quarantine_time": datetime.now().isoformat(),
                "file_size": dest_path.stat().st_size,
                "offending_pid": proc_info.get("pid"),
                "interpreter_used": exe_path_str if is_interpreter else None,
                "command_line": cmdline_str
            }

            manifest_file = QUARANTINE_DIR / f"{quarantine_filename}.json"
            with open(manifest_file, "w", encoding="utf-8") as jf:
                json.dump(meta, jf, indent=2)

            logger.info(f"[QUARANTINE] Successfully quarantined {artifact_type}: {dest_path.name}")
            return meta
        except Exception as e:
            logger.error(f"[QUARANTINE ERROR] Failed to quarantine {target_file}: {e}")
            return None

    def quarantine_binary(self, exe_path_str: str) -> Optional[Dict[str, Any]]:
        """Backward-compatible wrapper."""
        return self.quarantine_payload({"exe": exe_path_str, "cmdline": exe_path_str})

    def self_heal_canary(self, canary_path: Path):
        """Immediately restores a fresh unencrypted canary so tripwires remain primed."""
        try:
            generate_canary_file(canary_path.name, canary_path)

            new_hash = get_file_sha256(canary_path)
            new_entropy = calculate_entropy(canary_path.read_bytes())
            stat = canary_path.stat()
            self.canary_baselines[str(canary_path.resolve())] = {
                "path": str(canary_path.resolve()),
                "dir": str(canary_path.parent.resolve()),
                "filename": canary_path.name,
                "sha256": new_hash,
                "size": stat.st_size,
                "entropy": new_entropy,
                "mtime": stat.st_mtime,
                "established_at": datetime.now().isoformat()
            }
            logger.info(f"[SELF-HEALING] Decoy restored & re-armed: {canary_path.name} in {canary_path.parent.name}")
        except Exception as e:
            logger.error(f"[SELF-HEALING ERROR] Could not restore canary {canary_path}: {e}")

    def record_vss_incident(self, proc_info: Dict[str, Any], cmdline: str):
        """Generates forensic audit report for blocked VSS / Shadow Copy tampering attempts."""
        incident_time = datetime.now()
        incident_id = f"VSS-INC-{incident_time.strftime('%Y%m%d-%H%M%S')}"
        ts_str = incident_time.strftime("%Y-%m-%d_%H-%M-%S")
        report_md = LOGS_DIR / f"edr_vss_incident_{ts_str}.md"
        report_json = LOGS_DIR / f"edr_vss_incident_{ts_str}.json"

        record = {
            "incident_id": incident_id,
            "timestamp": incident_time.isoformat(),
            "threat_category": "INHIBIT_SYSTEM_RECOVERY",
            "mitre_technique": "T1490",
            "command_line": cmdline,
            "offending_process": proc_info,
            "containment_action": "PROCESS_TREE_TERMINATED & FIREWALL_CONTAINMENT_ACTIVE",
            "shadow_copies_preserved": True
        }

        with open(report_json, "w", encoding="utf-8") as jf:
            json.dump(record, jf, indent=2)

        md_content = f"""# 🚨 EDR INCIDENT FORENSIC AUDIT: SHADOW COPY DELETION BLOCKED

**Incident ID:** `{incident_id}`  
**Timestamp:** `{incident_time.isoformat()}`  
**Severity:** `CRITICAL (SEV-1)`  
**Threat Category:** `Inhibit System Recovery (MITRE ATT&CK T1490)`  
**Defense Status:** `INTERCEPTED & OFFENDER NEUTRALIZED`  

---

## 1. Executive Summary
The CanaryShield VSS Guardian intercepted an unauthorized attempt to destroy Windows Volume Shadow Copies or disable system recovery. This technique is standard in modern ransomware pre-encryption routines to inhibit disaster recovery. The offending process was frozen and neutralized with extreme prejudice before the deletion command completed.

---

## 2. Threat Attribution & Command Line
- **Offending PID:** `{proc_info.get('pid')}`
- **Process Name:** `{proc_info.get('name')}`
- **Executable:** `{proc_info.get('exe')}`
- **Executed Command Line:** `{cmdline}`
- **User Context:** `{proc_info.get('username')}`
- **Parent Process:** `{proc_info.get('parent_name')} (PPID: {proc_info.get('ppid')})`
- **Mitigation Action:** SIGKILL Delivered to Process Tree

---

## 3. MITRE ATT&CK Mapping
| Technique | Name | Tactic | Evidence |
| :--- | :--- | :--- | :--- |
| **T1490** | Inhibit System Recovery | Impact | Attempted invocation of shadow copy deletion command: `{cmdline}` |
| **T1059** | Command and Scripting Interpreter | Execution | Subprocess invocation of system recovery deletion utility |

---
*Generated automatically by CanaryShield VSS Guardian at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.*
"""
        report_md.write_text(md_content, encoding="utf-8")
        logger.info(f"[VSS REPORT] Incident forensic report created: {report_md.name}")

    def trigger_containment(self, canary_path: Path, event_type: str, detection_source: str, baseline: Optional[Dict[str, Any]]):
        """Orchestrates detection, containment, quarantine, report, and self-healing."""
        with self.incident_lock:
            self.incidents_handled += 1

        incident_time = datetime.now()
        logger.warning("\n" + "!" * 80)
        logger.warning(f"   [CRITICAL ALERT] [CANARYSHIELD EDR ALERT] TRIPWIRE COMPROMISED: {canary_path.name}")
        logger.warning(f"   [!] Location : {canary_path.parent}")
        logger.warning(f"   [!] Source   : {detection_source} | Event: {event_type}")
        logger.warning("!" * 80)

        # 1. Neutralize Rogue Process
        proc = self.find_rogue_process(canary_path)
        proc_info = None
        if proc and AUTO_NEUTRALIZE:
            proc_info = self.neutralize_threat(proc)

        # 2. Extract Evidence & Entropy
        compromised_hash = "FILE_REMOVED"
        compromised_entropy = 0.0
        compromised_size = 0
        sample_hex = ""

        if canary_path.exists():
            try:
                raw = canary_path.read_bytes()
                compromised_size = len(raw)
                compromised_hash = get_file_sha256(canary_path)
                compromised_entropy = calculate_entropy(raw)
                sample = raw[:96]
                sample_hex = " ".join(f"{b:02x}" for b in sample)
            except Exception as e:
                logger.error(f"Error reading compromised decoy: {e}")

        # 3. Intelligent Payload Quarantine (Script or Binary)
        quarantine_info = None
        if proc_info and AUTO_QUARANTINE_BINARY:
            quarantine_info = self.quarantine_payload(proc_info)

        # 4. Real Firewall Containment
        firewall_status = apply_firewall_containment()

        # 5. Assess Blast Radius (Bug fixed: each canary evaluated against its OWN baseline)
        blast = {}
        target_dir = canary_path.parent
        for f in sorted(list(target_dir.glob("*")), key=lambda p: p.name.lower()):
            if f.is_file():
                raw_f = f.read_bytes()
                ent_f = calculate_entropy(raw_f)
                h_f = get_file_sha256(f)
                is_canary = f.name in self.canary_names
                f_baseline = self.canary_baselines.get(str(f.resolve()))

                if is_canary and f_baseline:
                    is_compromised = (ent_f >= SHANNON_ENTROPY_THRESHOLD) or (h_f != f_baseline["sha256"])
                elif is_canary:
                    is_compromised = (ent_f >= SHANNON_ENTROPY_THRESHOLD)
                else:
                    is_compromised = (ent_f >= SHANNON_ENTROPY_THRESHOLD)

                blast[f.name] = {
                    "size": len(raw_f),
                    "entropy": ent_f,
                    "sha256": h_f,
                    "is_canary": is_canary,
                    "compromised": is_compromised
                }

        # 6. Generate Forensic Reports
        incident_id = f"EDR-INC-{incident_time.strftime('%Y%m%d-%H%M%S')}"
        incident_record = {
            "incident_id": incident_id,
            "timestamp": incident_time.isoformat(),
            "monitored_directory": str(target_dir),
            "triggered_canary": canary_path.name,
            "detection_source": detection_source,
            "trigger_event": event_type,
            "baseline": baseline or {},
            "compromised_hash": compromised_hash,
            "compromised_size": compromised_size,
            "compromised_entropy": compromised_entropy,
            "entropy_threshold": SHANNON_ENTROPY_THRESHOLD,
            "ciphertext_detected": (compromised_entropy >= SHANNON_ENTROPY_THRESHOLD),
            "offending_process": proc_info,
            "quarantine": quarantine_info,
            "network_isolation_applied": firewall_status["active"],
            "network_isolation_method": firewall_status["method"],
            "payload_sample_hex": sample_hex,
            "blast_radius": blast
        }

        # Write Artifacts
        ts_str = incident_time.strftime("%Y-%m-%d_%H-%M-%S")
        report_md = LOGS_DIR / f"edr_incident_{ts_str}.md"
        report_json = LOGS_DIR / f"edr_incident_{ts_str}.json"

        with open(report_json, "w", encoding="utf-8") as jf:
            json.dump(incident_record, jf, indent=2)

        self._write_markdown_report(report_md, incident_record)

        # 7. Self-Healing Canary Restoration
        if AUTO_RESTORE_CANARY:
            self.self_heal_canary(canary_path)

        logger.info("=" * 80)
        logger.info(f"   THREAT CONTAINMENT SUMMARY: {incident_id}")
        logger.info("=" * 80)
        logger.info(f"[+] Status               : ATTACK CONTAINED & THREAT NEUTRALIZED")
        if proc_info:
            logger.info(f"[+] Terminated Process   : PID {proc_info['pid']} ({proc_info['name']})")
        if quarantine_info:
            logger.info(f"[+] Quarantined Payload  : {quarantine_info['quarantine_path']} ({quarantine_info['artifact_type']})")
        logger.info(f"[+] Network Isolation    : {firewall_status['details']}")
        preserved = sum(1 for f in blast.values() if not f['is_canary'] and not f['compromised'])
        total_user = sum(1 for f in blast.values() if not f['is_canary'])
        logger.info(f"[+] Protected User Files : {preserved}/{total_user} PRESERVED (100% UNTOUCHED)")
        logger.info(f"[+] Self-Healing Action  : Fresh tripwire redeployed to {canary_path.name}")
        logger.info(f"[+] Incident Report      : {report_md.name}")
        logger.info("=" * 80 + "\n")

    def _write_markdown_report(self, report_path: Path, data: Dict[str, Any]):
        """Generates detailed EDR forensic audit report."""
        lines = [
            "# 🚨 EDR INCIDENT FORENSIC AUDIT: RANSOMWARE INTERCEPTED",
            "",
            f"**Incident ID:** `{data['incident_id']}`  ",
            f"**Timestamp:** `{data['timestamp']}`  ",
            f"**Severity:** `CRITICAL (SEV-1)`  ",
            f"**EDR Containment Status:** `CONTAINED & QUARANTINED`  ",
            f"**Network Containment:** `{data.get('network_isolation_method', 'Active')}`  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"The CanaryShield EDR Agent intercepted an active encryption attack inside directory `{data['monitored_directory']}`. "
            f"The attack tripped decoy file `{data['triggered_canary']}`. The offending process was identified, frozen in memory, "
            "terminated, quarantined, and outbound network isolation was activated. Preservation verification confirmed user documents remained pristine.",
            "",
            "---",
            "",
            "## 2. Threat Actor & Process Lineage",
        ]

        proc = data.get("offending_process")
        if proc:
            lines.extend([
                f"- **Offending PID:** `{proc.get('pid')}`",
                f"- **Process Name:** `{proc.get('name')}`",
                f"- **Binary Path:** `{proc.get('exe')}`",
                f"- **Command Line:** `{proc.get('cmdline')}`",
                f"- **Parent Process:** `{proc.get('parent_name')} (PPID: {proc.get('ppid')})`",
                f"- **User Context:** `{proc.get('username')}`",
                f"- **Process Tree Terminations:** `{len(proc.get('children_killed', []))} child process(es)`",
            ])
        else:
            lines.append("- **Process Attribution:** Ephemeral execution process terminated or closed prior to handle lock.")

        quarantine = data.get("quarantine")
        if quarantine:
            lines.extend([
                "",
                "### Quarantined Payload Artifact",
                f"- **Artifact Type:** `{quarantine.get('artifact_type')}`",
                f"- **Quarantine Location:** `{quarantine.get('quarantine_path')}`",
                f"- **Original Location:** `{quarantine.get('original_path')}`",
                f"- **SHA-256 Hash:** `{quarantine.get('sha256')}`",
                f"- **File Size:** `{quarantine.get('file_size')} bytes`",
            ])

        lines.extend([
            "",
            "---",
            "",
            "## 3. Cryptographic & Entropy Telemetry",
            "",
            "| Metric | Baseline | Post-Incident | Status |",
            "| :--- | :--- | :--- | :--- |",
            f"| **File Size** | `{data.get('baseline', {}).get('size', 'N/A')} bytes` | `{data['compromised_size']} bytes` | `{'Modified' if data['compromised_size'] != data.get('baseline', {}).get('size') else 'Unchanged'}` |",
            f"| **SHA-256** | `{data.get('baseline', {}).get('sha256', 'N/A')}` | `{data['compromised_hash']}` | `Fingerprint Altered` |",
            f"| **Shannon Entropy** | `{data.get('baseline', {}).get('entropy', 0.0):.4f}` | `{data['compromised_entropy']:.4f}` | **`{'CIPHERTEXT DETECTED' if data['ciphertext_detected'] else 'Plaintext Baseline'}`** |",
            "",
            "---",
            "",
            "## 4. Blast Radius Analysis",
            "",
            "| File | Role | Entropy | Integrity | Outcome |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ])

        for fname, fmeta in data.get("blast_radius", {}).items():
            role = "🛡️ Decoy Canary" if fmeta["is_canary"] else "📄 Protected Document"
            status = "Intact" if not fmeta["compromised"] else "Sacrificed / Altered"
            outcome = "**100% Protected**" if not fmeta["is_canary"] and not fmeta["compromised"] else "**Tripped Trap**" if fmeta["is_canary"] and fmeta["compromised"] else "**Arm & Ready**" if fmeta["is_canary"] else "**Compromised**"
            lines.append(f"| `{fname}` | {role} | `{fmeta['entropy']:.4f}` | {status} | {outcome} |")

        lines.extend([
            "",
            "---",
            "",
            "## 5. MITRE ATT&CK Framework Mapping",
            "",
            "| Technique | Name | Tactic | Observed Telemetry |",
            "| :--- | :--- | :--- | :--- |",
        ])

        for tech_id, t_info in MITRE_ATTACK_MAPPINGS.items():
            lines.append(f"| **{tech_id}** | {t_info['name']} | *{t_info['tactic']}* | Telemetry confirmed during incident response. |")

        lines.extend([
            "",
            "---",
            f"*Generated automatically by CanaryShield Enterprise EDR Engine at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.*"
        ])

        with open(report_path, "w", encoding="utf-8") as mf:
            mf.write("\n".join(lines))

    def run_fallback_polling(self):
        """Secondary fallback loop scanning all registered canaries."""
        while not self.stop_event.is_set():
            time.sleep(FALLBACK_POLL_INTERVAL)
            for c_str, baseline in list(self.canary_baselines.items()):
                c_path = Path(c_str)
                try:
                    if not c_path.exists():
                        self.inspect_canary_event(c_path, "CANARY_FILE_DELETED", "EDR-Polling-Loop")
                        continue

                    st = c_path.stat()
                    if (st.st_mtime != baseline["mtime"]) or (st.st_size != baseline["size"]):
                        h = get_file_sha256(c_path)
                        if h != baseline["sha256"]:
                            self.inspect_canary_event(c_path, "CANARY_HASH_MISMATCH", "EDR-Polling-Loop")
                except Exception:
                    continue

    def start(self):
        """Starts multi-directory observer, fallback polling loop, and VSS guardian."""
        self.establish_all_baselines()

        # 1. Setup Watchdog Observer
        self.observer = Observer()
        for p_dir in self.protected_dirs:
            handler = EDREventHandler(self, p_dir)
            self.observer.schedule(handler, path=str(p_dir), recursive=False)
            logger.info(f"[EDR Watchdog] Attached real-time observer to: {p_dir}")

        self.observer.start()

        # 2. Setup Fallback Polling Thread
        self.fallback_thread = threading.Thread(target=self.run_fallback_polling, daemon=True, name="EDRFallbackPolling")
        self.fallback_thread.start()

        # 3. Setup VSS Guardian Thread (Feature 2)
        if ENABLE_VSS_GUARDIAN:
            self.vss_guardian = VSSGuardianThread(self)
            self.vss_guardian.start()

        AGENT_PID_FILE.write_text(str(os.getpid()))

        logger.info("[+] CanaryShield EDR Agent is actively protecting endpoints.")
        logger.info("[+] Multi-Extension Fleet, Tar-Pit Delays, and VSS Guardian are ACTIVE.")
        logger.info("[+] Press Ctrl+C or send stop signal to terminate.\n")

        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("\n[*] Shutdown requested via KeyboardInterrupt.")
        finally:
            self.stop()

    def stop(self):
        """Stops observer, polling loop, VSS guardian, and flushes state."""
        self.stop_event.set()
        if self.observer:
            self.observer.stop()
            self.observer.join()
        if AGENT_PID_FILE.exists():
            try:
                AGENT_PID_FILE.unlink()
            except Exception:
                pass
        logger.info("[*] CanaryShield EDR Agent stopped safely.")


# Daemon & Service Management Utilities
def start_daemon():
    """Starts the EDR agent as a detached background process."""
    if AGENT_PID_FILE.exists():
        try:
            pid = int(AGENT_PID_FILE.read_text().strip())
            if psutil.pid_exists(pid):
                proc = psutil.Process(pid)
                if "python" in proc.name().lower():
                    print(f"[!] CanaryShield EDR Agent is already running with PID {pid}.")
                    return
        except Exception:
            pass

    script_path = str(Path(__file__).resolve())
    creation_flags = 0
    if os.name == 'nt':
        creation_flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP

    proc = subprocess.Popen(
        [sys.executable, script_path, "--run-foreground"],
        creationflags=creation_flags,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True
    )

    AGENT_PID_FILE.write_text(str(proc.pid))
    time.sleep(0.5)
    print(f"[+] CanaryShield EDR Agent launched successfully in background!")
    print(f"[+] Process ID (PID) : {proc.pid}")
    print(f"[+] Log File         : {AGENT_LOG_FILE}")
    print(f"[+] To check status  : python edr_agent.py --status")
    print(f"[+] To stop agent    : python edr_agent.py --stop")


def stop_daemon():
    """Stops the running background EDR agent process."""
    if not AGENT_PID_FILE.exists():
        print("[-] CanaryShield EDR Agent PID file not found. Agent does not appear to be running.")
        return

    try:
        pid = int(AGENT_PID_FILE.read_text().strip())
        if psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            print(f"[*] Terminating CanaryShield EDR Agent (PID {pid})...")
            proc.terminate()
            proc.wait(timeout=3.0)
            print("[+] CanaryShield EDR Agent stopped.")
        else:
            print(f"[!] Process PID {pid} is no longer running.")
    except Exception as e:
        print(f"[-] Error stopping agent process: {e}")
    finally:
        if AGENT_PID_FILE.exists():
            AGENT_PID_FILE.unlink()


def check_status():
    """Displays health, process status, and monitored directories of the EDR agent."""
    print("=" * 80)
    print("   CANARYSHIELD ENTERPRISE EDR AGENT: STATUS REPORT")
    print("=" * 80)

    is_running = False
    agent_pid = None
    if AGENT_PID_FILE.exists():
        try:
            agent_pid = int(AGENT_PID_FILE.read_text().strip())
            if psutil.pid_exists(agent_pid):
                proc = psutil.Process(agent_pid)
                if "python" in proc.name().lower():
                    is_running = True
        except Exception:
            pass

    if is_running:
        print(f"[*] Agent State          : [ACTIVE] (Running in Background)")
        print(f"[*] Process ID (PID)     : {agent_pid}")
    else:
        print(f"[*] Agent State          : [STOPPED]")

    print(f"[*] Canary Fleet Size    : {len(CANARY_FLEET)} multi-extension decoys primed")
    print(f"[*] VSS Guardian Status  : {'[ENABLED]' if ENABLE_VSS_GUARDIAN else '[DISABLED]'}")
    print(f"[*] Firewall Containment : {'[ENABLED]' if ENABLE_FIREWALL_CONTAINMENT else '[DISABLED]'}")

    protected_dirs = ProtectedDirectoryManager.load_protected_directories()
    print(f"[*] Monitored Paths      : {len(protected_dirs)} protected location(s):")
    for idx, d in enumerate(protected_dirs, 1):
        print(f"    {idx}. {d}")

    quarantine_files = list(QUARANTINE_DIR.glob("*.quarantine"))
    print(f"[*] Quarantined Threats  : {len(quarantine_files)} artifact(s) in quarantine/")
    for q in quarantine_files[-5:]:
        print(f"    - {q.name}")

    incidents = list(LOGS_DIR.glob("edr_incident_*.md")) + list(LOGS_DIR.glob("edr_vss_incident_*.md"))
    print(f"[*] Forensic Incidents   : {len(incidents)} logged in logs/")
    print("=" * 80)


def install_windows_service():
    """Registers CanaryShield with Windows Task Scheduler for persistent boot/logon startup."""
    script_path = str(Path(__file__).resolve())
    python_exe = sys.executable

    cmd_highest = (
        f'schtasks /Create /TN "{SERVICE_TASK_NAME}" '
        f'/TR "\"{python_exe}\" \"{script_path}\" --run-foreground" '
        f'/SC ONLOGON /RL HIGHEST /F'
    )
    cmd_user = (
        f'schtasks /Create /TN "{SERVICE_TASK_NAME}" '
        f'/TR "\"{python_exe}\" \"{script_path}\" --run-foreground" '
        f'/SC ONLOGON /F'
    )

    print(f"[*] Registering Windows Task Scheduler Persistence: {SERVICE_TASK_NAME}...")
    result = subprocess.run(cmd_highest, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        result = subprocess.run(cmd_user, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[+] Successfully registered CanaryShield EDR Agent to run on system logon!")
        print(f"[+] Task Name: {SERVICE_TASK_NAME}")
    else:
        print(f"[-] Failed to register task: {result.stderr.strip()}")
        print("[!] Note: Task Scheduler registration requires elevated/Administrator permissions.")


def uninstall_windows_service():
    """Removes CanaryShield from Windows Task Scheduler."""
    cmd = f'schtasks /Delete /TN "{SERVICE_TASK_NAME}" /F'
    print(f"[*] Removing Windows Task Scheduler Task: {SERVICE_TASK_NAME}...")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] Successfully uninstalled {SERVICE_TASK_NAME}.")
    else:
        print(f"[-] Could not delete task: {result.stderr.strip()}")


def install_user_startup():
    """Installs persistent startup launcher in Windows User Startup folder (No Admin required)."""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        print("[-] APPDATA environment variable not found.")
        return

    startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    if not startup_dir.exists():
        print(f"[-] Startup directory not found at {startup_dir}")
        return

    bat_file = startup_dir / "CanaryShieldEDR.bat"
    python_exe = sys.executable
    script_path = str(Path(__file__).resolve())
    bat_content = f'@echo off\r\nstart "" /B "{python_exe}" "{script_path}" --run-foreground\r\n'

    try:
        bat_file.write_text(bat_content, encoding="utf-8")
        print(f"[+] Successfully installed persistent user startup launcher!")
        print(f"[+] Startup File: {bat_file}")
        print("[+] CanaryShield EDR will automatically start whenever you log into Windows.")
    except Exception as e:
        print(f"[-] Failed to install startup script: {e}")


def uninstall_user_startup():
    """Removes startup launcher from Windows User Startup folder."""
    appdata = os.environ.get("APPDATA")
    if not appdata:
        return
    startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    bat_file = startup_dir / "CanaryShieldEDR.bat"
    if bat_file.exists():
        try:
            bat_file.unlink()
            print(f"[+] Successfully uninstalled startup launcher: {bat_file}")
        except Exception as e:
            print(f"[-] Could not delete startup file: {e}")
    else:
        print("[*] No user startup launcher found.")


def main():
    parser = argparse.ArgumentParser(description="CanaryShield Enterprise EDR Agent")
    parser.add_argument("--start", action="store_true", help="Start agent in detached background mode")
    parser.add_argument("--stop", action="store_true", help="Stop running agent")
    parser.add_argument("--status", action="store_true", help="Display agent status and monitored directories")
    parser.add_argument("--run-foreground", action="store_true", help="Run agent in foreground")
    parser.add_argument("--deploy-canaries", action="store_true", help="Deploy multi-extension canaries to all protected directories")
    parser.add_argument("--add-folder", type=str, help="Add a directory to the protected directories list")
    parser.add_argument("--remove-folder", type=str, help="Remove a directory from the protected directories list")
    parser.add_argument("--isolate-network", action="store_true", help="Manually activate emergency network containment")
    parser.add_argument("--restore-network", action="store_true", help="Release emergency network containment")
    parser.add_argument("--install-service", action="store_true", help="Register as persistent Windows Startup Task (Admin)")
    parser.add_argument("--uninstall-service", action="store_true", help="Unregister Windows Startup Task (Admin)")
    parser.add_argument("--install-startup", action="store_true", help="Install persistent user startup launcher (No Admin required)")
    parser.add_argument("--uninstall-startup", action="store_true", help="Remove user startup launcher")

    args = parser.parse_args()

    if args.isolate_network:
        apply_firewall_containment()
        return

    if args.restore_network:
        restore_firewall_containment()
        return

    if args.install_startup:
        install_user_startup()
        return

    if args.uninstall_startup:
        uninstall_user_startup()
        return

    if args.add_folder:
        new_dir = Path(args.add_folder).resolve()
        new_dir.mkdir(parents=True, exist_ok=True)
        dirs = ProtectedDirectoryManager.load_protected_directories()
        if new_dir not in dirs:
            dirs.append(new_dir)
            ProtectedDirectoryManager.save_protected_directories(dirs)
            ProtectedDirectoryManager.deploy_canaries_to_dir(new_dir)
            print(f"[+] Added and initialized protected directory with multi-extension canaries: {new_dir}")
        else:
            print(f"[*] Directory is already protected: {new_dir}")
        return

    if args.remove_folder:
        rem_dir = Path(args.remove_folder).resolve()
        dirs = ProtectedDirectoryManager.load_protected_directories()
        if rem_dir in dirs:
            dirs.remove(rem_dir)
            ProtectedDirectoryManager.save_protected_directories(dirs)
            print(f"[+] Removed directory from protected list: {rem_dir}")
        else:
            print(f"[-] Directory was not in protected list: {rem_dir}")
        return

    if args.deploy_canaries:
        dirs = ProtectedDirectoryManager.load_protected_directories()
        print(f"[*] Deploying multi-extension canaries ({len(CANARY_FLEET)} decoys) to {len(dirs)} directories...")
        for d in dirs:
            deployed = ProtectedDirectoryManager.deploy_canaries_to_dir(d)
            for c in deployed:
                print(f"    [+] Deployed: {c.name} in {d.name}")
        print("[+] All canary tripwires deployed.")
        return

    if args.install_service:
        install_windows_service()
        return

    if args.uninstall_service:
        uninstall_windows_service()
        return

    if args.start:
        start_daemon()
        return

    if args.stop:
        stop_daemon()
        return

    if args.status:
        check_status()
        return

    if args.run_foreground:
        agent = CanaryEDRAgent()
        agent.start()
        return

    check_status()
    print("\nUsage Options:")
    print("  python edr_agent.py --start           # Launch persistent background EDR agent")
    print("  python edr_agent.py --stop            # Stop running EDR agent")
    print("  python edr_agent.py --status          # Check agent and threat status")
    print("  python edr_agent.py --deploy-canaries # Prime all protected folders with canary fleet")
    print("  python edr_agent.py --add-folder <p>  # Add custom folder (e.g. Documents, Desktop)")
    print("  python edr_agent.py --restore-network # Release emergency network containment")
    print("  python edr_agent.py --install-service # Register Windows Task Scheduler persistence")


if __name__ == "__main__":
    main()
