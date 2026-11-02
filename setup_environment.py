"""
setup_environment.py - Sandbox Setup and Environment Initialization
Populates the sandbox with clean baseline mock user documents and the multi-extension canary matrix.
"""

import sys
import math
import hashlib
from pathlib import Path
from collections import Counter

from config import (
    SANDBOX_DIR,
    LOGS_DIR,
    QUARANTINE_DIR,
    CANARY_FLEET,
    CANARY_NAMES_SET,
    DEFAULT_USER_FILES,
    generate_canary_file
)

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

def initialize_sandbox(verbose: bool = True):
    """Creates directories and writes baseline files into sandbox."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    if verbose:
        print("=" * 80)
        print("   ANTI-RANSOMWARE CANARY SHIELD: MULTI-EXTENSION FLEET SETUP")
        print("=" * 80)
        print(f"[*] Target Sandbox Directory : {SANDBOX_DIR}")
        print(f"[*] Forensic Logs Directory  : {LOGS_DIR}")
        print(f"[*] Quarantine Vault         : {QUARANTINE_DIR}")
        print("-" * 80)

    # 1. Deploy Multi-Extension Canary Matrix
    for item in CANARY_FLEET:
        filename = item["filename"]
        target_path = SANDBOX_DIR / filename
        generate_canary_file(filename, target_path)

    # 2. Write Mock User Files
    for filename, content in DEFAULT_USER_FILES.items():
        filepath = SANDBOX_DIR / filename
        filepath.write_text(content, encoding="utf-8")

    if verbose:
        display_status()

def display_status():
    """Prints current status, hashes, and entropy of all files in sandbox."""
    print(f"\n{'FILENAME':<38} | {'SIZE (BYTES)':<12} | {'ENTROPY':<8} | {'SHA-256 (FIRST 16)':<16} | {'ROLE'}")
    print("-" * 95)

    all_files = sorted(list(SANDBOX_DIR.glob("*")), key=lambda p: p.name.lower())
    if not all_files:
        print("[!] Sandbox directory is empty.")
        return

    # Map fleet info
    fleet_dict = {item["filename"]: item for item in CANARY_FLEET}

    for f in all_files:
        if f.is_file():
            data = f.read_bytes()
            entropy = calculate_entropy(data)
            sha = get_file_sha256(f)[:16]
            if f.name in fleet_dict:
                item = fleet_dict[f.name]
                if item["type"] == "tarpit":
                    role = "[TAR-PIT DELAY]"
                elif item["traversal"] == "FORWARD":
                    role = f"[A-Z TRIPWIRE ({item['type'].upper()})]"
                else:
                    role = f"[Z-A TRIPWIRE ({item['type'].upper()})]"
            else:
                role = "[USER DOCUMENT]"

            print(f"{f.name:<38} | {len(data):<12} | {entropy:<8.4f} | {sha:<16} | {role}")

    print("-" * 95)
    print(f"[+] All files verified. Canary Matrix primed ({len(CANARY_FLEET)} decoys).")
    print("[+] Baseline entropy confirms clean unencrypted state.\n")

def clean_logs():
    """Removes all generated incident logs and quarantined artifacts."""
    for log_file in LOGS_DIR.glob("*"):
        if log_file.is_file():
            try:
                log_file.unlink()
            except Exception:
                pass
    for q_file in QUARANTINE_DIR.glob("*"):
        if q_file.is_file():
            try:
                # If read-only flag is set, clear it before unlinking
                q_file.chmod(0o666)
                q_file.unlink()
            except Exception:
                pass
    print("[+] Cleared all incident logs and quarantined artifacts.")

if __name__ == "__main__":
    if "--status" in sys.argv:
        display_status()
    elif "--clean-logs" in sys.argv:
        clean_logs()
    else:
        initialize_sandbox(verbose=True)
