"""
advanced_mock_ransomware.py - Advanced Ransomware Simulator for CanaryShield EDR
Simulates:
1. Forward (A-Z) and Reverse (Z-A) multi-extension file crawler traversals.
2. Adversarial Volume Shadow Copy (VSS) tampering commands (MITRE T1490).
Strictly scoped to authorized target directories.
"""

import os
import sys
import time
import math
import argparse
import subprocess
from pathlib import Path
from collections import Counter

from config import SANDBOX_DIR, CANARY_NAMES_SET


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


def generate_ciphertext_payload(original_length: int) -> bytes:
    """Generates high-entropy scrambled simulated ciphertext."""
    header = b"--- [ENCRYPTED BY ADVANCED-RANSOMWARE-SIMULATOR | MITRE T1486] ---\n"
    random_bytes_needed = max(original_length, 256)
    return header + os.urandom(random_bytes_needed)


def simulate_vss_tamper():
    """
    Simulates adversarial execution of recovery inhibition (MITRE T1490).
    Spawns a mock subprocess with command line invoking 'vssadmin delete shadows /all /quiet'.
    The CanaryShield VSS Guardian should catch and kill this subprocess immediately.
    """
    print("=" * 78)
    print("   [!] SIMULATING ADVERSARIAL VSS SHADOW COPY DELETION (MITRE T1490)")
    print("=" * 78)
    print("[*] Spawning subprocess invoking mock shadow copy deletion command:")
    cmd = [sys.executable, "-c", "import time; print('[VSS Inhibit Payload] Active: vssadmin delete shadows /all /quiet'); time.sleep(15)"]
    print(f"[*] Command: {' '.join(cmd)}")
    print("[*] Waiting for CanaryShield VSS Guardian to intercept and neutralize...")

    proc = subprocess.Popen(cmd)
    try:
        proc.wait(timeout=5.0)
        print(f"[!] Subprocess exited with returncode: {proc.returncode}")
        if proc.returncode != 0:
            print("[+] Interception confirmed: Process was terminated by CanaryShield EDR!")
        else:
            print("[!] Process ran to completion. Is EDR Agent running with VSS Guardian enabled?")
    except subprocess.TimeoutExpired:
        print("[!] Timeout: Process was not killed within 5 seconds.")
        proc.kill()


def simulate_attack(target_dir: Path, reverse_order: bool = False, delay: float = 1.0):
    pid = os.getpid()
    resolved_dir = target_dir.resolve()

    print("=" * 78)
    print("   [!] ADVANCED RANSOMWARE SIMULATOR (SAFE LAB TEST HARNESS)")
    print(f"   [!] Process ID (PID)  : {pid}")
    print(f"   [!] Target Directory  : {resolved_dir}")
    print(f"   [!] Traversal Pattern : {'REVERSE (Z -> A)' if reverse_order else 'FORWARD (A -> Z)'}")
    print("=" * 78)

    if not resolved_dir.exists():
        print(f"[ERROR] Target directory {resolved_dir} does not exist!")
        return

    # Safety: avoid system directories
    if resolved_dir in [Path("C:/"), Path("C:/Windows"), Path.home().resolve()]:
        print("[CRITICAL] Safety check failed: Cannot target root or home directly!")
        return

    all_files = sorted([f for f in resolved_dir.glob("*") if f.is_file()], key=lambda f: f.name.lower(), reverse=reverse_order)

    if not all_files:
        print("[!] No files found in target directory.")
        return

    print(f"[*] Discovery Phase: Found {len(all_files)} target file(s) in order of attack:")
    canary_names_lower = {n.lower() for n in CANARY_NAMES_SET}
    for idx, f in enumerate(all_files, 1):
        is_canary = f.name.lower() in canary_names_lower
        tag = " <--- [DECEPTION TRIPWIRE]" if is_canary else ""
        print(f"    {idx}. {f.name}{tag}")

    print("\n[*] Commencing simulated encryption attack traversal...")
    print(f"[*] (Inserting {delay}s delay between targets to observe live EDR intervention)\n")

    files_encrypted = 0
    for idx, target_file in enumerate(all_files, 1):
        print(f"--> [TARGET {idx}/{len(all_files)}] Overwriting: {target_file.name}")
        try:
            sz = target_file.stat().st_size
            payload = generate_ciphertext_payload(sz)
            entropy = calculate_entropy(payload)

            with open(target_file, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())

            files_encrypted += 1
            print(f"    [+] Overwritten with ciphertext ({len(payload)} bytes).")
            print(f"    [+] Calculated Entropy: {entropy:.4f} bits/byte (High Entropy > 7.0)")

            if target_file.name.lower() in canary_names_lower:
                print(f"    [!] WARNING: Tripwire decoy '{target_file.name}' has been altered!")
                print("    [!] Waiting for CanaryShield EDR Agent to neutralize attack...")

            time.sleep(delay)

        except Exception as e:
            print(f"    [X] Attack halted on {target_file.name}: {e}")
            break

    print("\n" + "=" * 78)
    print(f"[*] Attack Cycle Ended. Files encrypted: {files_encrypted}/{len(all_files)}")
    if files_encrypted == len(all_files):
        print("[!] All files were encrypted. Ensure EDR agent is running!")
    else:
        print("[+] Early attack termination observed! EDR successfully safeguarded assets.")
    print("=" * 78)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Ransomware Simulation Harness")
    parser.add_argument("--reverse", action="store_true", help="Perform reverse alphabetical traversal (Z to A)")
    parser.add_argument("--dir", type=str, default=str(SANDBOX_DIR), help="Target directory for simulation")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between files in seconds")
    parser.add_argument("--vss-tamper", action="store_true", help="Simulate Volume Shadow Copy deletion attack (MITRE T1490)")

    args = parser.parse_args()

    if args.vss_tamper:
        simulate_vss_tamper()
    else:
        simulate_attack(target_dir=Path(args.dir), reverse_order=args.reverse, delay=args.delay)
