"""
mock_ransomware.py - Safe, Non-Destructive Ransomware Attack Simulator
STRICTLY SCOPED TO sandbox/ DIRECTORY.

This simulator mimics realistic modern ransomware behavior:
1. Enumerates files alphabetically (A to Z) so the tripwire canary is attacked first.
2. In-place overwrites target files with high-entropy scrambled ciphertext.
3. Introduces a deliberate 1-second delay between target files so the automated
   interception and process termination can be observed in real time.
"""

import os
import sys
import time
import math
from pathlib import Path
from collections import Counter

from config import SANDBOX_DIR, CANARY_FILENAME, CANARY_NAMES_SET

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
    """
    Generates high-entropy scrambled payload simulating AES-256 / ChaCha20 encryption.
    Prepend a simulated ransomware header followed by cryptographic pseudorandom bytes.
    """
    header = b"--- [ENCRYPTED BY MOCK-RANSOMWARE v2.4 | CONTACT DECRYPT@TEST.LOCAL] ---\n"
    random_bytes_needed = max(original_length, 256)
    payload = header + os.urandom(random_bytes_needed)
    return payload

def run_attack():
    current_pid = os.getpid()
    print("=" * 75)
    print("   [!] MOCK RANSOMWARE SIMULATOR (SAFE LAB TEST HARNESS)")
    print(f"   [!] Process ID (PID) : {current_pid}")
    print(f"   [!] Target Sandbox   : {SANDBOX_DIR}")
    print("=" * 75)

    # SAFETY CHECK: Strictly verify that target directory is sandbox/
    sandbox_resolved = SANDBOX_DIR.resolve()
    if not sandbox_resolved.exists():
        print(f"[ERROR] Target sandbox directory {sandbox_resolved} does not exist!")
        print("[!] Please run `python setup_environment.py` first.")
        sys.exit(1)

    # Safety check against root or parent directory traversal
    if sandbox_resolved == Path.cwd().resolve() or sandbox_resolved == Path.home().resolve():
        print("[CRITICAL] Safety check failed: Target directory must be isolated sandbox!")
        sys.exit(1)

    # Discover and sort files alphabetically (A-Z)
    # The canary '!_canary_financial_records.txt' starts with '!' (ASCII 33),
    # guaranteeing it appears first before any letters or numbers.
    target_files = sorted([f for f in sandbox_resolved.glob("*") if f.is_file()])

    if not target_files:
        print("[!] No target files found in sandbox. Run `python setup_environment.py` first.")
        sys.exit(0)

    print(f"[*] Discovery Phase: Found {len(target_files)} target file(s) in sandbox:")
    for idx, f in enumerate(target_files, start=1):
        is_canary = (f.name in CANARY_NAMES_SET)
        tag = " <--- [TRIPWIRE CANARY]" if is_canary else ""
        print(f"    {idx}. {f.name}{tag}")

    print("\n[*] Commencing simulated high-entropy encryption traversal...")
    print("[*] (A 1.0-second delay is inserted between targets to observe live defense)\n")

    files_encrypted_count = 0

    for idx, target_file in enumerate(target_files, start=1):
        target_name = target_file.name
        print(f"--> [TARGET {idx}/{len(target_files)}] Infiltrating: {target_name}")

        try:
            original_size = target_file.stat().st_size
            payload = generate_ciphertext_payload(original_size)
            entropy = calculate_entropy(payload)

            # Write high-entropy payload
            with open(target_file, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())

            files_encrypted_count += 1
            print(f"    [+] Overwritten with high-entropy ciphertext ({len(payload)} bytes).")
            print(f"    [+] Calculated Payload Entropy: {entropy:.4f} bits/byte (High Entropy: > 7.0)")

            if target_name in CANARY_NAMES_SET:
                print(f"    [!] WARNING: Tripwire Canary '{target_name}' has been modified!")
                print("    [!] Waiting for CanaryShield Defender to intervene...")

            # 1-second delay so defender has time to intercept before next file
            time.sleep(1.0)

        except Exception as e:
            print(f"    [X] Attack interrupted on {target_name}: {e}")
            break

    print("\n" + "=" * 75)
    print(f"[*] Attack Simulation Cycle Finished. Total files encrypted: {files_encrypted_count}/{len(target_files)}")
    if files_encrypted_count == len(target_files):
        print("[!] Warning: All files were encrypted. Was canary_monitor.py running?")
    else:
        print("[+] Early termination observed! Tripwire successfully quarantined the threat.")
    print("=" * 75)

if __name__ == "__main__":
    run_attack()
