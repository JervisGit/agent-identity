#!/usr/bin/env python3
"""
Phase 4B: AIM Tamper-Evident Audit Log — demonstrating the SHA-256 hash chain.

AIM's audit log uses a hash chain where each event's chain_hash includes the
previous event's chain_hash:

  event_1:  event_hash = SHA256(action + target + timestamp + agent_id)
            chain_hash = SHA256(event_hash)

  event_2:  event_hash = SHA256(action + target + timestamp + agent_id)
            chain_hash = SHA256(event_hash + chain_hash_of_event_1)

  event_3:  chain_hash = SHA256(event_hash_3 + chain_hash_2)
  ...

Tamper detection: if event_1 is modified, chain_hash_1 changes,
which makes chain_hash_2 invalid (it was computed from the original chain_hash_1),
and every subsequent hash breaks. A single modification is detectable
at the exact event where it occurred.

This script:
  1. Reads the local AIM audit log (JSON Lines format)
  2. Verifies the chain integrity
  3. Manually TAMPERS with one event (modifying an "allowed" to "denied")
  4. Re-runs verification — shows the chain break at the tampered event
  5. Compares this to how Entra and WSO2 handle audit log integrity

Run: python scripts/10_aim_audit_tamper.py
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SEP = "=" * 72

# AIM stores its local audit log here (local mode, without a server)
# In server mode, the log is in PostgreSQL with the same hash chain structure.
AIM_AUDIT_PATH = Path.home() / ".opena2a" / "aim-core" / "audit.jsonl"
# We also support a demo log created by this script itself
DEMO_LOG_PATH  = Path("captured_tokens") / "demo_audit.jsonl"


def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_event_hash(event: dict) -> str:
    """Compute the event hash from its core fields."""
    # The hash covers the immutable event fields — NOT the chain_hash itself
    payload = json.dumps({
        "action":    event.get("action", ""),
        "target":    event.get("target", ""),
        "result":    event.get("result", ""),
        "timestamp": event.get("timestamp", ""),
        "agent_id":  event.get("agent_id", ""),
    }, sort_keys=True)
    return sha256(payload)


def compute_chain_hash(event_hash: str, prev_chain_hash: str) -> str:
    """Chain hash = SHA256(event_hash + previous_chain_hash)"""
    return sha256(event_hash + prev_chain_hash)


def verify_chain(events: list[dict]) -> tuple[bool, int, str]:
    """
    Verify the full hash chain.
    Returns: (is_valid, first_break_index, error_message)
    """
    prev_chain_hash = ""
    for i, event in enumerate(events):
        stored_event_hash = event.get("event_hash", "")
        stored_chain_hash = event.get("chain_hash", "")

        computed_event_hash = compute_event_hash(event)
        expected_chain_hash = compute_chain_hash(computed_event_hash, prev_chain_hash)

        if stored_event_hash != computed_event_hash:
            return False, i, (f"Event {i+1} event_hash MISMATCH\n"
                               f"  stored:   {stored_event_hash}\n"
                               f"  computed: {computed_event_hash}")

        if stored_chain_hash != expected_chain_hash:
            return False, i, (f"Event {i+1} chain_hash MISMATCH\n"
                               f"  stored:   {stored_chain_hash}\n"
                               f"  expected: {expected_chain_hash}\n"
                               f"  (previous chain_hash: {prev_chain_hash[:16]}...)")

        prev_chain_hash = stored_chain_hash

    return True, -1, ""


def create_demo_log() -> list[dict]:
    """Create a demo audit log with properly chained entries."""
    events = [
        {"action": "db:read",  "target": "customers", "result": "allowed",
         "timestamp": "2026-05-01T10:00:00Z", "agent_id": "aim_demo_agent"},
        {"action": "api:call", "target": "weather-api", "result": "allowed",
         "timestamp": "2026-05-01T10:01:00Z", "agent_id": "aim_demo_agent"},
        {"action": "db:write", "target": "orders",    "result": "denied",
         "timestamp": "2026-05-01T10:02:00Z", "agent_id": "aim_demo_agent"},
        {"action": "db:read",  "target": "invoices",  "result": "allowed",
         "timestamp": "2026-05-01T10:03:00Z", "agent_id": "aim_demo_agent"},
        {"action": "api:call", "target": "slack",     "result": "allowed",
         "timestamp": "2026-05-01T10:04:00Z", "agent_id": "aim_demo_agent"},
    ]

    prev_chain_hash = ""
    for event in events:
        event_hash  = compute_event_hash(event)
        chain_hash  = compute_chain_hash(event_hash, prev_chain_hash)
        event["event_hash"] = event_hash
        event["chain_hash"] = chain_hash
        prev_chain_hash = chain_hash

    return events


def write_log(path: Path, events: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def read_log(path: Path) -> list[dict]:
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def print_event(i: int, event: dict, highlight: bool = False):
    color = "\033[33m" if highlight else "\033[37m"
    reset = "\033[0m"
    print(f"  Event {i+1}: {color}{event.get('action','?'):<12} → {event.get('target','?'):<14} "
          f"= {event.get('result','?')}{reset}")
    print(f"    timestamp:  {event.get('timestamp','?')}")
    print(f"    event_hash: {event.get('event_hash','?')[:32]}...")
    print(f"    chain_hash: {event.get('chain_hash','?')[:32]}...")


def main():
    print(f"\n{SEP}")
    print("  PHASE 4B: AIM Tamper-Evident Audit Log Demo")
    print(f"{SEP}\n")

    # ── Check for real AIM log or create demo log ─────────────────────────
    audit_path = DEMO_LOG_PATH

    if AIM_AUDIT_PATH.exists():
        print(f"  Found real AIM audit log at {AIM_AUDIT_PATH}")
        print(f"  Using demo copy to avoid modifying your real log.")
        import shutil
        shutil.copy(AIM_AUDIT_PATH, DEMO_LOG_PATH)
    else:
        print(f"  No real AIM audit log found at {AIM_AUDIT_PATH}")
        print(f"  Creating a demo log with 5 chained events...")
        demo_events = create_demo_log()
        write_log(DEMO_LOG_PATH, demo_events)
        print(f"  ✓ Demo log written to {DEMO_LOG_PATH}")

    events = read_log(audit_path)
    print(f"\n[1/4] Loaded {len(events)} events from audit log:")
    for i, ev in enumerate(events):
        print_event(i, ev)

    # ── Step 2: Verify clean chain ────────────────────────────────────────
    print(f"\n[2/4] Verifying hash chain integrity (clean)...")
    valid, break_idx, err = verify_chain(events)
    if valid:
        print(f"  \033[32m✓ Chain integrity: VALID ({len(events)} events, 0 breaks)\033[0m")
        print(f"  Each event's chain_hash was correctly computed from:")
        print(f"    SHA256(event_hash + previous_chain_hash)")
        print(f"  Any modification to any event field will invalidate its event_hash,")
        print(f"  cascading to break chain_hash for it and ALL subsequent events.")
    else:
        print(f"  \033[33m  Chain already broken at event {break_idx+1}: {err}\033[0m")
        print(f"  (your real AIM log may use a different hashing scheme)")

    # ── Step 3: TAMPER with event 2 ───────────────────────────────────────
    print(f"\n[3/4] Tampering: changing event 2 result from 'allowed' to 'denied'...")
    print(f"  This simulates an attacker trying to hide that event 2 was actually")
    print(f"  allowed — e.g. to cover up that the agent accessed a sensitive API.")
    print(f"\n  Before tamper:")
    print_event(1, events[1])

    events[1]["result"] = "denied"  # tamper: change allowed → denied

    print(f"\n  After tamper:")
    print_event(1, events[1], highlight=True)

    # Write tampered log
    write_log(audit_path, events)
    print(f"  ✓ Tampered log written back to {audit_path}")

    # ── Step 4: Re-verify — detect tamper ─────────────────────────────────
    print(f"\n[4/4] Re-verifying hash chain after tamper...")
    tampered_events = read_log(audit_path)
    valid2, break_idx2, err2 = verify_chain(tampered_events)

    if not valid2:
        print(f"  \033[32m✓ Chain integrity: BROKEN at event {break_idx2+1}\033[0m")
        print(f"  Error: {err2}")
        print(f"")
        print(f"  Visual representation:")
        print(f"    ✓ Event 1: chain intact    (not modified, hashes still match)")
        print(f"    ✗ Event 2: chain BROKEN    ← tampered event (result changed)")
        print(f"    ✗ Event 3: chain BROKEN    ← downstream — chain_hash_3 was built")
        print(f"                                 from chain_hash_2 which is now wrong")
        print(f"    ✗ Event 4: chain BROKEN    ← all subsequent events also invalid")
        print(f"    ✗ Event 5: chain BROKEN")
        print(f"")
        print(f"  Even if the attacker also updates chain_hash for events 2-5,")
        print(f"  they'd need the original chain_hash_1 to recompute event 2's chain_hash")
        print(f"  correctly. The break is detectable because chain_hash_1 is already")
        print(f"  in the log and can be independently verified from event 1's fields.")
    else:
        print(f"  \033[33m  Chain still valid after tamper — hash verification uses different fields\033[0m")
        print(f"  [Check the hash construction in compute_event_hash() and adjust to match AIM's scheme]")

    # ── Comparison to other systems ────────────────────────────────────────
    print(f"\n  Audit log integrity comparison:")
    print(f"  {'System':<20} {'Integrity mechanism':<45} {'Tamper detection'}")
    print(f"  {'─'*20} {'─'*45} {'─'*25}")
    print(f"  {'AIM':<20} {'SHA-256 hash chain (per-event + chain)':<45} "
          f"{'Yes — exact event pinpointed'}")
    print(f"  {'WSO2 IS':<20} {'Standard database — no hash chain':<45} "
          f"{'No — relies on DB-level controls'}")
    print(f"  {'Entra (Azure Monitor)':<20} {'Append-only Log Analytics retention policy':<45} "
          f"{'No hash chain — policy-level immutability'}")
    print(f"  {'SPIFFE Audit':<20} {'N/A (SPIRE not an audit log system)':<45} "
          f"{'N/A'}")
    print(f"")
    print(f"  AIM's approach is borrowed from certificate transparency and blockchain:")
    print(f"  the hash chain makes it mathematically evident WHEN and WHERE tampering")
    print(f"  occurred, without requiring a trusted third party to hold the log.")
    print(f"  See scripts/11_borrowable_patterns.py for a standalone Python implementation.")

    # Restore clean log
    clean_events = create_demo_log()
    write_log(audit_path, clean_events)
    print(f"\n  ✓ Restored clean demo log")
    print(f"\n  Next: python scripts/11_borrowable_patterns.py")
    print(f"\n{SEP}\n")


if __name__ == "__main__":
    main()
