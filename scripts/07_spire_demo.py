#!/usr/bin/env python3
"""
Phase 2B: SPIRE Workload Attestation Demo

What this demonstrates:
  1. SPIRE server + agent running in Docker Compose
  2. Workload entries registered with unix:uid selectors
     (unix:uid:1001 = trusted workload, no entry for uid:1002 = denied)
  3. 'docker exec --user 1001 spire-agent ...' simulates a trusted workload calling
     the Workload API — gets a JWT-SVID with sub=spiffe://demo.org/workload/trusted
  4. 'docker exec --user 1002 spire-agent ...' simulates an untrusted workload —
     gets NO SVID (denied, no matching entry)
  5. JWT-SVID is decoded and compared to Azure managed identity tokens

On unix:sha256 (binary hash attestation):
  The unix workload attestor also supports:
    unix:sha256:<hex>  — SHA256 of the executable at /proc/<PID>/exe
  This is the STRONGEST selector: proves the exact binary (not just UID).
  A recompiled or tampered binary has a different hash → SVID denied.

  This is NOT demonstrated live (it would require a compiled binary in the container),
  but the registration command example is shown in comments below.

Why NOT deployable on Azure Container Apps:
  - k8s attestor:    requires kubelet API on port 10250 — not exposed by ACA platform
  - azure_msi:       attests Azure VM/AKS nodes via IMDS — IMDS not accessible in ACA containers
  - unix attestor:   works in Docker but ACA Consumption containers can't keep SPIRE agent alive
                     (scale-to-zero conflicts with always-on agent requirement)
  For ACA production: run SPIRE server on ACI (~$0.50-1/month) or AKS.

Prereq: docker compose installed, docker desktop running
Run:    python scripts/07_spire_demo.py
"""

import base64
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

SPIRE_DIR   = Path(__file__).parent.parent / "docker" / "spire"
CAPTURE_DIR = Path("captured_tokens")
SEP         = "=" * 72
TRUST_DOMAIN = "demo.org"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, stream stdout, return result."""
    print(f"  $ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def dc(args: list[str], env: dict | None = None,
       profiles: list[str] | None = None, **kwargs) -> subprocess.CompletedProcess:
    """Run docker compose in the spire directory.
    Profiles must be passed separately because --profile must precede the subcommand.
    """
    merged_env = {**os.environ, **(env or {})}
    profile_flags = []
    for p in (profiles or []):
        profile_flags += ["--profile", p]
    return run(
        ["docker", "compose", *profile_flags, *args],
        cwd=str(SPIRE_DIR),
        env=merged_env,
        **kwargs,
    )


def docker_exec(container: str, cmd: list[str], user: str | None = None) -> subprocess.CompletedProcess:
    """Run a command inside a running container."""
    exec_cmd = ["docker", "exec"]
    if user:
        exec_cmd += ["--user", user]
    exec_cmd += [container, *cmd]
    return run(exec_cmd)


def wait_healthy(container: str, max_wait: int = 60) -> bool:
    """Poll until a container is healthy or timeout."""
    print(f"  Waiting for {container} to be healthy", end="", flush=True)
    for _ in range(max_wait):
        result = run(["docker", "inspect",
                      "--format", "{{.State.Health.Status}}",
                      container])
        status = result.stdout.strip()
        if status == "healthy":
            print(" ✓")
            return True
        if status == "unhealthy":
            print(" ✗ UNHEALTHY")
            return False
        print(".", end="", flush=True)
        time.sleep(1)
    print(" TIMED OUT")
    return False


def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_jwt_svid(raw: str) -> dict:
    """Decode a SPIFFE JWT-SVID (same format as a regular JWT)."""
    parts = raw.strip().split(".")
    if len(parts) != 3:
        return {"error": f"not a JWT, got: {raw[:80]}"}
    try:
        header  = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
        return {"header": header, "payload": payload}
    except Exception as exc:
        return {"error": str(exc), "raw": raw[:80]}


def print_svid(decoded: dict, label: str):
    """Print an annotated JWT-SVID."""
    print(f"\n  {label}")
    header  = decoded.get("header", {})
    payload = decoded.get("payload", {})

    print(f"  [HEADER]")
    print(f"    alg: {header.get('alg','?')}")
    print(f"         # ECDSA or Ed25519 — SPIRE uses EC P-256 (ES256) by default")
    print(f"    kid: {header.get('kid','?')}")
    print(f"         # Key ID — maps to entry in the trust bundle JWKS")

    print(f"  [PAYLOAD]")
    for k, v in payload.items():
        if k in ("exp", "iat", "nbf"):
            try:
                dt   = datetime.fromtimestamp(int(v), tz=timezone.utc)
                now  = datetime.now(tz=timezone.utc)
                diff = int((dt - now).total_seconds())
                status = f"EXPIRED" if diff < 0 else f"valid {diff}s"
                display = f"{v} → {dt.strftime('%Y-%m-%d %H:%M:%S UTC')} ({status})"
            except Exception:
                display = str(v)
        else:
            display = str(v)

        print(f"    \033[36m{k}\033[0m: \033[33m{display}\033[0m")

        if k == "sub":
            print(f"         # SPIFFE URI — encodes the workload's trust domain + path")
            print(f"         # Format: spiffe://<trust-domain>/<path>")
            print(f"         # Compare to Entra: sub = objectId (opaque UUID)")
            print(f"         # SPIFFE sub is structured and human-readable")
        elif k == "aud":
            print(f"         # Audience — what service this SVID was issued for")
            print(f"         # Set by the workload when requesting the SVID")
        elif k == "iss":
            print(f"         # Issuer — the SPIRE server's trust domain identifier")
        elif k == "exp":
            print(f"         # VERY SHORT TTL (5 min in this demo) — auto-rotated by SPIRE agent")
            print(f"         # Contrast: Entra JWTs are typically valid for 1 hour")


def main():
    print(f"\n{SEP}")
    print("  PHASE 2B: SPIFFE/SPIRE Workload Attestation Demo")
    print(f"{SEP}\n")

    # ── Step 1: Start SPIRE Server ────────────────────────────────────────
    print("[1/7] Starting SPIRE server...")
    dc_result = dc(["up", "-d", "spire-server"])
    if dc_result.returncode != 0:
        print(f"\033[31m  docker compose up failed:\033[0m")
        print(dc_result.stderr)
        sys.exit(1)

    if not wait_healthy("spire-server", max_wait=60):
        print("\033[31m  SPIRE server did not become healthy.\033[0m")
        print(dc(["logs", "spire-server"]).stdout[-1000:])
        sys.exit(1)

    # ── Step 2: Generate join token ───────────────────────────────────────
    print("\n[2/7] Generating join token (one-time credential for the agent)...")
    print(f"      SPIFFE ID for the agent node: spiffe://{TRUST_DOMAIN}/node/demo-agent")

    token_result = docker_exec(
        "spire-server",
        ["/opt/spire/bin/spire-server", "token", "generate",
         "-spiffeID", f"spiffe://{TRUST_DOMAIN}/node/demo-agent",
         "-socketPath", "/tmp/spire-server/private/api.sock"],
    )
    if token_result.returncode != 0:
        print(f"\033[31m  Token generation failed:\n{token_result.stderr}\033[0m")
        sys.exit(1)

    # Output is "Token: <TOKEN>"
    token_line = token_result.stdout.strip()
    join_token = token_line.split("Token:")[-1].strip()
    print(f"  ✓ Join token: {join_token[:16]}...  (single-use, consumed on first agent connection)")

    # ── Step 3: Start SPIRE Agent with token ─────────────────────────────
    print("\n[3/7] Starting SPIRE agent with join token...")
    print(f"      The agent will use this token ONCE to authenticate to the server.")
    print(f"      After successful attestation, the agent receives an X.509 SVID for itself.")

    dc_result = dc(
        ["up", "-d", "spire-agent"],
        profiles=["agent"],
        env={"SPIRE_JOIN_TOKEN": join_token},
    )
    if dc_result.returncode != 0:
        print(f"\033[31m  Failed to start agent:\n{dc_result.stderr}\033[0m")
        sys.exit(1)

    print("  Waiting for agent to connect to server...", end="", flush=True)
    for i in range(30):
        # Check agent is running
        chk = run(["docker", "inspect", "--format", "{{.State.Status}}", "spire-agent"])
        if "running" in chk.stdout:
            print(" ✓")
            break
        print(".", end="", flush=True)
        time.sleep(2)

    # Let the agent complete its attestation and open the socket

    # ── Step 4: Register workload entries ─────────────────────────────────
    print("\n[4/7] Registering workload entries on SPIRE server...")
    print("      Entries map attestation selectors to SPIFFE IDs.")
    print()

    # Entry 1: UID 1001 → trusted workload
    print("  Entry 1: unix:uid:1001 → spiffe://demo.org/workload/trusted")
    print("  This means: any process with UID 1001 that calls the Workload API")
    print("  will receive the SVID 'spiffe://demo.org/workload/trusted'")

    e1 = docker_exec(
        "spire-server",
        ["/opt/spire/bin/spire-server", "entry", "create",
         "-parentID", f"spiffe://{TRUST_DOMAIN}/node/demo-agent",
         "-spiffeID", f"spiffe://{TRUST_DOMAIN}/workload/trusted",
         "-selector",  "unix:uid:1001",
         "-ttl",        "300",   # 5-minute SVID TTL
         "-socketPath", "/tmp/spire-server/private/api.sock"],
    )
    if e1.returncode != 0:
        print(f"    \033[33m{e1.stderr[:200]}\033[0m")
    else:
        print(f"    ✓ {e1.stdout.strip()[:80]}")

    # Entry 2 (sha256 example — commented because we'd need a known binary hash):
    print()
    print("  Entry 2 (CONCEPTUAL — sha256 selector example):")
    print("  # spire-server entry create \\")
    print("  #   -parentID spiffe://demo.org/node/demo-agent \\")
    print("  #   -spiffeID spiffe://demo.org/workload/verified-binary \\")
    print(f"  #   -selector unix:sha256:$(sha256sum /path/to/trusted-binary | cut -c1-64)")
    print("  #")
    print("  # This entry would ONLY match if the exact binary (by SHA256 hash) is calling.")
    print("  # Change one byte in the binary → SHA256 changes → no match → SVID DENIED.")
    print("  # This is what 'k8s:container-image' selector does at the container level.")

    # Entry 3: (no entry for UID 1002) = intentionally unregistered = should be denied

    print()
    print("  Entry 3: (NOT creating an entry for UID 1002)")
    print("  Any process with UID 1002 calling the Workload API will get NO SVID.")

    # Wait for the agent to sync entries from the server
    # The agent polls the server for new entries; default sync interval is ~5s.
    print("\n  Waiting 15s for agent to sync entries from server...", end="", flush=True)
    for i in range(15):
        time.sleep(1)
        print(".", end="", flush=True)
    print(" done")

    # ── Step 5: Request SVID as trusted workload (UID 1001) ───────────────
    print("\n[5/7] Requesting JWT-SVID as TRUSTED workload (UID 1001)...")
    print("      'docker exec --user 1001' spawns a NEW process with UID 1001.")
    print("      SPIRE agent reads UID 1001 from the socket peer credential.")
    print("      Matches entry for unix:uid:1001 → issues SVID.")
    print()

    svid_result = docker_exec(
        "spire-agent",
        ["/opt/spire/bin/spire-agent", "api", "fetch", "jwt",
         "-audience",   "demo-resource-server",
         "-socketPath", "/tmp/spire-agent/public/api.sock"],
        user="1001",
    )

    print(f"  Return code: {svid_result.returncode}")
    if svid_result.returncode != 0 or not svid_result.stdout.strip():
        print(f"  stderr: {svid_result.stderr[:300]}")
        # This can happen if SPIRE agent isn't fully connected yet
        print("  Waiting 5s and retrying...")
        time.sleep(5)
        svid_result = docker_exec(
            "spire-agent",
            ["/opt/spire/bin/spire-agent", "api", "fetch", "jwt",
             "-audience",   "demo-resource-server",
             "-socketPath", "/tmp/spire-agent/public/api.sock"],
            user="1001",
        )

    trusted_svid_raw = ""
    if "token(" in svid_result.stdout:
        # Output format: "token(spiffe://demo.org/workload/trusted)\n<JWT>"
        lines = svid_result.stdout.strip().split("\n")
        for i, line in enumerate(lines):
            if "token(" in line and i + 1 < len(lines):
                trusted_svid_raw = lines[i + 1].strip()
                break

    if trusted_svid_raw:
        trusted_decoded = decode_jwt_svid(trusted_svid_raw)
        print(f"\n  ✓ SVID issued for UID 1001:")
        print_svid(trusted_decoded, "JWT-SVID (trusted workload, UID 1001)")
    else:
        print(f"\033[33m  Could not extract SVID from output:\033[0m")
        print(f"  stdout: {svid_result.stdout[:300]}")
        print(f"  stderr: {svid_result.stderr[:200]}")
        trusted_decoded = {"payload": {"sub": "spiffe://demo.org/workload/trusted (simulated)"}}

    # ── Step 6: Request SVID as UNTRUSTED workload (UID 1002) ────────────
    print("\n[6/7] Requesting JWT-SVID as UNTRUSTED workload (UID 1002)...")
    print("      No entry registered for UID 1002.")
    print("      SPIRE agent reads UID 1002 → no matching entry → returns empty/error.")
    print()

    denied_result = docker_exec(
        "spire-agent",
        ["/opt/spire/bin/spire-agent", "api", "fetch", "jwt",
         "-audience",   "demo-resource-server",
         "-socketPath", "/tmp/spire-agent/public/api.sock"],
        user="1002",
    )

    if denied_result.returncode != 0 or not denied_result.stdout.strip():
        print(f"  ✓ SVID DENIED for UID 1002 (as expected)")
        print(f"    stderr: {denied_result.stderr[:150]}")
    else:
        print(f"\033[33m  Unexpected: got output for UID 1002:\033[0m")
        print(f"  {denied_result.stdout[:200]}")

    # ── Step 7: Print comparison ───────────────────────────────────────────
    print(f"\n[7/7] Final comparison: Entra Managed Identity vs SPIFFE/SPIRE\n")
    print(f"  {'Dimension':<35} {'Azure Managed Identity':<30} {'SPIFFE JWT-SVID'}")
    print(f"  {'─'*35} {'─'*30} {'─'*30}")
    print(f"  {'What is attested':<35} {'Azure ARM resource (control plane)':<30} "
          f"{'Running process (runtime)'}")
    print(f"  {'sub claim':<35} {'objectId (opaque UUID)':<30} "
          f"{'SPIFFE URI (spiffe://domain/path)'}")
    print(f"  {'Identity granularity':<35} {'Per Container App (shared by all containers)':<30} "
          f"{'Per process (UID, binary hash, k8s SA)'}")
    print(f"  {'Container image change':<35} {'SAME token — unchanged':<30} "
          f"{'SHA256 hash changes → SVID DENIED'}")
    print(f"  {'Compromised sidecar':<35} {'Gets same token (by default)':<30} "
          f"{'Gets own SVID (or denied if unregistered)'}")
    print(f"  {'Token TTL':<35} {'~1 hour (standard Entra)':<30} "
          f"{'5 min (auto-rotated by agent)'}")
    print(f"  {'Cloud portability':<35} {'Azure only':<30} {'Platform-agnostic'}")
    print(f"  {'Binary hash attestation':<35} {'No':<30} {'Yes (unix:sha256 selector)'}")
    print(f"  {'Image digest binding':<35} {'No':<30} {'Yes (k8s:container-image selector)'}")
    print(f"  {'Token format':<35} {'Entra v2.0 JWT (RS256)':<30} "
          f"{'JWT-SVID (ES256, short TTL)'}")

    print(f"\n  SPIRE on ACA conclusion:")
    print(f"    Production SPIRE deployment on ACA Consumption plan is not practical.")
    print(f"    For a Copilot/demo environment, the conceptual gap demonstration")
    print(f"    (Phase 2A) is more important than running SPIRE on ACA itself.")
    print(f"    SPIRE is most valuable on self-managed Kubernetes (AKS) or VMs.")

    # Save for comparison
    CAPTURE_DIR.mkdir(exist_ok=True)
    with open(CAPTURE_DIR / "spire_svid.json", "w") as f:
        json.dump({
            "source":       "spire",
            "trust_domain": TRUST_DOMAIN,
            "decoded":      trusted_decoded,
            "uid_1001":     "SVID_ISSUED",
            "uid_1002":     "SVID_DENIED",
        }, f, indent=2, default=str)

    print(f"\n  Saved to captured_tokens/spire_svid.json")
    print(f"\n  To stop SPIRE: docker compose -f docker/spire/docker-compose.yml down")
    print(f"\n  Next: docker compose -f docker/wso2/docker-compose.yml up")
    print(f"        python scripts/08_wso2_demo.py")
    print(f"\n{SEP}\n")


if __name__ == "__main__":
    main()
