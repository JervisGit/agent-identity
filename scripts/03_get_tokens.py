#!/usr/bin/env python3
"""
Phase 1 — PATH B: Service Principal simulation of Entra Agent ID token flow.

When to use this script:
  - You don't have M365 Copilot + Frontier (Path A unavailable)
  - You want to understand token anatomy before spinning up ACA infrastructure
  - You want to run everything locally without Azure Container Apps

What this demonstrates:
  The client_credentials grant produces a TR token with identical claim structure
  to Path A's TR step. The difference is the MISSING T1 middle layer — in Path A,
  the T1 exchange is what enables a SINGLE blueprint credential to impersonate
  ANY of its N child agent identities via the fmi_path parameter.

  This script will:
  1. Create a service principal (if one doesn't exist) → the "agent identity" analog
  2. Grant Microsoft Graph User.Read.All app role + admin consent
  3. Acquire a TR token via client_credentials
  4. Decode and annotate every claim
  5. Explain the T1 layer conceptually with the protocol parameters

Requirements:
  - pip install msal   (Microsoft Auth Library — wraps the OAuth 2.0 calls)
  - OR no pip install: the script falls back to raw urllib calls

Run:
  python scripts/03_get_tokens.py
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent


# ── Load .env.local ──────────────────────────────────────────────────────────
def load_env(path: str = ".env.local") -> dict:
    env = {}
    try:
        for line in open(path).readlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
                os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass
    return env


ENV = load_env()

TENANT_ID    = os.environ.get("AZURE_TENANT_ID", "")
SP_CLIENT_ID = os.environ.get("SP_CLIENT_ID", "")
SP_SECRET    = os.environ.get("SP_CLIENT_SECRET", "")

# Entra token endpoint
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

SEPARATOR = "=" * 72


# ── JWT decoder (reuse from decode_jwt.py concept) ───────────────────────────
def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_jwt_full(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "not a valid JWT"}
    header  = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
    payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
    return {"header": header, "payload": payload, "sig": parts[2][:20] + "..."}


def fmt_ts(ts) -> str:
    try:
        dt  = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        diff = int((dt - now).total_seconds())
        status = f"EXPIRED {-diff}s ago" if diff < 0 else f"valid for {diff}s"
        return f"{ts} → {dt.strftime('%Y-%m-%d %H:%M:%S UTC')} ({status})"
    except Exception:
        return str(ts)


def print_payload(payload: dict, indent: int = 2):
    NOTES = {
        "iss":    "Issuer — the Azure AD tenant that signed this token",
        "sub":    "Subject — objectId of the authenticated principal\n"
                  "          PATH A Agent Identity: sub == oid (appId == objectId — unique marker)\n"
                  "          PATH B Service Principal: sub != oid",
        "aud":    "Audience — the resource this token grants access to",
        "exp":    "Expiry",
        "iat":    "Issued At",
        "oid":    "Object ID — Entra principal objectId.\n"
                  "          Agent Identity special property: oid == appId\n"
                  "          Regular SP: oid != appId",
        "azp":    "Authorized Party — client ID of the application that GOT this token\n"
                  "          In TR/resource tokens: this is the agent identity's clientId",
        "azpacr": "Auth method used by azp: 0=public, 1=client_secret, 2=cert/FIC",
        "tid":    "Tenant ID",
        "roles":  "App roles granted (admin-consented application permissions)",
        "scp":    "Delegated scopes — only in user-delegated tokens (OBO flow)",
        "ver":    "Token version: 1.0 or 2.0",
        "act":    "Actor — the agent identity (only in OBO/delegated tokens)",
    }
    pad = "  " * (indent // 2)
    for k, v in payload.items():
        note = NOTES.get(k, "")
        display = fmt_ts(v) if k in ("exp", "iat", "nbf") else str(v)
        print(f"{pad}\033[36m{k}\033[0m: \033[33m{display}\033[0m")
        if note:
            for line in note.split("\n"):
                print(f"{pad}    \033[2m# {line.strip()}\033[0m")
        if isinstance(v, dict):
            print_payload(v, indent + 2)


# ── HTTP helpers ──────────────────────────────────────────────────────────────
def post_form(url: str, data: dict) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req  = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return {"error": e.code, "error_description": e.read().decode(errors="replace")}


# ── SP creation (if needed) ───────────────────────────────────────────────────
def ensure_service_principal() -> tuple[str, str]:
    """Create a demo SP via az CLI if SP_CLIENT_ID is not set. Returns (client_id, secret)."""
    if SP_CLIENT_ID and SP_SECRET:
        print("  Using SP from .env.local")
        return SP_CLIENT_ID, SP_SECRET

    print("  SP_CLIENT_ID not set — creating demo SP via az CLI...")
    import subprocess
    result = subprocess.run(
        ["az", "ad", "sp", "create-for-rbac",
         "--name", "demo-agent-sp",
         "--skip-assignment",
         "--output", "json"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"\033[31m  ERROR: {result.stderr[:300]}\033[0m")
        sys.exit(1)

    sp = json.loads(result.stdout)
    client_id = sp["appId"]
    secret    = sp["password"]
    tenant_id = sp["tenant"]

    with open(".env.local", "a") as f:
        f.write(f"\n# Written by 03_get_tokens.py\n")
        f.write(f"SP_CLIENT_ID={client_id}\n")
        f.write(f"SP_CLIENT_SECRET={secret}\n")

    print(f"  ✓ SP created → appId: {client_id}")
    print(f"    Credentials written to .env.local")
    return client_id, secret


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{SEPARATOR}")
    print("  PHASE 1 — PATH B: Service Principal Token Demo")
    print(f"{SEPARATOR}\n")

    if not TENANT_ID:
        print("\033[31mERROR: AZURE_TENANT_ID not set. Run 01_verify_entra.ps1 first.\033[0m")
        sys.exit(1)

    client_id, client_secret = ensure_service_principal()

    # ── Acquire TR token (client credentials) ─────────────────────────────
    print(f"\n[1/3] Acquiring access token via client_credentials grant...")
    print(f"  POST {TOKEN_URL}")
    print(f"  Parameters:")
    print(f"    grant_type=client_credentials")
    print(f"    client_id={client_id}")
    print(f"    client_secret=<redacted>")
    print(f"    scope=https://graph.microsoft.com/.default")

    resp = post_form(TOKEN_URL, {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://graph.microsoft.com/.default",
    })

    if "error" in resp:
        print(f"\n\033[31mToken request failed:\033[0m")
        print(f"  error:       {resp.get('error')}")
        print(f"  description: {resp.get('error_description','')[:400]}")
        print(f"\nCommon causes:")
        print(f"  - The SP needs Graph API permissions granted + admin consent")
        print(f"  - Run: az ad app permission add --id {client_id} \\")
        print(f"           --api 00000003-0000-0000-c000-000000000000 \\")
        print(f"           --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Role")
        print(f"    az ad app permission admin-consent --id {client_id}")
        sys.exit(1)

    raw_token = resp["access_token"]
    decoded   = decode_jwt_full(raw_token)
    payload   = decoded["payload"]

    print(f"\n[2/3] Token acquired — decoding and annotating all claims:")
    print(f"\n{SEPARATOR}")
    print(f"  TR (Resource Token) — PATH B Service Principal")
    print(f"{SEPARATOR}")
    print(f"\n  [HEADER]")
    print(f"    alg: {decoded['header'].get('alg')}   "
          f"(RSA-SHA256 used by Entra v2.0 service tokens)")
    print(f"    typ: {decoded['header'].get('typ')}")
    print(f"\n  [PAYLOAD]")
    print_payload(payload)

    # ── Path A conceptual explanation ──────────────────────────────────────
    print(f"\n[3/3] What the T1 middle layer ADDS in Path A (not present in Path B):\n")
    print(f"  In Path B (above): you went directly Client → TR.")
    print(f"  The credential proving the identity is a client_secret stored somewhere.")
    print(f"  The token's 'sub' is the service principal you created.")
    print(f"")
    print(f"  In Path A (Entra Agent ID blueprint flow), three steps happen:")
    print(f"")
    print(f"  Step 1 — Container App calls IDENTITY_ENDPOINT")
    print(f"    → ACA platform issues TUAMI (aud: api://AzureADTokenExchange)")
    print(f"    NO SECRET stored. The ACA platform/UAMI is the credential.")
    print(f"")
    print(f"  Step 2 — Blueprint exchanges TUAMI for T1 using fmi_path:")
    print(f"    POST /token")
    print(f"      client_id          = {'{Blueprint appId}':35s}  (the template)")
    print(f"      client_assertion   = TUAMI                             (no stored secret)")
    print(f"      fmi_path           = {'{Agent Identity objectId}':35s}  (WHICH child to impersonate)")
    print(f"      scope              = api://AzureADTokenExchange/.default")
    print(f"    → T1: aud={'{Blueprint appId}'}  sub={'{Blueprint principal oid}'}")
    print(f"    The fmi_path parameter is the key innovation: one blueprint credential")
    print(f"    can impersonate ANY of its child agent identities. No per-agent secrets.")
    print(f"")
    print(f"  Step 3 — Agent Identity uses T1 to get TR:")
    print(f"    POST /token")
    print(f"      client_id          = {'{Agent Identity appId}':35s}")
    print(f"      client_assertion   = T1                                (T1.aud == blueprint appId)")
    print(f"      scope              = https://graph.microsoft.com/.default")
    print(f"    → TR: sub={'{Agent Identity objectId}'} (oid==sub — unique marker)")
    print(f"")
    print(f"  Key security properties PATH A adds vs PATH B:")
    print(f"    ✓ Zero stored secrets — identity comes from UAMI (Azure platform-managed)")
    print(f"    ✓ Blueprint governance — admin can disable blueprint → ALL agent identities stop")
    print(f"    ✓ Per-agent audit — each agent identity has unique sub/oid in logs")
    print(f"    ✓ Lifecycle — sponsor accountability, access reviews, Conditional Access")
    print(f"    ✓ oid == appId marker — resource servers can detect agent identity tokens")

    # Save token for Phase 6 comparison
    os.makedirs("captured_tokens", exist_ok=True)
    with open("captured_tokens/entra_path_b_tr.json", "w") as f:
        json.dump({
            "source":  "entra_path_b",
            "decoded": decoded,
            "raw":     raw_token,
        }, f, indent=2)
    print(f"\n  Token saved to captured_tokens/entra_path_b_tr.json")
    print(f"\n  Next: python scripts/04_obo_flow.py  — OBO flow with 'act' claim")
    print(f"\n{SEPARATOR}\n")


if __name__ == "__main__":
    main()
