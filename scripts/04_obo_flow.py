#!/usr/bin/env python3
"""
Phase 1: OBO (On-Behalf-Of) flow demo — shows the 'act' claim.

What this demonstrates:
  In the OBO flow, an agent acts on behalf of a signed-in human user.
  The resulting token carries BOTH identities:
    sub     = user objectId       ← the human who granted consent
    act.sub = agent objectId      ← the agent making the actual API call

  This is how you distinguish "a user did X" from "an agent did X on behalf of a user"
  in resource server audit logs. Both identities are attributable.

OBO Flow steps:
  1. User signs in to a "calling client" app via device code flow
     → Tc: user access token where Tc.aud == Blueprint client ID (or SP client ID for Path B)
  2. Client presents Tc to the agent
  3. Agent performs OBO exchange:
     - Path A: T1 (from blueprint) + Tc → delegated token
     - Path B: client_secret + Tc → delegated token
     → Delegated token: sub=user, act.sub=agent, scp=delegated scopes

Prerequisites for Path B:
  1. The SP app must expose an API scope:
     az ad app update --id $SP_CLIENT_ID --set oauth2Permissions='[{"id":"...","value":"access_as_user",...}]'
  2. A "calling client" app must be registered and given permission to call this scope
  3. A user must be able to sign into the calling client app

This script handles all prerequisite setup automatically via az CLI.

Run:
  python scripts/04_obo_flow.py
"""

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
import uuid


# ── Load .env.local ──────────────────────────────────────────────────────────
def load_env():
    env = {}
    for path in (".env.local", ".env.example"):
        try:
            for line in open(path):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    k, v = k.strip(), v.strip()
                    env[k] = v
                    os.environ.setdefault(k, v)
        except FileNotFoundError:
            pass
    return env


ENV        = load_env()
TENANT_ID  = os.environ.get("AZURE_TENANT_ID", "")
SP_CLIENT_ID  = os.environ.get("SP_CLIENT_ID", "")
SP_SECRET     = os.environ.get("SP_CLIENT_SECRET", "")
OBO_CALLER_ID = os.environ.get("OBO_CLIENT_APP_ID", "")

TOKEN_URL  = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
DEVICE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
SEP        = "=" * 72


def _b64pad(s): return s + "=" * (-len(s) % 4)


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    try:
        h = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        p = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
        return {"header": h, "payload": p}
    except Exception as e:
        return {"error": str(e)}


def post_form(url, data):
    body = urllib.parse.urlencode(data).encode()
    req  = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            # Device code polling returns 400 with a JSON body that has the real error code
            body = json.loads(raw)
            return body   # e.g. {"error": "authorization_pending", ...}
        except Exception:
            return {"error": str(e.code), "error_description": raw}


def az_run(*args) -> dict:
    """Run an az CLI command and return parsed JSON."""
    result = subprocess.run(["az", *args, "--output", "json"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\033[31m  az error: {result.stderr[:200]}\033[0m")
        return {}
    try:
        return json.loads(result.stdout)
    except Exception:
        return {}


def ensure_obo_caller_app(sp_app_id: str) -> tuple[str, str]:
    """
    Ensure a 'calling client' app exists that is allowed to call the SP's exposed scope.
    Returns (caller_client_id, caller_app_object_id).
    """
    if OBO_CALLER_ID:
        print(f"  Using caller app from .env.local: {OBO_CALLER_ID}")
        return OBO_CALLER_ID, ""

    caller_name = "obo-caller-demo"
    print(f"  Creating calling client app '{caller_name}'...")

    # Check if it already exists
    existing = az_run("ad", "app", "list",
                      "--display-name", caller_name,
                      "--query", "[0]")
    if existing and existing.get("appId"):
        caller_id = existing["appId"]
        print(f"  ✓ Found existing: {caller_id}")
        return caller_id, existing.get("id", "")

    # Create public client (no secret needed for device code flow)
    sp_scope_id = str(uuid.uuid4())
    manifest = json.dumps([{
        "id":             sp_scope_id,
        "type":           "User",
        "value":          "access_as_agent",
        "userConsentDisplayName":  "Access this agent on your behalf",
        "userConsentDescription":  "Allows calling this agent on your behalf",
        "adminConsentDisplayName": "Access agent on behalf of user",
        "adminConsentDescription": "Allows the app to call this agent on behalf of a user",
        "isEnabled":      True,
    }])

    # First add the scope to the SP app
    subprocess.run(["az", "ad", "app", "update",
                    "--id", sp_app_id,
                    "--set", f"api.oauth2PermissionScopes={manifest}"],
                    capture_output=True, text=True)

    # Create caller app with redirect URI for device flow
    caller = az_run("ad", "app", "create",
                    "--display-name",   caller_name,
                    "--public-client-redirect-uris", "https://login.microsoftonline.com/common/oauth2/nativeclient")

    if not caller.get("appId"):
        print("\033[31m  Could not create caller app — add OBO_CLIENT_APP_ID to .env.local manually\033[0m")
        sys.exit(1)

    caller_id  = caller["appId"]
    caller_obj = caller["id"]

    # Grant permission to call SP's scope
    subprocess.run(["az", "ad", "app", "permission", "add",
                    "--id", caller_id,
                    "--api", sp_app_id,
                    "--api-permissions", f"{sp_scope_id}=Scope"],
                    capture_output=True, text=True)

    with open(".env.local", "a") as f:
        f.write(f"\n# Written by 04_obo_flow.py\n")
        f.write(f"OBO_CLIENT_APP_ID={caller_id}\n")
        f.write(f"OBO_SCOPE_ID={sp_scope_id}\n")

    print(f"  ✓ Caller app created: {caller_id}")
    return caller_id, caller_obj


def device_code_flow(caller_id: str, sp_app_id: str) -> str:
    """
    Perform device code flow to get a user access token (Tc).

    Tc.aud must equal the SP client ID (or blueprint client ID in Path A),
    because the OBO exchange requires the user token to target the
    intermediate service (the agent/SP), not the final resource.
    """
    scope = f"api://{sp_app_id}/access_as_agent openid profile"

    print(f"\n  Initiating device code flow...")
    print(f"  scope: {scope}")
    print(f"  (Tc.aud will be: api://{sp_app_id} = the SP/blueprint client ID)")

    resp = post_form(DEVICE_URL, {
        "client_id": caller_id,
        "scope":     scope,
    })

    if "error" in resp and "device_code" not in resp:
        print(f"\033[31m  Device code error: {resp}\033[0m")
        print(f"  If scope fails with AADSTS errors, try: 'openid profile offline_access'")
        print(f"  and use OBO with a generic Graph scope instead.")
        sys.exit(1)

    print(f"\n  {'─'*60}")
    print(f"  ACTION REQUIRED → Open: {resp.get('verification_uri','https://microsoft.com/devicelogin')}")
    print(f"  Enter code:  \033[1m\033[32m{resp.get('user_code','????')}\033[0m")
    print(f"  {'─'*60}")
    print(f"  Waiting for you to sign in", end="", flush=True)

    # Poll for the token
    interval = int(resp.get("interval", 5))
    device_code = resp.get("device_code", "")
    for _ in range(60):  # 5 min max
        time.sleep(interval)
        print(".", end="", flush=True)
        token_resp = post_form(TOKEN_URL, {
            "grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
            "client_id":   caller_id,
            "device_code": device_code,
        })
        if token_resp.get("access_token"):
            print(" ✓")
            return token_resp["access_token"]
        if token_resp.get("error") == "authorization_pending":
            continue
        if token_resp.get("error") == "expired_token":
            print("\n  Device code expired. Rerun the script to get a new code.")
            sys.exit(1)
        print(f"\n  Unexpected: {token_resp}")
        sys.exit(1)

    print("\n  Timed out")
    sys.exit(1)


def obo_exchange(tc: str, sp_client_id: str, sp_secret: str) -> dict:
    """
    Perform OBO exchange: present Tc (user token) + SP credential
    → get delegated token with sub=user, act.sub=agent.

    grant_type:           urn:ietf:params:oauth:grant-type:jwt-bearer  (RFC 8693 / RFC 7523)
    assertion:            Tc (the user's access token — Tc.aud MUST == SP client ID)
    requested_token_use:  on_behalf_of
    """
    return post_form(TOKEN_URL, {
        "grant_type":          "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id":           sp_client_id,
        "client_secret":       sp_secret,
        "assertion":           tc,
        "requested_token_use": "on_behalf_of",
        "scope":               "https://graph.microsoft.com/User.Read offline_access",
    })


def main():
    print(f"\n{SEP}")
    print("  PHASE 1: OBO (On-Behalf-Of) Flow — act claim demo")
    print(f"{SEP}\n")

    if not TENANT_ID or not SP_CLIENT_ID or not SP_SECRET:
        print("\033[31mERROR: AZURE_TENANT_ID, SP_CLIENT_ID, and SP_CLIENT_SECRET must be set.\033[0m")
        print("  Run 03_get_tokens.py first (it creates the SP).")
        sys.exit(1)

    # ── Step 1: Set up OBO caller app ─────────────────────────────────────
    print("[1/4] Ensuring OBO caller app exists...")
    caller_id, _ = ensure_obo_caller_app(SP_CLIENT_ID)

    # ── Step 2: Get user token (Tc) via device code flow ──────────────────
    print(f"\n[2/4] Getting user token (Tc) via device code flow...")
    print(f"  The user must sign in to the calling client app.")
    print(f"  Tc.aud will equal '{SP_CLIENT_ID}' (the SP/agent app).")
    print(f"  This is required — if Tc.aud pointed directly to Graph, OBO would fail.")
    print(f"  The SP acts as the 'middle tier' that the user explicitly consented to.")

    tc = device_code_flow(caller_id, SP_CLIENT_ID)
    tc_decoded = decode_jwt(tc)
    tc_payload = tc_decoded.get("payload", {})

    print(f"\n  User token (Tc) decoded:")
    print(f"    sub:  {tc_payload.get('sub','?')}  ← user objectId")
    print(f"    aud:  {tc_payload.get('aud','?')}  ← MUST == SP client ID ({SP_CLIENT_ID})")
    print(f"    name: {tc_payload.get('name','?')}")
    print(f"    upn:  {tc_payload.get('upn', tc_payload.get('unique_name','?'))}")

    if tc_payload.get("aud") != SP_CLIENT_ID and tc_payload.get("aud") != f"api://{SP_CLIENT_ID}":
        print(f"\n  \033[33mWARNING: Tc.aud ({tc_payload.get('aud')}) may not match SP client ID.\033[0m")
        print(f"  OBO requires Tc.aud == SP client ID. If exchange fails, check app scope config.")

    # ── Step 3: OBO exchange ──────────────────────────────────────────────
    print(f"\n[3/4] Performing OBO exchange...")
    print(f"  POST {TOKEN_URL}")
    print(f"  grant_type: urn:ietf:params:oauth:grant-type:jwt-bearer  (RFC 8693)")
    print(f"  assertion:  Tc (user token with aud={SP_CLIENT_ID})")
    print(f"  requested_token_use: on_behalf_of")

    obo_resp = obo_exchange(tc, SP_CLIENT_ID, SP_SECRET)

    if "error" in obo_resp:
        print(f"\n\033[31m  OBO exchange failed:\033[0m")
        print(f"  error:       {obo_resp.get('error')}")
        print(f"  description: {obo_resp.get('error_description','')[:400]}")
        print(f"\n  Common causes:")
        print(f"  - 'invalid_grant': The app scope on SP isn't exposing an API  "
              f"(try az ad app update)")
        print(f"  - 'AADSTS50013': Tc.aud doesn't match the SP client ID")
        print(f"  - Tc expired: rerun device_code_flow")
        sys.exit(1)

    obo_token   = obo_resp["access_token"]
    obo_decoded = decode_jwt(obo_token)
    obo_payload = obo_decoded.get("payload", {})

    # ── Step 4: Decode and compare ────────────────────────────────────────
    print(f"\n[4/4] Delegated token decoded:")
    print(f"\n{SEP}")
    print(f"  OBO Delegated Token — sub=USER, act.sub=AGENT")
    print(f"{SEP}\n")

    act    = obo_payload.get("act", {})
    sub    = obo_payload.get("sub", "?")
    sub_act = act.get("sub", "absent — check if SP exposes an API scope") if act else "absent"

    print(f"  \033[1mKEY DELEGATION CLAIMS:\033[0m")
    print(f"")
    print(f"    sub:     \033[32m{sub}\033[0m")
    print(f"             # Human user objectId — WHO this token acts on behalf of")
    print(f"             # This matches Tc.sub = '{tc_payload.get('sub','?')}'")
    if tc_payload.get("sub") == sub:
        print(f"             \033[32m✓ Confirmed same user (sub matches Tc.sub)\033[0m")
    print(f"")
    print(f"    act.sub: \033[32m{sub_act}\033[0m")
    print(f"             # Agent objectId — WHO is actually calling the resource server")
    print(f"             # This is the SP/agent identity objectId")
    print(f"")
    print(f"    scp:     \033[33m{obo_payload.get('scp','?')}\033[0m")
    print(f"             # Delegated scopes — what the agent can do on the user's behalf")
    print(f"             # NOTICE: these are user-granted, not admin-granted roles")
    print(f"")
    print(f"    azp:     \033[33m{obo_payload.get('azp','?')}\033[0m")
    print(f"             # The agent/SP client ID (same as SP_CLIENT_ID)")
    print(f"")
    print(f"  Full payload:")
    for k, v in obo_payload.items():
        print(f"    {k}: {v}")

    print(f"\n  \033[1mCOMPARISON — Three tokens in this flow:\033[0m")
    print(f"  {'Token':<12}  {'sub':<38}  {'aud':<38}  {'act.sub'}")
    print(f"  {'─'*12}  {'─'*38}  {'─'*38}  {'─'*36}")
    print(f"  {'Tc':<12}  {tc_payload.get('sub','?')[:36]:<38}  "
          f"{str(tc_payload.get('aud','?'))[:36]:<38}  (not present)")
    print(f"  {'Delegated':<12}  {sub[:36]:<38}  "
          f"{str(obo_payload.get('aud','?'))[:36]:<38}  {sub_act[:36]}")
    print(f"")
    print(f"  In Path A (Entra Agent ID), the flow is identical EXCEPT:")
    print(f"    - SP_SECRET is replaced by T1 (no stored secret)")
    print(f"    - T1 is obtained from the blueprint via TUAMI + fmi_path")
    print(f"    - act.sub = Agent Identity objectId (instead of SP objectId)")
    print(f"    - act.sub == act.oid (unique marker of Agent Identity objects)")

    # Save for Phase 6 comparison
    os.makedirs("captured_tokens", exist_ok=True)
    with open("captured_tokens/entra_obo.json", "w") as f:
        json.dump({"source": "entra_obo", "decoded": obo_decoded}, f, indent=2, default=str)
    print(f"\n  Saved to captured_tokens/entra_obo.json")
    print(f"\n  Next: check docker/spire/ and run python scripts/07_spire_demo.py")
    print(f"\n{SEP}\n")


if __name__ == "__main__":
    main()
