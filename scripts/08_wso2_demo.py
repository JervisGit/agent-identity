#!/usr/bin/env python3
"""
Phase 3: WSO2 Identity Server — Agent Identity Demo

WSO2 Agent ID philosophy: Administer / Authorize / Authenticate / Audit

This script demonstrates:
  1. Registering an AI agent as an M2M Application in WSO2 IS
  2. Requesting an OAuth 2.0 client_credentials token → WSO2 JWT
  3. Decoding and comparing claims to Entra Agent ID TR token
  4. SCIM 2.0 lifecycle: creating agent as a User entity → suspending → reactivating
  5. Showing how WSO2's OIDC JWT differs structurally from Entra's

WSO2 IS token anatomy comparison:
  Entra TR token:
    sub   = Agent Identity objectId   (opaque UUID, oid == appId for Agent Identity objects)
    azp   = Agent Identity clientId
    iss   = https://login.microsoftonline.com/<tenant>/v2.0
    roles = admin-granted app roles
    act   = actor claim (OBO only)

  WSO2 M2M token:
    sub   = <clientId>@carbon.super   (human-readable: clientId@tenantDomain)
    iss   = https://localhost:9443/oauth2/token
    aud   = ['api://<clientId>']       (array — OIDC standard)
    aut   = APPLICATION               (authorized user type — M2M/app vs user)
    jti   = unique token identifier   (useful for token revocation checks)
    binding_type = sso-session        (session binding type)

Prereq: docker compose -f docker/wso2/docker-compose.yml up
        (wait ~90-120 seconds for WSO2 to start)
Run:    python scripts/08_wso2_demo.py
"""

import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

WSO2_BASE = os.environ.get("WSO2_BASE_URL", "https://localhost:9443")
ADMIN_USER = os.environ.get("WSO2_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("WSO2_ADMIN_PASS", "admin")

CAPTURE_DIR = Path("captured_tokens")
SEP = "=" * 72

# WSO2 IS uses a self-signed certificate in development mode.
# We disable SSL verification for local demo only.
# NEVER do this in production.
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def _b64 (u: str, p: str) -> str:
    return base64.b64encode(f"{u}:{p}".encode()).decode()


def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    h = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
    p = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
    return {"header": h, "payload": p}


def api_call(method: str, path: str, body: dict | None = None,
             auth: str | None = None, form_data: str | None = None) -> dict:
    """Make an API call to WSO2 IS."""
    url = f"{WSO2_BASE}{path}"
    headers = {}
    if auth:
        headers["Authorization"] = auth
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    elif form_data is not None:
        data = form_data.encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        data = None

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as r:
            resp_body = r.read()
            # Extract id from Location header (WSO2 201 responses)
            location = r.headers.get("Location", "")
            location_id = location.rstrip("/").split("/")[-1] if location else ""
            if resp_body:
                result = json.loads(resp_body)
                if location_id and "id" not in result:
                    result["_location_id"] = location_id
                return result
            return {"status": r.status, "_location_id": location_id}
    except urllib.error.HTTPError as e:
        err = e.read().decode(errors="replace")
        try:
            return {"error": e.code, "body": json.loads(err)}
        except Exception:
            return {"error": e.code, "raw": err[:300]}


def wait_for_wso2(max_wait: int = 180) -> bool:
    """Poll until WSO2 IS is ready to serve requests."""
    print("  Waiting for WSO2 IS to start", end="", flush=True)
    basic = f"Basic {_b64(ADMIN_USER, ADMIN_PASS)}"
    for _ in range(max_wait // 5):
        try:
            resp = api_call("GET", "/api/server/v1/configs", auth=basic)
            if "error" not in resp or resp.get("error") != 503:
                print(" ✓")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(5)
    print(" TIMED OUT")
    return False


def print_payload_comparison(payload: dict, label: str, notes: dict):
    """Print a decoded token payload with contextual notes."""
    print(f"\n  {label}")
    print(f"  {'─' * 60}")
    for k, v in payload.items():
        display = v
        if k in ("exp", "iat", "nbf"):
            try:
                dt   = datetime.fromtimestamp(int(v), tz=timezone.utc)
                now  = datetime.now(tz=timezone.utc)
                diff = int((dt - now).total_seconds())
                display = f"{v} → {dt.strftime('%H:%M:%S UTC')} ({'EXPIRED' if diff < 0 else f'valid {diff}s'})"
            except Exception:
                pass
        note = notes.get(k, "")
        print(f"    \033[36m{k}\033[0m: \033[33m{display}\033[0m")
        if note:
            print(f"         \033[2m# {note}\033[0m")


def main():
    print(f"\n{SEP}")
    print("  PHASE 3: WSO2 Identity Server — Agent Identity Demo")
    print(f"{SEP}\n")
    print("  Prereq: docker compose -f docker/wso2/docker-compose.yml up")
    print(f"  Admin console (once running): {WSO2_BASE}/console")
    print()

    basic = f"Basic {_b64(ADMIN_USER, ADMIN_PASS)}"

    # ── Wait for WSO2 ────────────────────────────────────────────────────
    if not wait_for_wso2():
        print("\033[31m  WSO2 IS is not responding. Is it started?\033[0m")
        print(f"  Run: docker compose -f docker/wso2/docker-compose.yml up -d")
        sys.exit(1)

    # ── Step 1: Create M2M application ───────────────────────────────────
    print("\n[1/5] Creating M2M application (agent) in WSO2...")
    app_name = "demo-ai-agent"

    # Check if it already exists
    existing = api_call("GET", f"/api/server/v1/applications?filter=name+eq+{app_name}",
                        auth=basic)
    existing_apps = existing.get("applications", [])

    if existing_apps:
        app_id    = existing_apps[0]["id"]
        app_name  = existing_apps[0]["name"]
        print(f"  ✓ Found existing app: {app_name} (id: {app_id})")
    else:
        # Step 1a: Create app with minimal OIDC config (no accessToken.type yet).
        # WSO2 IS 7.0.0: partial accessToken objects cause 500. Create first,
        # then GET the full default OIDC config, merge JWT type, PUT back.
        create_payload = {
            "name":        app_name,
            "description": "AI agent demo — autonomous agent identity",
            "inboundProtocolConfiguration": {
                "oidc": {
                    "grantTypes":    ["client_credentials"],
                    "callbackURLs":  [],
                }
            }
        }
        resp = api_call("POST", "/api/server/v1/applications",
                        body=create_payload, auth=basic)

        if "error" in resp:
            print(f"  \033[31mFailed to create application:\033[0m {resp}")
            sys.exit(1)

        app_id = resp.get("id") or resp.get("applicationId") or resp.get("_location_id", "")
        print(f"  ✓ Application created: {app_name} (id: {app_id})")

        # Step 1b: GET full OIDC config (populated with all defaults), upgrade to JWT.
        # Sending a partial PUT body causes 500 in WSO2 IS 7.0.0 — must PUT full object.
        print(f"  Upgrading token type to JWT (GET config → set type=JWT → PUT back)...")
        full_oidc = api_call("GET",
            f"/api/server/v1/applications/{app_id}/inbound-protocols/oidc",
            auth=basic)
        if "clientId" in full_oidc:
            full_oidc["accessToken"] = {
                **full_oidc.get("accessToken", {}),
                "type": "JWT",
            }
            put_resp = api_call("PUT",
                f"/api/server/v1/applications/{app_id}/inbound-protocols/oidc",
                body=full_oidc, auth=basic)
            if "error" in put_resp:
                print(f"  \033[33m  JWT upgrade warning: {put_resp} — will use Default tokens\033[0m")
            else:
                print(f"  ✓ Token type set to JWT")

    # ── Step 2: Get client credentials ───────────────────────────────────
    print("\n[2/5] Retrieving OAuth 2.0 client credentials from application...")

    inbound = api_call("GET",
                       f"/api/server/v1/applications/{app_id}/inbound-protocols/oidc",
                       auth=basic)
    client_id     = inbound.get("clientId", "")
    client_secret = inbound.get("clientSecret", "")

    if not client_id:
        print(f"  \033[33m  Could not retrieve client credentials automatically.\033[0m")
        print(f"  Open {WSO2_BASE}/console → Applications → {app_name} → Protocol → copy credentials")
        client_id = input("  client_id: ").strip()
        client_secret = input("  client_secret: ").strip()
    else:
        print(f"  ✓ client_id:     {client_id}")
        print(f"    client_secret: {client_secret[:6]}...  (redacted)")

    # ── Step 3: Acquire token (client_credentials) ────────────────────────
    print("\n[3/5] Acquiring agent access token via client_credentials grant...")
    print(f"  POST {WSO2_BASE}/oauth2/token")
    print(f"  grant_type=client_credentials")
    print(f"  Authorization: Basic <base64({client_id}:{client_secret[:4]}...)>")

    token_resp = api_call(
        "POST", "/oauth2/token",
        auth=f"Basic {_b64(client_id, client_secret)}",
        form_data=urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "scope":      "openid",
        }),
    )

    if "error" in token_resp:
        print(f"\033[31m  Token request failed: {token_resp}\033[0m")
        sys.exit(1)

    raw_token    = token_resp.get("access_token", "")
    token_type   = token_resp.get("token_type", "")
    expires_in   = token_resp.get("expires_in", "")
    decoded      = decode_jwt(raw_token)
    wso2_payload = decoded.get("payload", {})

    print(f"\n  ✓ Token acquired (expires in {expires_in}s)")

    # ── Step 4: Decode and compare to Entra ───────────────────────────────
    print(f"\n[4/5] Decoded WSO2 JWT — claim-by-claim comparison with Entra:")

    WSO2_NOTES = {
        "iss":          "Issuer — WSO2 IS OAuth2 endpoint (not a cloud DNS)",
        "sub":          f"Subject = clientId@tenantDomain — format: '{client_id}@carbon.super'\n"
                        "          Compare Entra: sub = opaque objectId (UUID)\n"
                        "          WSO2: sub is human-readable, embeds client_id",
        "aud":          "Audience — array form (OIDC standard). Compare Entra: scalar string.",
        "exp":          "Expiry",
        "iat":          "Issued At",
        "jti":          "JWT ID — unique per token. Useful for exact token revocation checks.\n"
                        "          Entra also has 'uti' (Unique Token Identifier) for tracing.",
        "client_id":    "OAuth2 client ID of this application. Absent in Entra tokens\n"
                        "          (Entra uses 'azp' instead).",
        "aut":          "Authorized User Type:\n"
                        "          APPLICATION = M2M / service account token (no user context)\n"
                        "          APPLICATION_USER = delegated user token\n"
                        "          Compare Entra: distinguished by presence/absence of 'scp'",
        "binding_type": "Session binding type. 'sso-session' = bound to WSO2 session.\n"
                        "          No equivalent in Entra Agent ID tokens.",
        "azp":          "Authorized Party (present in some WSO2 versions). Same meaning as Entra.",
    }

    print_payload_comparison(wso2_payload, "WSO2 M2M Token Payload", WSO2_NOTES)

    print(f"\n  Key structural differences (WSO2 vs Entra):")
    print(f"  {'Claim':<15} {'WSO2':<40} {'Entra Agent ID TR'}")
    print(f"  {'─'*15} {'─'*40} {'─'*30}")
    print(f"  {'sub':<15} {str(wso2_payload.get('sub','?'))[:38]:<40} <agent-identity-objectId>")
    print(f"  {'aud':<15} {'array [api://clientId]':<40} scalar string")
    print(f"  {'iss':<15} {'WSO2 local endpoint':<40} login.microsoftonline.com/<tenant>")
    print(f"  {'aut':<15} {'APPLICATION':<40} (absent — inferred from scp absence)")
    print(f"  {'jti':<15} {str(wso2_payload.get('jti','?'))[:38]:<40} absent (use uti)")
    print(f"  {'act':<15} {'absent':<40} present in OBO flow only")
    print(f"  {'roles':<15} {'absent (RBAC via groups)':<40} app roles if admin-consented")
    print(f"  {'No T1 layer':<15} {'Direct client_credentials':<40} Blueprint → T1 → Agent TR")
    print(f"  {'MCP support':<15} {'OAuth2.1 Auth Proxy (separate)':<40} not documented yet")

    # ── Step 5: SCIM lifecycle demo ────────────────────────────────────────
    print(f"\n[5/5] SCIM 2.0 Agent Lifecycle Demo (suspend → reactivate)...")
    print(f"  WSO2 uses SCIM 2.0 to manage agent identities as 'Users' or 'Groups'.")
    print(f"  The SCIM 'active' attribute controls whether the identity can authenticate.")
    print(f"  Compare Entra: disabling the blueprint cascades to ALL agent identities.")

    # Create a SCIM user to represent the agent identity
    scim_user = {
        "schemas":  ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "agent-demo-user",
        "password": "Demo@Agent123",
        "name":     {"givenName": "Demo", "familyName": "Agent"},
        "emails":   [{"value": "demo-agent@example.com", "primary": True}],
        "active":   True,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "organization":  "AI Agents",
            "department":    "Autonomous Systems",
        },
    }

    # Create user
    scim_resp = api_call("POST", "/scim2/Users", body=scim_user,
                         auth=basic)
    user_id = scim_resp.get("id", "")

    if user_id:
        print(f"  ✓ SCIM user created: {user_id}")

        # Suspend (deactivate)
        patch_suspend = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": False}}],
        }
        suspend_resp = api_call("PATCH", f"/scim2/Users/{user_id}",
                                body=patch_suspend, auth=basic)
        print(f"  ✓ Agent suspended (active=False)")
        print(f"    Audit reason: agent underwent security review, temporarily deactivated")

        # Try to get token while suspended (will fail with active=False)
        # The app credentials are separate from the SCIM user — this demo shows
        # the SCIM lifecycle concept; in WSO2 Agent ID, the SCIM user and app
        # identity are linked via the 'agentType' extension
        print(f"  [NOTE: In WSO2 Agent ID, suspending the agent via SCIM also revokes")
        print(f"   its OAuth tokens. This demo shows the SCIM lifecycle concept.]")

        # Reactivate
        patch_reactivate = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "value": {"active": True}}],
        }
        api_call("PATCH", f"/scim2/Users/{user_id}", body=patch_reactivate, auth=basic)
        print(f"  ✓ Agent reactivated (active=True)")

        # Clean up
        api_call("DELETE", f"/scim2/Users/{user_id}", auth=basic)
        print(f"  ✓ Demo SCIM user removed")
    else:
        print(f"  \033[33m  SCIM user creation response: {scim_resp}\033[0m")
        print(f"  [SCIM lifecycle demo skipped — manually test via {WSO2_BASE}/console]")

    # Save for comparison
    CAPTURE_DIR.mkdir(exist_ok=True)
    with open(CAPTURE_DIR / "wso2_token.json", "w") as f:
        json.dump({
            "source":  "wso2",
            "decoded": decoded,
            "raw":     raw_token,
        }, f, indent=2, default=str)

    print(f"\n  Token saved to captured_tokens/wso2_token.json")
    print(f"\n  Next: start AIM (see docker/aim/docker-compose.yml)")
    print(f"        then run python scripts/09_aim_demo.py")
    print(f"\n{SEP}\n")
    print(f"  To stop WSO2: docker compose -f docker/wso2/docker-compose.yml down")


if __name__ == "__main__":
    main()
