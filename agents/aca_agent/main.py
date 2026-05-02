"""
ACA Agent — deployed to Azure Container Apps to demonstrate the Entra Agent ID
3-step token exchange (TUAMI → T1 → TR) and OBO flow.

Token flow:
  STEP 1:  GET $IDENTITY_ENDPOINT  (ACA platform injects this env var)
           Headers: X-IDENTITY-HEADER: $IDENTITY_HEADER  (SSRF guard)
           → TUAMI: managed identity token for the blueprint's UAMI credential
             aud: "api://AzureADTokenExchange"
             sub: <UAMI principal objectId>

  STEP 2:  POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
           grant_type=client_credentials
           client_id=<blueprint appId>
           client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
           client_assertion=<TUAMI>
           scope=api://AzureADTokenExchange/.default
           fmi_path=<agent-identity-id>    ← tells Entra WHICH agent identity to impersonate
           → T1: exchange token
             aud: <blueprint appId>        ← Entra validates this in step 3
             sub/oid: <blueprint principal objectId in this tenant>

  STEP 3:  POST .../token
           grant_type=client_credentials
           client_id=<agent identity clientId>
           client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
           client_assertion=<T1>
           scope=https://graph.microsoft.com/.default
           → TR: resource access token
             sub: <Agent Identity objectId>    ← NOT the blueprint's objectId
             oid: <Agent Identity objectId>    ← for Agent Identities: oid == appId (unique)
             azp: <Agent Identity clientId>

  OBO:     Tc (user token, aud=blueprint clientId) + T1 (client_assertion)
           → delegated access token
             sub: <user objectId>          ← the human user
             act.sub: <Agent objectId>     ← the agent acting on behalf of the user

Environment variables (injected by ACA platform or set by deploy script):
  IDENTITY_ENDPOINT    — Platform-injected: ACA managed identity proxy URL
  IDENTITY_HEADER      — Platform-injected: SSRF protection token (opaque UUID)
  AZURE_TENANT_ID      — Your Entra tenant ID
  BLUEPRINT_CLIENT_ID  — Blueprint app registration client ID (Path A only)
  AGENT_IDENTITY_ID    — Agent Identity object ID (Path A only)
  UAMI_CLIENT_ID       — UAMI client ID (needed to select the right identity)
  RESOURCE_SCOPE       — Scope for TR (default: Microsoft Graph)
"""

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="Entra Agent ID Demo Agent", version="1.0.0")

# ── Configuration from environment ───────────────────────────────────────────
TENANT_ID           = os.environ.get("AZURE_TENANT_ID", "")
BLUEPRINT_CLIENT_ID = os.environ.get("BLUEPRINT_CLIENT_ID", "")
AGENT_IDENTITY_ID   = os.environ.get("AGENT_IDENTITY_ID", "")
UAMI_CLIENT_ID      = os.environ.get("UAMI_CLIENT_ID", "")
RESOURCE_SCOPE      = os.environ.get("RESOURCE_SCOPE", "https://graph.microsoft.com/.default")

# ACA injects these — they are NOT set by the deploy script
IDENTITY_ENDPOINT   = os.environ.get("IDENTITY_ENDPOINT", "")
IDENTITY_HEADER     = os.environ.get("IDENTITY_HEADER", "")

TOKEN_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"


# ── JWT utilities ─────────────────────────────────────────────────────────────

def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_jwt(token: str) -> dict:
    """Base64-decode a JWT without signature validation. For inspection only."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "not a JWT", "raw_preview": token[:40]}
    try:
        header  = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
        return {
            "header":  header,
            "payload": payload,
            "sig_prefix": parts[2][:24] + "...",
        }
    except Exception as exc:
        return {"error": str(exc)}


def annotate(payload: dict) -> dict:
    """Add human-readable annotations alongside each claim."""
    NOTES = {
        "iss":  "Issuer — Azure AD tenant URL that signed this token",
        "sub":  "Subject — the principal this token represents "
                "(Agent Identity objectId for app-only; user objectId for delegated)",
        "aud":  "Audience — intended recipient. Must match what the resource server expects.",
        "exp":  "Expiry (Unix timestamp)",
        "iat":  "Issued At (Unix timestamp)",
        "oid":  "Object ID — Entra principal OID. "
                "NOTE: For Agent Identity objects, oid == appId. "
                "For regular SPs, oid != appId.",
        "azp":  "Authorized Party — client ID of the app that REQUESTED this token",
        "azpacr": "Client auth method: 0=public, 1=client_secret, 2=cert/FIC",
        "tid":  "Tenant ID",
        "act":  "Actor — the agent identity acting on behalf of the subject (OBO tokens only)",
        "scp":  "Delegated scopes (only in OBO/user-delegated tokens, absent in client_credentials)",
        "roles": "App roles assigned (only in app-only tokens with admin-consented app roles)",
        "ver":  "Token format version: 1.0 or 2.0",
    }
    out = {}
    for k, v in payload.items():
        note = NOTES.get(k, "")
        if k in ("exp", "iat", "nbf"):
            try:
                dt = datetime.fromtimestamp(int(v), tz=timezone.utc)
                v = f"{v} → {dt.isoformat()}"
            except Exception:
                pass
        out[k] = {"value": v, "note": note} if note else v
    return out


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def http_post_form(url: str, data: dict) -> dict:
    """POST application/x-www-form-urlencoded and return parsed JSON."""
    body = urllib.parse.urlencode(data).encode("utf-8")
    req  = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        return {
            "error": f"HTTP {exc.code}",
            "error_description": err_body,
            "url": url,
            "data_keys": list(data.keys()),
        }


def http_get(url: str, headers: dict) -> dict:
    """GET with custom headers and return parsed JSON."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {exc.code}", "error_description": err_body}


# ── Token exchange steps ──────────────────────────────────────────────────────

def step1_get_tuami() -> tuple[str, dict]:
    """
    STEP 1: Get TUAMI from the ACA managed identity proxy endpoint.

    This is NOT raw IMDS (169.254.169.254). Azure Container Apps uses a
    platform-managed proxy (IDENTITY_ENDPOINT) with an SSRF guard
    (X-IDENTITY-HEADER — an opaque UUID injected into the container env).

    The SSRF guard prevents an attacker-controlled URL redirect from making
    the container call the identity endpoint on behalf of another workload.

    Returns: (raw_token_string, response_dict)
    """
    if not IDENTITY_ENDPOINT or not IDENTITY_HEADER:
        return "", {
            "error": "IDENTITY_ENDPOINT or IDENTITY_HEADER not set.",
            "cause": "Is this container running inside Azure Container Apps with a UAMI assigned?",
            "tip": "Run local Path B demo (scripts/03_get_tokens.py) if not on ACA.",
        }

    params = urllib.parse.urlencode({
        "resource":    "api://AzureADTokenExchange",  # audience for the TUAMI
        "api-version": "2019-08-01",
        "client_id":   UAMI_CLIENT_ID,  # selects the UAMI (not system identity)
    })
    url = f"{IDENTITY_ENDPOINT}?{params}"

    resp = http_get(url, headers={
        "X-IDENTITY-HEADER": IDENTITY_HEADER,   # SSRF guard
        "Metadata": "true",
    })
    token = resp.get("access_token", "")
    return token, resp


def step2_get_t1(tuami: str) -> tuple[str, dict]:
    """
    STEP 2: Exchange TUAMI for T1 (the exchange token).

    Key parameter: fmi_path = Agent Identity ID
      This tells Azure AD: "Issue T1 for THIS specific child agent identity,
      not for the blueprint itself." The resulting T1.aud equals the Blueprint
      client ID — it's not a resource access token, it's an intermediate token
      specifically designed to be used as a client_assertion in Step 3.

    Why two steps? The blueprint can manage N agent identities. The fmi_path
    allows one set of credentials (UAMI FIC) to impersonate any specific agent
    identity — without needing separate credentials per agent.
    """
    data = {
        "grant_type":            "client_credentials",
        "client_id":             BLUEPRINT_CLIENT_ID,
        "scope":                 "api://AzureADTokenExchange/.default",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      tuami,
        "fmi_path":              AGENT_IDENTITY_ID,  # ← the key Agent ID parameter
    }
    resp  = http_post_form(TOKEN_ENDPOINT, data)
    token = resp.get("access_token", "")
    return token, resp


def step3_get_tr(t1: str) -> tuple[str, dict]:
    """
    STEP 3: Use T1 as client_assertion to get TR (the actual resource token).

    Azure AD validates that T1.aud == BLUEPRINT_CLIENT_ID before issuing TR.
    This prevents a T1 from one blueprint being used to impersonate a different
    blueprint's agent identities.

    The resulting TR:
      sub  = Agent Identity objectId        (NOT the blueprint's oid)
      oid  = Agent Identity objectId        (same as sub — unique to Agent Identities)
      azp  = Agent Identity clientId
      aud  = <resource> (e.g., https://graph.microsoft.com/)
    """
    data = {
        "grant_type":            "client_credentials",
        "client_id":             AGENT_IDENTITY_ID,
        "scope":                 RESOURCE_SCOPE,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      t1,
    }
    resp  = http_post_form(TOKEN_ENDPOINT, data)
    token = resp.get("access_token", "")
    return token, resp


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":    "ok",
        "agent":     "aca-demo-agent",
        "path":      "A" if BLUEPRINT_CLIENT_ID else "B (no blueprint configured)",
        "blueprint": BLUEPRINT_CLIENT_ID or "(not set)",
        "agent_id":  AGENT_IDENTITY_ID or "(not set)",
        "uami":      UAMI_CLIENT_ID or "(not set)",
        "identity_endpoint_set": bool(IDENTITY_ENDPOINT),
    }


@app.get("/tokens")
def get_tokens():
    """
    Drive the full TUAMI → T1 → TR exchange and return every token decoded.

    Call this endpoint from a browser or curl to observe the 3-step Entra
    Agent ID autonomous app flow in its entirety. Each token is base64-decoded
    and annotated inline so you can see exactly what information is transferred
    at each step.
    """
    out = {
        "flow":        "Entra Agent ID — Autonomous App (app-only) Flow",
        "description": "Blueprint UAMI → T1 exchange token → TR resource token",
        "note":        "Tokens are decoded for inspection. Signatures are NOT validated.",
        "steps":       {},
    }

    # ── Step 1: TUAMI ──────────────────────────────────────────────────────
    tuami_raw, tuami_resp = step1_get_tuami()
    if "error" in tuami_resp:
        out["steps"]["step1_tuami"] = {"status": "FAILED", **tuami_resp}
        return JSONResponse(content=out, status_code=500)

    tuami_decoded = decode_jwt(tuami_raw)
    out["steps"]["step1_tuami"] = {
        "status":  "OK",
        "title":   "TUAMI — Managed Identity token for the UAMI",
        "what_it_proves": (
            "This token proves: the UAMI exists and the calling code is running inside "
            "an Azure resource (ACA) that has this UAMI assigned. "
            "Azure AD will accept this as a client_assertion on the blueprint app."
        ),
        "key_claims": {
            "aud":  "api://AzureADTokenExchange  ← only valid for token exchange, not resource access",
            "sub":  f"{tuami_decoded.get('payload',{}).get('sub','?')}  ← UAMI principal objectId",
            "iss":  tuami_decoded.get('payload',{}).get('iss','?'),
        },
        "decoded":           tuami_decoded,
        "annotated_payload": annotate(tuami_decoded.get("payload", {})),
        "raw_preview":       tuami_raw[:50] + "...",
    }

    # ── Step 2: T1 ────────────────────────────────────────────────────────
    t1_raw, t1_resp = step2_get_t1(tuami_raw)
    if "error" in t1_resp:
        out["steps"]["step2_t1"] = {"status": "FAILED", **t1_resp}
        return JSONResponse(content=out, status_code=500)

    t1_decoded = decode_jwt(t1_raw)
    t1_payload = t1_decoded.get("payload", {})
    out["steps"]["step2_t1"] = {
        "status":  "OK",
        "title":   "T1 — Exchange token (intermediate; NOT a resource access token)",
        "what_it_proves": (
            "T1 proves: the blueprint's UAMI FIC was validated, AND fmi_path named a specific "
            "agent identity. T1 is used ONLY as client_assertion in Step 3 to trigger the "
            "blueprint-to-agent-identity impersonation. Never send T1 to a resource server."
        ),
        "key_claims": {
            "aud": f"{t1_payload.get('aud','?')}  ← MUST equal Blueprint client ID; validated by Entra in Step 3",
            "sub": f"{t1_payload.get('sub','?')}  ← Blueprint principal objectId in this tenant",
            "oid": f"{t1_payload.get('oid','?')}  ← same as sub",
        },
        "fmi_path_used": AGENT_IDENTITY_ID,
        "decoded":           t1_decoded,
        "annotated_payload": annotate(t1_payload),
        "raw_preview":       t1_raw[:50] + "...",
    }

    # ── Step 3: TR ────────────────────────────────────────────────────────
    tr_raw, tr_resp = step3_get_tr(t1_raw)
    if "error" in tr_resp:
        out["steps"]["step3_tr"] = {"status": "FAILED", **tr_resp}
        return JSONResponse(content=out, status_code=500)

    tr_decoded = decode_jwt(tr_raw)
    tr_payload = tr_decoded.get("payload", {})
    tr_sub = tr_payload.get("sub", "?")
    tr_oid = tr_payload.get("oid", "?")
    tr_azp = tr_payload.get("azp", "?")

    out["steps"]["step3_tr"] = {
        "status":  "OK",
        "title":   "TR — Resource access token for the Agent Identity",
        "what_it_proves": (
            "TR proves: the agent identity is authenticated and is authorised to access "
            "the target resource. This is the bearer token you attach to downstream API calls."
        ),
        "key_claims": {
            "sub": f"{tr_sub}  ← Agent Identity objectId (NOT the blueprint)",
            "oid": f"{tr_oid}  ← same as sub (oid==sub is unique to Agent Identity objects)",
            "azp": f"{tr_azp}  ← Agent Identity clientId (same as AGENT_IDENTITY_ID env var)",
            "aud": f"{tr_payload.get('aud','?')}  ← resource this token grants access to",
        },
        "decoded":           tr_decoded,
        "annotated_payload": annotate(tr_payload),
        "raw_token":         tr_raw,   # full TR so it can be copied for testing
    }

    # ── Final insight ─────────────────────────────────────────────────────
    out["summary"] = {
        "tuami_sub_uami_oid":  tuami_decoded.get("payload", {}).get("sub", "?"),
        "t1_aud_blueprint_id": t1_payload.get("aud", "?"),
        "tr_sub_agent_oid":    tr_sub,
        "blueprint_client_id": BLUEPRINT_CLIENT_ID,
        "insight": (
            "Notice: tr.sub == tr.oid — this equality is a unique marker of Entra Agent "
            "Identity objects. Regular service principals always have oid != appId. "
            "Resource servers can use this property to distinguish agent tokens from "
            "regular SP tokens in their authorization logic."
        ),
    }

    return JSONResponse(content=out)


@app.get("/obo")
def obo_exchange(user_token: str = Query(..., description="User access token (Tc) with aud=Blueprint client ID")):
    """
    Perform an On-Behalf-Of (OBO) exchange.

    Requires: a user access token (Tc) where Tc.aud == Blueprint client ID.
    The calling client app must have been configured to expose an API scope
    with the blueprint as its resource, and the user must have consented.

    The resulting delegated token will have:
      sub     = user objectId   (the human user being represented)
      act.sub = agent objectId  (the agent identity doing the acting)
      scp     = the delegated scopes the agent can exercise on behalf of the user

    OBO flow POST parameters:
      grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer   (RFC 8693)
      client_id=<agent identity clientId>
      client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
      client_assertion=<T1>
      assertion=<Tc>                  ← the user's token
      requested_token_use=on_behalf_of
      scope=<target resource scope>
    """
    # First get T1 (needs TUAMI first)
    tuami_raw, tuami_err = step1_get_tuami()
    if "error" in tuami_err:
        raise HTTPException(500, detail=tuami_err)

    t1_raw, t1_err = step2_get_t1(tuami_raw)
    if "error" in t1_err:
        raise HTTPException(500, detail=t1_err)

    # OBO exchange
    data = {
        "grant_type":             "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id":              AGENT_IDENTITY_ID,
        "client_assertion_type":  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":       t1_raw,
        "assertion":              user_token,          # Tc
        "requested_token_use":    "on_behalf_of",
        "scope":                  RESOURCE_SCOPE,
    }
    obo_resp  = http_post_form(TOKEN_ENDPOINT, data)
    obo_token = obo_resp.get("access_token", "")

    if "error" in obo_resp:
        raise HTTPException(500, detail=obo_resp)

    obo_decoded = decode_jwt(obo_token)
    obo_payload = obo_decoded.get("payload", {})
    act_claim   = obo_payload.get("act", {})

    return {
        "flow":    "OBO — On-Behalf-Of (delegated user context)",
        "decoded": obo_decoded,
        "key_claims": {
            "sub":     f"{obo_payload.get('sub','?')}  ← Human user objectId (the 'who' being helped)",
            "act.sub": f"{act_claim.get('sub','?')}  ← Agent Identity objectId (the 'who' is helping)",
            "scp":     f"{obo_payload.get('scp','?')}  ← Delegated user scopes agent can exercise",
            "azp":     f"{obo_payload.get('azp','?')}  ← Agent Identity clientId",
        },
        "insight": (
            "The act claim is the delegation fingerprint. It tells the resource server: "
            "'A human user (sub) granted consent, but an agent (act.sub) is actually making "
            "this call.' Both the user and the agent are auditable in resource server logs."
        ),
    }
