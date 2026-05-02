#!/usr/bin/env python3
"""
decode_jwt.py — Decode and annotate any JWT without signature validation.

This is an INSPECTION tool only — it does NOT validate signatures.
Use this to understand what information is encoded in each token.

Usage:
    python scripts/decode_jwt.py <token>          # direct argument
    python scripts/decode_jwt.py                  # paste token interactively
    echo "<token>" | python scripts/decode_jwt.py # pipe

The annotated output explains what each claim means in the context of
Azure Entra Agent ID, WSO2, SPIFFE, and OpenA2A AIM tokens.
"""

import base64
import json
import sys
from datetime import datetime, timezone

# ─── Claim annotations ───────────────────────────────────────────────────────
# Maps JWT claim name → human-readable description.
# Covers standard OIDC/OAuth2, Entra-specific, SPIFFE, and AIM claims.
CLAIM_ANNOTATIONS = {
    # ── Standard OAuth 2.0 / OIDC ────────────────────────────────────────────
    "iss":  "Issuer — who issued and signed this token (IdP URL or Entra tenant URL)",
    "sub":  "Subject — who this token represents. "
            "App-only tokens: agent/SP objectId. "
            "Delegated tokens: human user objectId. "
            "SPIFFE tokens: SPIFFE URI (spiffe://trust-domain/path).",
    "aud":  "Audience — the intended recipient. Token MUST be rejected if aud doesn't match.",
    "exp":  "Expiry (Unix timestamp) — token is invalid after this time",
    "iat":  "Issued At (Unix timestamp) — when the token was created",
    "nbf":  "Not Before (Unix timestamp) — token is invalid before this time",
    "jti":  "JWT ID — unique identifier for this specific token (used for replay prevention)",

    # ── Azure Entra / Azure AD ────────────────────────────────────────────────
    "oid":  "Object ID — the Entra ID object ID of the authenticated principal. "
            "For Agent Identity objects: oid == appId (unique Entra property). "
            "For regular service principals: oid != appId.",
    "azp":  "Authorized Party (azp) — client ID of the app that REQUESTED this token "
            "(i.e. the agent identity's client ID in TR tokens).",
    "azpacr": "Client authentication method used by azp: "
              "0 = public client (no secret), 1 = client secret, 2 = certificate/FIC.",
    "tid":  "Tenant ID — the Azure AD / Entra tenant that issued this token.",
    "ver":  "Token format version: '1.0' (legacy) or '2.0' (recommended).",
    "scp":  "Scopes — delegated permissions granted (only present in user-delegated/OBO tokens). "
            "Absent in pure app-only (client_credentials) tokens.",
    "roles": "App roles — application permissions granted to this app identity "
             "(only in app-only tokens where admin has granted app roles).",
    "act":  "Actor claim — identifies who is ACTING on behalf of the subject. "
            "Present in OBO (On-Behalf-Of) tokens. "
            "act.sub = the agent identity objectId making the call. "
            "sub = the human user being acted upon.",
    "acr":  "Authentication Context Class Reference — how the user authenticated.",
    "amr":  "Authentication Methods References — list of auth methods used.",
    "appid":  "(v1.0 tokens) Application ID — equivalent to azp in v2.0.",
    "appidacr": "(v1.0 tokens) Client authentication method for the app.",
    "idp":  "Identity Provider URL — who authenticated the subject (may differ from iss for guests).",
    "unique_name": "(v1.0) UPN or email address of the user.",
    "upn":  "User Principal Name — the user's login name.",
    "name": "Display name of the principal.",
    "family_name": "Last name (user tokens only).",
    "given_name":  "First name (user tokens only).",
    "email": "Email address.",
    # Internal Azure claims that carry no business meaning:
    "aio":  "(Azure internal) Opaque internal optimization claim — safe to ignore.",
    "rh":   "(Azure internal) Replay hash for internal validation — safe to ignore.",
    "uti":  "(Azure internal) Unique token identifier for tracing — safe to ignore.",
    "xms_tcdt": "Tenant creation datetime (internal).",

    # ── Entra Agent ID specific ───────────────────────────────────────────────
    # Note: As of Preview (May 2026) agent-specific claims beyond sub/oid/azp
    # are not documented in the public spec. These are anticipated additions.
    "fmi_path": "FMI Path — passed during T1 acquisition to specify which Agent Identity "
                "the Blueprint should impersonate. NOT present in the resulting token itself.",
    "agent_id": "Agent Identity ID (if added by custom claims mapping).",

    # ── SPIFFE JWT-SVID ───────────────────────────────────────────────────────
    # SPIFFE JWT-SVIDs use sub as the SPIFFE URI and have very short TTL.
    # They also carry the trust domain in iss.
    # sub for SPIFFE looks like: spiffe://trust-domain/workload/path

    # ── WSO2 Identity Server ──────────────────────────────────────────────────
    "client_id":  "(WSO2) OAuth 2.0 client ID of the requesting application.",
    "binding_type": "(WSO2) Token binding type (e.g., 'sso-session', 'certificate').",
    "aut":   "(WSO2) Authorized User Type: 'APPLICATION' for M2M tokens, 'APPLICATION_USER' for delegated.",
    "nbf":   "Not Before (Unix timestamp) — same as standard JWT.",

    # ── OpenA2A AIM specific ──────────────────────────────────────────────────
    "aim_agent_id":     "OpenA2A AIM agent identifier (base58 Ed25519 public key fingerprint).",
    "aim_trust_score":  "AIM trust score at token issuance (0.0–1.0, 8-factor weighted).",
    "aim_capabilities": "AIM capability list granted to this agent at issuance.",
    "aim_chain":        "AIM delegation chain — list of agent IDs in the delegation path.",
}


def _b64pad(s: str) -> str:
    """Add base64url padding characters."""
    return s + "=" * (-len(s) % 4)


def decode_part(b64url: str) -> dict:
    """Decode a base64url-encoded JWT part into a dict."""
    raw = base64.urlsafe_b64decode(_b64pad(b64url))
    return json.loads(raw.decode("utf-8"))


def fmt_ts(ts) -> str:
    """Format a Unix timestamp with ISO datetime and relative 'expires in N seconds'."""
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        diff = int((dt - now).total_seconds())
        if diff < 0:
            status = f"  *** EXPIRED {-diff}s ago ***"
        else:
            status = f"  (valid for {diff}s)"
        return f"{ts}  →  {dt.strftime('%Y-%m-%d %H:%M:%S UTC')}{status}"
    except Exception:
        return str(ts)


def _color(text: str, code: str) -> str:
    """Wrap text in ANSI color code (skipped on Windows without ANSI support)."""
    return f"\033[{code}m{text}\033[0m"


def print_claims(claims: dict, indent: int = 2):
    """Recursively print JWT claims with annotations."""
    pad = " " * indent
    for key, value in claims.items():
        annotation = CLAIM_ANNOTATIONS.get(key, "")
        is_timestamp = key in ("exp", "iat", "nbf", "xms_tcdt")

        if is_timestamp:
            display_val = fmt_ts(value)
        elif isinstance(value, (dict, list)):
            display_val = None  # printed recursively below
        else:
            display_val = str(value)

        # Claim name in cyan, value in yellow
        print(f"{pad}\033[36m{key}\033[0m: \033[33m{display_val or ''}\033[0m")

        if annotation:
            # Annotation in dim grey, wrapped at 90 chars
            words = annotation.split()
            line = f"{pad}    \033[2m# "
            for word in words:
                if len(line) + len(word) > 94:
                    print(line)
                    line = f"{pad}    \033[2m#   {word} "
                else:
                    line += word + " "
            print(line.rstrip() + "\033[0m")

        if isinstance(value, dict):
            print_claims(value, indent + 4)
        elif isinstance(value, list):
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    print(f"{pad}    [{i}]:")
                    print_claims(item, indent + 6)
                else:
                    print(f"{pad}    [{i}]: \033[33m{item}\033[0m")


def decode_token(raw_token: str, label: str = "JWT TOKEN") -> dict:
    """
    Decode a JWT and return the payload dict.
    Prints annotated header and payload to stdout.
    """
    token = raw_token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        print(f"\033[31mERROR: Not a valid JWT — expected 3 dot-separated parts, got {len(parts)}\033[0m")
        print("       Make sure you're passing only the JWT, not a JSON wrapper around it.")
        return {}

    try:
        header  = decode_part(parts[0])
        payload = decode_part(parts[1])
    except Exception as e:
        print(f"\033[31mERROR decoding JWT: {e}\033[0m")
        return {}

    alg = header.get("alg", "unknown")
    typ = header.get("typ", "JWT")
    kid = header.get("kid", "")

    print(f"\n{'═' * 72}")
    print(f"  \033[1m{label}\033[0m")
    print(f"{'═' * 72}")

    # ── Header ──
    print(f"\n\033[1m[HEADER]\033[0m")
    print(f"  alg: \033[33m{alg}\033[0m")
    if alg.startswith("Ed"):
        print(f"       \033[2m# Ed25519 signature — OpenA2A AIM non-standard OKP key (RFC 8037).\033[0m")
        print(f"       \033[2m# Standard OAuth middleware (RS256/ES256 only) will REJECT this token.\033[0m")
    elif alg in ("RS256", "RS384", "RS512"):
        print(f"       \033[2m# RSA signature — standard for Entra ID and WSO2 tokens.\033[0m")
    elif alg.startswith("ES"):
        print(f"       \033[2m# ECDSA signature — used in SPIFFE JWT-SVIDs.\033[0m")
    elif alg.startswith("ML-DSA") or "CRYSTALS" in alg:
        print(f"       \033[2m# Post-quantum CRYSTALS-Dilithium (ML-DSA) — AIM future token format.\033[0m")
    print(f"  typ: \033[33m{typ}\033[0m")
    if kid:
        print(f"  kid: \033[33m{kid}\033[0m   \033[2m# Key ID — tells the verifier which public key to use\033[0m")
    for k, v in header.items():
        if k not in ("alg", "typ", "kid"):
            print(f"  {k}: \033[33m{v}\033[0m")

    # ── Payload ──
    print(f"\n\033[1m[PAYLOAD]\033[0m")
    print_claims(payload)

    # ── Signature note ──
    print(f"\n\033[1m[SIGNATURE]\033[0m  \033[2m(NOT validated — inspection only)\033[0m")
    print(f"  Algorithm:  {alg}")
    print(f"  Raw prefix: {parts[2][:48]}...")
    print(f"  \033[2m# To validate, you would fetch the public key from the issuer's JWKS endpoint\033[0m")
    if payload.get("iss"):
        iss = payload["iss"].rstrip("/")
        if "microsoftonline" in iss:
            print(f"  \033[2m# Entra JWKS: {iss}/discovery/v2.0/keys\033[0m")
        elif "spiffe" in str(payload.get("sub", "")):
            print(f"  \033[2m# SPIFFE JWKS: fetched from SPIRE server trust bundle endpoint\033[0m")
        elif "localhost:9443" in iss or "wso2" in iss.lower():
            print(f"  \033[2m# WSO2 JWKS: {iss}/.well-known/jwks.json (or /oauth2/jwks)\033[0m")
    print()

    return payload


def identify_token_type(payload: dict) -> str:
    """Heuristically identify what kind of token this is."""
    iss = payload.get("iss", "")
    sub = payload.get("sub", "")
    act = payload.get("act")

    if "microsoftonline" in iss:
        if act:
            return "Entra — Delegated OBO token (sub=user, act=agent)"
        elif payload.get("scp"):
            return "Entra — Delegated access token (sub=user, has scopes)"
        elif payload.get("roles") or not payload.get("scp"):
            if payload.get("oid") == payload.get("azp"):
                return "Entra — Agent Identity TR resource token (oid==azp is Agent Identity marker)"
            return "Entra — App-only access token (client_credentials)"
    elif "spiffe://" in sub:
        return "SPIFFE JWT-SVID (workload identity)"
    elif payload.get("aut") == "APPLICATION" or payload.get("client_id"):
        return "WSO2 — M2M application token"
    elif payload.get("aim_agent_id") or payload.get("aim_trust_score") is not None:
        return "OpenA2A AIM — Ed25519-signed agent token"
    return "Unknown token type"


if __name__ == "__main__":
    # Read token from argument or stdin
    if len(sys.argv) > 1:
        raw_token = sys.argv[1]
    else:
        print("Paste JWT token (then press Enter + Ctrl+Z on Windows / Ctrl+D on Unix):")
        raw_token = sys.stdin.read().strip()

    if not raw_token:
        print("No token provided.")
        sys.exit(1)

    # Quick type identification before full decode
    try:
        parts = raw_token.strip().split(".")
        payload_preview = decode_part(parts[1]) if len(parts) == 3 else {}
        token_type = identify_token_type(payload_preview)
        print(f"\n\033[1mToken type (heuristic): \033[32m{token_type}\033[0m")
    except Exception:
        pass

    decode_token(raw_token)
