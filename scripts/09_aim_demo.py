#!/usr/bin/env python3
"""
Phase 4: OpenA2A AIM (Agent Identity Management) Demo

OpenA2A AIM unique security features vs WSO2 Agent ID and Entra Agent ID:
  1. Ed25519 + ML-DSA (post-quantum) cryptographic identity â€” agent holds its own keypair
  2. Tamper-evident hash-chain audit log â€” SHA-256 chained events
  3. 5-step FGA with Intent Check â€” step 4 (chain check) and step 5 (intent check) are unique
  4. 8-factor trust scoring â€” behavioral score gates per-capability access
  5. MCP attestation via multi-agent consensus â€” 3+ unique attesters from 2+ owners
  6. Secretless 3-tier credential injection â€” LLM-context-aware
  7. Break-glass dual-auth with SEPARATE audit stream
  8. Non-standard JWT: Ed25519 OKP signed â€” won't validate in RS256/ES256-only middleware

This script uses the AIM REST API directly (more transparent than the SDK).

Prereq:
  Option A: git clone https://github.com/opena2a-org/agent-identity-management
            cd agent-identity-management && docker compose -f docker-compose.quickstart.yml up
  Option B: docker compose -f docker/aim/docker-compose.yml up

Run: python scripts/09_aim_demo.py
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# â”€â”€ Load .env.local â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_env_path = Path(".env.local")
if _env_path.exists():
    for _line in _env_path.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

AIM_API    = os.environ.get("AIM_API_URL", "http://127.0.0.1:8080")
AIM_API_KEY = os.environ.get("AIM_API_KEY", "")
AIM_AGENT_ID = os.environ.get("AIM_AGENT_ID", "")
CAPTURE_DIR = Path("captured_tokens")
SEP = "=" * 72


def _b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        return {"raw": token[:80]}
    try:
        h = json.loads(base64.urlsafe_b64decode(_b64pad(parts[0])))
        p = json.loads(base64.urlsafe_b64decode(_b64pad(parts[1])))
        return {"header": h, "payload": p}
    except Exception as exc:
        return {"error": str(exc)}


def api(method: str, path: str, body: dict | None = None,
        token: str | None = None) -> tuple[int, dict]:
    url = f"{AIM_API}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            resp = r.read()
            return r.status, json.loads(resp) if resp else {}
    except urllib.error.HTTPError as e:
        body_ = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(body_)
        except Exception:
            return e.code, {"raw": body_[:300]}
    except urllib.error.URLError as e:
        return 0, {"error": str(e)}


def wait_for_aim(max_wait: int = 60) -> bool:
    print("  Waiting for AIM server", end="", flush=True)
    for _ in range(max_wait // 3):
        code, _ = api("GET", "/health")
        if code == 200:
            print(" âœ“")
            return True
        print(".", end="", flush=True)
        time.sleep(3)
    print(" TIMED OUT")
    return False


def fmt_ts(ts) -> str:
    try:
        dt  = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        diff = int((dt - now).total_seconds())
        return f"{ts} â†’ {dt.strftime('%Y-%m-%d %H:%M:%S UTC')} ({'valid ' + str(diff) + 's' if diff > 0 else 'EXPIRED'})"
    except Exception:
        return str(ts)


def main():
    print(f"\n{SEP}")
    print("  PHASE 4: OpenA2A AIM â€” Agent Identity Demo")
    print(f"{SEP}\n")
    print(f"  AIM API: {AIM_API}")
    print(f"  Dashboard: {os.environ.get('AIM_DASHBOARD_URL','http://localhost:3000')}\n")

    if not wait_for_aim():
        print("\033[31m  AIM server is not responding.\033[0m")
        print(f"  Start AIM with one of:")
        print(f"    docker compose -f docker/aim/docker-compose.yml up -d")
        sys.exit(1)

    # â”€â”€ Auth: login to get a session JWT for admin ops â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    #   AIM has two auth tiers:
    #     1. User JWT  (from /api/v1/public/login) â€” for admin-level management APIs
    #     2. Agent API key (aim_live_...) â€” for agent-level runtime APIs (FGA, authorize)
    #   The API key is provisioned once during agent creation and stored in .env.local.
    if not AIM_API_KEY:
        print("\033[31m  AIM_API_KEY not set in .env.local.\033[0m")
        print("  Run: python scripts/09_aim_demo.py  (after AIM containers are up)")
        sys.exit(1)

    print("[0/7] Authenticating with AIM server...")
    _, login_resp = api("POST", "/api/v1/public/login", body={
        "email": "admin@opena2a.org",
        "password": "AIM2025!Secure",
    })
    session_jwt = login_resp.get("accessToken", "")
    if not session_jwt:
        print(f"  \033[31m  Login failed: {login_resp}\033[0m")
        sys.exit(1)
    print(f"  âœ“ Admin session JWT obtained (valid for management APIs)")
    print(f"  âœ“ Agent API key: {AIM_API_KEY[:20]}...  (used for runtime FGA calls)")
    print(f"\n  Auth scheme:")
    print(f"    User session JWT  â†’ Bearer token for /api/v1/admin/*, /api/v1/trust-score/*, etc.")
    print(f"    Agent API key     â†’ Bearer token for /api/v1/agents/{{id}}/authorize, etc.")
    print(f"    Both are HS256 JWT or opaque bearer strings â€” unlike SPIRE (X.509 SVID)")
    print(f"    and unlike Entra (RS256 JWT signed by Microsoft)")

    # â”€â”€ Step 1: Reuse or register an agent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[1/7] Agent identity registration...")
    print("  AIM provisions agents with Ed25519 keypairs â€” the public key IS the")
    print("  stable identity handle alongside the UUID. Agents can sign without calling AIM.")

    agent_id = AIM_AGENT_ID
    pub_key  = ""

    if agent_id:
        status, reg = api("GET", f"/api/v1/agents/{agent_id}", token=session_jwt)
        if status == 200:
            pub_key = reg.get("publicKey", "")
            print(f"  âœ“ Reusing existing agent: {agent_id}")
        else:
            agent_id = ""  # fall through to create

    if not agent_id:
        status, reg = api("POST", "/api/v1/agents", body={
            "name":         "demo-agent",
            "display_name": "Demo Agent",
            "description":  "Demonstration AI agent for identity management comparison",
            "agent_type":   "ai_agent",
        }, token=session_jwt)
        if status in (200, 201):
            agent_id = reg.get("id", "")
            pub_key  = reg.get("publicKey", "")
            # Register capabilities for FGA testing
            for cap in ("db:read", "api:call", "file:read"):
                api("POST", f"/api/v1/agents/{agent_id}/capabilities",
                    body={"capabilityType": cap}, token=session_jwt)
            print(f"  âœ“ Agent created: {agent_id}")
        else:
            print(f"  \033[31m  Agent creation failed {status}: {reg}\033[0m")
            sys.exit(1)

    print(f"    Agent UUID:   {agent_id}")
    print(f"    Public key:   {pub_key or '(not returned)'}")
    print(f"    Technology note: Ed25519 key â€” NOT a UUID assigned by a cloud provider.")
    print(f"    The agent CAN sign data with its private key without calling any server.")
    print(f"    Compare Entra: identity = objectId (cloud-assigned, server-controlled)")
    print(f"    Compare WSO2:  identity = clientId (cloud-assigned, server-controlled)")

    # â”€â”€ Step 2: Inspect the AIM API key (agent credential) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[2/7] AIM Agent Credential â€” API Key Structure...")
    print(f"  AIM provides an opaque API key (aim_live_...) as the agent runtime credential.")
    print(f"  This differs from Entra (RS256-signed JWT) and WSO2 (RS256/HS256 JWT).")
    print()
    key_prefix = AIM_API_KEY[:20]
    print(f"  API key (first 20 chars): \033[33m{key_prefix}...\033[0m")
    print(f"  Format: aim_live_<base64url-encoded-secret>")
    print(f"  NOT a JWT â€” no header/payload/signature dot-separated sections.")
    print(f"  The AIM server validates it via bcrypt hash lookup in the database.")
    print(f"\n  Session JWT decoded (the user management token):")
    decoded_session = decode_jwt(session_jwt)
    h = decoded_session.get("header", {})
    p = decoded_session.get("payload", {})
    print(f"    alg: \033[33m{h.get('alg','?')}\033[0m  (HS256 â€” symmetric, not RS256/EdDSA)")
    print(f"    sub: \033[33m{p.get('sub','?')}\033[0m  (user UUID)")
    print(f"    role: \033[33m{p.get('role','?')}\033[0m")
    for k in ("iat", "exp"):
        if k in p:
            print(f"    {k}: \033[33m{fmt_ts(p[k])}\033[0m")
    aim_token = session_jwt

    # â”€â”€ Step 3: FGA â€” 5-step authorization pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[3/7] Fine-Grained Authorization (FGA) â€” Authorization Pipeline Demo...")
    print(f"  AIM evaluates every action through a gate pipeline.")
    print(f"  All gates must pass. A failure returns a typed denial with the blocking step.")
    print()

    # Test 1: allowed action (db:read â€” registered)
    print(f"  Test 1: capability='db:read', resource='customers', riskLevel='normal'")
    _, fga_allow = api("POST", f"/api/v1/agents/{agent_id}/authorize", body={
        "capability": "db:read",
        "resource":   "customers",
        "context":    {"riskLevel": "normal", "intent": "read customer data for report"},
    }, token=AIM_API_KEY)

    print(f"  Result: {json.dumps(fga_allow, indent=4)}")
    if fga_allow.get("allowed"):
        print(f"  \033[32m  âœ“ ALLOWED â€” passed all FGA gates\033[0m")
    else:
        denied_at = fga_allow.get("deniedBy", fga_allow.get("deniedAt", "?"))
        reason = fga_allow.get("deniedReason", fga_allow.get("reason", "?"))
        print(f"  \033[33m  âœ— DENIED at gate '{denied_at}': {reason}\033[0m")

    print()

    # Test 2: denied action (db:write â€” NOT registered)
    print(f"  Test 2: capability='db:write', resource='invoices', riskLevel='elevated'")
    _, fga_deny = api("POST", f"/api/v1/agents/{agent_id}/authorize", body={
        "capability": "db:write",
        "resource":   "invoices",
        "context":    {"riskLevel": "elevated", "intent": "update invoice amounts"},
    }, token=AIM_API_KEY)

    print(f"  Result: {json.dumps(fga_deny, indent=4)}")
    if not fga_deny.get("allowed"):
        denied_at = fga_deny.get("deniedBy", fga_deny.get("deniedAt", "gate unknown"))
        reason    = fga_deny.get("deniedReason", fga_deny.get("reason", "no reason given"))
        print(f"  \033[32m  âœ“ DENIED (as expected) at gate '{denied_at}': {reason}\033[0m")
        print(f"\n  The FGA gates (stepsTriggered shows which were evaluated):")
        print(f"    capability_check: Does agent have this capability registered?")
        print(f"    attribute_check:  Agent attributes satisfy policy conditions?")
        print(f"    context_check:    Context (riskLevel/intent) satisfies policy?")
        print(f"    chain_check:      Delegation chain valid and within scope?")
        print(f"    intent_check:     Declared intent matches the action?")
        print(f"                      â† UNIQUE to AIM â€” not in Entra or WSO2")
    else:
        print(f"  (Unexpectedly allowed â€” check FGA policy config in AIM dashboard)")

    # â”€â”€ Step 4: Trust score â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[4/7] Trust Score â€” Multi-Factor Behavioral Model...")
    # Trust score API requires session JWT (admin read), not the API key
    _, trust_resp = api("GET", f"/api/v1/trust-score/agents/{agent_id}", token=session_jwt)

    overall = trust_resp.get("score", trust_resp.get("trustScore", "?"))
    factors = trust_resp.get("factors", {})

    print(f"  Overall trust score: \033[33m{overall}\033[0m  (0.0 = untrusted, 1.0 = fully trusted)")
    print()
    print(f"  {'Factor':<25} {'Score':<8} Description")
    print(f"  {'â”€'*25} {'â”€'*8} {'â”€'*40}")

    FACTOR_INFO = {
        "verificationStatus": "Is agent verified by AIM server?",
        "uptime":             "Availability / reliability track record",
        "successRate":        "Ratio of successful vs. failed actions",
        "securityAlerts":     "Number & severity of security events",
        "compliance":         "Adherence to declared capability policies",
        "age":                "How long the agent identity has existed",
        "driftDetection":     "Behavioral deviation from established baseline",
        "userFeedback":       "Explicit human feedback/ratings",
        "executionIsolation": "Isolation enforced for code execution",
    }
    for name, desc in FACTOR_INFO.items():
        val = factors.get(name, "n/a")
        print(f"  {name:<25} {str(val):<8} {desc}")

    print(f"\n  Trust score usage:")
    print(f"    Per-capability thresholds: e.g., system:admin requires â‰¥0.70 trust")
    print(f"    Delegation attenuation: each hop multiplies effective trust by 0.8x")
    print(f"    Compare Entra: no behavioral trust score. Identity Protection provides")
    print(f"    ML risk SIGNALS but not a weighted per-capability gate.")
    print(f"    Compare WSO2: no behavioral trust scoring (policy-based only).")

    # â”€â”€ Step 5: MCP Attestation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[5/7] MCP Attestation â€” Multi-Agent Consensus...")
    _, mcp_resp = api("GET", f"/api/v1/agents/{agent_id}/mcp-servers", token=session_jwt)

    mcp_servers = mcp_resp.get("mcpServers", mcp_resp.get("servers", []))
    print(f"  MCP servers connected to this agent: {len(mcp_servers)}")
    print(f"  MCP attestation concept:")
    print(f"    Each MCP server gets an attestation status: 'verified' (3+ attesters")
    print(f"    from 2+ owners), 'pending', or 'drifted' (capabilities changed).")
    print(f"    This detects MCP supply chain attacks â€” if a server's tools change")
    print(f"    unexpectedly, drift is detected before the agent trusts the server.")
    print(f"    Compare: Entra/WSO2 have NO MCP-level attestation mechanism.")

    # â”€â”€ Step 6: Audit log â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[6/7] Audit Log â€” Admin audit trail...")

    _, audit_resp = api("GET", "/api/v1/admin/audit-logs?limit=10", token=session_jwt)
    logs = audit_resp.get("logs", [])
    print(f"  Admin audit events ({len(logs)} recent):")
    for ev in logs[:5]:
        action      = ev.get("action", "?")
        resource    = ev.get("resourceType", "?")
        ts          = ev.get("timestamp", "?")[:19]
        print(f"    {action:<12} {resource:<15} at {ts}")

    print(f"\n  Audit log properties:")
    print(f"    Every management action (create agent, grant capability, issue key)")
    print(f"    is recorded with userId, IP, userAgent, and metadata.")
    print(f"    See scripts/10_aim_audit_tamper.py for tamper-detection demo.")

    # â”€â”€ Step 7: Secretless credential pattern â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print(f"\n[7/7] Secretless Credential Concept (Tier 1: in-process zero-copy)...")
    print(f"  AIM's secretless design: credentials are resolved INTO the call stack")
    print(f"  and zeroed from memory immediately after use via ctypes.memset().")
    print(f"  The credential value NEVER appears in:")
    print(f"    - Environment variables (visible in ps, /proc/PID/environ)")
    print(f"    - Log files")
    print(f"    - LLM context / prompt (the AI coding tool cannot read it)")
    print(f"    - MCP config JSON (which normally stores API keys in plaintext)")
    print(f"")
    print(f"  Demo (Python implementation):")
    print(f"    See scripts/11_borrowable_patterns.py â†’ SecretlessCredential class")
    print(f"    The pattern is borrowable and works WITHOUT AIM (standalone Python).")
    print(f"")
    print(f"  Compare Entra: UAMI + managed identity achieves secretless for Azure-hosted code.")
    print(f"  Compare WSO2:  Has vault integration but no LLM-context-aware injection.")

    # Save for comparison
    CAPTURE_DIR.mkdir(exist_ok=True)
    with open(CAPTURE_DIR / "aim_token.json", "w") as f:
        json.dump({
            "source":         "aim",
            "credential_type": "opaque_api_key + HS256_session_jwt",
            "api_key_prefix": AIM_API_KEY[:20] + "...",
            "session_jwt_decoded": decoded_session,
            "agent_id":       agent_id,
            "agent_pubkey":   pub_key,
            "trust_score":    overall,
            "fga_allow":      fga_allow,
            "fga_deny":       fga_deny,
        }, f, indent=2, default=str)

    print(f"\n  Saved to captured_tokens/aim_token.json")
    print(f"\n  Next: python scripts/10_aim_audit_tamper.py  â€” tamper-evident log demo")
    print(f"\n{SEP}\n")
    print(f"  To stop AIM: docker compose -f docker/aim/docker-compose.yml down")


if __name__ == "__main__":
    main()
