# Borrowable Patterns from OpenA2A AIM (Script 11)

*These are five security patterns extracted from AIM's architecture and implemented as standalone Python in `scripts/11_borrowable_patterns.py`. Each pattern can be dropped on top of **any** identity system — Entra, WSO2, SPIRE, or even a plain managed identity. None requires an AIM server.*

Run them:
```
python scripts/11_borrowable_patterns.py           # all 5
python scripts/11_borrowable_patterns.py --pattern 3  # just FGA
```

---

## Pattern 1: Hash-Chain Audit Log

**Class:** `HashChainAuditLog`

**What it does:** Wraps a JSONL file where each event includes:
- `event_hash` = `SHA256(action + target + result + timestamp + agent_id)`
- `chain_hash` = `SHA256(event_hash + previous_chain_hash)`

Because each hash covers the previous one, modifying any past record cascades into a broken chain from that point forward. The log file can be handed to an auditor and verified independently with no external system.

**Why it matters:** Azure Monitor and Entra audit logs are trustworthy at the platform level (Microsoft controls tamper-proofing). But your *application-layer* logs — what tool the agent called, what data it read, what decision it made — are flat files. Anyone with write access can alter them silently. This pattern makes that impossible to hide.

**How to use it with any identity system:**

```python
from scripts.eleven_borrowable_patterns import HashChainAuditLog

log = HashChainAuditLog("logs/agent_audit.jsonl")

# After getting a token from Entra/WSO2/SPIRE — log with agent's identity
token_sub = decoded_jwt["sub"]  # e.g. "b8011268-72f7-47fc-..." (Entra oid)

log.append("db:read",  "customers",    "allowed", agent_id=token_sub)
log.append("api:call", "slack/notify", "allowed", agent_id=token_sub,
           metadata={"notification_type": "alert"})
log.append("db:write", "invoices",     "denied",  agent_id=token_sub)

# Verify at any time (e.g. in a compliance job)
valid, errors = log.verify()
# valid=True → untouched. valid=False → errors[0] = "Event 2: event_hash MISMATCH"
```

**What the tamper test showed (demo output):**
```
+ db:read     → customers   = allowed    chain: a3f1c2e8b9d4f801...
+ api:call    → weather     = allowed    chain: 7b2e9d3c1f5a0e24...
+ db:write    → orders      = denied     chain: 9c4f1a7b2e6d3c08...

Verify (clean):    ✓ VALID
Tampered event 2:  result changed allowed → denied
Verify (tampered): ✗ BROKEN
  ! Event 2 (api:call → weather): event_hash MISMATCH — data was modified
  ! Event 3 (db:write → orders):  chain_hash MISMATCH — upstream event was modified
```

---

## Pattern 2: 8-Factor Trust Scorer

**Class:** `TrustScorer`, `TrustFactors`

**What it does:** Computes a `0.0–1.0` trust score from 8 behavioral factors with fixed weights:

| Factor | Weight | Meaning |
|---|---|---|
| `verification` | 25% | Is the agent registered and confirmed? |
| `uptime` | 15% | Availability track record |
| `action_success` | 15% | Ratio of successful to total actions |
| `security_alerts` | 15% | Inverse of security incident count |
| `compliance` | 10% | Policy-compliant action ratio |
| `age` | 10% | `min(days_old / 30, 1.0)` — saturates at 30 days |
| `drift` | 5% | Absence of behavioral drift |
| `user_feedback` | 5% | Normalized user rating |

The score also applies **delegation attenuation**: each hop in a delegation chain multiplies the score by 0.8. An agent with score 0.90 that was called through 2 delegation hops effectively presents 0.90 × 0.64 = 0.576 to the resource it's accessing.

**Per-capability thresholds (built-in defaults):**

| Capability | Minimum Trust |
|---|---|
| `db:read`, `api:call` | 0.0 (open) |
| `file:read` | 0.3 |
| `db:write` | 0.6 |
| `deploy` | 0.7 |
| `system:admin` | 0.85 |
| `secrets:rotate` | 0.90 |
| `infra:destroy` | 0.95 |

**How to use it:**

```python
from scripts.eleven_borrowable_patterns import TrustScorer, TrustFactors

# Fetch behavioral data from your monitoring system
factors = TrustFactors(
    verification=1.0,
    uptime=0.97,
    action_success=0.994,
    security_alerts=0.95,   # one minor alert in past month
    compliance=1.0,
    age=min(agent_days_old / 30, 1.0),
    drift=0.98,
    user_feedback=0.80,
)

scorer = TrustScorer(factors, delegation_hop=0)
print(scorer.score)              # e.g. 0.923

allowed, reason = scorer.check("db:write")
# True  → "Trust 0.92 ≥ threshold 0.60"
# False → "Trust 0.45 < threshold 0.60 for 'db:write'. Improve: 'age' factor (current: 0.10)"
```

**What the demo showed:**
```
New agent (just registered):  trust = 0.25
  ✓ db:read            Trust 0.25 ≥ threshold 0.00
  ✗ db:write           Trust 0.25 < threshold 0.60
  ✗ system:admin       Trust 0.25 < threshold 0.85

Established agent (30+ days): trust = 0.95
  ✓ db:read, db:write, system:admin
  ✗ infra:destroy      Trust 0.95 < threshold 0.95  (borderline)

After 2 delegation hops: trust = 0.61
  ✗ db:write           Trust 0.61 < threshold 0.60  (near-miss after attenuation)
```

---

## Pattern 3: 5-Step FGA Gateway

**Class:** `FGAGateway`, `FGAContext`, `FGADecision`

**What it does:** Runs every authorization request through 5 sequential gates. First denial stops the chain and returns which gate blocked it.

```
capability_check → attribute_check → context_check → chain_check → intent_check
```

| Gate | What it checks |
|---|---|
| 1. `capability` | Does the agent's registered capability list include this action? |
| 2. `attribute` | Does the agent's trust score meet the per-capability minimum? |
| 3. `context` | Is the runtime risk level (normal/elevated/critical) compatible with the action? |
| 4. `chain` | Is the delegation chain depth within policy? Are all intermediate agents trusted? |
| 5. `intent` | Does the declared reason for the action semantically match the action type? |

Gates 4 and 5 are not present in Entra Conditional Access, WSO2 RBAC, or Azure RBAC. They are specific to AIM's model.

**How to use it as FastAPI middleware:**

```python
from fastapi import Depends, HTTPException, Request
from scripts.eleven_borrowable_patterns import FGAGateway, FGAContext

# Initialize from your identity token
def build_gateway(token_payload: dict) -> FGAGateway:
    return FGAGateway(
        agent_id=token_payload["sub"],
        capabilities=token_payload.get("roles", []),
        trust_score=get_trust_score(token_payload["sub"]),  # from AIM or your own scorer
        policy={"max_delegation_depth": 2}
    )

@app.post("/api/data/write")
async def write_data(request: Request, payload: WriteRequest):
    gw = build_gateway(request.state.token)
    ctx = FGAContext(
        action="db:write",
        resource=payload.table,
        risk_level="normal",
        declared_intent=payload.intent,     # from the LLM's stated reasoning
        delegation_chain=request.headers.getlist("X-Agent-Chain"),
    )
    decision = gw.evaluate(ctx)
    if not decision:
        raise HTTPException(403, f"Denied at '{decision.denied_at}': {decision.reason}")
    # proceed
```

**What the demo showed:**

```
✓ db:read      risk=normal     chain=0
✗ db:write     risk=elevated   chain=1   [gate: context]
    reason: Elevated risk + privileged action requires human approval
✗ db:write     risk=normal     chain=1   [gate: intent]
    reason: Declared intent ('read order data') doesn't match action 'db:write'
✗ db:read      risk=normal     chain=3   [gate: chain]
    reason: Unknown agents in delegation chain: ['unknown_agent_xyz']
```

---

## Pattern 4: Secretless Credential

**Class:** `SecretlessCredential`

**What it does:** A Python context manager that:
1. Reads a credential from env var, file, or vault backend
2. Provides it as a `bytes` object inside the `with` block
3. On exit, calls `ctypes.memset()` to **zero the credential bytes directly in C memory**

**Why `del my_secret` is not enough:** Python strings are immutable and interned. `del` removes the variable reference but the bytes can persist in memory indefinitely until GC overwrites them. A memory snapshot, core dump, or LLM tool call that reads process memory could see the credential. `ctypes.memset()` overwrites the internal C buffer immediately.

**How to use it:**

```python
from scripts.eleven_borrowable_patterns import SecretlessCredential

# Credential lives only inside the 'with' block
with SecretlessCredential("AZURE_CLIENT_SECRET", source="env") as cred:
    token = requests.post(token_url, data={
        "client_secret": cred.decode(),
        ...
    })
# cred is gone; memory is zeroed

# File-based (reads and deletes the file):
with SecretlessCredential("/run/secrets/api_key", source="file") as cred:
    make_api_call(cred)
```

**Relevance to AI agents specifically:** When an agent calls an LLM tool that has access to process inspection (e.g. a code execution sandbox), or when the LLM itself summarizes "what's in your environment variables" in a chain-of-thought step, credentials in `os.environ` or local variables can leak into the LLM's context window or tool outputs. This pattern limits the credential's in-memory lifetime to the minimum necessary window.

---

## Pattern 5: Break-Glass Token with Separate Audit Stream

**Class:** `BreakGlassToken`

**What it does:** Issues HMAC-SHA256-signed, time-limited emergency tokens for operations that would normally be blocked by FGA (e.g. `infra:destroy` at critical risk). Two key properties:

1. **Short TTL** (default 5 minutes). Expired tokens are auto-denied regardless of signature validity. Safe default: emergency tokens cannot be pre-staged.
2. **Separate audit stream.** Break-glass actions are written to a *different log file* (`breakglass_audit.jsonl`) than normal operations. The main audit log gets a redacted marker entry. An attacker who compromises the main log still cannot erase the evidence in the break-glass stream — they'd need to compromise both simultaneously.

**Token format:**
```
base64url( "{agent_id}:{issued_at}:{reason}" ||| {hmac_sha256_hex} )
```

**How to use it:**

```python
from scripts.eleven_borrowable_patterns import BreakGlassToken, FGAGateway, FGAContext
import os

bg = BreakGlassToken(secret_key=os.environ["BREAKGLASS_HMAC_KEY"].encode())

# Human operator (or PagerDuty automation) generates a break-glass token
token = bg.generate(agent_id="svc-deployer-prod", reason="P0 rollback, prod down 14:32 UTC")

# Agent receives the token, verifies it, and logs the protected action
valid, issuer_agent_id = bg.verify(token)
if not valid:
    raise PermissionError(f"Break-glass token invalid: {issuer_agent_id}")

bg.log("infra:destroy", "prod-cluster", agent_id="svc-deployer-prod", used_token=token)
# → written to breakglass_audit.jsonl + marker in normal_audit.jsonl
```

**What the demo showed:**
```
Normal FGA for 'infra:destroy' at critical risk:
✗ DENIED at 'context' — Critical risk level requires human approval

Break-glass token generated: BG_TOKEN_abc123...
Verify (immediate):  ✓ VALID — agent: svc-deployer-prod
Operation logged to both audit streams.

[5 seconds later]
Verify (after 5-min TTL): ✗ EXPIRED — expired 2s ago. Safe default: auto-denied.

Main audit log:  1 BREAKGLASS_MARKER entry
Break-glass log: 1 BREAKGLASS_GENERATED + 1 BREAKGLASS_ACTION
→ Tamper both logs to hide event? Would require compromising two separate storage paths.
```

---

## When to Use Which Pattern

| You need... | Use |
|---|---|
| Auditors to verify your log wasn't altered | Pattern 1 (Hash-Chain Audit) |
| High-value ops gated on agent track record | Pattern 2 (Trust Scorer) |
| Per-operation, per-intent authorization in your API | Pattern 3 (FGA Gateway) |
| Credentials that auto-erase from memory after use | Pattern 4 (Secretless Credential) |
| Emergency overrides with minimal attack surface | Pattern 5 (Break-Glass Token) |
| Working with Entra tokens | Any — use `decoded_jwt["sub"]` as `agent_id` |
| Working with WSO2 tokens | Any — use `decoded_jwt["client_id"]` as `agent_id` |
| Working with SPIRE SVIDs | Any — use the SVID `sub` (SPIFFE URI) as `agent_id` |

All five patterns are **identity-system-agnostic**. They add a security layer on top of whatever token you already have.
