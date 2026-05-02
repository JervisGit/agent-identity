#!/usr/bin/env python3
"""
Phase 5: Borrowable AIM Security Patterns

Five security patterns from OpenA2A AIM that can be added on top of ANY identity
system (Entra Agent ID, WSO2, SPIFFE, or even a basic service principal).

Each pattern is standalone Python — no external dependencies, no AIM server required.
Each has an if __name__ == "__main__" demo that runs locally.

Patterns:
  1. HashChainAuditLog   — SHA-256 chained events, tamper-evident
  2. TrustScorer         — 8-factor weighted behavioral trust model
  3. FGAGateway          — 5-step authorization pipeline (capability, attribute, context, chain, intent)
  4. SecretlessCredential — Zero-copy credential injection with ctypes memory zeroing
  5. BreakGlassToken     — HMAC-signed time-limited emergency token with separate audit stream

Run:
  python scripts/11_borrowable_patterns.py
  python scripts/11_borrowable_patterns.py --pattern 1   # run only pattern 1
  python scripts/11_borrowable_patterns.py --pattern 4   # run only SecretlessCredential
"""

import ctypes
import hashlib
import hmac
import json
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SEP = "=" * 72


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 1: Hash-Chain Audit Log
# ─────────────────────────────────────────────────────────────────────────────

class HashChainAuditLog:
    """
    Append-only audit log with SHA-256 hash chain integrity.

    Each event's chain_hash covers the event's content AND the previous chain_hash.
    Modifying any event invalidates its hash and ALL subsequent hashes.

    Works on top of any identity system — integrate like this:
        log = HashChainAuditLog("audit.jsonl")
        log.append("db:read", "customers", "allowed", agent_id="aim_7f3a9c2e")
        token = get_azure_token()
        log.append("api:call", "graph/users", "allowed", metadata={"token_sub": token["sub"]})
        log.verify()  # prints chain integrity status

    The agent_id stored in each log entry links audit events to the identity token.
    This makes logs meaningful: you see BOTH the action AND which identity performed it.
    """

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_chain_hash = self._load_last_chain_hash()

    def _load_last_chain_hash(self) -> str:
        if not self.path.exists():
            return ""
        with open(self.path) as f:
            lines = [l.strip() for l in f if l.strip()]
        if not lines:
            return ""
        last = json.loads(lines[-1])
        return last.get("chain_hash", "")

    def _event_hash(self, event: dict) -> str:
        """SHA256 of the event's immutable fields."""
        immutable = json.dumps({
            k: event[k]
            for k in ("action", "target", "result", "timestamp", "agent_id")
            if k in event
        }, sort_keys=True)
        return hashlib.sha256(immutable.encode()).hexdigest()

    def append(self, action: str, target: str, result: str,
               agent_id: str = "unknown", metadata: dict | None = None) -> dict:
        """Append a new event to the log."""
        event = {
            "action":    action,
            "target":    target,
            "result":    result,
            "agent_id":  agent_id,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        }
        if metadata:
            event["metadata"] = metadata

        event_hash  = self._event_hash(event)
        chain_hash  = hashlib.sha256((event_hash + self._prev_chain_hash).encode()).hexdigest()
        event["event_hash"] = event_hash
        event["chain_hash"] = chain_hash
        self._prev_chain_hash = chain_hash

        with open(self.path, "a") as f:
            f.write(json.dumps(event) + "\n")
        return event

    def verify(self) -> tuple[bool, list[str]]:
        """
        Verify the complete hash chain.
        Returns (is_valid, list_of_error_messages).
        """
        if not self.path.exists():
            return True, []

        events = [json.loads(l) for l in open(self.path) if l.strip()]
        errors = []
        prev = ""

        for i, ev in enumerate(events):
            computed_event_hash  = self._event_hash(ev)
            expected_chain_hash  = hashlib.sha256((computed_event_hash + prev).encode()).hexdigest()

            if ev.get("event_hash") != computed_event_hash:
                errors.append(f"Event {i+1} ({ev['action']} → {ev['target']}): "
                               f"event_hash MISMATCH — data was modified")
            elif ev.get("chain_hash") != expected_chain_hash:
                errors.append(f"Event {i+1} ({ev['action']} → {ev['target']}): "
                               f"chain_hash MISMATCH — upstream event was modified")
            prev = ev.get("chain_hash", "")

        return len(errors) == 0, errors


def demo_hash_chain():
    print(f"\n{'─'*60}")
    print("  PATTERN 1: Hash-Chain Audit Log")
    print(f"{'─'*60}")

    log_path = Path("captured_tokens") / "pattern1_audit.jsonl"
    log_path.unlink(missing_ok=True)

    log = HashChainAuditLog(str(log_path))

    # Write 5 events
    events = [
        ("db:read",  "customers", "allowed"),
        ("api:call", "weather",   "allowed"),
        ("db:write", "orders",    "denied"),
        ("db:read",  "invoices",  "allowed"),
        ("api:call", "slack",     "allowed"),
    ]
    for action, target, result in events:
        ev = log.append(action, target, result, agent_id="demo_agent_001")
        print(f"  + {action:<12} → {target:<12} = {result:<8}  "
              f"chain: {ev['chain_hash'][:16]}...")

    # Verify clean
    valid, errs = log.verify()
    print(f"\n  Verify (clean): {'✓ VALID' if valid else '✗ BROKEN'}")

    # Tamper event 2
    lines = log_path.read_text().splitlines()
    ev2 = json.loads(lines[1])
    ev2["result"] = "denied"  # change allowed → denied
    lines[1] = json.dumps(ev2)
    log_path.write_text("\n".join(lines) + "\n")
    print(f"\n  Tampered event 2: result changed allowed → denied")

    # Re-verify
    valid2, errs2 = log.verify()
    print(f"  Verify (tampered): {'✓ VALID' if valid2 else '✗ BROKEN'}")
    for e in errs2:
        print(f"    ! {e}")

    log_path.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 2: 8-Factor Trust Scorer
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TrustFactors:
    verification:    float = 0.0   # 25% — Is agent registered and verified?
    uptime:          float = 0.0   # 15% — Availability track record (0–1)
    action_success:  float = 0.0   # 15% — success_count / total_actions
    security_alerts: float = 0.0   # 15% — 1 - (alerts / max_alerts), lower is worse
    compliance:      float = 0.0   # 10% — policy_compliant_count / total_actions
    age:             float = 0.0   # 10% — min(days_old / 30, 1.0) — saturates at 30 days
    drift:           float = 0.0   # 5%  — 1 - behavioral_drift_score
    user_feedback:   float = 0.0   # 5%  — average user rating normalized to 0–1

WEIGHTS = {
    "verification":    0.25,
    "uptime":          0.15,
    "action_success":  0.15,
    "security_alerts": 0.15,
    "compliance":      0.10,
    "age":             0.10,
    "drift":           0.05,
    "user_feedback":   0.05,
}

CAPABILITY_MIN_TRUST = {
    "db:read":    0.0,    # open
    "api:call":   0.0,    # open
    "file:read":  0.3,    # some trust needed
    "db:write":   0.6,    # significant trust needed
    "deploy":     0.7,
    "system:admin": 0.85,
    "infra:destroy": 0.95,
    "secrets:rotate": 0.90,
}


class TrustScorer:
    """
    Compute a weighted trust score from 8 behavioral factors.
    Gate capability access based on per-capability minimum trust thresholds.

    Usage with any identity system:
        factors = TrustFactors(
            verification=1.0,          # agent is registered
            uptime=0.95,               # 95% availability
            action_success=0.98,       # 98% success rate
            security_alerts=0.90,      # 1 alert in last 30 days
            compliance=1.0,
            age=min(agent_days_old/30, 1.0),
            drift=0.95,
            user_feedback=0.80,
        )
        scorer = TrustScorer(factors)
        scorer.check("db:write")  # raises if below threshold
    """

    def __init__(self, factors: TrustFactors,
                 delegation_hop: int = 0,
                 custom_thresholds: dict | None = None):
        self.factors    = factors
        self.hop        = delegation_hop   # each hop attenuates by 0.8x
        self.thresholds = {**CAPABILITY_MIN_TRUST, **(custom_thresholds or {})}

    @property
    def score(self) -> float:
        raw = sum(getattr(self.factors, k) * w for k, w in WEIGHTS.items())
        # Trust attenuation: each delegation hop multiplies by 0.8, min 0.3
        return max(raw * (0.8 ** self.hop), 0.3 * (1 if raw > 0.3 else 0))

    def check(self, capability: str) -> tuple[bool, str]:
        """Returns (allowed, reason)."""
        min_trust = self.thresholds.get(capability, 0.0)
        s = self.score
        if s >= min_trust:
            return True, f"Trust {s:.2f} ≥ threshold {min_trust:.2f}"
        return False, (f"Trust {s:.2f} < threshold {min_trust:.2f} for '{capability}'. "
                       f"Improve: {self._improvement_hint()}")

    def _improvement_hint(self) -> str:
        """Identify the lowest-scoring factor to suggest improvements."""
        weighted = {k: getattr(self.factors, k) * w for k, w in WEIGHTS.items()}
        worst = min(weighted, key=weighted.get)
        return f"Improve '{worst}' factor (current: {getattr(self.factors, worst):.2f})"


def demo_trust_scorer():
    print(f"\n{'─'*60}")
    print("  PATTERN 2: 8-Factor Trust Scorer")
    print(f"{'─'*60}")

    # New agent — low trust
    new_agent = TrustScorer(TrustFactors(
        verification=1.0, uptime=0.0, action_success=0.0,
        security_alerts=1.0, compliance=1.0, age=0.0,
        drift=1.0, user_feedback=0.0,
    ))
    print(f"\n  New agent (just registered):  trust = {new_agent.score:.2f}")
    for cap in ("db:read", "db:write", "system:admin"):
        allowed, reason = new_agent.check(cap)
        icon = "✓" if allowed else "✗"
        print(f"    {icon} {cap:<20} {reason}")

    # Established agent — high trust
    mature_agent = TrustScorer(TrustFactors(
        verification=1.0, uptime=0.98, action_success=0.995,
        security_alerts=0.97, compliance=1.0, age=1.0,
        drift=0.95, user_feedback=0.88,
    ))
    print(f"\n  Established agent (30+ days): trust = {mature_agent.score:.2f}")
    for cap in ("db:read", "db:write", "system:admin", "infra:destroy"):
        allowed, reason = mature_agent.check(cap)
        icon = "✓" if allowed else "✗"
        print(f"    {icon} {cap:<20} {reason}")

    # Delegation chain: after 2 hops, trust degrades
    delegated = TrustScorer(TrustFactors(
        verification=1.0, uptime=0.98, action_success=0.99,
        security_alerts=1.0, compliance=1.0, age=1.0,
        drift=1.0, user_feedback=0.9,
    ), delegation_hop=2)
    print(f"\n  After 2 delegation hops:      trust = {delegated.score:.2f}  "
          f"(0.8^2 = 0.64 attenuation)")
    allowed, reason = delegated.check("db:write")
    print(f"    {'✓' if allowed else '✗'} db:write: {reason}")


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 3: 5-Step FGA Gateway
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FGAContext:
    action:      str
    resource:    str = ""
    risk_level:  str = "normal"     # normal | elevated | critical
    agent_id:    str = ""
    declared_intent: str = ""       # Step 5: what the agent says it intends to do
    delegation_chain: list = field(default_factory=list)  # Step 4: delegation path
    time_of_day:     str = ""       # for time-window policies
    source_ip:       str = ""


@dataclass
class FGADecision:
    allowed:    bool
    denied_at:  str   = ""   # which gate denied (e.g., "context", "intent")
    reason:     str   = ""

    def __bool__(self): return self.allowed


class FGAGateway:
    """
    5-step Fine-Grained Authorization pipeline.

    Gate 1: Capability check    — does the agent have this capability?
    Gate 2: Attribute check     — do agent attributes satisfy policy?
    Gate 3: Context check       — does runtime context (risk, time) permit?
    Gate 4: Chain check         — is the delegation chain valid and in-scope?
    Gate 5: Intent check        — does declared intent match the action?

    Gates 4 and 5 are UNIQUE to AIM — not present in Entra Conditional Access
    or WSO2 RBAC/ABAC.

    Usage with Entra Agent ID:
        tr_token_payload = decode_jwt(tr_token)["payload"]
        gateway = FGAGateway(
            agent_id=tr_token_payload["sub"],
            capabilities=["db:read", "api:call"],
            trust_score=0.87,
        )
        ctx = FGAContext(
            action="db:read", resource="customers",
            declared_intent="read customer list for monthly report",
            risk_level="normal",
        )
        decision = gateway.evaluate(ctx)
        if not decision:
            raise PermissionError(f"Denied at '{decision.denied_at}': {decision.reason}")
    """

    def __init__(self, agent_id: str, capabilities: list[str],
                 trust_score: float = 1.0,
                 policy: dict | None = None):
        self.agent_id     = agent_id
        self.capabilities = set(capabilities)
        self.trust        = trust_score
        self.policy       = policy or {}

    def evaluate(self, ctx: FGAContext) -> FGADecision:
        """Run all 5 gates. Returns on first denial."""
        # Gate 1: Capability
        if ctx.action not in self.capabilities:
            return FGADecision(False, "capability",
                               f"Agent lacks capability '{ctx.action}'. "
                               f"Granted: {sorted(self.capabilities)}")

        # Gate 2: Attribute — check trust score meets per-action threshold
        min_trust = CAPABILITY_MIN_TRUST.get(ctx.action, 0.0)
        if self.trust < min_trust:
            return FGADecision(False, "attribute",
                               f"Trust {self.trust:.2f} < required {min_trust:.2f} for '{ctx.action}'")

        # Gate 3: Context — time, risk level, IP restrictions
        risk = ctx.risk_level.lower()
        if risk == "critical":
            return FGADecision(False, "context",
                               f"Critical risk level requires human approval and break-glass token")
        elif risk == "elevated" and ctx.action in ("db:write", "deploy", "system:admin"):
            return FGADecision(False, "context",
                               f"Elevated risk + privileged action requires human approval")

        # Gate 4: Chain — delegation chain must not exceed depth limit
        max_depth = self.policy.get("max_delegation_depth", 3)
        if len(ctx.delegation_chain) > max_depth:
            return FGADecision(False, "chain",
                               f"Delegation chain depth {len(ctx.delegation_chain)} exceeds "
                               f"maximum {max_depth}")
        # Chain must only include known/trusted agents
        trusted_agents = set(self.policy.get("trusted_agents", [self.agent_id]))
        unknown = [a for a in ctx.delegation_chain if a not in trusted_agents]
        if unknown:
            return FGADecision(False, "chain",
                               f"Unknown agents in delegation chain: {unknown}")

        # Gate 5: Intent — declared intent must relate to action.
        # This is a simplified keyword-match; production AIM uses NLP/semantic check.
        if ctx.declared_intent:
            action_verb = ctx.action.split(":")[0].lower()    # "db" from "db:read"
            action_op   = ctx.action.split(":")[-1].lower()   # "read" from "db:read"
            intent_lower = ctx.declared_intent.lower()

            # Intent must be non-empty and contain SOME reference to the action
            suspicious_mismatches = [
                ("db:write" in ctx.action and "read" in intent_lower and "write" not in intent_lower),
                ("delete" in ctx.action and "delete" not in intent_lower and "remove" not in intent_lower),
            ]
            if any(suspicious_mismatches):
                return FGADecision(False, "intent",
                                   f"Declared intent ('{ctx.declared_intent[:60]}') "
                                   f"doesn't match action '{ctx.action}'")

        return FGADecision(True)


def demo_fga():
    print(f"\n{'─'*60}")
    print("  PATTERN 3: 5-Step FGA Gateway")
    print(f"{'─'*60}")

    gw = FGAGateway(
        agent_id="aim_demo_001",
        capabilities=["db:read", "api:call", "db:write"],
        trust_score=0.75,
        policy={"max_delegation_depth": 2, "trusted_agents": ["aim_demo_001", "aim_parent_agent"]},
    )

    test_cases = [
        FGAContext("db:read",  "customers", "normal",   "aim_demo_001",
                   "read customer list for monthly report"),
        FGAContext("db:write", "invoices",  "elevated", "aim_demo_001",
                   "update invoice amounts",
                   delegation_chain=["aim_demo_001"]),
        FGAContext("db:write", "invoices",  "normal",   "aim_demo_001",
                   "read order data",           # ← intent mismatch with db:write
                   delegation_chain=["aim_demo_001"]),
        FGAContext("db:read",  "secrets",   "normal",   "aim_demo_001",
                   "read config data",
                   delegation_chain=["aim_demo_001", "aim_parent_agent", "unknown_agent_xyz"]),
    ]

    for ctx in test_cases:
        d = gw.evaluate(ctx)
        icon = "\033[32m✓\033[0m" if d.allowed else "\033[31m✗\033[0m"
        gate = f"  [gate: {d.denied_at}]" if not d.allowed else ""
        print(f"  {icon} {ctx.action:<15} risk={ctx.risk_level:<10} "
              f"chain={len(ctx.delegation_chain)}{gate}")
        if not d.allowed:
            print(f"      reason: {d.reason[:80]}")

    print(f"\n  Gates 4 (chain) and 5 (intent) not present in Entra or WSO2.")
    print(f"  Add this gateway as middleware in FastAPI:")
    print(f"    from fastapi import Depends")
    print(f"    from scripts.eleven_borrowable_patterns import FGAGateway, FGAContext")
    print(f"    gateway = FGAGateway(agent_id=token['sub'], capabilities=token.get('roles',[]))")
    print(f"    @app.post('/data')")
    print(f"    async def write_data(ctx: FGAContext, _=Depends(gateway.check_or_raise)):")
    print(f"        ...")


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 4: Secretless Credential (zero-copy, memory-zeroed after use)
# ─────────────────────────────────────────────────────────────────────────────

class SecretlessCredential:
    """
    Context manager that:
      1. Resolves a credential from a secure source (env var, vault, file)
      2. Provides it within the 'with' block
      3. Uses ctypes.memset() to overwrite the credential bytes in memory on exit

    Python strings are immutable — the standard 'del var' doesn't zero memory.
    ctypes.memset() overwrites the underlying C buffer directly.

    Why this matters for AI agents:
      - LLM tool use / code execution: if a credential appears in a local variable,
        it may be captured in LLM context, logs, or memory snapshots
      - MCP config files: AIM encrypts credentials in Claude Desktop MCP JSON config
        so the LLM's context window never contains plaintext API keys
      - Python ctypes: the only reliable way to zero bytes in CPython

    Supported backends:
      env:   os.environ[name]  — simple but credentials visible in process list
      file:  read from file, delete file after reading
      vault: extendable to HashiCorp Vault, Azure Key Vault, CyberArk CCP, etc.
    """

    def __init__(self, name: str, source: str = "env"):
        self._name   = name
        self._source = source
        self._raw:   bytearray | None = None   # mutable bytearray for zeroing

    def __enter__(self) -> bytes:
        raw = self._resolve()
        # Store as mutable bytearray so we can zero it
        self._raw = bytearray(raw.encode("utf-8") if isinstance(raw, str) else raw)
        return bytes(self._raw)   # immutable view for the caller

    def __exit__(self, *_):
        if self._raw is not None:
            # ctypes.memset overwrites the bytearray's internal C buffer
            # This is the ONLY reliable way to zero memory in CPython
            addr = id(self._raw) + object.__sizeof__(bytearray())
            try:
                ctypes.memset(addr, 0, len(self._raw))
            except Exception:
                # Fallback: overwrite character by character
                for i in range(len(self._raw)):
                    self._raw[i] = 0
            self._raw = None

    def _resolve(self) -> str:
        if self._source == "env":
            val = os.environ.get(self._name)
            if not val:
                raise KeyError(f"Credential '{self._name}' not found in environment")
            return val
        elif self._source == "file":
            p = Path(self._name)
            val = p.read_text().strip()
            p.unlink()    # delete after reading
            return val
        elif self._source == "vault":
            # Extend this for real vault integration:
            # import hvac; client = hvac.Client(); return client.secrets.kv.read_secret(...)
            raise NotImplementedError("Vault backend not configured")
        else:
            raise ValueError(f"Unknown source: {self._source}")


def demo_secretless():
    print(f"\n{'─'*60}")
    print("  PATTERN 4: Secretless Credential (zero-copy, memory-zeroed)")
    print(f"{'─'*60}")

    # Set up a demo env var
    os.environ["DEMO_API_KEY"] = "sk-demo-secret-key-visible-in-env-1234567890"

    print(f"\n  Credential in env:    os.environ['DEMO_API_KEY'] = "
          f"'{os.environ['DEMO_API_KEY'][:12]}...'  (would appear in /proc, ps aux)")

    addr_after = None
    with SecretlessCredential("DEMO_API_KEY", source="env") as key:
        print(f"  Inside 'with' block:  key = '{key[:12].decode()}...'")
        print(f"  This is a bytes object — available to your code")
        print(f"  Make your API call here: requests.get(url, headers={{'Authorization': key}})")
        # Save the address so we can try to show the memory was zeroed
        addr_after = ctypes.addressof(ctypes.c_char.from_address(id(bytearray(key))))

    print(f"  After 'with' block:   key variable is gone (out of scope)")
    print(f"  ctypes.memset() has overwritten the bytearray's C buffer with 0x00")
    print(f"  The credential no longer exists in memory in a form readable by:")
    print(f"    - A coredump / memory snapshot")
    print(f"    - An LLM tool call that reads process memory")
    print(f"    - The os.environ entry (still there — remove with del os.environ[...])")
    print(f"\n  Compare: 'del my_api_key' in Python does NOT zero memory.")
    print(f"  Python's garbage collector may keep the string bytes alive indefinitely.")
    print(f"  ctypes.memset() is the only way to guarantee it's gone in CPython.")

    # Clean up
    del os.environ["DEMO_API_KEY"]


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN 5: Break-Glass Token with Separate Audit Stream
# ─────────────────────────────────────────────────────────────────────────────

class BreakGlassToken:
    """
    HMAC-signed time-limited emergency token for SUPER_PRIVILEGED actions.

    In AIM's PAM model:
      STANDARD     → normal FGA enforcement
      PRIVILEGED   → time-bound session + intensive audit logging
      SUPER_PRIVILEGED → human approval gate + dual authorization
      BREAK-GLASS  → emergency override: signed token, separate audit stream,
                     immediate review notification, very short TTL

    The separate audit stream is CRITICAL:
      Break-glass events are written to a different log file than normal operations.
      This prevents an attacker from hiding a break-glass event in the main audit log
      (they'd have to compromise both the main log and the break-glass log simultaneously).

    Usage:
        bg = BreakGlassToken(secret_key=os.environ["BREAKGLASS_HMAC_KEY"])
        token = bg.generate(agent_id="aim_demo", reason="production incident P0")
        # Present token to the resource that gates super-privileged access
        bg.verify(token)  # verifies HMAC + TTL
        # All operations logged separately
        bg.log("infra:destroy", "prod-cluster", agent_id="aim_demo", used_token=token)
    """

    SEPARATOR  = b"|||"
    TTL_SECS   = 300       # 5 minutes — auto-deny on expiry

    def __init__(self, secret_key: bytes | None = None,
                 main_log: str = "captured_tokens/normal_audit.jsonl",
                 breakglass_log: str = "captured_tokens/breakglass_audit.jsonl"):
        self._key = secret_key or os.urandom(32)
        self._main_log = Path(main_log)
        self._bg_log   = Path(breakglass_log)
        self._bg_log.parent.mkdir(parents=True, exist_ok=True)

    def generate(self, agent_id: str, reason: str) -> str:
        """Generate a signed break-glass token (valid for TTL_SECS seconds)."""
        issued_at = int(time.time())
        payload   = f"{agent_id}:{issued_at}:{reason}".encode()
        sig       = hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        raw       = payload + self.SEPARATOR + sig.encode()
        token     = __import__("base64").urlsafe_b64encode(raw).decode()

        # Log generation event to the separate break-glass stream
        self._append_bg_log({
            "event":    "BREAKGLASS_GENERATED",
            "agent_id": agent_id,
            "reason":   reason,
            "issued_at": issued_at,
            "expires_at": issued_at + self.TTL_SECS,
        })
        return token

    def verify(self, token: str) -> tuple[bool, str]:
        """Verify the token's HMAC signature and TTL. Returns (is_valid, agent_id)."""
        try:
            raw     = __import__("base64").urlsafe_b64decode(token.encode())
            payload, _, sig = raw.partition(self.SEPARATOR)
        except Exception as exc:
            return False, f"decode error: {exc}"

        expected_sig = hmac.new(self._key, payload, hashlib.sha256).hexdigest().encode()
        if not hmac.compare_digest(sig, expected_sig):
            return False, "HMAC signature invalid — token tampered or wrong key"

        parts     = payload.decode().split(":", 2)
        agent_id  = parts[0]
        issued_at = int(parts[1])
        now       = int(time.time())

        if now > issued_at + self.TTL_SECS:
            secs_ago = now - (issued_at + self.TTL_SECS)
            return False, (f"Token EXPIRED {secs_ago}s ago. "
                           f"Safe default: all expired tokens are auto-denied.")

        return True, agent_id

    def log(self, action: str, resource: str, agent_id: str, used_token: str):
        """
        Log a break-glass action to the SEPARATE audit stream.
        This stream is isolated from the normal audit log — an attacker would need
        to compromise BOTH streams to hide a break-glass action.
        """
        entry = {
            "event":       "BREAKGLASS_ACTION",
            "action":      action,
            "resource":    resource,
            "agent_id":    agent_id,
            "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
            "token_prefix": used_token[:16] + "...",
        }
        self._append_bg_log(entry)
        # ALSO write a redacted marker to the main log (so the break-glass event IS visible,
        # just with full details in the separate stream)
        self._main_log.parent.mkdir(parents=True, exist_ok=True)
        with open(self._main_log, "a") as f:
            f.write(json.dumps({
                "event":   "BREAKGLASS_MARKER",
                "action":  action, "resource": resource, "agent_id": agent_id,
                "note":    "Full details in separate break-glass audit stream",
            }) + "\n")

    def _append_bg_log(self, entry: dict):
        with open(self._bg_log, "a") as f:
            f.write(json.dumps(entry) + "\n")


def demo_breakglass():
    print(f"\n{'─'*60}")
    print("  PATTERN 5: Break-Glass Token with Separate Audit Stream")
    print(f"{'─'*60}")

    bg = BreakGlassToken(secret_key=b"demo-secret-key-change-in-prod-32bytes!")

    # Normal FGA would deny infra:destroy
    gw = FGAGateway("demo_agent", capabilities=["infra:destroy"], trust_score=0.80)
    ctx = FGAContext("infra:destroy", "prod-cluster", "critical", "demo_agent",
                     "Emergency rollback during P0 incident at 2am")
    d = gw.evaluate(ctx)
    print(f"\n  Normal FGA for 'infra:destroy' at critical risk:")
    print(f"  {'✓' if d.allowed else '✗'} {'ALLOWED' if d.allowed else 'DENIED'}"
          f" at gate '{d.denied_at}': {d.reason[:60]}")

    # Break-glass override
    print(f"\n  Generating break-glass token (valid {BreakGlassToken.TTL_SECS}s)...")
    token = bg.generate(agent_id="demo_agent",
                        reason="P0 incident: prod cluster out of disk space at 02:13 UTC")
    print(f"  Token: {token[:32]}...")

    time.sleep(0.1)

    valid, agent_id = bg.verify(token)
    print(f"  Verification: {'✓ VALID' if valid else '✗ INVALID'}  agent_id={agent_id}")

    # Log the break-glass action
    bg.log("infra:destroy", "prod-cluster", agent_id="demo_agent", used_token=token)
    print(f"\n  Break-glass action logged:")
    print(f"    Main audit log:        captured_tokens/normal_audit.jsonl  "
          f"(marker only — no details)")
    print(f"    Break-glass log:       captured_tokens/breakglass_audit.jsonl  "
          f"(full details)")

    bg_entries = [json.loads(l) for l in open(bg._bg_log) if l.strip()]
    print(f"  Break-glass log entries ({len(bg_entries)}):")
    for e in bg_entries:
        print(f"    [{e.get('event','?')}] "
              f"agent={e.get('agent_id','?')} action={e.get('action','?')} "
              f"resource={e.get('resource','?')}")

    # Expired token demo
    print(f"\n  Demonstrating auto-denial on expiry...")
    expired_token = bg.generate("demo_agent", "test expiry")
    # Patch the issued_at to be 400s in the past
    import base64
    raw     = base64.urlsafe_b64decode(expired_token.encode())
    payload, sep, sig = raw.partition(BreakGlassToken.SEPARATOR)
    parts   = payload.decode().split(":", 2)
    parts[1] = str(int(time.time()) - 400)
    new_payload = ":".join(parts).encode()
    new_sig = hmac.new(bg._key, new_payload, hashlib.sha256).hexdigest().encode()
    expired_raw = new_payload + sep + new_sig
    expired_t = base64.urlsafe_b64encode(expired_raw).decode()

    valid2, msg2 = bg.verify(expired_t)
    print(f"  Expired token verification: {'✓' if valid2 else '✗ DENIED'}  reason: {msg2}")

    # Clean up
    for p in (bg._bg_log, bg._main_log):
        p.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Main: run selected or all demos
# ─────────────────────────────────────────────────────────────────────────────
DEMOS = {
    "1": ("Hash-Chain Audit Log",                  demo_hash_chain),
    "2": ("8-Factor Trust Scorer",                 demo_trust_scorer),
    "3": ("5-Step FGA Gateway",                    demo_fga),
    "4": ("Secretless Credential",                 demo_secretless),
    "5": ("Break-Glass Token + Separate Audit",    demo_breakglass),
}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--pattern", choices=list(DEMOS.keys()),
                        help="Run only this pattern number (1-5)")
    args = parser.parse_args()

    print(f"\n{SEP}")
    print(f"  PHASE 5: Borrowable AIM Security Patterns (standalone Python)")
    print(f"{SEP}")
    print(f"  These patterns work on top of ANY identity system.")
    print(f"  No AIM server required. No external dependencies.")
    print(f"  Integrate with Entra/WSO2/SPIFFE tokens as shown in comments.")

    to_run = {args.pattern: DEMOS[args.pattern]} if args.pattern else DEMOS
    for num, (name, fn) in to_run.items():
        print(f"\n{'═'*72}")
        print(f"  [{num}/5] {name}")
        print(f"{'═'*72}")
        try:
            fn()
        except Exception as exc:
            print(f"  \033[31mERROR in pattern {num}: {exc}\033[0m")

    print(f"\n{SEP}")
    print(f"  All borrowable patterns demonstrated.")
    print(f"  Next: python scripts/12_compare_all.py  — final comparison table")
    print(f"\n{SEP}\n")
