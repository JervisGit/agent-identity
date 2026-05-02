#!/usr/bin/env python3
"""
Phase 6: Final Comparison — All 4 Identity Systems

Reads token captures from captured_tokens/ and prints a side-by-side comparison
of all four agent identity systems explored in this project:

  System 1: Azure Entra Agent ID (Preview)
  System 2: SPIFFE/SPIRE (open source)
  System 3: WSO2 Identity Server 7.0.0 (open source)
  System 4: OpenA2A AIM (open source)

What this covers:
  A. Token anatomy  — alg, sub structure, key claims
  B. Delegation     — how machines delegate to machines
  C. TTL & rotation — expiry model
  D. Attestation    — how identity is PROVED to be from a specific workload
  E. Revocation     — can you kill a token mid-flight?
  F. Audit          — what's logged and how tamper-evident?
  G. MCP / AI-native support
  H. Unique features and gaps

Run:
  python scripts/12_compare_all.py

If captured_tokens/*.json are missing (scripts 03-09 not run),
the script shows the static knowledge comparison table only.
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

SEP = "=" * 72
COL = 25   # column width for each system


# ─────────────────────────────────────────────────────────────────────────────
# Load captured tokens
# ─────────────────────────────────────────────────────────────────────────────

CAPTURES = {
    "entra_tr":  "captured_tokens/entra_path_b_tr.json",
    "entra_obo": "captured_tokens/entra_obo.json",
    "spire":     "captured_tokens/spire_svid.json",
    "wso2":      "captured_tokens/wso2_token.json",
    "aim":       "captured_tokens/aim_token.json",
}

def load_captured() -> dict[str, dict | None]:
    out = {}
    for key, path in CAPTURES.items():
        try:
            with open(path) as f:
                out[key] = json.load(f)
        except FileNotFoundError:
            out[key] = None
    return out


def _p(d: dict | None, *keys, default="—") -> str:
    """Safe nested key access."""
    if d is None:
        return default
    val = d
    for k in keys:
        if not isinstance(val, dict):
            return default
        val = val.get(k)
        if val is None:
            return default
    return str(val)


# ─────────────────────────────────────────────────────────────────────────────
# Table helpers
# ─────────────────────────────────────────────────────────────────────────────

def _hdr(*cells) -> str:
    cells = list(cells)
    label = cells[0].ljust(26)
    cols  = "  ".join(str(c)[:COL].ljust(COL) for c in cells[1:])
    return f"  {label}  {cols}"

def _row(label: str, *cells) -> str:
    label = str(label).ljust(26)
    cols  = "  ".join(str(c)[:COL].ljust(COL) for c in cells)
    return f"  {label}  {cols}"

def _divider(char="─") -> str:
    return "  " + char * (26 + 2 + (COL + 2) * 4)


# ─────────────────────────────────────────────────────────────────────────────
# Token Anatomy Section
# ─────────────────────────────────────────────────────────────────────────────

def print_token_anatomy(caps: dict):
    entra = caps.get("entra_tr")
    obo   = caps.get("entra_obo")
    spire = caps.get("spire")
    wso2  = caps.get("wso2")
    aim   = caps.get("aim")

    # Extract from captured JSON structures
    entra_pay = _p(entra, "payload")
    obo_pay   = _p(obo,   "delegated", "payload")
    spire_pay = _p(spire, "payload")
    wso2_pay  = _p(wso2,  "payload")
    aim_pay   = _p(aim,   "payload")

    def g(d, key, default="—"):
        if isinstance(d, dict):
            return str(d.get(key, default))[:COL]
        return default

    # Try to parse nested dicts
    def parse(d):
        if isinstance(d, dict): return d
        if isinstance(d, str):
            try: return json.loads(d)
            except: pass
        return {}

    ep = parse(entra_pay if isinstance(entra_pay, dict) else
               (entra.get("payload") if entra else {}))
    op = parse(obo_pay if isinstance(obo_pay, dict) else
               (obo.get("delegated", {}).get("payload") if obo else {}))
    sp = parse(spire_pay if isinstance(spire_pay, dict) else
               (spire.get("payload") if spire else {}))
    wp = parse(wso2_pay if isinstance(wso2_pay, dict) else
               (wso2.get("payload") if wso2 else {}))
    ap = parse(aim_pay if isinstance(aim_pay, dict) else
               (aim.get("payload") if aim else {}))

    # Fall back to known-correct static values when not captured
    def fallback(captured_val, static_val):
        return captured_val if captured_val and captured_val != "—" else static_val

    print(f"\n{'─'*72}")
    print("  A. TOKEN ANATOMY (from captured tokens where available)")
    print(f"{'─'*72}")
    print(_hdr("", "Entra TR", "Entra OBO", "SPIFFE/SPIRE", "WSO2 M2M", "AIM"))
    print(_divider())
    print(_row("Format",
               fallback(g(ep,"token_type"), "JWT (RS256)"),
               fallback(g(op,"token_type"), "JWT (RS256)"),
               fallback(g(sp,"spiffe_id"),  "JWT-SVID"),
               fallback(g(wp,"token_type"), "JWT (RS256)"),
               fallback(g(ap,"token_type"), "JWT (Ed25519)")))
    print(_row("alg",
               fallback(g(ep,"alg"),  "RS256"),
               fallback(g(op,"alg"),  "RS256"),
               "ES256 (ECDSA)",
               fallback(g(wp,"alg"),  "RS256"),
               fallback(g(ap,"alg"),  "EdDSA (OKP)")))
    print(_row("issuer",
               "sts.windows.net/{tid}",
               "sts.windows.net/{tid}",
               "spiffe://demo.org",
               "https://localhost:9443",
               "localhost:8080 (AIM)"))
    print(_row("sub",
               "agent objectId",
               "agent objectId",
               "spiffe://...workload",
               "clientId@carbon.super",
               "agent UUID"))
    print(_row("oid == appId?",
               "✓ YES (Agent ID marker)",
               "✓ YES",
               "N/A",
               "✗ No",
               "✗ No"))
    print(_row("TTL",
               fallback(g(ep,"exp"),  "3600s / 1h"),
               fallback(g(op,"exp"),  "3600s / 1h"),
               "300s / 5min",
               fallback(g(wp,"exp"),  "3600s / 1h"),
               fallback(g(ap,"exp"),  "3600s / 1h")))
    print(_row("Audience",
               "resource appId / URL",
               "resource appId / URL",
               "spiffe://demo.org",
               "resource URI",
               "AIM server"))
    print(_row("Delegation claim",
               "—",
               "act.sub = agent oid",
               "—",
               "— (no act claim)",
               "delegation_chain[]"))
    print(_row("Post-quantum alg",
               "✗",
               "✗",
               "✗",
               "✗",
               "✓ ML-DSA (CRYSTALS)"))


# ─────────────────────────────────────────────────────────────────────────────
# Identity Architecture Section
# ─────────────────────────────────────────────────────────────────────────────

def print_identity_architecture():
    print(f"\n{'─'*72}")
    print("  B. IDENTITY ARCHITECTURE")
    print(f"{'─'*72}")
    print(_hdr("", "Entra Agent ID", "SPIFFE/SPIRE", "WSO2 IS", "AIM"))
    print(_divider())
    print(_row("Identity model",
               "Blueprint → Agent (1:N)",
               "SPIFFE ID → Workload",
               "App → Client (1:N)",
               "Registered agent (1:1)"))
    print(_row("Credential type",
               "UAMI + FIC (cert)",
               "SVID (X.509/JWT)",
               "client_id + secret",
               "Ed25519 keypair"))
    print(_row("Workload attestation",
               "UAMI injection (ACA)",
               "✓ OS kernel (binary hash)",
               "✗ No",
               "Partial (MCP consensus)"))
               
    print(_row("Delegation model",
               "Blueprint FIC → UAMI",
               "Workload Attestor rules",
               "OAuth scopes",
               "Parent→child chain"))
    print(_row("OBO / act claim",
               "✓ (Tc + T1 → delegated)",
               "✗ No",
               "✗ No",
               "✓ chain embedded"))
    print(_row("SPIFFE compatible",
               "Not natively",
               "✓ This is SPIFFE",
               "✗ No",
               "✗ No (own format)"))
    print(_row("Revocation",
               "Token expiry only\n(no short-circuit)",
               "TTL (5min JWT-SVID)",
               "Client deactivation\n(SCIM suspend)",
               "Agent disable API"))


# ─────────────────────────────────────────────────────────────────────────────
# Authorization Section
# ─────────────────────────────────────────────────────────────────────────────

def print_authorization():
    print(f"\n{'─'*72}")
    print("  C. AUTHORIZATION MODEL")
    print(f"{'─'*72}")
    print(_hdr("", "Entra Agent ID", "SPIFFE/SPIRE", "WSO2 IS", "AIM"))
    print(_divider())
    print(_row("Auth model",
               "RBAC (Entra roles)",
               "Attestation only\n(no FGA built-in)",
               "RBAC + ABAC",
               "5-step FGA pipeline"))
    print(_row("Gate 1: Capability",
               "App roles / API perms",
               "N/A",
               "RBAC + scopes",
               "✓"))
    print(_row("Gate 2: Attribute",
               "Conditional Access",
               "N/A",
               "Claim-based ABAC",
               "✓"))
    print(_row("Gate 3: Context",
               "CA policies (time/IP)",  
               "N/A",
               "Partially",
               "✓ risk + time + IP"))
    print(_row("Gate 4: Chain check",
               "✗ Not built-in",
               "N/A",
               "✗ Not built-in",
               "✓ Delegation depth"))
    print(_row("Gate 5: Intent check",
               "✗ Not built-in",
               "N/A",
               "✗ Not built-in",
               "✓ NLP/semantic check"))
    print(_row("Trust score",
               "✗",
               "✗",
               "✗",
               "✓ 8-factor weighted"))
    print(_row("PAM tiers",
               "Conditional Access",
               "✗",
               "✗",
               "✓ 4 tiers + break-glass"))


# ─────────────────────────────────────────────────────────────────────────────
# Audit & Compliance Section
# ─────────────────────────────────────────────────────────────────────────────

def print_audit():
    print(f"\n{'─'*72}")
    print("  D. AUDIT & TAMPER EVIDENCE")
    print(f"{'─'*72}")
    print(_hdr("", "Entra Agent ID", "SPIFFE/SPIRE", "WSO2 IS", "AIM"))
    print(_divider())
    print(_row("Audit log location",
               "Azure Monitor / LAW",
               "Local + syslog",
               "WSO2 IS local logs",
               "AIM server + chain"))
    print(_row("Hash chain integrity",
               "✗",
               "✗",
               "✗",
               "✓ SHA-256 chain"))
    print(_row("Tamper detection",
               "Azure immutable logs\n(optional)",
               "✗",
               "✗",
               "✓ chain_hash verify"))
    print(_row("Break-glass audit",
               "✗",
               "✗",
               "✗",
               "✓ separate stream"))
    print(_row("MCP event capture",
               "✗",
               "✗",
               "✗",
               "✓ per tool call"))


# ─────────────────────────────────────────────────────────────────────────────
# AI / MCP Section
# ─────────────────────────────────────────────────────────────────────────────

def print_ai_native():
    print(f"\n{'─'*72}")
    print("  E. AI-NATIVE / MCP SUPPORT")
    print(f"{'─'*72}")
    print(_hdr("", "Entra Agent ID", "SPIFFE/SPIRE", "WSO2 IS", "AIM"))
    print(_divider())
    print(_row("MCP integration",
               "Manual (token in\nMCP server header)",
               "✗",
               "✗",
               "✓ Built-in MCP config"))
    print(_row("MCP attestation",
               "✗",
               "✗",
               "✗",
               "✓ 3-server consensus"))
    print(_row("LLM-safe credentials",
               "✗ (token in memory)",
               "✗",
               "✗",
               "✓ Encrypted MCP config"))
    print(_row("Agent-to-agent A2A",
               "✓ OBO act claim",
               "Partial (SVID chain)",
               "Via OAuth token\nexchange",
               "✓ First-class (A2A)"))
    print(_row("Human-in-loop gate",
               "✗",
               "✗",
               "✗",
               "✓ 5min approve window"))
    print(_row("Agent lifecycle API",
               "Graph agentIdentities",
               "✗",
               "SCIM 2.0",
               "✓ REST API"))


# ─────────────────────────────────────────────────────────────────────────────
# Operational Section
# ─────────────────────────────────────────────────────────────────────────────

def print_operational():
    print(f"\n{'─'*72}")
    print("  F. OPERATIONAL PROFILE")
    print(f"{'─'*72}")
    print(_hdr("", "Entra Agent ID", "SPIFFE/SPIRE", "WSO2 IS", "AIM"))
    print(_divider())
    print(_row("Status",
               "PREVIEW",
               "GA (CNCF incubating)",
               "GA",
               "Early (pre-1.0)"))
    print(_row("M365 Copilot needed",
               "Yes (Path A)\nSP sim (Path B)",
               "No",
               "No",
               "No"))
    print(_row("Cost (Azure)",
               "ACA Consumption free\n+ M365 E5 if Path A",
               "ACI ~$0.50/mo\n(server always-on)",
               "Local Docker free",
               "Local Docker free"))
    print(_row("Docker image size",
               "~200MB (custom)",
               "~30MB (SPIRE)",
               "~1.2GB (WSO2 IS)",
               "~400MB (AIM)"))
    print(_row("Open source",
               "✗ (MSFT proprietary)",
               "✓ Apache 2.0",
               "✓ Apache 2.0",
               "✓ Apache 2.0"))
    print(_row("Works offline/local",
               "✗ (requires Azure AD)",
               "✓",
               "✓",
               "✓"))
    print(_row("Kubernetes native",
               "Via AKS + OIDC",
               "✓ Designed for K8s",
               "Partial",
               "Partial"))


# ─────────────────────────────────────────────────────────────────────────────
# Gaps and Unique Features
# ─────────────────────────────────────────────────────────────────────────────

def print_gaps_and_unique():
    print(f"\n{'─'*72}")
    print("  G. UNIQUE FEATURES & GAPS")
    print(f"{'─'*72}")

    systems = [
        ("Entra Agent ID", [
            "UNIQUE: oid == appId in agent identity token",
            "UNIQUE: FIC → UAMI workload identity chain",
            "UNIQUE: 3-hop trust chain (TUAMI→T1→TR)" ,
            "UNIQUE: OBO act claim for user delegation",
            "UNIQUE: Official MS support + Conditional Access",
            "GAP: No workload attestation (same oid for any image)",
            "GAP: PREVIEW — no SLA, subject to breaking changes",
            "GAP: Requires M365 E5 + Frontier for Path A",
            "GAP: No hash-chain audit, no 5-step FGA",
        ]),
        ("SPIFFE / SPIRE", [
            "UNIQUE: OS-kernel workload attestation",
            "UNIQUE: Binary SHA-256 hash → SPIFFE ID",
            "UNIQUE: Automatic SVID rotation (5 min JWT-SVID)",
            "UNIQUE: Workload API socket (no long-lived secrets)",
            "UNIQUE: CNCF standard, k8s-native",
            "GAP: No authorization layer (auth is separate)",
            "GAP: Not deployable on ACA Consumption",
            "GAP: No MCP/AI-native integration",
            "GAP: SPIRE agent requires always-on server",
        ]),
        ("WSO2 IS 7.0.0", [
            "UNIQUE: SCIM 2.0 agent lifecycle (suspend / reactivate)",
            "UNIQUE: Enterprise admin console GUI",
            "UNIQUE: Mature RBAC + ABAC policy engine",
            "UNIQUE: Standard RS256 JWT (works with any middleware)",
            "UNIQUE: sub format clientId@carbon.super",
            "GAP: No workload attestation",
            "GAP: No delegation act claim",
            "GAP: No MCP/AI integration",
            "GAP: 1.2GB Docker image",
        ]),
        ("OpenA2A AIM", [
            "UNIQUE: Ed25519 + ML-DSA (post-quantum) signing",
            "UNIQUE: SHA-256 hash-chain audit log",
            "UNIQUE: 5-step FGA (chain + intent gates unique)",
            "UNIQUE: 8-factor behavioral trust score",
            "UNIQUE: MCP attestation (3-server consensus)",
            "UNIQUE: Break-glass with separate audit stream",
            "UNIQUE: Secretless credential (encrypted MCP config)",
            "UNIQUE: 4-tier PAM model",
            "GAP: Ed25519/OKP tokens won't validate in RS256/ES256 middleware",
            "GAP: Early-stage, pre-1.0 API stability",
            "GAP: Not SPIFFE / OIDC compatible",
        ]),
    ]

    for name, points in systems:
        print(f"\n  {'─'*60}")
        print(f"  {name}")
        print(f"  {'─'*60}")
        for pt in points:
            icon = "+" if pt.startswith("UNIQUE") else "−"
            fmt  = pt.replace("UNIQUE: ", "").replace("GAP: ", "")
            print(f"    {icon} {fmt}")


# ─────────────────────────────────────────────────────────────────────────────
# Recommendation
# ─────────────────────────────────────────────────────────────────────────────

def print_recommendation():
    recs = {
        "Azure-hosted agents needing\nenterprise SSO": (
            "Entra Agent ID",
            "Native Conditional Access, OBO delegation, M365 breadcrumbs"),
        "On-prem / K8s, zero-trust\nworkload attestation": (
            "SPIFFE/SPIRE",
            "Binary hash proves WHAT is running, not just WHO"),
        "Self-hosted enterprise\nwith SCIM lifecycle": (
            "WSO2 IS",
            "Admin GUI, SCIM 2.0 suspend/reactivate, standard JWT"),
        "AI-native agents needing\nFGA + audit + MCP safety": (
            "AIM + borrowable patterns",
            "5-step FGA, hash-chain audit, MCP attestation, break-glass"),
        "Enterprise production\n(ideal combination)": (
            "Entra Agent ID + AIM patterns",
            "Entra for SSO/CA; AIM patterns for FGA, audit, MCP safety"),
    }

    print(f"\n{'─'*72}")
    print("  H. RECOMMENDATION BY USE CASE")
    print(f"{'─'*72}")
    for use_case, (winner, reason) in recs.items():
        print(f"\n  Use case:   {use_case}")
        print(f"  Recommend:  {winner}")
        print(f"  Reason:     {reason}")


# ─────────────────────────────────────────────────────────────────────────────
# Capture status
# ─────────────────────────────────────────────────────────────────────────────

def print_capture_status(caps: dict):
    print(f"\n{'─'*72}")
    print("  TOKEN CAPTURE STATUS")
    print(f"{'─'*72}")
    FILES = {
        "entra_tr":  ("Entra TR token",           "scripts/03_get_tokens.py"),
        "entra_obo": ("Entra OBO delegated token", "scripts/04_obo_flow.py"),
        "spire":     ("SPIFFE JWT-SVID",           "scripts/07_spire_demo.py"),
        "wso2":      ("WSO2 M2M token",            "scripts/08_wso2_demo.py"),
        "aim":       ("AIM Ed25519 token",         "scripts/09_aim_demo.py"),
    }
    any_missing = False
    for key, (label, cmd) in FILES.items():
        status = "✓ captured" if caps.get(key) else "✗ not yet captured"
        if not caps.get(key):
            any_missing = True
        padding = "  " if caps.get(key) else ""
        print(f"  {('✓' if caps.get(key) else '✗')} {label:<35}  {CAPTURES[key]}")

    if any_missing:
        print(f"\n  To capture missing tokens, run the corresponding scripts:")
        for key, (label, cmd) in FILES.items():
            if not caps.get(key):
                requires = {
                    "entra_tr":  "Azure credentials in .env.local",
                    "entra_obo": "Azure credentials in .env.local",
                    "spire":     "docker/spire/ (Docker Desktop running)",
                    "wso2":      "docker compose -f docker/wso2/docker-compose.yml up -d",
                    "aim":       "docker compose -f docker/aim/docker-compose.yml up -d",
                }.get(key, "")
                print(f"    python {cmd:<40}  (requires: {requires})")
    else:
        print(f"\n  All tokens captured! Live claim comparison included above.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{SEP}")
    print(f"  PHASE 6: Final Comparison — Agent Identity Systems")
    print(f"  Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{SEP}")

    caps = load_captured()

    print_token_anatomy(caps)
    print_identity_architecture()
    print_authorization()
    print_audit()
    print_ai_native()
    print_operational()
    print_gaps_and_unique()
    print_recommendation()
    print_capture_status(caps)

    print(f"\n{SEP}")
    print(f"  Comparison complete.")
    print(f"\n  Key takeaways:")
    print(f"    1. Entra Agent ID: oid==appId is the definitive agent identity marker")
    print(f"    2. SPIFFE/SPIRE:   workload attestation (binary hash) — nothing else does this")
    print(f"    3. WSO2:           SCIM lifecycle is the cleanest agent lifecycle API")
    print(f"    4. AIM:            5-step FGA + hash-chain audit fill real gaps in all others")
    print(f"    5. No single system covers all four dimensions;")
    print(f"       AIM's borrowable patterns work on top of ANY of the other three.")
    print(f"\n  Project files are in: {Path.cwd()}")
    print(f"{SEP}\n")
