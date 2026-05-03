# What Did We Actually Prove? A Plain-English Explainer

*You ran a bunch of scripts. Tokens got captured. Containers spun up. What does it all mean? This file explains everything in plain language — no IAM background needed.*

---

## Part 1: The Building Blocks

### What is a JWT?

A **JWT (JSON Web Token)** is a signed envelope you hand someone as proof of identity.

Think of it like a **laminated ID badge** that you print at a desk (`iss`), hand to a person (`sub`), and that only works at specific doors (`aud`). The lamination (`sig`) means no one can silently change what's written on the badge — if the text changes, the badge breaks.

A JWT has three sections separated by dots:
```
eyJhbGciOiJSUzI1NiJ9   .   eyJzdWIiOiJhbGljZSJ9   .   abc123sig
       header                      payload                signature
```

The header and payload are just Base64-encoded JSON. The signature is a cryptographic proof that the issuer (and only the issuer) wrote those exact bytes.

Anyone can read the badge. Only the signer can make a valid one.

---

### What does each claim mean?

| Claim | Pronunciation | Plain English |
|---|---|---|
| `iss` | "issuer" | **Who printed the badge.** An identity server URL (e.g. `https://sts.windows.net/...`). Your app looks up the issuer's public key to verify the signature. |
| `sub` | "subject" | **Who the badge is about.** The identity this token represents — a user, a service account, an AI agent. |
| `aud` | "audience" | **Which doors this badge opens.** The specific API or service this token is valid for. If the badge says `aud: https://graph.microsoft.com` and you try to use it at a different API, that API should reject it. This prevents "stolen token abuse" — a token valid for one system can't be replayed at another. |
| `exp` | "expiry" | **When the badge expires.** Unix timestamp. After this time, the token must not be accepted. Most tokens expire after 1 hour. |
| `iat` | "issued at" | **When it was printed.** |
| `nbf` | "not before" | **Earliest valid time.** Usually same as `iat`. |
| `jti` | "JWT ID" | **Serial number.** A UUID unique to this specific token. Lets you detect replay attacks — same token shouldn't be used twice if you log `jti`s. |
| `oid` | "object ID" | **Azure AD's internal ID for the identity.** A UUID that stays the same forever regardless of name changes. Entra's stable primary key for any user or service. |
| `appid` | "app ID" | **The ID of the registered application** in Azure AD. This is the `client_id` in OAuth speak. |
| `idtyp` | "identity type" | **Entra marker for "is this a machine or a human?"** Value `"app"` = machine/service account. Value `"user"` = human. Used by Microsoft APIs to distinguish agent traffic from user traffic in logs. |
| `tid` | "tenant ID" | **Which Azure directory issued this.** UUID of the Azure AD tenant. |
| `azp` | "authorized party" | **Which application is actively using this token.** For a token issued to app A so it can call Microsoft Graph, `azp` = app A's client ID. |
| `scp` | "scope" | **What delegated permissions the user consented to.** Comma-separated list: `"User.Read profile openid email"`. Only present when a user is involved (delegated tokens). |

---

### What is `act.sub`?

`act` stands for "actor." It's a **nested JSON object** inside an OBO (On-Behalf-Of) token.

The scenario: Alice (a human) granted permission to an AI agent to call Microsoft Graph. The agent makes the call, presenting a token. Who technically sent the request?

```json
{
  "sub":     "1hgbadnqNan...KCJCY",    ← Alice (the user being acted FOR)
  "act": {
    "sub":   "b8011268-72f7-47fc..."   ← the agent doing the acting
  }
}
```

Plain English: **"This badge belongs to Alice, but the agent `b8011268...` is the one holding it."**

Microsoft Graph logs show BOTH identities. You can filter audit logs for all actions taken by agent `b8011268...` even when it was acting on behalf of different users.

---

### What is `fmi_path`?

`fmi_path` is an **Entra Agent ID-specific claim** only present in tokens obtained via the blueprint→agent impersonation flow (the flow that requires M365 Copilot / Frontier access).

It's a path string that looks like:
```
/blueprints/{blueprintId}/agents/{agentInstanceId}
```

Plain English: **"Here's the lineage — this token was issued for agent instance XYZ, which was created from blueprint ABC."**

This is what makes Entra Agent ID special. A regular service principal just says "I am app-123." An Agent Identity says "I am an instance of blueprint-ABC, specifically instance-XYZ." You can write Conditional Access policies that say "only allow agents from approved blueprint ABC to access this resource."

We couldn't capture a real `fmi_path` because it requires the Frontier program. We captured the Path B fallback (a plain service principal token) instead.

---

### What is `aut`?

`aut` is a **WSO2-proprietary claim** (not in any RFC or OIDC standard). Values:
- `"APPLICATION"` → the token was issued directly to a machine (M2M, no user involved)
- `"APPLICATION_USER"` → the token was issued to an application acting on behalf of a user

Plain English: **"WSO2's extra label saying whether this is a robot or a human-in-the-loop token."**

---

## Part 2: What We Actually Proved (Phase by Phase)

### Phase 1: Azure Entra — Service Principal as an Agent (Path B)

**What we did:** Created a service principal called `demo-agent-sp` in Azure AD, gave it Microsoft Graph permissions, and got a client credentials token for it.

**What the token proved:**
```
iss: https://sts.windows.net/d179eaa0.../   → Azure AD in our tenant signed this
sub: b8011268-72f7-47fc-94ad-93d0770676d3   → this is the agent's permanent Entra object ID
aud: https://graph.microsoft.com            → this badge opens Microsoft Graph
idtyp: app                                  → Entra knows this is a machine, not a human
oid == appid? YES: oid = b8011268...        → on real Agent Identities, oid == appId
                    appid = 0769044c...     → wait — NOT the same here!
```

**The punchline: `oid ≠ appid` in Path B.** On a real Entra Agent Identity (Frontier), `oid` and `appId` are the same UUID — this is the cryptographic marker that says "this is a true agent identity." Our service principal has different values because it's a regular SP, not an Agent Identity. We proved the *shape* of the mechanism but hit the paywall for the actual feature.

---

### Phase 2: Azure Entra — On-Behalf-Of (OBO) Flow

**What we did:** Had a human user (Jervis) log in with their Microsoft account. Then had the `demo-agent-sp` exchange that user's token for a new token that carried both the user's identity AND the agent's identity.

**What the token proved:**
```
sub:     1hgbadnqNan...KCJCY    → Jervis (the user the agent is acting FOR)
act.sub: b8011268-72f7-47fc...  → demo-agent-sp (the agent doing the acting)
aud:     https://graph.microsoft.com
idtyp:   user                   → this is a delegated token (user-in-the-loop)
name:    Jervis Lee
email:   jervislee.JL@gmail.com
```

**The punchline:** We proved the **delegation chain works**. The agent's calls to Microsoft Graph carry the user's permissions + the agent's identity simultaneously. Audit logs can answer: "what did agent `b8011268...` do while acting for user Jervis?"

---

### Phase 3: SPIFFE/SPIRE — Cryptographic Workload Identity

**What we did:** Ran two Docker containers. One had user ID 1001 (trusted worker), one had user ID 1002 (untrusted). Configured SPIRE to issue SVID (SPIFFE Verifiable Identity Document) only to workloads with UID 1001.

**What we proved:**
```
uid:1001 request → SVID issued:
  sub: spiffe://demo.org/workload/trusted
  aud: ["spiffe://demo.org"]
  iss: https://demo.org   (SPIRE server)
  exp: 1777698295

uid:1002 request → DENIED
  Error: "no identity issued" (no matching registration entry)
```

**The punchline:** SPIRE doesn't use passwords. It identifies workloads by **what they ARE** (kernel-attested UID, running binary, container image) not by what they know (secrets). This is called "workload attestation." An attacker can't steal a credential that was never created.

---

### Phase 4: WSO2 Identity Server — M2M JWT + SCIM Lifecycle

**What we did:** Spun up WSO2 IS 7.0 in Docker. Created an M2M application representing an AI agent, configured it to issue JWTs, got a token, and then ran a full lifecycle: suspend the agent, verify the token stops working, reactivate it, verify it works again.

**What the token proved:**
```
sub: YxVcAzqM5OB_foN9VWMTDF8YcfIa     → the agent's client ID IS the subject
aut: APPLICATION                        → WSO2 says "this is a machine, not a human"
aud: YxVcAzqM5OB_foN9VWMTDF8YcfIa     → the token is valid for the agent itself (M2M)
org_id: 10084a8d-...                    → WSO2's internal org UUID (not in OIDC spec)
iss: https://localhost:9443/oauth2/token
```

**Suspension proved:**
```
active: true  → GET token → 200 OK, valid JWT
PATCH active: false (suspend)
              → GET token → 401 "The client is disabled"
PATCH active: true (reactivate)
              → GET token → 200 OK, valid JWT again
```

**The punchline:** WSO2 IS proves you can manage AI agent lifecycle the same way you manage users — enable/disable with SCIM. The `aut: APPLICATION` claim is WSO2's proprietary way of tagging agent tokens. There's no delegation chain, no blueprint hierarchy. It's a machine credential with lifecycle controls.

---

### Phase 5: OpenA2A AIM — Fine-Grained Authorization + Trust Score

**What we did:** Deployed the full AIM stack (server + dashboard + postgres). Created an agent with an Ed25519 public key. Got an API key (opaque, BCrypt-stored). Registered capabilities. Ran FGA authorization requests — one for a capability the agent HAD (`db:read`) and one it DIDN'T (`db:write`).

**What we proved:**

The agent's session JWT:
```
user_id: a0000000-...-00000002     → admin user
role: admin
iss: "agent-identity-management"   → literal string, not a URL
alg: HS256                         → symmetric signature (admin session)
```

FGA ALLOW:
```
POST /authorize  { "capability": "db:read" }
→ { "allowed": true, "outcome": "ALLOW", "stepsTriggered": ["capability_check"], "latencyMs": 5 }
```

FGA DENY:
```
POST /authorize  { "capability": "db:write" }
→ { "allowed": false, "deniedBy": "capability_check", "deniedReason": "Agent does not have the requested capability" }
```

Trust score: `0.835` — new agent (age factor = 0.1) but otherwise well-configured.

Hash-chain audit log: modified a historical entry manually in the DB → chain verification failed at that entry → tamper detected.

**The punchline:** AIM doesn't just authenticate agents (prove who they are) — it **authorizes** them (decide what they can do, per-operation, per-context) with a traceable, tamper-evident audit trail. The trust score means "this agent has a track record" — not just a credential.

---

## Part 3: The 5 Tokens We Captured, Plain English

### Token 1: `entra_path_b_tr.json` — Azure App Token

```
"I am the app 'demo-agent-sp', running in Azure tenant d179eaa0...
 I can call Microsoft Graph.
 Entra signed me with RS256.
 I am a machine (idtyp: app).
 I expire in 1 hour."
```

This is what an Azure service gets when it calls Microsoft Graph without any user involved. If this were a real Agent Identity, `oid` and `appId` would be the same number.

---

### Token 2: `entra_obo.json` — Azure Delegation Token

```
"I am Jervis Lee (jervislee.JL@gmail.com).
 The app 'demo-agent-sp' is acting on my behalf.
 So: sub = Jervis's object ID, act.sub = the agent's object ID.
 Entra signed me.
 Valid for Microsoft Graph.
 I can look up User.Read, profile, openid, email."
```

Two identities in one badge. The agent is the messenger; Jervis is the person whose permissions are being used.

---

### Token 3: `spire_svid.json` — Workload Identity Document

```
"I am the workload running at spiffe://demo.org/workload/trusted.
 The SPIRE server at demo.org signed me.
 My audience is other services in the demo.org trust domain.
 I prove my identity by the fact that I am RUNNING as UID 1001
 on the approved host — not by knowing a password."
```

No secrets. No stored credentials. The OS kernel told SPIRE who I am.

---

### Token 4: `wso2_token.json` — WSO2 Machine Token

```
"I am the M2M client YxVcAzqM5OB_foN9VWMTDF8YcfIa.
 WSO2 IS signed me with RS256.
 I am a machine (aut: APPLICATION).
 I live in the 'Super' organization (WSO2's default tenant).
 I expire in 1 hour.
 My unique serial number (jti) is da06daf9-cb76-..."
```

Most similar to a classical service account token. Standards-compliant. No delegation features.

---

### Token 5: `aim_token.json` — AIM Two-Part Credential

**Part A (Session JWT — for human admin):**
```
"I am the admin user a0000000-...-000002 (admin@opena2a.org).
 I'm an 'admin' role in organization a0000000-...-000001.
 AIM server signed me with HS256 (symmetric key).
 I expire in 2 hours."
```

**Part B (API key — for the agent process):**
```
"aim_live_OqL6z1LZxmMSpI3-1ijXXD6jK5czFY2jPWcfdSGrcBs="
```

This opaque string IS the agent's credential. It's never stored anywhere — only a BCrypt hash lives in the DB. If you lose it, you generate a new one. The agent uses this key as a Bearer token for all FGA calls.

Plus the agent's Ed25519 public key: `7/4sU6whtpAooxqAHgEtJivzo8kDIXTSoNLMaJgDiPM=`

This is like an SSH public key. The agent proves it controls the private key without ever sending the private key.

---

## Part 4: Why Does Any of This Matter?

### Old world (before AI agents were common)

- A service had ONE identity: a username/password or a client secret in an env var.
- If that secret leaked, everything was compromised.
- Logs said "service-account-prod did this action" — no further detail about *which part* of the system, *on whose behalf*, for *what purpose*.

### What changes with AI agents

- An AI agent might act autonomously OR on behalf of a human — the token needs to carry both identities (`act.sub`).
- An organization might deploy 1000 identical customer service agents from the same blueprint — you need a blueprint→instance hierarchy so you can revoke ALL of them at once, or audit them as a fleet.
- AI agents call tools via MCP — the authorization system needs to know not just "who is asking" but "what capability does this specific agent instance have, in this context, at this trust level."
- When something goes wrong, you need tamper-proof logs you can hand to an auditor.

### What each system we tested solves

| System | Core Contribution |
|---|---|
| Entra Agent ID | Blueprint→instance hierarchy; `oid==appId` agent marker; delegation chain in `act.sub`; `fmi_path` lineage |
| SPIRE | No-secret workload identity; kernel-attested; zero credential exposure |
| WSO2 | Standards-compliant M2M lifecycle via SCIM; OAuth 2.1 for MCP; production-ready open(ish) source |
| OpenA2A AIM | 5-gate FGA; 9-factor trust score; tamper-evident hash-chain audit; purpose-built for AI agents |

None of them does everything. A production AI agent platform would likely combine SPIRE (for workload attestation), an IAM (WSO2 or Entra) for token issuance, and AIM-style FGA for per-operation authorization decisions.
