# AI Agent Identity: WSO2 Agent ID & OpenA2A AIM — Technical Deep Dive (May 2026)

*Companion to `research.md`. Same depth as the Microsoft Entra Agent ID section. All data verified against live Docker deployments run during this project.*

---

## 2. WSO2 Agent ID (WSO2 Identity Server 7.x)

### What It Is

**WSO2 Agent ID** is WSO2's framework for managing non-human AI agent identities, shipped as part of **WSO2 Identity Server 7.0** (GA) and expanded in 7.1. It extends WSO2's established OAuth 2.0 / OIDC / SCIM 2.0 stack with agent-specific tooling rather than introducing a parallel credential system.

**Product family:** Self-hosted Identity Server (IS) + cloud-hosted Asgardeo SaaS. The on-premises IS 7.0 was tested in this project. Asgardeo adds a management UI and hosted "Agent Identity" section but uses the same underlying API surface.

**Problem it solves:** WSO2 IS already handled machine-to-machine (M2M) clients, but had no explicit modelling for AI agents as distinct from generic service accounts. IS 7.x adds:
- A dedicated **SCIM 2.0 extension schema** for agents (`/scim2/Agents`), separate from Users and Groups
- An **Agent Management API** (`/apis/scim2-agents-rest-apis/`) for lifecycle (create, suspend, reactivate, delete)
- First-class representation in the admin console as "AI Agents" vs regular M2M clients
- Native **MCP (Model Context Protocol) proxy support** via the companion **Open MCP Auth Proxy** project
- OAuth 2.1 enforcement for MCP tool grant flows

**What it is NOT:** WSO2 IS 7.0/7.1 does not implement a blueprint→instance delegation chain. Each agent is an independent M2M OAuth client. There is no `act` / `act.sub` in tokens, no FIC credential forwarding, and no parent/child hierarchy.

---

### Core Object Model

| Object | WSO2 Equivalent | Description |
|---|---|---|
| **Organization** | Tenant / Root Organization | All agents live within a tenant (`carbon.super` in IS, a named org in Asgardeo). Agents are scoped to one tenant. |
| **AI Agent** | OIDC Application (M2M template) | Created from the "Machine-to-Machine" application template. Represents one agent identity. Has its own `clientId` / `clientSecret`. |
| **SCIM Agent Resource** | `/scim2/Agents/{id}` entry | Parallel resource to `/scim2/Users`. Carries agent metadata and `active` status for lifecycle. |
| **Roles / Scopes** | OAuth Scopes + Application Roles | Permissions are granted as OAuth scopes associated with the application. No built-in FGA. |
| **MCP Tool Context** | Open MCP Auth Proxy | A reverse proxy that wraps any MCP server with OAuth 2.1 `resource_indicator`-based authorization without code changes to the MCP server. |

```
Organization (Tenant: carbon.super)
├── AI Agent App 1  (clientId: YxVcAzqM5OB...)
│   ├── OAuth scopes   ["read:customers", "write:orders"]
│   ├── SCIM agent resource   /scim2/Agents/YxVcAzqM5OB...
│   └── JWKS (shared org key, RS256, kid: OWRiMzZiYTEx...)
├── AI Agent App 2  (clientId: ...)
└── Open MCP Auth Proxy  (separate container, no changes to MCP server)
```

---

### Authentication: The Token Flows

WSO2 IS 7.x for agents uses **OAuth 2.0 Client Credentials grant** (machine-to-machine, no user). On Asgardeo and IS 7.1+, there is also support for agent-to-agent OBO delegation, but that was not testable in the IS 7.0 local deployment.

#### Flow 1: Client Credentials (M2M, the Primary Agent Flow)

```
Agent                            WSO2 IS Token Endpoint
  │                                    │
  │  POST /oauth2/token                │
  │  Authorization: Basic base64(clientId:clientSecret)
  │  Content-Type: application/x-www-form-urlencoded
  │  grant_type=client_credentials     │
  │  ──────────────────────────────►  │
  │                                    │  verify client, issue JWT
  │  ◄──────────────────────────────  │
  │  {                                 │
  │    "access_token": "eyJ...",       │
  │    "token_type": "Bearer",         │
  │    "expires_in": 3600,             │
  │    "scope": ""                     │
  │  }                                 │
```

**Token endpoint:** `https://<IS_HOST>:9443/oauth2/token`

The returned `access_token` is a JWT (after enabling `type: JWT` in the OIDC config — by default IS 7.0 returns opaque tokens and must be changed via the admin API).

**How to force JWT access tokens in IS 7.0 (three-step pattern, validated in testing):**

```
# Step 1: GET the current OIDC config for the application
GET /api/server/v1/applications/{appId}/inbound-protocols/oidc
Authorization: Basic YWRtaW46YWRtaW4=

# Step 2: Modify — change accessToken.type from "Default" to "JWT"
# Step 3: PUT the entire modified object back (partial updates rejected)
PUT /api/server/v1/applications/{appId}/inbound-protocols/oidc
Content-Type: application/json
{ ...full_oidc_config..., "accessToken": { "type": "JWT", ... } }
```

#### Flow 2: MCP Tool Authorization (via Open MCP Auth Proxy)

```
MCP Client                       Open MCP Auth Proxy       WSO2 IS
  │                                     │                     │
  │  1. Request MCP tool (no token)     │                     │
  │  ──────────────────────────────►   │                     │
  │  ◄──────────────────────────────   │                     │
  │  401 + WWW-Authenticate: Bearer     │                     │
  │     resource_metadata={...}         │                     │
  │                                     │                     │
  │  2. Follow resource_metadata URL    │                     │
  │  ──────────────────────────────────────────────────────► │
  │  ◄──────────────────────────────────────────────────────  │
  │  OAuth 2.1 metadata (token_endpoint, scopes)              │
  │                                     │                     │
  │  3. POST /oauth2/token (client_credentials + resource param)
  │  ──────────────────────────────────────────────────────► │
  │  ◄──────────────────────────────────────────────────────  │
  │  access_token with aud = resource   │                     │
  │                                     │                     │
  │  4. Call MCP tool with Bearer token │                     │
  │  ──────────────────────────────►   │                     │
  │                     validate aud & scopes, proxy to MCP server
  │  ◄──────────────────────────────   │                     │
  │  Tool result                        │                     │
```

The Open MCP Auth Proxy is an open-source project (`wso2/open-mcp-auth-proxy`) that enforces Draft RFC `resource_indicators` (RFC 8707) and OAuth 2.1. The MCP server itself requires no code changes.

---

### Token Anatomy: Decoded JWT Claims

**Actual token captured in testing** (IS 7.0 M2M client credentials, RS256):

```json
Header:
{
  "x5t": "OWRiMzZiYTExYTIxZGFkNTU2...",
  "kid": "OWRiMzZiYTExYTIxZGFkNTU2..._RS256",
  "typ": "at+jwt",
  "alg": "RS256"
}

Payload:
{
  "sub":       "YxVcAzqM5OB_foN9VWMTDF8YcfIa",
  "aut":       "APPLICATION",
  "aud":       "YxVcAzqM5OB_foN9VWMTDF8YcfIa",
  "nbf":       1777709410,
  "azp":       "YxVcAzqM5OB_foN9VWMTDF8YcfIa",
  "org_id":    "10084a8d-113f-4211-a0d5-efe36b082211",
  "iss":       "https://localhost:9443/oauth2/token",
  "exp":       1777713010,
  "org_name":  "Super",
  "iat":       1777709410,
  "jti":       "da06daf9-cb76-48fe-ab48-c7db25f2652b",
  "client_id": "YxVcAzqM5OB_foN9VWMTDF8YcfIa"
}
```

**Claim-by-claim breakdown:**

| Claim | Value Pattern | Meaning |
|---|---|---|
| `sub` | `{clientId}` | The OAuth client ID — this IS the agent's identity in WSO2. Note: unlike Entra, there is no separate `oid` vs `appid` distinction. The `sub` IS the `clientId`. In older WSO2 IS versions, `sub` was `{clientId}@{tenantDomain}` (e.g. `YxV...@carbon.super`); IS 7.0 drops the tenant suffix in the `sub` but keeps tenant info in `org_id`/`org_name`. |
| `aut` | `"APPLICATION"` | **WSO2 proprietary claim.** States whether the token was issued to a machine application (`APPLICATION`) or on behalf of a user (`APPLICATION_USER`). Not in any OAuth/OIDC RFC. This is the *only* built-in signal that distinguishes a machine agent from a delegated user token. |
| `aud` | `["{clientId}"]` | Audience — who the token is intended for. For M2M tokens, WSO2 sets `aud` = `clientId` of the application itself. If additional audiences are configured (e.g. a downstream API), they are appended as an array. |
| `azp` | `"{clientId}"` | Authorized party (RFC 7519). The client that requested this token. For M2M, same as `sub` and `aud`. |
| `org_id` | UUID | WSO2 internal organization ID for the tenant. Not in OIDC spec. |
| `org_name` | `"Super"` | Human-readable org/tenant name. Not in OIDC spec. |
| `iss` | `"https://<host>:9443/oauth2/token"` | Token issuer URL. Standard OIDC claim. |
| `exp` | Unix timestamp | Token expiry. Default 3600s for M2M. |
| `iat` | Unix timestamp | Issued at. |
| `nbf` | Unix timestamp | Not valid before. Same value as `iat` for M2M. |
| `jti` | UUID | JWT ID — unique identifier for this specific token. Used for replay prevention. |
| `client_id` | `"{clientId}"` | The OAuth client ID. Redundant with `sub` for M2M tokens, but included for clarity. |
| `kid` | Long hash string | Key ID for JWKS lookup. Used by resource servers to verify the signature. |
| `x5t` | Base64 cert thumbprint | X.509 certificate thumbprint for the signing key. |

**What is absent vs Entra:**
- No `oid` (object ID) as a separate concept from `clientId`
- No `act` / `act.sub` (no delegation chain claim)
- No `idtyp` ("app" marker)
- No `fmi_path` or blueprint reference
- No `tid` (tenant ID) — instead uses `org_id`/`org_name`

---

### SCIM 2.0 Agent Lifecycle

WSO2 IS 7.x manages agent lifecycle through SCIM 2.0. Agents have their own resource endpoint parallel to users.

**Endpoints:**

| Action | Method | Endpoint | Body |
|---|---|---|---|
| List all agents | GET | `/scim2/Agents` | — |
| Get one agent | GET | `/scim2/Agents/{id}` | — |
| Create agent | POST | `/scim2/Agents` | `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"agent-name","active":true}` |
| Suspend agent | PATCH | `/scim2/Agents/{id}` | `{"Operations":[{"op":"replace","value":{"active":false}}]}` |
| Reactivate agent | PATCH | `/scim2/Agents/{id}` | `{"Operations":[{"op":"replace","value":{"active":true}}]}` |
| Delete agent | DELETE | `/scim2/Agents/{id}` | — |

> **Note:** In IS 7.0, the `/scim2/Agents` endpoint exists but was not yet fully surfaced in the admin console UI. The `/scim2/Users` endpoint also accepts agent-type entries with the M2M client role. In IS 7.1 and Asgardeo, the agent management UI is promoted to first-class.

**Lifecycle demonstrated in testing (IS 7.0 workaround using `/scim2/Users`):**

```bash
# Create agent (as M2M user-type entry)
POST /scim2/Users
Authorization: Basic YWRtaW46YWRtaW4=
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "demo-agent-lifecycle@carbon.super",
  "password": "Agent@123!",
  "active": true
}

# Suspend
PATCH /scim2/Users/{id}
{ "Operations": [{ "op": "replace", "value": { "active": false } }] }

# Verify token issuance fails after suspension
POST /oauth2/token  →  401 Unauthorized ("The client is disabled")

# Reactivate
PATCH /scim2/Users/{id}
{ "Operations": [{ "op": "replace", "value": { "active": true } }] }

# Verify token issuance succeeds again
POST /oauth2/token  →  200 OK
```

---

### Token Validation: JWKS Endpoint

Resource servers validate WSO2 tokens by fetching the public key from the JWKS endpoint:

```
GET https://<IS_HOST>:9443/oauth2/jwks

Response:
{
  "keys": [{
    "kty": "RSA",
    "e":   "AQAB",
    "use": "sig",
    "kid": "OWRiMzZiYTExYTIxZGFkNTU2..._RS256",
    "alg": "RS256",
    "n":   "3WoCb9H_..." (RSA modulus)
  }]
}
```

**Discovery endpoint** (OpenID Connect standard):
```
GET https://<IS_HOST>:9443/oauth2/token/.well-known/openid-configuration
```
Returns `jwks_uri`, `token_endpoint`, `introspection_endpoint`, `userinfo_endpoint`.

---

### Admin API Reference

All application management in IS 7.x is through the DCR-style REST API.

| Operation | Method | Endpoint |
|---|---|---|
| List applications | GET | `/api/server/v1/applications` |
| Create application | POST | `/api/server/v1/applications` |
| Get application detail | GET | `/api/server/v1/applications/{appId}` |
| Get OIDC config | GET | `/api/server/v1/applications/{appId}/inbound-protocols/oidc` |
| Update OIDC config | PUT | `/api/server/v1/applications/{appId}/inbound-protocols/oidc` |
| Delete application | DELETE | `/api/server/v1/applications/{appId}` |
| Get application templates | GET | `/api/server/v1/application-templates` |

**M2M template ID (IS 7.0.0):** `b9c5e11e-fc78-484b-9bec-015d247561b8`
*(In IS 7.1+ and Asgardeo, the string `"machine-to-machine"` also works as a template name alias.)*

**Create M2M agent application request:**
```json
POST /api/server/v1/applications
Authorization: Basic YWRtaW46YWRtaW4=
Content-Type: application/json

{
  "name": "my-ai-agent",
  "templateId": "b9c5e11e-fc78-484b-9bec-015d247561b8",
  "description": "AI agent identity for order processing",
  "inboundProtocolConfiguration": {
    "oidc": {
      "grantTypes": ["client_credentials"],
      "accessToken": { "type": "JWT", "userAccessTokenExpiryInSeconds": 3600 }
    }
  }
}
```

---

### Relation to Existing Industry Concepts

| Feature | WSO2 IS 7.x Approach | RFC / Standard |
|---|---|---|
| Agent credential | OAuth `client_id` + `client_secret` | RFC 6749 |
| Token format | JWT access token (RFC 9068 `at+jwt`) | RFC 9068 |
| Token grant | `client_credentials` | RFC 6749 §4.4 |
| Resource indicators | Supported via Open MCP Auth Proxy | RFC 8707 |
| Token introspection | `/oauth2/introspect` | RFC 7662 |
| Agent lifecycle | SCIM 2.0 `active:false` to suspend | RFC 7644 |
| MCP authorization | OAuth 2.1 (draft) via proxy | MCP Auth draft spec |
| Key discovery | JWKS endpoint | RFC 7517 |

---

### What Was Tested vs What Requires Asgardeo / IS 7.1

| Feature | IS 7.0 Local Docker | IS 7.1 / Asgardeo |
|---|---|---|
| M2M client credentials JWT tokens | ✅ Tested | ✅ |
| JWT token type via admin API | ✅ Tested (3-step PUT) | ✅ (UI option) |
| Agent lifecycle (create/suspend/reactivate) | ✅ Tested via /scim2/Users | ✅ Native /scim2/Agents |
| JWKS validation | ✅ Tested | ✅ |
| Agent-to-agent OBO delegation | ❌ Not available | 🔶 Beta in Asgardeo |
| Agent Management UI | ❌ Not surfaced | ✅ Full UI |
| Open MCP Auth Proxy | ❌ Not tested (requires proxy container) | ✅ Documented |
| Blueprint hierarchy | ❌ Not a feature | ❌ Not a feature |
| `act` / `act.sub` delegation chain | ❌ Not a feature | ❌ Not a feature |

---

## 3. OpenA2A AIM (Agent Identity Management)

### What It Is

**OpenA2A AIM** (Agent Identity Management) is an open-source project by the **OpenA2A** initiative, providing purpose-built identity infrastructure for AI agents. Version **3.1.0** was tested (current as of May 2026). The project is **pre-1.0** and explicitly states API stability is not guaranteed.

**Repository:** `openA2A/aim`
**Stack:** Go backend, PostgreSQL 16, Next.js dashboard, Docker Compose deployment
**License:** Open source (Apache 2.0)

**Problem it solves:** Unlike WSO2 (which extends existing IAM) and Entra (which extends Azure AD), AIM is built from scratch with AI agent-specific security primitives:
- **Two-tier authentication:** Human admin UI uses JWT sessions; agent processes use opaque API keys backed by bcrypt hashes. Never stored in plaintext.
- **Fine-Grained Authorization (FGA):** A multi-gate pipeline that evaluates agent capability, attributes, context, chain of trust, and intent before authorizing any operation. Not just RBAC.
- **Trust Score:** A computed, multi-factor reputation metric per agent (9 factors), used in authorization decisions.
- **Hash-Chain Audit Log:** Tamper-evident audit trail using SHA-256 chaining. The integrity function is cryptographically verifiable by anyone with the log.
- **Ed25519 Keypair Identity:** Each agent can register a public key. The private key never leaves the agent. Identity is asserted by signature.
- **MCP Attestation:** Agents serving MCP tools can register their MCP server metadata; the identity system tracks which agent is behind which MCP endpoint.

---

### Core Object Model

```
Organization (UUID: a0000000-0000-0000-0000-000000000001)
└── Agent (UUID: b392e2c2-6ee8-4539-8d62-da8af5858669)
    ├── display_name: "Demo Agent"
    ├── agent_type:   "ai_agent"
    ├── public_key:   "7/4sU6whtpAooxqAHgEtJivzo8kDIXTSoNLMaJgDiPM=" (Ed25519)
    ├── Capabilities
    │   ├── db:read   (registered)
    │   └── db:write  (NOT registered → FGA DENY)
    ├── API Keys
    │   └── aim_live_OqL6z1LZxmMSpI3-...  (BCrypt hash stored, prefix index)
    ├── Trust Score: 0.835
    │   ├── verification_status:  1.0 (verified)
    │   ├── uptime:               1.0 (100%)
    │   ├── success_rate:         0.9
    │   ├── security_alerts:      1.0 (none)
    │   ├── compliance:           1.0
    │   ├── age:                  0.1 (brand new agent)
    │   ├── drift_detection:      1.0 (no config drift)
    │   ├── user_feedback:        0.5 (no reviews)
    │   └── execution_isolation:  0.9
    └── MCP Server Metadata  (registered via /api/v1/agents/{id}/mcp-servers)
```

---

### Two-Tier Authentication Model

AIM separates human operator access from automated agent access at the authentication layer.

#### Tier 1: Human Admin — Session JWT (HS256)

Used by: dashboard UI, admin API calls, initial setup.

```
POST /api/v1/public/login
Content-Type: application/json

{
  "email":    "admin@opena2a.org",
  "password": "AIM2025!Secure"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a0000000-0000-0000-0000-000000000002",
    "email": "admin@opena2a.org",
    "role": "admin"
  }
}
```

**Session JWT payload (decoded):**
```json
{
  "user_id":         "a0000000-0000-0000-0000-000000000002",
  "organization_id": "a0000000-0000-0000-0000-000000000001",
  "email":           "admin@opena2a.org",
  "role":            "admin",
  "iss":             "agent-identity-management",
  "sub":             "a0000000-0000-0000-0000-000000000002",
  "exp":             1777737363,
  "nbf":             1777730163,
  "iat":             1777730163,
  "jti":             "46c71ca1-1443-4e34-acd8-ca8050420077"
}
```

Algorithm: HS256 (symmetric — the server and client share the same secret). Suitable for session tokens. Note: `iss` is the literal string `"agent-identity-management"`, not a URL. This is non-standard but functional.

#### Tier 2: Agent Process — Opaque API Key

Used by: agent processes making automated calls (FGA, trust score, MCP registration).

```
POST /api/v1/api-keys
Authorization: Bearer {session_jwt}
Content-Type: application/json

{
  "name": "demo-agent-key",
  "agent_id": "b392e2c2-6ee8-4539-8d62-da8af5858669",
  "expires_at": "2026-12-31T00:00:00Z"
}

Response:
{
  "key": "aim_live_OqL6z1LZxmMSpI3-1ijXXD6jK5czFY2jPWcfdSGrcBs=",
  "id":  "...",
  "name": "demo-agent-key"
}
```

The key is returned **only once**. The server stores only a BCrypt hash + the `aim_live_` prefix for lookup. Format: `aim_live_{url-safe-base64-random}`.

Agent API calls use this key as a Bearer token:
```
Authorization: Bearer aim_live_OqL6z1LZxmMSpI3-1ijXXD6jK5czFY2jPWcfdSGrcBs=
```

---

### Fine-Grained Authorization (FGA) Pipeline

This is AIM's most distinctive feature. Every authorization decision passes through a **5-gate evaluation pipeline**. Gates run in order; the first gate to deny stops evaluation.

```
Request                Gate 1           Gate 2          Gate 3
──────────────────►  capability_check → attribute_check → context_check
                      "does agent have  "does agent have "is context (time,
                       this capability?" right attributes?" env, etc.) OK?"
                            │
                      Gate 4           Gate 5
                    chain_check     → intent_check
                     "is the call    "does the declared
                      chain valid?"   intent match?"
                            │
                            ▼
                     ALLOW or DENY (with gate name that triggered deny)
```

**FGA request (allow case — agent has `db:read` capability):**
```
POST /api/v1/agents/{agentId}/authorize
Authorization: Bearer aim_live_...
Content-Type: application/json

{
  "capability": "db:read",
  "resource":   "customers",
  "context": {
    "requestedBy": "user-session-123",
    "environment": "production"
  }
}

Response:
{
  "allowed":        true,
  "outcome":        "ALLOW",
  "stepsTriggered": ["capability_check"],
  "latencyMs":      5
}
```

**FGA request (deny case — agent does NOT have `db:write`):**
```
POST /api/v1/agents/{agentId}/authorize
{
  "capability": "db:write",
  "resource":   "customers"
}

Response:
{
  "allowed":       false,
  "outcome":       "DENY",
  "stepsTriggered": ["capability_check"],
  "deniedBy":      "capability_check",
  "deniedReason":  "Agent does not have the requested capability",
  "latencyMs":     2
}
```

**Capability registration:**
```
POST /api/v1/agents/{agentId}/capabilities
Authorization: Bearer {session_jwt_or_api_key}
Content-Type: application/json

{ "capabilityType": "db:read" }

Response: 201 Created
{ "id": "...", "capabilityType": "db:read", "agentId": "...", "createdAt": "..." }
```

> **Field name caveat (verified in testing):** The field MUST be `capabilityType`. Using `capability`, `name`, or `type` returns 400/422.

---

### Trust Score: 9-Factor Reputation Model

AIM computes a trust score for each agent on demand. The score is a weighted composite of 9 factors.

```
GET /api/v1/trust-score/agents/{agentId}
Authorization: Bearer aim_live_...

Response:
{
  "agentId":    "b392e2c2-6ee8-4539-8d62-da8af5858669",
  "score":      0.835,
  "components": {
    "verificationStatus": 1.0,   // agent identity verified
    "uptime":             1.0,   // 100% uptime (or no data yet → defaults high)
    "successRate":        0.9,   // 90% successful FGA outcomes
    "securityAlerts":     1.0,   // no security incidents
    "compliance":         1.0,   // meets compliance policy
    "age":                0.1,   // penalty for brand-new agent (low)
    "driftDetection":     1.0,   // no config drift detected
    "userFeedback":       0.5,   // no human feedback yet (neutral)
    "executionIsolation": 0.9    // good isolation posture
  }
}
```

The `age` factor (0.1 for new agents) is the main reason our test agent scored 0.835 instead of ~1.0. Trust is earned over time.

The trust score can be used as a gate in the FGA pipeline (e.g. "only allow high-trust agents to access sensitive resources") by configuring trust threshold policies in AIM.

---

### Hash-Chain Audit Log

AIM maintains a tamper-evident audit log where each entry includes a SHA-256 hash chain.

**Hash construction for each event:**
```
event_hash   = SHA256(event_type + agent_id + resource + timestamp + metadata_json)
chain_hash   = SHA256(event_hash + prev_chain_hash)
```

The `chain_hash` of entry N covers all entries from 0 to N. If any past entry is modified, the chain_hash will not validate.

**Tamper detection query:**
```
GET /api/v1/admin/audit-logs?limit=100
Authorization: Bearer {session_jwt}

Response (each entry):
{
  "id":          "...",
  "event_type":  "fga.authorize",
  "agent_id":    "b392e2c2-...",
  "outcome":     "ALLOW",
  "event_hash":  "a3f1...",
  "chain_hash":  "9b7c...",
  "created_at":  "2026-05-01T..."
}
```

Verified in testing (`10_aim_audit_tamper.py`): modifying any historical record causes chain_hash revalidation to fail beginning from that entry.

---

### Ed25519 Keypair Identity

Agents can optionally register an Ed25519 public key. This allows:
- Cryptographic proof of identity without transmitting secrets
- Key-bound tokens / signed requests
- Future: attestation of agent binary integrity

**Agent creation with public key:**
```
POST /api/v1/agents
Authorization: Bearer {session_jwt}
Content-Type: application/json

{
  "name":         "demo-agent",
  "display_name": "Demo Agent",
  "description":  "Test agent for identity demo",
  "agent_type":   "ai_agent",
  "public_key":   "7/4sU6whtpAooxqAHgEtJivzo8kDIXTSoNLMaJgDiPM="
}
```

The public key is stored; the private key never touches the server.

---

### MCP Server Registration

Agents can register their MCP server metadata, linking agent identity to MCP endpoint.

```
# Register
POST /api/v1/agents/{agentId}/mcp-servers
{
  "url":         "https://agent-host:3001/mcp",
  "name":        "demo-agent-mcp",
  "description": "MCP server for demo agent"
}

# Query
GET /api/v1/agents/{agentId}/mcp-servers
Response: [ { "id": "...", "url": "...", "name": "...", "status": "registered" } ]
```

---

### Full API Endpoint Reference

| Category | Method | Endpoint |
|---|---|---|
| **Auth** | POST | `/api/v1/public/login` |
| **Auth** | POST | `/api/v1/public/register` |
| **Agents** | POST | `/api/v1/agents` — create |
| **Agents** | GET | `/api/v1/agents` — list |
| **Agents** | GET | `/api/v1/agents/{id}` — get |
| **Agents** | PUT | `/api/v1/agents/{id}` — update |
| **Agents** | DELETE | `/api/v1/agents/{id}` — delete |
| **Capabilities** | POST | `/api/v1/agents/{id}/capabilities` |
| **Capabilities** | GET | `/api/v1/agents/{id}/capabilities` |
| **Capabilities** | DELETE | `/api/v1/agents/{id}/capabilities/{capId}` |
| **FGA** | POST | `/api/v1/agents/{id}/authorize` |
| **FGA** | GET | `/api/v1/agents/{id}/authorization-history` |
| **Trust Score** | GET | `/api/v1/trust-score/agents/{id}` |
| **MCP** | POST | `/api/v1/agents/{id}/mcp-servers` |
| **MCP** | GET | `/api/v1/agents/{id}/mcp-servers` |
| **API Keys** | POST | `/api/v1/api-keys` — create |
| **API Keys** | GET | `/api/v1/api-keys` — list |
| **API Keys** | DELETE | `/api/v1/api-keys/{id}` — revoke |
| **Admin — Audit** | GET | `/api/v1/admin/audit-logs` |
| **Admin — Users** | GET | `/api/v1/admin/users` |
| **Admin — Agents** | GET | `/api/v1/admin/agents` |
| **Health** | GET | `/health` |

---

### Database Schema (Key Tables)

From PostgreSQL inspection and migration files (90 migrations as of v3.1.0):

```sql
-- agents
CREATE TABLE agents (
  id               UUID PRIMARY KEY,
  organization_id  UUID NOT NULL,
  name             TEXT NOT NULL,
  display_name     TEXT,
  description      TEXT,
  agent_type       TEXT, -- "ai_agent", "service_agent", etc.
  public_key       TEXT, -- Ed25519 base64
  status           TEXT, -- "active", "suspended", "revoked"
  trust_score      FLOAT,
  created_at       TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ
);

-- api_keys
CREATE TABLE api_keys (
  id           UUID PRIMARY KEY,
  agent_id     UUID,
  name         TEXT,
  key_hash     TEXT,  -- BCrypt hash of full key
  key_prefix   TEXT,  -- "aim_live_OqL6..." (first N chars for lookup)
  expires_at   TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ
);

-- agent_capabilities
CREATE TABLE agent_capabilities (
  id              UUID PRIMARY KEY,
  agent_id        UUID,
  capability_type TEXT,  -- "db:read", "db:write", "api:invoke", etc.
  created_at      TIMESTAMPTZ
);

-- audit_log
CREATE TABLE audit_log (
  id          UUID PRIMARY KEY,
  event_type  TEXT,
  agent_id    UUID,
  outcome     TEXT,
  metadata    JSONB,
  event_hash  TEXT,   -- SHA256 of event fields
  chain_hash  TEXT,   -- SHA256(event_hash + prev.chain_hash)
  created_at  TIMESTAMPTZ
);
```

---

### Relation to Existing Industry Concepts

| AIM Feature | Closest Analogue | Key Difference |
|---|---|---|
| Agent API key | GitHub PAT, Stripe API key | Scoped to one agent, BCrypt-stored, never plaintext after issuance |
| Session JWT | OAuth access token | HS256 (symmetric), admin-only, short-lived session |
| FGA pipeline | AWS Cedar / OPA / Google Zanzibar | Purpose-built for AI agent capabilities, not general-purpose policy |
| Trust score | Credit score / risk score | Computed, multi-factor, runtime-updated, used in authorization |
| Hash-chain audit | Certificate transparency logs / blockchain | SHA-256 chain, no distributed ledger needed |
| Ed25519 public key | SSH authorized_keys / WebAuthn COSE key | Agent asserting its own identity by cryptographic proof |
| MCP registration | Service mesh service registry | Binds agent identity to MCP endpoint |

---

### Version Caveat

AIM v3.1.0 is **pre-1.0**. The 90 database migrations in this version include frequent table renames and schema changes. API endpoints and field names have changed between minor versions (confirmed by breaking field name differences from early docs vs actual behavior). Do not rely on API stability in production without locking to a specific version.

---

## 4. WSO2 Agent ID vs OpenA2A AIM: Side-by-Side

| Dimension | WSO2 IS 7.x | OpenA2A AIM v3.1.0 |
|---|---|---|
| **Maturity** | Production-ready (7.0 GA) | Pre-1.0, breaking changes expected |
| **Architecture** | Extends existing IAM stack | Purpose-built from scratch for agents |
| **Token format** | JWT (RS256), RFC 9068 `at+jwt` | HS256 session JWT for humans, opaque API key for agents |
| **Authorization model** | RBAC via OAuth scopes | 5-gate FGA pipeline (capability, attribute, context, chain, intent) |
| **Agent lifecycle** | SCIM 2.0 `active:true/false` | `status` field + API (`active`, `suspended`, `revoked`) |
| **Identity proof** | OAuth `clientId` + `clientSecret` | Ed25519 public key OR opaque API key |
| **Audit** | Standard IS audit logs | Hash-chain tamper-evident audit log |
| **Trust model** | Binary (client enabled/disabled) | Continuous 9-factor trust score |
| **MCP support** | OAuth 2.1 via Open MCP Auth Proxy | MCP server registry binds agent identity to MCP endpoint |
| **Delegation chain** | Not supported | Not supported (no `act`/`act.sub`) |
| **Blueprint hierarchy** | Not supported | Not supported |
| **Standards compliance** | High: RFC 6749, 7519, 7644, 9068 | Partial: custom FGA, custom trust score — not standardized |
| **Self-hosted** | ✅ Docker, bare metal, K8s | ✅ Docker Compose |
| **Cloud SaaS** | ✅ Asgardeo | ❌ Not available |
| **Open source** | ✅ Source on GitHub (Apache 2.0); production use requires WSO2 Subscription (commercial) | ✅ Apache 2.0 |
