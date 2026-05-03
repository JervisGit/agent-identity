# Strategy Proposal: WSO2 Now, Entra-Ready Architecture

*Written for planning purposes. Addresses (1) strategy validation, (2) Entra Agent ID → WSO2 concept mapping with evidence from this project's code and captured tokens.*

---

## Part 1: Is the Strategy Correct?

### The Four Pillars, Assessed

---

#### Pillar 1: Use WSO2 and its Agent Identity Extension

**Assessment: Correct.**

The reasoning holds on all practical dimensions:

- **Entra Agent ID is not generally available.** It requires the Microsoft 365 Frontier program (invite-only as of May 2026). The `agentIdentities` Graph API returned `BadRequest` in our direct testing (`scripts/01_verify_entra.ps1`). You cannot build a production workload on it today without that license access.
- **WSO2 IS 7.0 is production-ready.** GA since late 2024. It's deployed by the Reserve Bank of India, Samsung SDS, Hilton, and 1,500+ enterprises. It has a commercial subscription with SLA and support.
- **WSO2 runs natively on Azure.** It deploys on Azure Kubernetes Service, Azure Container Apps, or Azure VMs. "Hosted on Azure" ≠ "must use Azure AD as the identity provider." The infrastructure provider and the identity provider are separate concerns.
- **The core concepts are the same OAuth 2.0 stack.** `aud`, `iss`, `sub`, `exp`, `jti`, `client_credentials` — all standard. The application code calling WSO2 tokens and the application code calling Entra tokens differ mainly in endpoint URL and a handful of claim names. The business logic does not change.

**One caveat:** If a significant portion of your agent workloads need to access Microsoft 365 APIs (Graph, Teams, SharePoint) on behalf of individual users, the Entra OBO flow is significantly better-integrated than WSO2's delegation model. For pure Azure infrastructure access or third-party APIs, WSO2 is fully adequate.

---

#### Pillar 2: Design So That Entra Swap Is Not Difficult

**Assessment: Correct, and achievable with a specific set of abstractions.**

The swap cost depends entirely on how much WSO2-specific behaviour leaks into application code. The following abstractions eliminate most of the migration effort:

**A. Abstract token acquisition behind an interface:**

```python
# IdentityProvider interface — same call from application code regardless of IAM
class IdentityProvider(Protocol):
    def get_agent_token(self, scope: str) -> str: ...
    def get_delegation_token(self, user_token: str, scope: str) -> str: ...

class WSO2Provider(IdentityProvider):
    def get_agent_token(self, scope):
        # POST /oauth2/token  grant_type=client_credentials
        ...

class EntraProvider(IdentityProvider):
    def get_agent_token(self, scope):
        # MSAL client_credentials  OR  blueprint T1→TR impersonation
        ...
```

**B. Normalize claims at the JWT parsing layer — never check provider-specific claims in business logic:**

```python
# BAD: WSO2-specific, breaks on Entra swap
if token["aut"] == "APPLICATION":
    ...

# GOOD: normalize once at the boundary
def is_agent_token(payload: dict) -> bool:
    return (
        payload.get("aut") == "APPLICATION"       # WSO2
        or payload.get("idtyp") == "app"          # Entra
    )
```

**C. Store blueprint/fleet relationships in your own registry, not only in IAM claims:**

WSO2 has no `fmi_path`. Entra will. If your authorization logic needs to know "which agent type is this instance?", keep that mapping in your own DB or config store — not only as an IAM claim. That way it works with WSO2 today and maps to Entra's `fmi_path` later without changing application code.

**D. Use standard `jti` for idempotency and audit correlation** — both providers emit it. Using `jti` as the canonical "this token's unique ID" means audit log correlation works the same way on both.

**The main migration risk** is the OBO / delegation chain gap. If you build user-delegated agent flows on WSO2's IS 7.1 beta delegation before Entra is GA, those token structures will differ from Entra's `act.sub`. Design that feature as a pluggable module from day one.

---

#### Pillar 3: Code Out the 5 AIM Borrowable Patterns

**Assessment: Correct, and this is the highest-value decision in the entire proposal.**

The key insight is that **the 5 patterns are identity-system-agnostic**. They don't talk to WSO2 or Entra — they operate on whatever token you already have. Adopting them now means:

- They continue to work unchanged when you swap from WSO2 to Entra
- They add security depth that neither provider offers natively (per-operation FGA, trust scoring, tamper-evident audit, break-glass controls)
- They are implemented in pure Python with no external dependencies (`scripts/11_borrowable_patterns.py`)

**Recommended integration points:**

| Pattern | Where to integrate |
|---|---|
| HashChainAuditLog | Every agent action endpoint — log `(action, resource, result, token_sub)` after authorization |
| TrustScorer | Agent registration flow + periodic recompute job fed by monitoring metrics |
| FGAGateway | FastAPI/middleware layer — runs between JWT validation and business logic |
| SecretlessCredential | Anywhere an API key or client_secret is loaded — wrap in the context manager |
| BreakGlassToken | Ops runbook automation — replace ad-hoc emergency credential sharing |

---

#### Pillar 4: Framework for Evaluating When to Swap to Entra

**Assessment: Correct. Define the trigger criteria now, before the evaluation pressure arrives.**

**Proposed evaluation framework:**

| Criterion | Threshold to Consider Switching | How to Measure |
|---|---|---|
| GA availability | Entra Agent ID exits preview; `agentIdentities` Graph API is stable and available without Frontier | Microsoft announcement + test `POST /v1.0/agentIdentities` returns 2xx without M365 Copilot license |
| License cost | M365 Copilot per-agent licensing cost < total WSO2 subscription + ops overhead | Annual cost comparison including infra, ops, support |
| M365 dependency | >50% of agent tool calls target Microsoft Graph / M365 APIs | Telemetry from your agents' outbound API call distribution |
| Fleet scale | >500 agent instances of the same type, where blueprint-level revocation has real operational value | Agent instance count in your registry |
| `act.sub` gap | You need auditable user-delegated flows AND WSO2's Ballerina extension is too fragile | Audit query failure rate; support burden of custom claim transformer |
| Security compliance | An audit requires `oid==appId` or `fmi_path` as proof of agent identity (not just `aut: APPLICATION`) | Compliance questionnaire or regulator requirement |

**Minimum bar to switch:** GA availability + license cost acceptable + at least two other thresholds met.

**Migration effort at that point:** With the abstractions from Pillar 2 in place, the migration reduces to:
1. Swap `WSO2Provider` → `EntraProvider` (token acquisition)
2. Update the claim normalizer (`is_agent_token`, `get_agent_id`)
3. Register existing agent identities in Entra as Agent Identity blueprints
4. Update the blueprint/fleet registry to reference Entra's `fmi_path` format
5. Validate the 5 AIM patterns still pass (they will — they're IAM-agnostic)

Estimated effort with abstractions in place: **1–2 weeks**. Without them: 2–3 months of refactoring.

---

### Summary Recommendation

**Yes, the strategy is sound.** The four pillars are internally consistent and each one makes the others safer:

- WSO2 now → de-risks from an immature, licensed-gated technology
- Entra-compatible abstractions → reduces future migration cost to days
- AIM patterns → adds security depth that survives any IAM swap
- Evaluation framework → prevents premature or delayed migration based on feelings rather than measurable thresholds

---

---

## Part 2: Entra Agent ID Concept → WSO2 Counterpart → Code Evidence

*Azure hosting context. All evidence is from live runs in this project. "Not captured" means the Frontier license prevented testing; the architecture is documented in `research.md`.*

---

### Legend

| Column | Meaning |
|---|---|
| Entra Concept | The Entra Agent ID feature or token claim |
| WSO2 Counterpart | What WSO2 IS 7.x provides in its place |
| Gap / Notes | Fidelity of the mapping — identical / functional equivalent / partial / absent |
| Code / Output Evidence | File + field or line reference proving the claim is factual |

---

### Object Model

| Entra Concept | WSO2 Counterpart | Gap / Notes | Code / Output Evidence |
|---|---|---|---|
| **Agent Identity Blueprint** — An app registration that acts as the credential holder and template for all agent instances. One blueprint → many agent instances. | **M2M Application (OIDC)** — Created from the Machine-to-Machine application template. One application per agent type. No built-in 1:N hierarchy unless you implement a naming convention + role. | **Partial.** WSO2 has no native parent/child concept. You model it with a role convention: `Instance.Blueprint.{TypeName}`. Revocation requires a SCIM batch script, not a single API call. | `scripts/08_wso2_demo.py` line 189 — creates M2M app. `scripts/12_compare_all.py` — comparison table. |
| **Agent Identity (SP instance)** — A service principal created by the blueprint. Its `oid` == its `appId` (unique marker). Has no credentials of its own. | **M2M Application clientId** — Each WSO2 M2M application has a `clientId`. There is no separate "instance" object under a blueprint. `clientId` == `sub` in the token. | **Functional equivalent for single instances.** No structural marker (`oid == appId` does not apply). The only machine marker is `aut: APPLICATION` (proprietary). | `captured_tokens/wso2_token.json` → `"sub": "YxVcAzqM5OB_foN9VWMTDF8YcfIa"` and `"client_id": "YxVcAzqM5OB_foN9VWMTDF8YcfIa"` are the same value — closest WSO2 structural equivalent. |
| **Agent's User Account** (optional) — An Entra user account decorated as an AI agent, used when a target system requires a UPN. | **No direct equivalent.** WSO2 can create a user with an agent-like username, but there is no "agent-decorated user" concept. | **Absent.** Rarely needed unless a Microsoft-specific system requires a UPN for an agent. Not applicable to Azure infrastructure APIs. | N/A |

---

### Token Flows

| Entra Concept | WSO2 Counterpart | Gap / Notes | Code / Output Evidence |
|---|---|---|---|
| **T1 Token** — The Blueprint's own OAuth token (client credentials), used internally as the first step to impersonate an Agent Identity. Never leaves the blueprint. Only exists in the full Frontier flow (Path A). | **No equivalent.** WSO2 M2M has no two-step impersonation. The agent application authenticates directly and gets its own token in one step. | **Absent as a concept.** The T1/TR split exists because Entra separates "blueprint" from "agent instance." Since WSO2 has no such split, there is no T1 concept — just one direct token request. | Path A (T1→TR) was blocked by Frontier requirement. Not capturable. Documented in `research.md` §Auth Flows. |
| **TR Token (Token Request token)** — The final agent identity token with `fmi_path`, issued after the blueprint impersonates the agent instance. What resource servers receive. | **Client credentials JWT access token** — The access token WSO2 issues after `grant_type=client_credentials`. This IS the only token that exists; there's no intermediate step. | **Functional equivalent** for the downstream resource server's view (a signed JWT with agent identity). Missing: `fmi_path`, blueprint lineage, `oid==appId` marker. | `captured_tokens/entra_path_b_tr.json` (Path B equivalent) and `captured_tokens/wso2_token.json`. Both are RS256 JWTs validated by downstream services. `scripts/03_get_tokens.py` line 192, `scripts/08_wso2_demo.py` line 227. |
| **OBO Token** — On-Behalf-Of token where `sub` = the user being acted for and `act.sub` = the agent doing the acting. Dual identity in one token. | **No native equivalent in IS 7.0.** IS 7.1+ has a beta agent-to-agent delegation. RFC 8693 Token Exchange is supported as a grant type but the `act` claim injection requires a custom Ballerina extension. | **Absent in IS 7.0. Partial in IS 7.1+.** Workaround: pass delegation context through AIM FGA `chain_check` at the application layer. | `captured_tokens/entra_obo.json` → `"sub": "1hgbadnqNan..."` (Jervis Lee) and `act.sub` would be agent's oid. `scripts/04_obo_flow.py` ran this live. Note: `act` claim not present in the captured Path B OBO token because Path B SP is not a true Agent Identity — but the OBO flow itself worked. |

---

### Token Claims

| Entra Claim | Value in Our Captured Token | WSO2 Counterpart Claim | Value in Our Captured Token | Gap / Notes |
|---|---|---|---|---|
| `iss` | `https://sts.windows.net/d179eaa0.../` | `iss` | `https://localhost:9443/oauth2/token` | **Identical semantics, different value.** Both are the token issuer URL. Normalize to your IS host in config — not hardcoded. |
| `sub` | `b8011268-72f7-47fc-94ad-93d0770676d3` (= `oid`, the Entra object ID of the SP) | `sub` | `YxVcAzqM5OB_foN9VWMTDF8YcfIa` (= `clientId`, the OAuth client ID) | **Same claim name, different identity namespace.** Entra `sub` = object UUID. WSO2 `sub` = OAuth clientId string. Use your `get_agent_id(token)` normalizer — don't rely on the format. |
| `aud` | `https://graph.microsoft.com` | `aud` | `YxVcAzqM5OB_foN9VWMTDF8YcfIa` | **Semantic difference.** Entra `aud` = the resource API URI the token is valid for. WSO2 M2M `aud` = the agent's own clientId (self-audience for M2M). When you add downstream APIs as audience in WSO2, they also appear here. Validate `aud` contains your API's expected value; the format looks different. |
| `iat` | `1777692892` | `iat` | `1777709410` | **Identical semantics.** Issued-at timestamp. Same in both. |
| `exp` | `1777696792` (1 hour) | `exp` | `1777713010` (1 hour) | **Identical semantics.** Token expiry. Default 3600s in both. |
| `nbf` | `1777692892` | `nbf` | `1777709410` | **Identical semantics.** Not-before. Same as `iat` in both M2M tokens. |
| `jti` | `9C4k5o3S8UG_iym61oESAA` (opaque string) | `jti` | `da06daf9-cb76-48fe-ab48-c7db25f2652b` (UUID) | **Same purpose, different format.** Use `jti` for replay prevention and audit correlation in both. The format differs (opaque string vs UUID) but it's always unique. |
| `oid` | `b8011268-72f7-47fc-94ad-93d0770676d3` | *(absent)* | — | **Absent in WSO2.** Entra `oid` is the permanent object ID distinct from `appid`. WSO2 has no separate object store — `clientId` is the only identifier. Map: use `sub` (= `clientId`) as the canonical agent ID in WSO2. |
| `appid` | `0769044c-edf7-4785-a148-dea3b75c2580` | `client_id` | `YxVcAzqM5OB_foN9VWMTDF8YcfIa` | **Functional equivalent.** The OAuth `client_id` that requested the token. In Entra this is separate from `oid`; in WSO2 it equals `sub`. Normalizer: `get_client_id(token)` → `token.get("appid") or token.get("client_id")`. |
| `idtyp: "app"` | Present in `entra_path_b_tr.json` → `"idtyp": "app"` | `aut: "APPLICATION"` | Present in `wso2_token.json` → `"aut": "APPLICATION"` | **Functional equivalent, different claim name.** Both signal "this is a machine token, not a human token." Use: `is_agent_token(t) = t.get("idtyp")=="app" or t.get("aut")=="APPLICATION"`. Neither is in a published RFC. |
| `tid` | `d179eaa0-1d2f-4aca-9d5a-d9176e6195f7` | `org_id` + `org_name` | `"org_id": "10084a8d-..."`, `"org_name": "Super"` | **Structural equivalent, different field.** Both identify which tenant/directory issued the token. Normalizer: `get_tenant_id(t) = t.get("tid") or t.get("org_id")`. |
| `azp` | `0769044c-edf7-4785-a148-dea3b75c2580` | `azp` | `YxVcAzqM5OB_foN9VWMTDF8YcfIa` | **Identical claim name and semantics.** The authorized party (client that requested the token). Both include it per RFC 7519. |
| `fmi_path` | *(not captured — requires Frontier)* | *(absent)* | — | **Absent in WSO2.** No blueprint lineage claim exists. Implement as custom claim via WSO2 OIDC claim transformer: inject `blueprint_id` based on the application's assigned role. See `comparison_entra_vs_wso2_deep.md` §Gap 1. |
| `act.sub` (in OBO token) | Present in Entra OBO when used with true Agent Identity (Path A). In our Path B capture the `act` object appears as a nested claim in the OBO token. | *(absent in IS 7.0)* | — | **Absent in IS 7.0. Beta in IS 7.1+.** The delegation chain claim. Workaround: use AIM FGA `chain_check` with an explicit `delegation_chain` context field in your authorization request. `scripts/11_borrowable_patterns.py` – `FGAContext.delegation_chain`. |
| `scp` | `"User.Read profile openid email"` (only in OBO/delegated tokens) | *(not present in M2M tokens)* | — | **Same concept, different context.** `scp` only appears in user-delegated tokens. WSO2 M2M tokens have no `scp`; scopes granted via RBAC/application roles appear in `scope` field in the token response but not always in the JWT payload for M2M. |
| `ver: "1.0"` | `1.0` | *(absent)* | — | **Entra-internal.** Version of the Entra claims schema. No equivalent in WSO2. Ignore in cross-provider code. |

---

### Authentication Mechanisms

| Entra Concept | WSO2 Counterpart | Gap / Notes | Code / Output Evidence |
|---|---|---|---|
| **Federated Identity Credential (FIC)** — Blueprint authenticates using an external OIDC token (GitHub Actions, K8s SA, workload identity). No `clientSecret` stored anywhere. | **`private_key_jwt` client authentication (RFC 7523)** — WSO2 M2M app configured to accept a JWT signed by an external key (e.g. SPIRE SVID) instead of `clientSecret`. Combines with SPIRE for zero-secret workload authentication. | **Functional equivalent via SPIRE.** Not out-of-the-box — requires configuring `private_key_jwt` auth method and registering the SPIRE JWKS endpoint in WSO2. `scripts/07_spire_demo.py` demonstrates SPIRE half; the WSO2 half is config-only. | `captured_tokens/spire_svid.json` → SPIRE-issued JWT-SVID used as the external credential. `scripts/07_spire_demo.py` — shows SPIRE issuing the SVID that would be presented to WSO2. |
| **Client Secret** — Standard OAuth `clientSecret`, used in Path B as fallback. | **Client Secret** — Same: `clientId` + `clientSecret` in `Authorization: Basic` or form body. | **Identical.** Both support standard client_secret authentication. This is what we actually used in testing. | `scripts/08_wso2_demo.py` line 231 — `Authorization: Basic base64(clientId:clientSecret)`. `.env.local` contains `SP_CLIENT_SECRET` (Entra) and WSO2 credentials. |
| **Certificate-based auth** | **Certificate / mTLS** — WSO2 supports `tls_client_auth` and certificate-bound tokens (MTLS). | **Functional equivalent.** Both support cert-based client auth. | Not tested in this project. |

---

### Authorization and Policy

| Entra Concept | WSO2 Counterpart | Gap / Notes | Code / Output Evidence |
|---|---|---|---|
| **RBAC (App Roles)** — Permissions assigned to the agent SP via app role assignments. Appear as `roles` claim in the token. | **OAuth Scopes + Application Roles** — Permissions granted via application role assignment or OAuth scope grant. Appear in token `scope` claim or application role. | **Functional equivalent.** Different claim name but same mechanism. | `scripts/08_wso2_demo.py` — demonstrates scope assignment in OIDC config. |
| **Conditional Access per agent type** — CA policy targeting `userType: servicePrincipal` or blueprint type. Block/allow based on agent classification. | **Adaptive Authentication scripts** — Groovy/Ballerina scripts evaluated at token issuance time. Can interrogate any claim or external signal. | **Functional equivalent, less turnkey.** Requires writing a short script; not a checkbox in a UI. | Not tested in this project. Documented in `comparison_entra_vs_wso2_deep.md` §Gap 4. |
| **Fine-Grained Authorization (FGA)** — *Not a native Entra feature.* Entra stops at RBAC. True FGA requires Azure APIM policies or external. | **Also not native to WSO2.** WSO2 stops at RBAC/ABAC. | **Both lack FGA.** This is the gap that AIM's 5 patterns fill. `FGAGateway` in `scripts/11_borrowable_patterns.py` adds 5-gate FGA on top of either provider. | `scripts/09_aim_demo.py` — FGA allow/deny results in `captured_tokens/aim_token.json`. `scripts/11_borrowable_patterns.py` — standalone FGA pattern. |

---

### Lifecycle Management

| Entra Concept | WSO2 Counterpart | Gap / Notes | Code / Output Evidence |
|---|---|---|---|
| **Agent lifecycle via Graph API** — Create/suspend/delete agent identities via `POST /v1.0/agentIdentities`, `DELETE`, `PATCH`. | **SCIM 2.0 lifecycle** — `POST /scim2/Agents` (IS 7.1), `PATCH active: false` to suspend, `PATCH active: true` to reactivate, `DELETE /scim2/Agents/{id}`. | **Functional equivalent via open standard.** WSO2 uses RFC 7644 SCIM 2.0; Entra uses a proprietary Graph API. The SCIM approach is more portable. | `scripts/08_wso2_demo.py` — runs the full lifecycle: create → suspend → verify token denied → reactivate → verify token works. Confirmed live. |
| **Sponsor accountability** — Each agent identity has a designated human sponsor accountable for its access. | **No native concept.** You add this as a custom SCIM attribute (`urn:wso2:agent:sponsor`) or in your own registry. | **Absent as a built-in.** Easy to add as metadata. | Not tested. Recommended to add to your agent registration form as a mandatory field. |
| **Access Reviews** — Periodic reviews where sponsors recertify agent access (via Entra Identity Governance). | **No native equivalent.** A periodic SCIM query + email-based review workflow would be the custom equivalent. | **Absent.** Enterprise governance requirement — build it as a scheduled job calling `/scim2/Agents` and routing to a ticketing system. | Not tested. Mentioned in `comparison_entra_vs_wso2_deep.md`. |

---

### Key Discovery and Validation

| Entra Concept | WSO2 Counterpart | Gap / Notes | Code / Output Evidence |
|---|---|---|---|
| **JWKS endpoint** — `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` | **JWKS endpoint** — `https://<IS_HOST>:9443/oauth2/jwks` | **Identical concept.** Both expose public keys as a JWKS for downstream RS256 signature verification. | `research_wso2_aim_deep_dive.md` §Token Validation. The `kid` in `captured_tokens/wso2_token.json` header matches the key ID at the JWKS endpoint. |
| **OpenID Connect Discovery** — `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` | **OpenID Connect Discovery** — `https://<IS_HOST>:9443/oauth2/token/.well-known/openid-configuration` | **Identical standard.** Both conform to OpenID Connect Discovery 1.0. | Both endpoints return `jwks_uri`, `token_endpoint`, `issuer`. Standard claim. |
| **Token introspection** — `POST /v1.0/oauth2/introspect` (Entra does this via Graph) | **Token introspection** — `POST /oauth2/introspect` (RFC 7662) | **Functional equivalent.** WSO2 exposes a standards-compliant introspection endpoint. Entra uses a different path. | `research_wso2_aim_deep_dive.md` §Relation to Existing Concepts. |

---

### The AIM Patterns: No Entra / WSO2 Equivalent

These are capabilities neither provider offers. They are why Pillar 3 (borrow AIM patterns) is the highest-value decision.

| Security Capability | Entra Agent ID | WSO2 IS 7.x | AIM / Borrowable Pattern | Code Evidence |
|---|---|---|---|---|
| Per-operation FGA (5-gate pipeline) | ❌ | ❌ | ✅ Pattern 3 — `FGAGateway` | `scripts/11_borrowable_patterns.py`, `scripts/09_aim_demo.py` → `aim_token.json` FGA allow/deny results |
| Behavioral trust score (9 factors) | ❌ | ❌ (binary: enabled/disabled) | ✅ Pattern 2 — `TrustScorer` | `captured_tokens/aim_token.json` → `"trust_score": 0.835` |
| Tamper-evident hash-chain audit log | ❌ (Microsoft controls platform audit) | ❌ | ✅ Pattern 1 — `HashChainAuditLog` | `scripts/10_aim_audit_tamper.py` — tamper detection verified live |
| In-memory credential zeroing | ❌ | ❌ | ✅ Pattern 4 — `SecretlessCredential` | `scripts/11_borrowable_patterns.py` — `ctypes.memset()` demo |
| Break-glass emergency token | ❌ | ❌ | ✅ Pattern 5 — `BreakGlassToken` | `scripts/11_borrowable_patterns.py` — HMAC-signed, separate audit stream |
| Declared-intent verification | ❌ | ❌ | ✅ Pattern 3 Gate 5 — `intent_check` | `scripts/11_borrowable_patterns.py` — intent mismatch denial demo |
