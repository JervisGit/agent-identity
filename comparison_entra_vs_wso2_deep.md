# Entra Agent ID vs WSO2 Agent ID: Full Comparison + Can the Gaps Be Closed?

*Extends the inline comparison from the previous session. Answers: what can Entra do that WSO2 can't, and can those gaps be bridged with code, configuration, or borrowed open-source libraries?*

---

## 1. The Five Gaps

### Gap 1: Blueprint → Instance Hierarchy (`fmi_path`, `oid == appId`)

**What Entra has:** A two-object model — a *blueprint* (the app registration that holds credentials) impersonates an *Agent Identity* (the SP that receives tokens). The token carries `fmi_path` showing which blueprint issued it. The blueprint's `oid` == its `appId`, which is a structural token marker resource servers can test.

**What WSO2 has:** One flat M2M application per agent. No parent/child relationship. No equivalent claim. The closest marker is `aut: APPLICATION` (proprietary, non-standard).

**Severity:** Medium. The blueprint hierarchy matters for *fleet management at scale* (revoke all 10,000 instances of blueprint-ABC in one operation) and for *Conditional Access policies tied to blueprint type*. For a single-agent or small-fleet deployment it is largely irrelevant.

**Can it be closed?**

Yes — with a convention, not with a built-in feature. You can model the hierarchy yourself in WSO2:

```
WSO2 Organization
├── Blueprint App (clientId: "blueprint-customer-svc")   ← holds the "canonical" credentials
│   └── Org-level role: Blueprint.CustomerService
├── Agent Instance 1 App (clientId: "agent-csvc-001")
│   └── Org-level role: Instance.Blueprint.CustomerService
├── Agent Instance 2 App (clientId: "agent-csvc-002")
│   └── Org-level role: Instance.Blueprint.CustomerService
```

- Add a custom OIDC claim transformer in WSO2 IS that injects `blueprint_id: "blueprint-customer-svc"` into every token from agents bearing the `Instance.Blueprint.CustomerService` role.
- To revoke all instances: write a SCIM batch PATCH script that queries apps by role and sets `active: false`. One script, 30 lines of Python. It's operational overhead, not a missing capability.
- The `oid == appId` marker cannot be replicated exactly in WSO2, but `aut: APPLICATION` combined with your custom `blueprint_id` claim gives the same functional signal to resource servers.

**Verdict: Closeable with a custom claim transformer and a naming/role convention. ~1 week of IS config work.**

---

### Gap 2: On-Behalf-Of Delegation Chain (`act` / `act.sub`)

**What Entra has:** RFC 8693 Token Exchange / OBO flow produces a token where `sub` = the user being acted for, and `act.sub` = the agent doing the acting. Both identities appear in every API call. Entra writes both to its audit log automatically.

**What WSO2 has:** IS 7.0 has no OBO for agents. IS 7.1 / Asgardeo has a beta "agent-to-agent delegation" but it's not RFC 8693-compliant and is not production-ready. Neither version provides the dual-identity audit trail automatically.

**Severity:** High if you are building user-delegated AI agents (an agent acting on a specific user's behalf with that user's permissions). Low if your agents are fully autonomous (no user context).

**Can it be closed?**

Partially, and there are two approaches:

**Approach A: Implement RFC 8693 Token Exchange in front of WSO2.**

WSO2 IS supports a Token Exchange grant (`urn:ietf:params:oauth:grant-type:token-exchange`) in IS 7.1+. The `act` claim injection requires a custom claim transformer that does:

```python
# WSO2 Custom Claim Transformer (Ballerina or Java extension)
# Reads the subject_token's sub, injects as act.sub in the new token
{
  "sub":  subject_token["sub"],     # the user
  "act": { "sub": client_id }       # the agent
}
```

This is documented in WSO2's Ballerina extension model. It requires writing a small Ballerina module and deploying it inside WSO2 IS. Non-trivial but achievable.

**Approach B: Use AIM's FGA chain_check as a proxy.**

Instead of encoding the delegation chain IN the token, record it in the authorization context at request time:

```json
POST /api/v1/agents/{agentId}/authorize
{
  "capability": "graph:read_user",
  "resource":   "users/jervis.lee",
  "context": {
    "on_behalf_of_user": "jervis.lee@example.com",
    "delegated_by":      "user_consent_token_jti_abc123"
  }
}
```

AIM's `chain_check` gate validates that the agent's delegation chain is legitimate. This doesn't put `act.sub` in the token, but it achieves the same security objective (auditable, validated delegation) at the application layer.

**Verdict: Closeable on IS 7.1+ with a Ballerina custom claim transformer (~2–3 weeks). On IS 7.0, use an application-layer delegation context passed through AIM FGA. NOT a show-stopper.**

---

### Gap 3: Federated Identity Credential (FIC) — Zero Stored Secrets

**What Entra has:** The blueprint can authenticate using an external OIDC token (e.g. GitHub Actions, a Kubernetes service account, a workload identity token from another cloud) without ever creating a `clientSecret`. The secret literally doesn't exist in any database.

**What WSO2 has:** M2M apps require a `clientSecret`. There is no native FIC / OIDC federation for machine authentication. You can rotate secrets, vault them, and reduce exposure, but the secret exists.

**Severity:** High from a secrets-management hygiene perspective. A clientSecret is a static credential that can be leaked, logged, and doesn't rotate automatically.

**Can it be closed?**

Yes — with SPIFFE/SPIRE as the credential bootstrap layer:

```
SPIRE (workload attestation)               WSO2 IS
    │                                           │
    │  1. Workload proves its kernel identity   │
    │     (UID, binary hash, container image)   │
    │                                           │
    │  2. SPIRE issues JWT-SVID                 │
    │     sub = spiffe://your-org/agent/svc-001 │
    │                                           │
    │  3. Agent presents JWT-SVID as            │
    │     client_assertion to WSO2              │
    │     grant_type=urn:ietf:params:oauth:      │
    │       grant-type:jwt-bearer               │
    │  ──────────────────────────────────────► │
    │                                           │  validate JWT against
    │                                           │  SPIRE JWKS endpoint
    │  ◄──────────────────────────────────────  │
    │  WSO2 access token                        │
```

WSO2 IS supports `private_key_jwt` client authentication (RFC 7523). You configure the M2M app to accept a JWT signed by the SPIRE server's private key instead of a `clientSecret`. The agent never holds a static secret — it gets a short-lived SVID from SPIRE and exchanges it for a WSO2 token.

This is the combination demonstrated across Phase 3 (SPIRE) and Phase 4 (WSO2) in this project. It works and we have the scripts for both halves.

**Verdict: Closeable by combining WSO2 + SPIRE. No custom code in WSO2 required — just configure `private_key_jwt` authentication and register the SPIRE JWKS endpoint. ~1 day of configuration.**

---

### Gap 4: Conditional Access Per Agent Type

**What Entra has:** CA policies can target `userType: servicePrincipal` and, with Frontier, specific blueprint types. Example: "Block all AI agents from accessing financial APIs unless they come from the approved `finance-agent-blueprint`."

**What WSO2 has:** Adaptive Authentication scripts (Ballerina/Groovy). Not as turnkey as Entra CA but functionally equivalent. WSO2 IS's adaptive auth can inspect any token claim or external signal and deny/challenge the authentication.

**Severity:** Low. The outcome (conditional grant/deny) is achievable in both platforms; the difference is configuration ease, not capability.

**Can it be closed?**

Trivially. In WSO2 adaptive authentication, add:

```javascript
// WSO2 Adaptive Authentication Script
// Applied per application or globally
function(context) {
  var agentType = context.request.params.agent_type;
  var blueprintId = context.request.params.blueprint_id;
  if (agentType === "ai_agent" && blueprintId !== "approved-finance-blueprint") {
    context.fail({ error: "unauthorized_agent_type" });
  }
}
```

Plus AIM's FGA `context_check` and `attribute_check` gates provide overlapping protection at the authorization layer (post-authentication).

**Verdict: Already closeable with existing WSO2 adaptive auth. Not a gap in capability, only in turnkey convenience.**

---

### Gap 5: Microsoft 365 / Azure Ecosystem Audit Breadcrumbs

**What Entra has:** When an Entra Agent Identity calls Microsoft Graph, the call appears in the Microsoft 365 Unified Audit Log with `ActorType: ServicePrincipal[AgentIdentity]`. This is automatic — no instrumentation required.

**What WSO2 has:** Nothing, because WSO2 doesn't touch Microsoft 365 at all. This is an ecosystem lock-in advantage, not a general IAM capability.

**Severity:** Only relevant if you are accessing Microsoft 365 APIs. For any other API, this gap doesn't exist.

**Can it be closed?**

Not in the same integrated way. You can achieve equivalent audit coverage by:
1. Enriching every Microsoft Graph request with a custom header (e.g. `X-Agent-Id`, `X-Blueprint-Id`)
2. Capturing Azure Monitor / App Insights telemetry from the calling agent
3. Correlating AIM's audit log (which has the agent's full decision trail) with Azure Monitor logs by `jti` or timestamp

It's more work than the Entra native integration but functionally equivalent for compliance purposes.

**Verdict: Not fully closeable in the same turnkey way. Acceptable workaround exists if M365 is your target ecosystem and you still want WSO2.**

---

## 2. Summary: Gap Severity and Closure Status

| Gap | Severity | Closeable? | How | Effort |
|---|---|---|---|---|
| Blueprint hierarchy / `fmi_path` | Medium | ✅ Yes | WSO2 custom claim transformer + role naming convention | ~1 week |
| OBO delegation chain (`act.sub`) | High (if user-delegated agents) | ✅ Yes (IS 7.1+) | Ballerina claim transformer; or app-layer via AIM FGA context | 2–3 weeks |
| FIC zero-secret auth | High (security hygiene) | ✅ Yes | SPIRE + WSO2 `private_key_jwt` federated auth | ~1 day config |
| Conditional Access per agent type | Low | ✅ Yes | WSO2 adaptive auth scripts | Hours |
| M365 native audit breadcrumbs | Low (M365-specific) | Partial | Custom headers + correlation via AIM audit log | 1–2 days |

**None of the Entra gaps are fundamental architectural blockers.** Every one of them can be closed with WSO2 IS + open-source tooling (SPIRE, AIM, Ballerina extensions) in a self-hosted stack. The trade-off is that Entra *ships the features turnkey*; WSO2 *gives you the building blocks to assemble them yourself*.

---

## 3. The AIM Factor: What Entra AND WSO2 Both Lack

Neither Entra Agent ID nor WSO2 Agent ID provides:
- **Per-operation FGA** (5-gate pipeline evaluating capability, attribute, context, delegation chain, intent)
- **Continuous trust scoring** (9-factor behavioral reputation, not just binary enabled/disabled)
- **Tamper-evident audit log** (hash-chain SHA-256, not just syslog)
- **Declared intent verification** (does the stated reason match the action?)

These are not gaps in WSO2 that Entra fills. They are gaps in **both** that only AIM addresses. The practical architecture for a production enterprise deployment is:

```
SPIRE                    WSO2 IS                     AIM
(Who are you?)    →      (Issue a token)       →     (What are you allowed to do?)
Workload          →      JWT access token      →     FGA decision
attestation              with blueprint_id           trust score
                         + act.sub claim             hash-chain audit
```

This three-layer stack covers everything Entra Agent ID offers (minus the M365 integration) and adds security depth that Entra does not provide.

---

## 4. The Honest Bottom Line

| Question | Answer |
|---|---|
| Can WSO2 replace Entra Agent ID? | Yes, for all non-Microsoft-365-specific agent deployments |
| Can WSO2 + SPIRE + AIM replace Entra Agent ID? | Yes, and with deeper per-operation security |
| Is the FIC zero-secret gap serious? | Yes — but SPIRE solves it exactly |
| Is the `act.sub` delegation gap serious? | Yes if user-delegated agents; no if fully autonomous |
| Is the blueprint hierarchy gap serious? | Only at fleet scale of hundreds+ agent types |
| Should you choose WSO2 over Entra for an Azure-native M365 stack? | No — use Entra; the native integration is worth it |
| Should you choose WSO2 for a multi-cloud or self-hosted stack? | Yes — it's the more flexible choice |
