# What Do You Lose Using a Traditional Managed Identity Per Container App?

*Concise analysis. Assumes one Azure Container App per AI agent, each with a User-Assigned or System-Assigned Managed Identity.*

---

## The Setup Being Compared

**Traditional approach:** Deploy Agent A in Container App A. Assign a Managed Identity. Grant it RBAC roles (e.g. `Storage Blob Data Reader`). That's the identity stack.

**Agent identity approach:** Same container, but identity is managed through Entra Agent ID, WSO2 + SPIRE, or AIM on top of the credential layer.

---

## What You Keep

A managed identity with RBAC still gives you:
- Passwordless credential issuance (no stored secrets) — this is the main win of managed identities
- Azure AD-issued JWT tokens, automatically rotated
- RBAC access control to Azure resources
- Basic Entra audit logs (who called what)

If your agent is a simple, single-purpose service — reads from a storage account, writes to a queue — this is probably fine.

---

## What You Lose

### 1. You cannot distinguish agents from services in audit logs

A managed identity produces a token with `idtyp: app` and an `oid`. The Entra unified audit log shows "service principal X called Graph endpoint Y." Across 50 container apps, those entries look identical to any other automated service call.

**What agent identity gives you:** `idtyp: app` + blueprint reference + `act.sub` (user in OBO flows). You can filter "show me everything any AI agent did" vs "show me what the billing ETL service did." With managed identities, you cannot make that distinction without external tagging conventions.

### 2. You cannot model "this agent acts on behalf of a user"

Managed identities cannot do OBO (On-Behalf-Of). If an agent needs to call Microsoft Graph with the user's permissions (read their calendar, send on their behalf), you need a delegated token flow. Managed identities only issue app-only tokens. You'd fall back to storing a user credential or service account — defeating the point.

**What agent identity gives you:** OBO produces a token with `sub` = the user, `act.sub` = the agent. The agent inherits the user's permissions for only the scopes the user consented to, and every call is attributed to both.

### 3. You get binary on/off — no per-operation authorization

RBAC says "this identity can read from this storage account." It does not say "this identity can read storage accounts only when the calling context is a read-only report generation task, not a bulk export."

There is no built-in mechanism to say "yes to this operation but no to that one, based on what the agent is trying to do right now."

**What agent identity gives you:** WSO2 OAuth scopes add per-resource granularity. AIM's FGA pipeline adds per-operation, per-context, per-intent granularity. You can deny `db:write` even if the agent has `db:read`, and you can deny `db:read` if the declared intent looks wrong.

### 4. You have no trust lifecycle — every agent is equally trusted from day one

A freshly deployed container app with a managed identity has exactly the same access as one that has been running correctly for a year. There is no history, no behavioral baseline, no reputation.

**What agent identity gives you:** AIM's trust score starts low (new agents score ~0.25 on `age`) and rises as the agent demonstrates reliable behavior. High-risk operations can be gated behind a minimum trust score. An agent that triggers security alerts drops instantly. You can enforce "no agent under 30 days old can call the payments API."

### 5. You have no fleet-level governance if agents are blueprinted

If you deploy 200 container apps all doing the same job (e.g. a customer service agent scaled with Container Apps replicas), each system-assigned managed identity is a separate Entra object with its own RBAC assignments. Revoking access means 200 separate operations.

**What agent identity gives you:** Entra Agent ID's blueprint→instance model lets you revoke the blueprint. WSO2 + a role-naming convention lets you batch-revoke all instances via a single SCIM query.

### 6. You cannot enforce "no agent may exceed N delegation hops"

With managed identities, if Agent A calls Agent B calls Agent C, each call is independently authorized. There is no cross-call chain validation. An attacker who compromises Agent B can call Agent C with full Agent B permissions, and there is no signal in the token that Agent C was reached through a chain.

**What agent identity gives you:** AIM's `chain_check` gate tracks the full delegation path. The FGA policy can say "deny if delegation depth > 2." The chain is validated at every hop.

### 7. You have no tamper-evident audit trail by default

Azure Monitor logs and Entra audit logs are tamper-evident at the Azure platform level (Microsoft controls it). But the application-layer logs your agent writes — what it decided, what tools it called, what it retrieved — are just flat log files. Anyone with storage write access can alter them.

**What agent identity gives you:** AIM's hash-chain audit log makes application-layer events tamper-evident. The chain can be independently verified by anyone with the log file — no Microsoft or WSO2 infrastructure required.

---

## Summary Table

| Capability | Managed Identity (traditional) | Agent Identity (modern) |
|---|---|---|
| No stored secrets | ✅ | ✅ |
| Agent vs service distinction in audit logs | ❌ | ✅ |
| User-delegated (OBO) token flow | ❌ | ✅ |
| Per-operation FGA | ❌ | ✅ (AIM) |
| Per-intent authorization | ❌ | ✅ (AIM) |
| Trust lifecycle / behavioral reputation | ❌ | ✅ (AIM) |
| Fleet-level revocation (blueprint model) | ❌ | ✅ (Entra / WSO2+convention) |
| Delegation chain depth enforcement | ❌ | ✅ (AIM chain_check) |
| App-layer tamper-evident audit | ❌ | ✅ (AIM hash-chain) |
| Azure-native integration | ✅ | ✅ (Entra) / requires setup (WSO2) |
| Works today without M365 Copilot license | ✅ | ✅ (WSO2 + AIM) |

---

## When Traditional Managed Identity Is Still Acceptable

Use a managed identity without agent identity tooling when:
- The agent is a **deterministic, single-purpose pipeline** (ETL, scheduled data sync) — not a general-purpose LLM that makes runtime decisions
- The agent **never acts on behalf of a user** — only app-to-app calls
- You have **≤10 agent instances** where fleet governance overhead doesn't justify additional tooling
- The agent accesses **only Azure-native resources** where RBAC granularity is sufficient
- Your security requirement is **perimeter-based** (network controls + RBAC), not behavior-based

## When You Should Move to Agent Identity

Add agent identity tooling when:
- Agents make **autonomous decisions** about what to access and when
- Agents act **on behalf of specific users**
- You need **per-operation audit trails** for compliance (SOC 2, ISO 27001, financial regulation)
- You are deploying **fleets of similar agents** that need central governance
- Your threat model includes **a compromised agent being used as a pivot point**
- The agent has access to **sensitive or regulated data** where knowing the *why* of each access matters
