<#
.SYNOPSIS
    Phase 0: Verify Azure Entra Agent ID access and determine Path A vs Path B.

.DESCRIPTION
    PATH A = M365 Copilot + Frontier → full blueprint / fmi_path token flow.
    PATH B = standard subscription → service principal simulation (same token anatomy,
             T1 middle layer explained conceptually).

    What happened May 1 2026:
      - The "Agent Registry" and "Agent Collections" blades in the Entra admin center
        were RETIRED today. Microsoft Agent 365 (admin.microsoft.com) is now the sole
        management plane. Entra Agent ID itself REMAINS IN PREVIEW.
      - M365 Copilot + Frontier license is still required for blueprint features.
      - The old registry Graph API is deprecated; use the new Agent 365-backed API.

    Output: writes discovered tenant/app IDs to .env.local for use by later scripts.

.NOTES
    Prereq: az login
    Run:    .\scripts\01_verify_entra.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$L = "=" * 72

function Write-Header($text) {
    Write-Host "`n$L" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "$L`n" -ForegroundColor Cyan
}

function Write-Step($n, $total, $text) {
    Write-Host "[$n/$total] $text" -ForegroundColor Yellow
}

function Write-Ok($text)   { Write-Host "  ✓ $text" -ForegroundColor Green }
function Write-Warn($text) { Write-Host "  ! $text" -ForegroundColor DarkYellow }
function Write-Info($text) { Write-Host "  $text"   -ForegroundColor Gray }

Write-Header "PHASE 0: Verify Azure Entra Agent ID Access"

# ── 1. Current account ────────────────────────────────────────────────────────
Write-Step 1 5 "Getting current Azure account..."
$account = az account show | ConvertFrom-Json
Write-Ok "Subscription: $($account.name)  ($($account.id))"
Write-Ok "Tenant ID:    $($account.tenantId)"
Write-Ok "User:         $($account.user.name)"

$TENANT_ID = $account.tenantId
$SUBSCRIPTION_ID = $account.id
$PATH_DECISION = "B"  # default; overridden below if Graph API succeeds

# ── 2. App registrations (blueprints) ────────────────────────────────────────
Write-Step 2 5 "Listing app registrations you own (looking for blueprints)..."
$apps = az ad app list --show-mine --output json | ConvertFrom-Json
Write-Info "Found $($apps.Count) app registration(s):"

$blueprintApp = $null
foreach ($app in $apps) {
    $isAgent = $app.displayName -match "blueprint|agent|aim" -and $app.displayName -notmatch "copilot"
    $marker  = if ($isAgent) { "  ← potential blueprint" } else { "" }
    $color   = if ($isAgent) { "Cyan" } else { "Gray" }
    Write-Host "    $($app.displayName)  (appId: $($app.appId))$marker" -ForegroundColor $color
    if ($isAgent -and -not $blueprintApp) { $blueprintApp = $app }
}

# ── 3. Service principals (agent identities) ─────────────────────────────────
Write-Step 3 5 "Looking for agent identity service principals..."
$spList   = az ad sp list --show-mine --output json | ConvertFrom-Json
$agentSPs = @($spList | Where-Object { $_.displayName -match "agent|blueprint" })

if ($agentSPs.Count -gt 0) {
    Write-Ok "Found agent-related service principals:"
    foreach ($sp in $agentSPs) {
        Write-Host "    $($sp.displayName)" -ForegroundColor White
        Write-Info "      appId:    $($sp.appId)"
        Write-Info "      objectId: $($sp.id)"

        # Key diagnostic: Agent Identity objects have appId == objectId.
        # Regular service principals always have appId != objectId.
        if ($sp.appId -eq $sp.id) {
            Write-Host "      *** appId == objectId → Confirmed Entra Agent Identity object ***" -ForegroundColor Cyan
            Write-Info "          (This uniquely identifies Agent Identity SPs vs regular SPs)"
        }
    }
} else {
    Write-Warn "No agent-related service principals found under your ownership."
}

# ── 4. Test Graph API /agentIdentities (M365 Copilot + Frontier gate) ────────
Write-Step 4 5 "Testing Graph API /agentIdentities endpoint..."
Write-Warn "NOTE: Entra Agent ID is still in PREVIEW as of May 1 2026."
Write-Warn "      The Agent Registry/Collections blades were retired TODAY."
Write-Warn "      Agent 365 (admin.microsoft.com) is now the sole management plane."
Write-Warn "      M365 Copilot + Frontier license still required."

$agentIdentitiesJson = $null
try {
    $raw = az rest --method GET `
        --url "https://graph.microsoft.com/v1.0/agentIdentities" `
        --headers "ConsistencyLevel=eventual" 2>&1

    # az rest returns a non-zero exit code on HTTP errors
    if ($LASTEXITCODE -ne 0 -or $raw -match '"error"') {
        throw $raw
    }

    $agentIdentitiesJson = $raw | ConvertFrom-Json
    $count = if ($agentIdentitiesJson.value) { $agentIdentitiesJson.value.Count } else { 0 }
    Write-Ok "Graph API returned 200 OK — PATH A (Full Entra Agent ID) is AVAILABLE"
    Write-Ok "Agent identity objects found: $count"
    $PATH_DECISION = "A"

    if ($count -gt 0) {
        Write-Host "`n  Agent Identity objects:" -ForegroundColor Cyan
        foreach ($ai in $agentIdentitiesJson.value) {
            $name = if ($ai.displayName) { $ai.displayName } else { $ai.id }
            Write-Host "    - $name" -ForegroundColor White
            Write-Info "        id:          $($ai.id)"
            Write-Info "        blueprintId: $(if ($ai.blueprintId) { $ai.blueprintId } else { 'n/a' })"
            Write-Info "        sponsor:     $(if ($ai.sponsor) { $ai.sponsor.userId } else { 'n/a' })"
        }
    }
}
catch {
    $err = $_ | Out-String
    if ($err -match "403|Forbidden") {
        Write-Warn "Graph API returned 403 — PATH B (Service Principal simulation)"
        Write-Warn "Tenant does not have M365 Copilot + Frontier, OR the API endpoint"
        Write-Warn "has moved post-retirement. Check admin.microsoft.com for Agent 365."
    } elseif ($err -match "404") {
        Write-Warn "Graph API returned 404 — PATH B (Service Principal simulation)"
        Write-Warn "The /agentIdentities v1.0 endpoint may have changed with the May 1"
        Write-Warn "retirement. Try: https://graph.microsoft.com/beta/agentIdentities"
        # Attempt beta fallback
        try {
            $rawBeta = az rest --method GET `
                --url "https://graph.microsoft.com/beta/agentIdentities" 2>&1
            if ($LASTEXITCODE -eq 0 -and $rawBeta -notmatch '"error"') {
                Write-Ok "Beta endpoint succeeded — PATH A available via beta Graph API"
                $PATH_DECISION = "A"
            }
        } catch { }
    } else {
        Write-Warn "Unexpected error querying agentIdentities: check permissions."
        Write-Warn $err.Substring(0, [Math]::Min(200, $err.Length))
    }
}

# ── 5. Write .env.local ───────────────────────────────────────────────────────
Write-Step 5 5 "Writing discovered values to .env.local..."

$envLines = @(
    "# Auto-generated by 01_verify_entra.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    "AZURE_TENANT_ID=$TENANT_ID"
    "AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID"
    "PATH_DECISION=$PATH_DECISION"
)

if ($blueprintApp) {
    $envLines += "BLUEPRINT_CLIENT_ID=$($blueprintApp.appId)"
    $envLines += "BLUEPRINT_APP_OBJECT_ID=$($blueprintApp.id)"
}

if ($agentSPs.Count -gt 0) {
    $envLines += "AGENT_IDENTITY_ID=$($agentSPs[0].id)"
    $envLines += "AGENT_IDENTITY_CLIENT_ID=$($agentSPs[0].appId)"
}

$envLines -join "`n" | Out-File -FilePath ".env.local" -Encoding utf8
Write-Ok "Written to .env.local"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Header "PHASE 0 SUMMARY"
Write-Host "  Tenant ID:  $TENANT_ID" -ForegroundColor White
Write-Host "  Path:       $PATH_DECISION" -ForegroundColor $(if ($PATH_DECISION -eq "A") { "Green" } else { "Yellow" })

if ($PATH_DECISION -eq "A") {
    Write-Host "`n  Next steps (PATH A — Full Entra Agent ID):" -ForegroundColor Cyan
    Write-Host "    1. .\scripts\02_setup_aca.ps1   — create UAMI + Container App"
    Write-Host "    2. .\scripts\02b_setup_fic.ps1  — configure FIC on blueprint"
    Write-Host "    3. .\scripts\05_deploy_aca.ps1  — build & deploy agent image"
    Write-Host "    4. GET https://<aca-url>/tokens  — observe TUAMI → T1 → TR flow"
} else {
    Write-Host "`n  Next steps (PATH B — Service Principal simulation):" -ForegroundColor Yellow
    Write-Host "    1. python scripts\03_get_tokens.py   — client_credentials → TR token"
    Write-Host "    2. python scripts\04_obo_flow.py     — OBO flow → delegated token with act claim"
    Write-Host ""
    Write-Host "  PATH B teaches identical token anatomy to PATH A." -ForegroundColor Gray
    Write-Host "  The T1 middle layer (fmi_path + blueprint impersonation) is" -ForegroundColor Gray
    Write-Host "  explained with inline comments and the protocol spec in the scripts." -ForegroundColor Gray
}
Write-Host "$L`n" -ForegroundColor Cyan
