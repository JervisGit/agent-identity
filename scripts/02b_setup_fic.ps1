<#
.SYNOPSIS
    Phase 1 (Path A): Configure the blueprint's Federated Identity Credential (FIC).

.DESCRIPTION
    A Federated Identity Credential (FIC) lets the blueprint app registration
    authenticate WITHOUT a stored client secret or certificate.

    Instead:
      1. The Blueprint is configured to TRUST tokens issued by Azure AD for the UAMI.
      2. When the agent calls IDENTITY_ENDPOINT, it gets a TUAMI (managed identity token).
      3. The TUAMI is presented as a 'client_assertion' to Azure AD token endpoint.
      4. Azure AD validates: "Does the blueprint trust tokens issued for this UAMI?"
      5. If yes → issues T1 (exchange token) with aud = Blueprint client ID.

    This is called Workload Identity Federation (WIF). It's the same mechanism used
    by GitHub Actions and Kubernetes workloads to authenticate to Azure without secrets.

    FIC configuration:
      - issuer:  https://login.microsoftonline.com/<tenant>/v2.0
      - subject: <UAMI objectId>  (the Entra object that issues TUAMI tokens)
      - audiences: ["api://AzureADTokenExchange"]  (the standard FIC exchange audience)

.NOTES
    Prereqs: az login, .env.local with BLUEPRINT_CLIENT_ID and UAMI_PRINCIPAL_ID
    Run:     .\scripts\02b_setup_fic.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Load .env.local ────────────────────────────────────────────────────────
if (Test-Path ".env.local") {
    Get-Content ".env.local" | ForEach-Object {
        if ($_ -match "^([^#=]+)=(.*)$") {
            [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
}

$TENANT_ID         = $env:AZURE_TENANT_ID
$BLUEPRINT_APP_ID  = $env:BLUEPRINT_CLIENT_ID   # The blueprint's appId (client ID)
$UAMI_PRINCIPAL_ID = $env:UAMI_PRINCIPAL_ID     # The UAMI's objectId in Entra (NOT clientId)

if (-not $BLUEPRINT_APP_ID) {
    Write-Host "ERROR: BLUEPRINT_CLIENT_ID not set in .env.local" -ForegroundColor Red
    Write-Host "       Run 01_verify_entra.ps1 first to discover the blueprint app ID." -ForegroundColor Red
    exit 1
}
if (-not $UAMI_PRINCIPAL_ID) {
    Write-Host "ERROR: UAMI_PRINCIPAL_ID not set in .env.local" -ForegroundColor Red
    Write-Host "       Run 02_setup_aca.ps1 first to create the UAMI." -ForegroundColor Red
    exit 1
}

$L = "=" * 72
Write-Host "`n$L" -ForegroundColor Cyan
Write-Host "  PHASE 1 (PATH A): Configure FIC on Blueprint App Registration" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan

Write-Host "Blueprint app ID:    $BLUEPRINT_APP_ID" -ForegroundColor White
Write-Host "UAMI principal ID:   $UAMI_PRINCIPAL_ID" -ForegroundColor White
Write-Host "Tenant ID:           $TENANT_ID" -ForegroundColor White
Write-Host ""

# ── What we're configuring ─────────────────────────────────────────────────
Write-Host "What this configures:" -ForegroundColor Yellow
Write-Host "  The blueprint app will TRUST managed identity tokens issued for UAMI."
Write-Host "  Specifically, Azure AD will accept a TUAMI where:"
Write-Host "    iss = https://login.microsoftonline.com/$TENANT_ID/v2.0"
Write-Host "    sub = $UAMI_PRINCIPAL_ID   (the UAMI's object ID)"
Write-Host "    aud = api://AzureADTokenExchange"
Write-Host "  ... as a client_assertion for the blueprint app."
Write-Host ""

# ── Build the FIC payload ──────────────────────────────────────────────────
$FIC_NAME   = "uami-fic-for-agent-demo"
$FIC_ISSUER = "https://login.microsoftonline.com/$TENANT_ID/v2.0"
$FIC_BODY   = @{
    name        = $FIC_NAME
    issuer      = $FIC_ISSUER
    subject     = $UAMI_PRINCIPAL_ID
    description = "FIC: blueprint trusts tokens for aim-demo-uami (for agent token flow demo)"
    audiences   = @("api://AzureADTokenExchange")
} | ConvertTo-Json -Depth 3

Write-Host "[1/3] Checking for existing FICs on the blueprint app..." -ForegroundColor Yellow

# Get blueprint object ID (needed for the app registration Graph API endpoint)
$blueprintApp = az ad app show --id $BLUEPRINT_APP_ID --output json | ConvertFrom-Json
$BLUEPRINT_OBJ_ID = $blueprintApp.id

$existingFICs = az rest `
    --method GET `
    --url "https://graph.microsoft.com/v1.0/applications/$BLUEPRINT_OBJ_ID/federatedIdentityCredentials" `
    --output json | ConvertFrom-Json

$existingFIC = $existingFICs.value | Where-Object { $_.name -eq $FIC_NAME }

if ($existingFIC) {
    Write-Host "  ✓ FIC '$FIC_NAME' already exists — skipping creation." -ForegroundColor Green
    Write-Host "    FIC ID: $($existingFIC.id)" -ForegroundColor Gray
} else {
    Write-Host "`n[2/3] Creating FIC on blueprint app registration..." -ForegroundColor Yellow
    Write-Host "  POST /v1.0/applications/$BLUEPRINT_OBJ_ID/federatedIdentityCredentials"
    Write-Host "  Body: $FIC_BODY" -ForegroundColor Gray

    $ficResult = az rest `
        --method POST `
        --url "https://graph.microsoft.com/v1.0/applications/$BLUEPRINT_OBJ_ID/federatedIdentityCredentials" `
        --body $FIC_BODY `
        --headers "Content-Type=application/json" `
        --output json | ConvertFrom-Json

    Write-Host "  ✓ FIC created:" -ForegroundColor Green
    Write-Host "    ID:       $($ficResult.id)" -ForegroundColor White
    Write-Host "    issuer:   $($ficResult.issuer)" -ForegroundColor White
    Write-Host "    subject:  $($ficResult.subject)" -ForegroundColor White
    Write-Host "    audience: $($ficResult.audiences -join ', ')" -ForegroundColor White
}

Write-Host "`n[3/3] Verifying FIC configuration by listing all FICs on blueprint..." -ForegroundColor Yellow
$allFICs = az rest `
    --method GET `
    --url "https://graph.microsoft.com/v1.0/applications/$BLUEPRINT_OBJ_ID/federatedIdentityCredentials" `
    --output json | ConvertFrom-Json

Write-Host "  FICs on blueprint app ($($allFICs.value.Count) total):" -ForegroundColor Green
foreach ($fic in $allFICs.value) {
    Write-Host "    $($fic.name)" -ForegroundColor White
    Write-Host "      issuer:   $($fic.issuer)" -ForegroundColor Gray
    Write-Host "      subject:  $($fic.subject)" -ForegroundColor Gray
    Write-Host "      audience: $($fic.audiences -join ', ')" -ForegroundColor Gray
}

Write-Host "`n$L" -ForegroundColor Cyan
Write-Host "  FIC SETUP COMPLETE" -ForegroundColor Cyan
Write-Host "$L" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Token flow is now configured:" -ForegroundColor White
Write-Host "  Container App → IDENTITY_ENDPOINT → TUAMI"
Write-Host "    sub: $UAMI_PRINCIPAL_ID"
Write-Host "    aud: api://AzureADTokenExchange"
Write-Host ""
Write-Host "  TUAMI + fmi_path → Blueprint app → T1"
Write-Host "    aud: $BLUEPRINT_APP_ID (blueprint client ID)"
Write-Host ""
Write-Host "  T1 → Agent Identity → TR (resource token)"
Write-Host "    sub/oid: <Agent Identity object ID>"
Write-Host ""
Write-Host "  Next: .\scripts\05_deploy_aca.ps1  — build and deploy the agent image" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan
