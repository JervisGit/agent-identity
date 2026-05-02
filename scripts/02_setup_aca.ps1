<#
.SYNOPSIS
    Phase 1 (Path A): Create Azure resources for the Entra Agent ID token flow demo.

.DESCRIPTION
    Creates (all in free tier / minimal cost):
      • Resource Group
      • User-Assigned Managed Identity (UAMI) — used as the blueprint's FIC credential
      • Azure Container Apps Environment (Consumption plan)
      • Azure Container App — hosts the demo Python agent

    The UAMI is then assigned to the Container App so the agent can call:
        $IDENTITY_ENDPOINT?resource=api://AzureADTokenExchange&client_id=<UAMI_CLIENT_ID>
    to get the TUAMI (Step 1 of the 3-step token exchange).

    Cost: Resource Group = free. UAMI = free. ACA Consumption = free tier
    (180k vCPU-s and 360k GiB-s free per subscription per month; scales to zero).

.NOTES
    Prereqs: az login, az extension add --name containerapp
    Run:     .\scripts\02_setup_aca.ps1
    After:   Run .\scripts\02b_setup_fic.ps1 to link UAMI to the blueprint via FIC.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Load .env.local if present ─────────────────────────────────────────────
if (Test-Path ".env.local") {
    Get-Content ".env.local" | ForEach-Object {
        if ($_ -match "^([^#=]+)=(.*)$") {
            [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
    Write-Host "Loaded .env.local" -ForegroundColor Gray
}

# ── Configuration — override via .env.local ────────────────────────────────
$TENANT_ID       = $env:AZURE_TENANT_ID
$SUBSCRIPTION_ID = $env:AZURE_SUBSCRIPTION_ID
$RG              = if ($env:RESOURCE_GROUP)   { $env:RESOURCE_GROUP }   else { "rg-agent-identity-demo" }
$LOCATION        = if ($env:ACA_LOCATION)     { $env:ACA_LOCATION }     else { "eastus" }
$ACA_ENV         = if ($env:ACA_ENVIRONMENT)  { $env:ACA_ENVIRONMENT }  else { "aca-env-agent-identity" }
$ACA_APP         = if ($env:ACA_APP_NAME)     { $env:ACA_APP_NAME }     else { "aca-demo-agent" }
$UAMI_NAME       = "aim-demo-uami"

$L = "=" * 72
Write-Host "`n$L" -ForegroundColor Cyan
Write-Host "  PHASE 1 (PATH A): Azure Container Apps Setup" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan

# ── 1. Resource Group ──────────────────────────────────────────────────────
Write-Host "[1/5] Creating resource group '$RG' in $LOCATION..." -ForegroundColor Yellow
az group create `
    --name        $RG `
    --location    $LOCATION `
    --output      table
Write-Host "  ✓ Resource group ready" -ForegroundColor Green

# ── 2. User-Assigned Managed Identity ─────────────────────────────────────
Write-Host "`n[2/5] Creating User-Assigned Managed Identity '$UAMI_NAME'..." -ForegroundColor Yellow
Write-Host "  A UAMI is a standalone Azure identity you can assign to any resource." -ForegroundColor Gray
Write-Host "  It will become the blueprint's Federated Identity Credential (FIC)." -ForegroundColor Gray
Write-Host "  The UAMI provides a token (TUAMI) that the blueprint exchanges for T1." -ForegroundColor Gray

$uami = az identity create `
    --name               $UAMI_NAME `
    --resource-group     $RG `
    --location           $LOCATION `
    --output             json | ConvertFrom-Json

Write-Host "  ✓ UAMI created:" -ForegroundColor Green
Write-Host "    clientId:     $($uami.clientId)" -ForegroundColor White
Write-Host "    principalId:  $($uami.principalId)" -ForegroundColor White
Write-Host "    resourceId:   $($uami.id)" -ForegroundColor White

$UAMI_CLIENT_ID   = $uami.clientId
$UAMI_PRINCIPAL_ID = $uami.principalId
$UAMI_RESOURCE_ID = $uami.id

# ── 3. Install containerapp extension if needed ────────────────────────────
Write-Host "`n[3/5] Ensuring 'containerapp' CLI extension is installed..." -ForegroundColor Yellow
az extension add --name containerapp --upgrade --output none 2>$null
Write-Host "  ✓ containerapp extension ready" -ForegroundColor Green

# ── 4. Container Apps Environment ─────────────────────────────────────────
Write-Host "`n[4/5] Creating Container Apps Environment '$ACA_ENV'..." -ForegroundColor Yellow
Write-Host "  Using Consumption workload profile (free tier: scales to zero)." -ForegroundColor Gray
Write-Host "  Important: ACA injects IDENTITY_ENDPOINT + IDENTITY_HEADER env vars" -ForegroundColor Gray
Write-Host "  when a UAMI is assigned. This is NOT the raw IMDS endpoint (169.254.169.254)." -ForegroundColor Gray
Write-Host "  It is a platform proxy that enforces SSRF protection via IDENTITY_HEADER." -ForegroundColor Gray

az containerapp env create `
    --name             $ACA_ENV `
    --resource-group   $RG `
    --location         $LOCATION `
    --output           table
Write-Host "  ✓ Container Apps Environment ready" -ForegroundColor Green

# ── 5. Container App (placeholder image, UAMI assigned) ───────────────────
Write-Host "`n[5/5] Creating Container App '$ACA_APP' with UAMI identity..." -ForegroundColor Yellow
Write-Host "  Using mcr.microsoft.com/k8se/quickstart as placeholder." -ForegroundColor Gray
Write-Host "  The real agent image will be deployed by 05_deploy_aca.ps1." -ForegroundColor Gray
Write-Host "  The UAMI must be assigned at creation or before the agent code runs." -ForegroundColor Gray

az containerapp create `
    --name              $ACA_APP `
    --resource-group    $RG `
    --environment       $ACA_ENV `
    --image             "mcr.microsoft.com/k8se/quickstart:latest" `
    --target-port       8000 `
    --ingress           external `
    --cpu               0.25 `
    --memory            "0.5Gi" `
    --min-replicas      0 `
    --max-replicas      1 `
    --user-assigned     $UAMI_RESOURCE_ID `
    --env-vars          "UAMI_CLIENT_ID=$UAMI_CLIENT_ID" `
    --output            table

Write-Host "  ✓ Container App created and UAMI assigned" -ForegroundColor Green
Write-Host "  Verifying identity assignment..." -ForegroundColor Gray

$identityInfo = az containerapp identity show `
    --name           $ACA_APP `
    --resource-group $RG `
    --output json | ConvertFrom-Json

if ($identityInfo.userAssignedIdentities) {
    Write-Host "  ✓ UAMI confirmed on Container App" -ForegroundColor Green
} else {
    Write-Host "  ✗ UAMI assignment not confirmed — check portal" -ForegroundColor Red
}

# ── Update .env.local with new values ─────────────────────────────────────
$envAppend = @"

# Written by 02_setup_aca.ps1
RESOURCE_GROUP=$RG
ACA_ENVIRONMENT=$ACA_ENV
ACA_APP_NAME=$ACA_APP
UAMI_CLIENT_ID=$UAMI_CLIENT_ID
UAMI_PRINCIPAL_ID=$UAMI_PRINCIPAL_ID
UAMI_RESOURCE_ID=$UAMI_RESOURCE_ID
"@
$envAppend | Add-Content -Path ".env.local" -Encoding utf8
Write-Host "`n  ✓ .env.local updated with UAMI and ACA values" -ForegroundColor Green

Write-Host "`n$L" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE" -ForegroundColor Cyan
Write-Host "$L" -ForegroundColor Cyan
Write-Host "  RG:               $RG" -ForegroundColor White
Write-Host "  UAMI client ID:   $UAMI_CLIENT_ID" -ForegroundColor White
Write-Host "  ACA Environment:  $ACA_ENV" -ForegroundColor White
Write-Host "  Container App:    $ACA_APP" -ForegroundColor White
Write-Host "`n  Next: .\scripts\02b_setup_fic.ps1  — attach UAMI to blueprint via FIC" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan
