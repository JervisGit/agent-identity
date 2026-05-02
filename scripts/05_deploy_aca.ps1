<#
.SYNOPSIS
    Phase 1: Build the agent Docker image and deploy it to Azure Container Apps.

.NOTES
    Prereqs: Docker Desktop, az login, .env.local populated by earlier scripts.
    Run:     .\scripts\05_deploy_aca.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (Test-Path ".env.local") {
    Get-Content ".env.local" | ForEach-Object {
        if ($_ -match "^([^#=]+)=(.*)$") {
            [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
}

$RG               = if ($env:RESOURCE_GROUP)  { $env:RESOURCE_GROUP }  else { "rg-agent-identity-demo" }
$ACA_ENV          = if ($env:ACA_ENVIRONMENT) { $env:ACA_ENVIRONMENT } else { "aca-env-agent-identity" }
$ACA_APP          = if ($env:ACA_APP_NAME)    { $env:ACA_APP_NAME }    else { "aca-demo-agent" }
$TENANT_ID        = $env:AZURE_TENANT_ID
$BLUEPRINT_ID     = $env:BLUEPRINT_CLIENT_ID
$AGENT_ID         = $env:AGENT_IDENTITY_ID
$UAMI_CLIENT_ID   = $env:UAMI_CLIENT_ID
$UAMI_RESOURCE_ID = $env:UAMI_RESOURCE_ID

$L = "=" * 72
Write-Host "`n$L" -ForegroundColor Cyan
Write-Host "  PHASE 1: Build + Deploy ACA Agent" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan

# ── Strategy: use ACR or build+push with az acr ─────────────────────────────
# For free-tier: Azure Container Registry Basic is ~$5/month. To avoid cost,
# we use docker build + az acr login + push to a newly created ACR.
# Alternatively, we use the az containerapp update --source flag for source-to-cloud.

Write-Host "[1/3] Building agent image using 'az acr build' (source-to-cloud)..." -ForegroundColor Yellow
Write-Host "  This avoids needing a local Docker daemon — builds happen in Azure." -ForegroundColor Gray
Write-Host "  Note: ACR Basic is ~`$5/month — only create if you don't already have one." -ForegroundColor Gray

$ACR_NAME = if ($env:ACR_NAME) { $env:ACR_NAME } else { "acragent$((Get-Random -Maximum 9999).ToString())" }

# Create ACR if it doesn't exist
$acrExists = az acr show --name $ACR_NAME --resource-group $RG 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Creating ACR '$ACR_NAME'..." -ForegroundColor Gray
    az acr create `
        --name           $ACR_NAME `
        --resource-group $RG `
        --sku            Basic `
        --admin-enabled  true `
        --output         table
    Write-Host "  ✓ ACR created" -ForegroundColor Green
} else {
    Write-Host "  ✓ ACR '$ACR_NAME' already exists" -ForegroundColor Green
}

# Build and push image using ACR Tasks (no local Docker needed)
Write-Host "`n[2/3] Building image via ACR Tasks (runs in Azure, ~2 min)..." -ForegroundColor Yellow
$IMAGE_TAG = "v1"
$FULL_IMAGE = "$ACR_NAME.azurecr.io/aca-demo-agent:$IMAGE_TAG"

az acr build `
    --registry       $ACR_NAME `
    --image          "aca-demo-agent:$IMAGE_TAG" `
    --file           "agents/aca_agent/Dockerfile" `
    agents/aca_agent/

Write-Host "  ✓ Image pushed to: $FULL_IMAGE" -ForegroundColor Green

# Grant ACA permission to pull from ACR
Write-Host "`n  Granting Container App permission to pull from ACR..." -ForegroundColor Gray
$ACR_ID = az acr show --name $ACR_NAME --resource-group $RG --query id -o tsv
$UAMI_ID = az identity show --name "aim-demo-uami" --resource-group $RG --query principalId -o tsv

az role assignment create `
    --assignee        $UAMI_ID `
    --role            "AcrPull" `
    --scope           $ACR_ID `
    --output none
Write-Host "  ✓ UAMI granted AcrPull on ACR" -ForegroundColor Green

# ── Deploy to ACA ─────────────────────────────────────────────────────────
Write-Host "`n[3/3] Updating Container App with agent image and environment variables..." -ForegroundColor Yellow
Write-Host "  Environment variables passed to the agent:" -ForegroundColor Gray
Write-Host "    AZURE_TENANT_ID:      $TENANT_ID" -ForegroundColor Gray
Write-Host "    BLUEPRINT_CLIENT_ID:  $BLUEPRINT_ID" -ForegroundColor Gray
Write-Host "    AGENT_IDENTITY_ID:    $AGENT_ID" -ForegroundColor Gray
Write-Host "    UAMI_CLIENT_ID:       $UAMI_CLIENT_ID" -ForegroundColor Gray
Write-Host "  Note: IDENTITY_ENDPOINT and IDENTITY_HEADER are injected automatically" -ForegroundColor Gray
Write-Host "  by the ACA platform — the agent code reads them from environment at runtime." -ForegroundColor Gray

az containerapp update `
    --name             $ACA_APP `
    --resource-group   $RG `
    --image            $FULL_IMAGE `
    --registry-server  "$ACR_NAME.azurecr.io" `
    --registry-identity $env:UAMI_RESOURCE_ID `
    --set-env-vars `
        "AZURE_TENANT_ID=$TENANT_ID" `
        "BLUEPRINT_CLIENT_ID=$BLUEPRINT_ID" `
        "AGENT_IDENTITY_ID=$AGENT_ID" `
        "UAMI_CLIENT_ID=$UAMI_CLIENT_ID" `
        "RESOURCE_SCOPE=https://graph.microsoft.com/.default" `
    --output table

# Get the app URL
$APP_URL = az containerapp show `
    --name           $ACA_APP `
    --resource-group $RG `
    --query          "properties.configuration.ingress.fqdn" `
    --output         tsv

Write-Host "`n  ✓ Agent deployed!" -ForegroundColor Green
Write-Host "    URL: https://$APP_URL" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Test the token exchange:" -ForegroundColor White
Write-Host "    curl https://$APP_URL/health" -ForegroundColor Gray
Write-Host "    curl https://$APP_URL/tokens | python scripts\decode_jwt.py" -ForegroundColor Gray

"APP_URL=https://$APP_URL" | Add-Content -Path ".env.local"

Write-Host "`n  Next: python scripts\04_obo_flow.py  — OBO flow demo" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan
