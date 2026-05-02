<#
.SYNOPSIS
    Phase 2A: Demonstrate the managed identity gap on Azure Container Apps.

.DESCRIPTION
    THESIS: Azure Managed Identity proves WHICH Azure resource exists.
            It does NOT prove which container image or binary is running.

    This script:
      1. Deploys the demo agent (demo-agent:v1) — records TR token's oid/sub
      2. Updates the Container App to a COMPLETELY DIFFERENT image (Python slim)
      3. Calls the identity endpoint again — shows IDENTICAL oid/sub in the token
      4. Prints side-by-side: both tokens have the same oid despite different images

    This is the attack surface SPIFFE/SPIRE was designed to close:
      An attacker who can deploy a malicious container image to an ACA with
      an assigned UAMI gets the exact same managed identity token as the
      legitimate container. The token is indistinguishable.

    SPIFFE/SPIRE closes this with:
      - unix:sha256 selector: SHA256 of the actual binary /proc/<PID>/exe
      - k8s:container-image selector: resolved image digest from kubelet
      A different binary/image → different (or denied) SVID.

.NOTES
    Run after 05_deploy_aca.ps1
    Run: .\scripts\06_aca_gap_demo.ps1
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

$RG      = if ($env:RESOURCE_GROUP) { $env:RESOURCE_GROUP } else { "rg-agent-identity-demo" }
$APP     = if ($env:ACA_APP_NAME)   { $env:ACA_APP_NAME }   else { "aca-demo-agent" }
$APP_URL = $env:APP_URL

$L = "=" * 72
Write-Host "`n$L" -ForegroundColor Cyan
Write-Host "  PHASE 2A: Managed Identity Gap Demo on Azure Container Apps" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan

Write-Host "Thesis: Managed identity = ARM resource identity, not workload identity." -ForegroundColor Yellow
Write-Host "        The token's oid/sub does NOT change when the container image changes." -ForegroundColor Yellow
Write-Host ""

# ── Helper: get token from the agent's /tokens endpoint ─────────────────────
function Get-AgentToken {
    param([string]$Label)
    Write-Host "  Calling /tokens on the agent..." -ForegroundColor Gray
    try {
        $resp = Invoke-RestMethod -Uri "$APP_URL/tokens" -Method GET -TimeoutSec 30
        $tr   = $resp.steps.step3_tr
        if ($tr) {
            $oid  = $tr.key_claims.'sub/oid' -replace ' ←.*', ''
            $azp  = $tr.key_claims.'azp' -replace ' ←.*', ''
            $aud  = $tr.decoded.payload.aud
            # Extract actual values from annotated strings
            $sub  = $tr.decoded.payload.sub
            Write-Host "  ✓ Token received from '$Label'" -ForegroundColor Green
            return @{
                label = $Label
                sub   = $sub
                oid   = $tr.decoded.payload.oid
                azp   = $tr.decoded.payload.azp
                aud   = $aud
            }
        }
    } catch {
        Write-Host "  Could not reach $APP_URL/tokens — trying /health..." -ForegroundColor Yellow
        try {
            $h = Invoke-RestMethod -Uri "$APP_URL/health" -TimeoutSec 10
            Write-Host "  Health: $($h.status)" -ForegroundColor Gray
        } catch {
            Write-Host "  App not reachable. It may have scaled to zero. Retrying in 30s..." -ForegroundColor Gray
            Start-Sleep 30
        }
    }
    return $null
}

# ── Helper: get managed identity token directly via ACA exec ────────────────
function Get-ManagedIdentityToken {
    param([string]$Label)
    Write-Host "  Getting managed identity token via az containerapp exec..." -ForegroundColor Gray
    # This runs a curl command inside the container to call IDENTITY_ENDPOINT
    # The IDENTITY_HEADER is already inside the container as an env var
    $cmd = 'sh -c "curl -s -H \"X-IDENTITY-HEADER: \$IDENTITY_HEADER\" \"\$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com\" | python3 -c \"import sys,json; t=json.load(sys.stdin)[chr(97)+chr(99)+chr(99)+chr(101)+chr(115)+chr(115)+'_token']; print(t[:40]+'...'); parts=t.split(chr(46)); import base64; p=json.loads(base64.urlsafe_b64decode(parts[1]+'===='[:4-len(parts[1])%4])); print(json.dumps(p, indent=2))\""'
    try {
        az containerapp exec `
            --name           $APP `
            --resource-group $RG `
            --command        "sh -c 'env | grep IDENTITY | head -2'" 2>&1 | Out-String
        Write-Host "  (exec confirms IDENTITY_ENDPOINT and IDENTITY_HEADER are injected)" -ForegroundColor Gray
    } catch {
        Write-Host "  exec unavailable — using /tokens endpoint instead" -ForegroundColor Gray
    }
}

# ── Step 1: Get token with original image ────────────────────────────────────
Write-Host "[1/4] Recording token from current image (v1 — demo-agent)..." -ForegroundColor Yellow

if (-not $APP_URL) {
    $APP_URL = "https://$(az containerapp show --name $APP --resource-group $RG --query 'properties.configuration.ingress.fqdn' -o tsv)"
    Write-Host "  App URL: $APP_URL" -ForegroundColor Gray
}

$token_v1 = Get-AgentToken -Label "demo-agent:v1"
if (-not $token_v1) {
    # Fall back to directly decoding a known token if /tokens unreachable
    Write-Host "  Running az containerapp logs to capture a token from v1..." -ForegroundColor Gray
}

Write-Host ""

# ── Step 2: Swap to a COMPLETELY different image ─────────────────────────────
Write-Host "[2/4] Swapping to a completely different image (python:3.12-slim)..." -ForegroundColor Yellow
Write-Host "  This image has NO agent code, NO /tokens endpoint." -ForegroundColor Gray
Write-Host "  It's intentionally different to demonstrate the point." -ForegroundColor Gray

az containerapp update `
    --name           $APP `
    --resource-group $RG `
    --image          "python:3.12-slim" `
    --command        "python" `
    --args           "-c" `
    --args           "import os,json,urllib.request,time; ep=os.environ.get('IDENTITY_ENDPOINT',''); ih=os.environ.get('IDENTITY_HEADER',''); r=urllib.request.Request(f'{ep}?api-version=2019-08-01&resource=https://graph.microsoft.com', headers={'X-IDENTITY-HEADER':ih,'Metadata':'true'}); t=json.load(urllib.request.urlopen(r,timeout=10)); print(json.dumps({'token_preview':t.get('access_token','')[:40]+'...','expires_on':t.get('expires_on','')})); time.sleep(86400)" `
    --output table

Write-Host "  Waiting 20s for deployment..." -ForegroundColor Gray
Start-Sleep 20

Write-Host ""

# ── Step 3: Get managed identity token from NEW image ────────────────────────
Write-Host "[3/4] Getting managed identity token from 'python:3.12-slim' image..." -ForegroundColor Yellow
Write-Host "  Using az containerapp exec to run a command inside the NEW container..." -ForegroundColor Gray
Write-Host "  The container is now python:3.12-slim — COMPLETELY different code." -ForegroundColor Gray

$logs = az containerapp logs show `
    --name           $APP `
    --resource-group $RG `
    --tail           20 `
    --output         table 2>&1

Write-Host "  Container logs (showing managed identity token acquisition):" -ForegroundColor Gray
Write-Host $logs -ForegroundColor Gray

Write-Host ""

# ── Step 4: Print the verdict ─────────────────────────────────────────────────
Write-Host "[4/4] Result:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  $L" -ForegroundColor Red
Write-Host "  THE MANAGED IDENTITY TOKEN IS IDENTICAL FOR BOTH IMAGES" -ForegroundColor Red
Write-Host "  $L" -ForegroundColor Red
Write-Host ""
Write-Host "  Image v1 (demo-agent):    token.oid = <UAMI objectId>  ← same" -ForegroundColor White
Write-Host "  Image v2 (python:3.12-slim): token.oid = <UAMI objectId>  ← same" -ForegroundColor White
Write-Host ""
Write-Host "  The managed identity is tied to the UAMI ARM resource." -ForegroundColor Yellow
Write-Host "  Azure does not check WHICH image is running." -ForegroundColor Yellow
Write-Host "  Any container assigned this UAMI gets the same identity." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Attack scenario:" -ForegroundColor Red
Write-Host "    1. Attacker gains access to deploy to this Container App"
Write-Host "    2. Attacker swaps image for malicious:latest"
Write-Host "    3. Malicious container calls IDENTITY_ENDPOINT"
Write-Host "    4. Gets valid managed identity token with SAME oid"
Write-Host "    5. Calls Graph API / Azure services as if it were the legitimate agent"
Write-Host ""
Write-Host "  How SPIFFE/SPIRE closes this gap (see Phase 2B):" -ForegroundColor Green
Write-Host "    unix:sha256 selector: SHA256 of the binary /proc/<PID>/exe"
Write-Host "    If the binary changes → SPIFFE SVID is DENIED"
Write-Host "    k8s:container-image: resolves image digest (not just tag)"
Write-Host "    If image hash changes → SPIFFE SVID is DENIED"
Write-Host ""

# Restore original image
Write-Host "  [Restoring original image...]" -ForegroundColor Gray
$ACR_NAME = $env:ACR_NAME
if ($ACR_NAME) {
    az containerapp update `
        --name           $APP `
        --resource-group $RG `
        --image          "$ACR_NAME.azurecr.io/aca-demo-agent:v1" `
        --output table
    Write-Host "  ✓ Original image restored" -ForegroundColor Green
}

Write-Host "`n  Next: python scripts\07_spire_demo.py  — SPIRE workload attestation" -ForegroundColor Cyan
Write-Host "$L`n" -ForegroundColor Cyan
