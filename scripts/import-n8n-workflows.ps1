#Requires -Version 5.1
<#
.SYNOPSIS
  Import LAB SOC n8n workflows from C:\lab\exports\n8n-workflows into lab_n8n.
.NOTES
  Requires lab up. First-time n8n may need owner account created in UI.
#>
param(
  [string]$WorkflowsDir = "C:\lab\exports\n8n-workflows",
  [switch]$Activate
)

$ErrorActionPreference = "Stop"

$running = docker ps --filter "name=lab_n8n" --format "{{.Names}}" 2>$null
if ($running -ne "lab_n8n") {
  Write-Error "lab_n8n is not running. Start with C:\lab\lab-up.ps1"
}

$files = @(
  "LAB-TI-Dispatcher.json",
  "LAB-IP-Reputation.json",
  "LAB-Domain-Reputation.json",
  "LAB-Hash-Reputation.json",
  "LAB-CVE-Info.json",
  "LAB-Close-Alert.json",
  "LAB-Manual-Demo-Pipeline.json",
  "LAB-Splunk-Warning-Poller.json"
)

Write-Host "Importing workflows into lab_n8n..." -ForegroundColor Cyan
foreach ($f in $files) {
  $src = Join-Path $WorkflowsDir $f
  if (-not (Test-Path $src)) {
    Write-Warning "Missing $src"
    continue
  }
  docker cp $src "lab_n8n:/tmp/$f" | Out-Null
  $out = docker exec lab_n8n n8n import:workflow --input="/tmp/$f" 2>&1 | Out-String
  Write-Host ("  {0} : {1}" -f $f, $out.Trim())
}

Write-Host ""
Write-Host "Publishing webhook/schedule workflows..." -ForegroundColor Cyan
$list = docker exec lab_n8n n8n list:workflow 2>$null
$publishNames = @(
  "LAB - TI Dispatcher",
  "LAB - Close Alert",
  "LAB - Splunk Warning Poller"
)
foreach ($line in $list) {
  if ($line -notmatch '^([a-f0-9]+)\|(.+)$') { continue }
  $id = $Matches[1]
  $name = $Matches[2].Trim()
  if ($publishNames -contains $name) {
    docker exec lab_n8n n8n publish:workflow --id=$id 2>&1 | Out-Host
  }
}

Write-Host "Restarting n8n so published workflows take effect..." -ForegroundColor DarkGray
docker restart lab_n8n | Out-Null
Start-Sleep -Seconds 12

Write-Host ""
Write-Host "Import done." -ForegroundColor Green
Write-Host "Open http://localhost:5678 - workflows should be published/active."
Write-Host "Test:"
Write-Host "  http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8"
Write-Host "  powershell -File C:\lab\scripts\demo-soc-pipeline.ps1"
