#Requires -Version 5.1
<#
.SYNOPSIS
  End-to-end demo checks for LAB SOC n8n + Splunk pipeline (portfolio).
#>
$ErrorActionPreference = "Stop"
$Reports = "C:\lab\data\soc-reports"
$Triage = "C:\lab\data\alerts-triage-inbox"
New-Item -ItemType Directory -Force -Path $Reports, $Triage | Out-Null

Write-Host "=== 1) TI Dispatcher webhook (IP) ===" -ForegroundColor Cyan
try {
  $html = Invoke-WebRequest -Uri "http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8" -UseBasicParsing -TimeoutSec 60
  if ($html.Content -match "LAB IP Reputation|ip-api|8\.8\.8\.8") {
    Write-Host "OK Dispatcher returned HTML report ($($html.Content.Length) bytes)" -ForegroundColor Green
  } else {
    Write-Warning "Unexpected HTML body. Is LAB - TI Dispatcher active?"
    Write-Host $html.Content.Substring(0, [Math]::Min(300, $html.Content.Length))
  }
} catch {
  Write-Warning "Dispatcher failed: $($_.Exception.Message)"
  Write-Host "Activate workflow 'LAB - TI Dispatcher' in n8n UI, then re-run."
}

Write-Host "=== 2) Sample triage open event ===" -ForegroundColor Cyan
& "$PSScriptRoot\alert-triage-sample.ps1"

Write-Host "=== 3) Close Alert webhook ===" -ForegroundColor Cyan
$sample = Get-ChildItem $Triage -Filter "sample-open-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($sample) {
  $obj = Get-Content $sample.FullName -Raw | ConvertFrom-Json
  $body = @{ alert_id = $obj.alert_id; owner = "demo" } | ConvertTo-Json -Compress
  try {
    $close = Invoke-RestMethod -Uri "http://localhost:5678/webhook/lab-close" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30
    Write-Host "OK Close: $($close | ConvertTo-Json -Compress)" -ForegroundColor Green
  } catch {
    Write-Warning "Close webhook failed: $($_.Exception.Message) (activate LAB - Close Alert)"
  }
} else {
  Write-Warning "No sample-open file found"
}

Write-Host "=== 4) Write demo SOC report (Dispatcher IP + CVE) ===" -ForegroundColor Cyan
$alertId = "demo-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
$triagePath = Join-Path $Triage ("open-" + $alertId + ".json")
$triageJson = (@{
  alert_id = $alertId
  status = "open"
  source_id = 41
  log_name = "System"
  level = "Errore"
  message = "Demo Kernel-Power unexpected shutdown. Related host 8.8.8.8 CVE-2021-44228"
  opened_at = (Get-Date).ToUniversalTime().ToString("o")
  closed_at = $null
  owner = $null
  iocs = @{ ip = "8.8.8.8"; cve = "CVE-2021-44228" }
} | ConvertTo-Json -Depth 5 -Compress)
Set-Content -Path $triagePath -Value $triageJson -Encoding UTF8
try {
  $ipHtml = (Invoke-WebRequest -Uri "http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8" -UseBasicParsing -TimeoutSec 60).Content
  $cveHtml = (Invoke-WebRequest -Uri "http://localhost:5678/webhook/lab-reputation?cve=CVE-2021-44228" -UseBasicParsing -TimeoutSec 60).Content
  $report = @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>$alertId</title></head>
<body style="font-family:sans-serif;background:#0f1419;color:#e7ecf3;padding:2rem">
<h1>Demo SOC Report</h1><p>$alertId</p>
<pre>Demo Kernel-Power unexpected shutdown. Related host 8.8.8.8 CVE-2021-44228</pre>
<hr/>$ipHtml<hr/>$cveHtml
</body></html>
"@
  $out = Join-Path $Reports ($alertId + ".html")
  Set-Content -Path $out -Value $report -Encoding UTF8
  Write-Host "OK Report: $out ($((Get-Item $out).Length) bytes)" -ForegroundColor Green
} catch {
  Write-Warning "Report generation failed: $($_.Exception.Message)"
}

Write-Host "=== 5) Inventory ===" -ForegroundColor Cyan
Write-Host "Triage files: $((Get-ChildItem $Triage -File -ErrorAction SilentlyContinue).Count)"
Write-Host "Reports: $((Get-ChildItem $Reports -File -ErrorAction SilentlyContinue).Count)"
Get-ChildItem $Reports -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 5 Name, Length, LastWriteTime

Write-Host ""
Write-Host "Demo checklist done. Portfolio docs: soc-automation-hub/docs/lab-n8n/" -ForegroundColor Green
Write-Host "Optional in n8n UI: Execute 'LAB - Manual Demo Pipeline' (writes report from inside the container)."
