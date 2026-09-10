#Requires -Version 5.1
<#
.SYNOPSIS
  Chiude un alert nel triage Splunk scrivendo un evento JSON status=closed.
.EXAMPLE
  .\alert-close.ps1 -AlertId "20260831-143022-T41-System" -Owner "feded"
#>
param(
  [Parameter(Mandatory = $true)]
  [string]$AlertId,
  [string]$Owner = $env:USERNAME,
  [string]$Inbox = "C:\lab\data\alerts-triage-inbox"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Inbox | Out-Null

$now = (Get-Date).ToUniversalTime().ToString("o")
$row = [ordered]@{
  alert_id   = $AlertId
  status     = "closed"
  closed_at  = $now
  owner      = $Owner
  opened_at  = $null
  message    = "Closed via alert-close.ps1"
}
$out = Join-Path $Inbox ("close-{0}-{1}.json" -f $AlertId, (Get-Date -Format "yyyyMMdd-HHmmss"))
($row | ConvertTo-Json -Compress) | Set-Content -Path $out -Encoding UTF8
Write-Host "Wrote closed event: $out"
Write-Host "Splunk index alerts_triage will pick it up within ~1 min."
