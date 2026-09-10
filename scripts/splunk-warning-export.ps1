#Requires -Version 5.1
<#
.SYNOPSIS
  Bridge for Splunk Free: run Warning+ search via docker exec and write JSONL for n8n.
  Splunk Free disables remote REST login; this host-side export keeps the demo honest.
#>
param(
  [string]$OutFile = "C:\lab\data\n8n-state\warning-plus.jsonl",
  [string]$Earliest = "-24h"
)

$ErrorActionPreference = "Continue"
$pw = ((Get-Content C:\lab\secrets\.env | Where-Object { $_ -match '^SPLUNK_PASSWORD=' }) -replace '^SPLUNK_PASSWORD=', '').Trim()
if (-not $pw) {
  Write-Error "SPLUNK_PASSWORD missing in C:\lab\secrets\.env"
}

$spl = 'index=main sourcetype=_json (Level="Avviso" OR Level="Warning" OR Level="Errore" OR Level="Error" OR Level="Critico" OR Level="Critical") | head 50 | table TimeCreated, LogName, Id, ProviderName, Level, Message'

New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null

# Run inside container; capture stdout only. Splunk prints TLS warnings on stderr.
$cmd = @"
/opt/splunk/bin/splunk search '$spl' -earliest_time $Earliest -output json -auth admin:$pw 2>/dev/null
"@
$raw = docker exec -u splunk lab_splunk bash -lc $cmd 2>$null
if ($raw -is [System.Array]) {
  $raw = $raw -join "`n"
}

$lines = @()
if ([string]::IsNullOrWhiteSpace($raw)) {
  Write-Warning "No Splunk output (container down, wrong password, or no Warning+ events)."
} else {
  try {
    $parsed = $raw | ConvertFrom-Json
    if ($parsed -is [System.Array]) {
      foreach ($r in $parsed) { $lines += ($r | ConvertTo-Json -Compress -Depth 6) }
    } elseif ($null -ne $parsed.results) {
      foreach ($r in $parsed.results) { $lines += ($r | ConvertTo-Json -Compress -Depth 6) }
    } elseif ($null -ne $parsed.result) {
      $lines += ($parsed.result | ConvertTo-Json -Compress -Depth 6)
    } else {
      $lines += ($parsed | ConvertTo-Json -Compress -Depth 6)
    }
  } catch {
    $lines = @($raw -split "`r?`n" | Where-Object { $_.Trim() -and $_.Trim().StartsWith('{') })
  }
}

Set-Content -Path $OutFile -Value ($lines -join "`n") -Encoding UTF8
Write-Host ("Wrote {0} events -> {1}" -f $lines.Count, $OutFile)
