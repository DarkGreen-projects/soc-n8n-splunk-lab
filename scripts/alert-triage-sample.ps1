#Requires -Version 5.1
<#
.SYNOPSIS
  Scrive eventi triage di esempio (1 open, 1 closed) per testare la dashboard.
#>
$Inbox = "C:\lab\data\alerts-triage-inbox"
New-Item -ItemType Directory -Force -Path $Inbox | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"

$open = [ordered]@{
  alert_id     = "sample-$stamp-T41-System"
  status       = "open"
  source_id    = 41
  log_name     = "System"
  level        = "Errore"
  time_created = (Get-Date).AddHours(-2).ToString("o")
  message      = "Sample: unexpected shutdown (Kernel-Power Id 41)"
  opened_at    = (Get-Date).ToUniversalTime().ToString("o")
  closed_at    = $null
  owner        = $null
}
$closed = [ordered]@{
  alert_id     = "sample-closed-$stamp-T4625-Security"
  status       = "closed"
  source_id    = 4625
  log_name     = "Security"
  level        = "Avviso"
  time_created = (Get-Date).AddHours(-5).ToString("o")
  message      = "Sample: login failed (closed)"
  opened_at    = (Get-Date).AddHours(-4).ToUniversalTime().ToString("o")
  closed_at    = (Get-Date).ToUniversalTime().ToString("o")
  owner        = $env:USERNAME
}

$openPath = Join-Path $Inbox "sample-open-$stamp.json"
$closedPath = Join-Path $Inbox "sample-closed-$stamp.json"
($open | ConvertTo-Json -Compress) | Set-Content $openPath -Encoding UTF8
($closed | ConvertTo-Json -Compress) | Set-Content $closedPath -Encoding UTF8
Write-Host "Sample triage events written:"
Write-Host "  $openPath"
Write-Host "  $closedPath"
