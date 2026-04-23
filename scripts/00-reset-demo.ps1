param(
  [switch]$KeepWebCache
)

$ErrorActionPreference = "Stop"

function Remove-PathSafe {
  param([string]$Path)
  if (Test-Path $Path) {
    Remove-Item -Recurse -Force $Path -ErrorAction Stop
    Write-Host "Removed: $Path"
  }
}

# 1) Remove generated PKI runtime artifacts only.
Remove-PathSafe "ca/root"
Remove-PathSafe "ca/intermediate"
Remove-PathSafe "server"
Remove-PathSafe "client"
Remove-PathSafe "artifacts"

# 2) Optional cleanup for local Python/runtime cache.
if (-not $KeepWebCache) {
  Remove-PathSafe "web/app/__pycache__"
}

# 3) Re-create clean demo baseline structure.
& "./scripts/00-init-structure.ps1"
if (-not $?) {
  throw "Failed to run scripts/00-init-structure.ps1"
}

Write-Host "Demo reset completed."
Write-Host "Current state is ready for a fresh demo run."
Write-Host "Next: run scripts/01-build-ca.ps1 -> scripts/02-issue-certs.ps1 -> scripts/04-verify.ps1"
