param(
  [string]$ClientName = "trainee"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Path "artifacts/logs" -Force | Out-Null

function Invoke-CheckedOut {
  param([scriptblock]$Command, [string]$OutputFile)
  $output = & $Command 2>&1
  $output | Out-File -FilePath $OutputFile -Encoding utf8
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $LASTEXITCODE. See $OutputFile"
  }
}

Invoke-CheckedOut { openssl verify -CAfile ca/root/certs/ca.cert.pem ca/intermediate/certs/intermediate.cert.pem } "artifacts/logs/verify-chain.log"
Invoke-CheckedOut { openssl verify -CAfile ca/intermediate/certs/ca-chain.cert.pem server/server.cert.pem } "artifacts/logs/verify-server.log"
Invoke-CheckedOut { openssl verify -CAfile ca/intermediate/certs/ca-chain.cert.pem client/client-$ClientName.cert.pem } "artifacts/logs/verify-client.log"

Write-Host "Certificate chain verification logs written to artifacts/logs."
