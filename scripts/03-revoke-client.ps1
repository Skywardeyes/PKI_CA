param(
  [string]$ClientName = "trainee"
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
  param([scriptblock]$Command)
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $LASTEXITCODE"
  }
}

$certPath = "client/client-$ClientName.cert.pem"
if (!(Test-Path $certPath)) {
  throw "Client certificate not found: $certPath"
}

Invoke-Checked { openssl ca -config ca/openssl-intermediate.cnf -revoke $certPath }
Invoke-Checked { openssl ca -config ca/openssl-intermediate.cnf -gencrl -out ca/intermediate/crl/intermediate.crl.pem }

Write-Host "Client certificate revoked and CRL generated."
