param(
  [string]$ClientName = "trainee"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Path "artifacts/logs" -Force | Out-Null

$serverLog = "artifacts/logs/mtls-server.log"
$serverErrLog = "artifacts/logs/mtls-server.err.log"
$successLog = "artifacts/logs/mtls-success.log"
$noCertLog = "artifacts/logs/mtls-no-cert.log"
$revokedLog = "artifacts/logs/mtls-revoked.log"

if (!(Test-Path "ca/intermediate/crl/intermediate.crl.pem")) {
  openssl ca -config ca/openssl-intermediate.cnf -gencrl -out ca/intermediate/crl/intermediate.crl.pem | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Failed to generate CRL" }
}

$serverArgs = @(
  "s_server",
  "-accept", "9443",
  "-cert", "server/server.cert.pem",
  "-key", "server/server.key.pem",
  "-CAfile", "ca/intermediate/certs/ca-chain.cert.pem",
  "-Verify", "1",
  "-verify_return_error",
  "-CRL", "ca/intermediate/crl/intermediate.crl.pem",
  "-crl_check_all"
)

$proc = Start-Process -FilePath "openssl" -ArgumentList $serverArgs -NoNewWindow -RedirectStandardOutput $serverLog -RedirectStandardError $serverErrLog -PassThru
Start-Sleep -Seconds 2

try {
  $successCmd = "echo Q | openssl s_client -connect 127.0.0.1:9443 -cert client/client-$ClientName.cert.pem -key client/client-$ClientName.key.pem -CAfile ca/intermediate/certs/ca-chain.cert.pem -brief"
  cmd /c $successCmd 2>&1 | Out-File -FilePath $successLog -Encoding utf8

  $noCertCmd = "echo Q | openssl s_client -connect 127.0.0.1:9443 -CAfile ca/intermediate/certs/ca-chain.cert.pem -brief"
  cmd /c $noCertCmd 2>&1 | Out-File -FilePath $noCertLog -Encoding utf8

  powershell -ExecutionPolicy Bypass -File ./scripts/03-revoke-client.ps1 -ClientName $ClientName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Failed to revoke client cert" }

  $revokedCmd = "echo Q | openssl s_client -connect 127.0.0.1:9443 -cert client/client-$ClientName.cert.pem -key client/client-$ClientName.key.pem -CAfile ca/intermediate/certs/ca-chain.cert.pem -brief"
  cmd /c $revokedCmd 2>&1 | Out-File -FilePath $revokedLog -Encoding utf8
}
finally {
  if (!$proc.HasExited) {
    Stop-Process -Id $proc.Id -Force
  }
}

Write-Host "mTLS validation logs generated under artifacts/logs."
