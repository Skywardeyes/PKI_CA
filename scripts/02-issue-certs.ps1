param(
  [string]$ClientName = "trainee",
  [string]$P12Password = "ChangeMe!2026"
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
  param([scriptblock]$Command)
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $LASTEXITCODE"
  }
}

if (!(Test-Path "server/server.cert.pem")) {
  Invoke-Checked { openssl genrsa -out server/server.key.pem 2048 }
  Invoke-Checked { openssl req -config ca/openssl-intermediate.cnf -new -sha256 -key server/server.key.pem `
    -subj "/C=CN/ST=Shanghai/O=Koal/OU=PKI/CN=localhost" `
    -out ca/intermediate/csr/server.csr.pem }

  Invoke-Checked { openssl ca -batch -config ca/openssl-intermediate.cnf -extensions server_cert -days 825 -notext -md sha256 `
    -in ca/intermediate/csr/server.csr.pem `
    -out server/server.cert.pem }
}

Invoke-Checked { openssl genrsa -out client/client-$ClientName.key.pem 2048 }
Invoke-Checked { openssl req -config ca/openssl-intermediate.cnf -new -sha256 -key client/client-$ClientName.key.pem `
  -subj "/C=CN/ST=Shanghai/O=Koal/OU=PKI/CN=$ClientName" `
  -out ca/intermediate/csr/client-$ClientName.csr.pem }

Invoke-Checked { openssl ca -batch -config ca/openssl-intermediate.cnf -extensions usr_cert -days 825 -notext -md sha256 `
  -in ca/intermediate/csr/client-$ClientName.csr.pem `
  -out client/client-$ClientName.cert.pem }

Invoke-Checked { openssl pkcs12 -export `
  -inkey client/client-$ClientName.key.pem `
  -in client/client-$ClientName.cert.pem `
  -certfile ca/intermediate/certs/ca-chain.cert.pem `
  -out client/client-$ClientName.p12 `
  -password pass:$P12Password }

Write-Host "Server and client certificates issued."
Write-Host "Client P12 file: client/client-$ClientName.p12"
