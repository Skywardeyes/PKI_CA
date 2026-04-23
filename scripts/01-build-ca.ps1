param()

$ErrorActionPreference = "Stop"

function Invoke-Checked {
  param([scriptblock]$Command)
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code $LASTEXITCODE"
  }
}

Invoke-Checked { openssl genrsa -out ca/root/private/ca.key.pem 4096 }
Invoke-Checked { openssl req -config ca/openssl-root.cnf `
  -key ca/root/private/ca.key.pem `
  -new -x509 -days 3650 -sha256 -extensions v3_ca `
  -subj "/C=CN/ST=Shanghai/O=Koal/OU=Training/CN=Koal Root CA" `
  -out ca/root/certs/ca.cert.pem }

Invoke-Checked { openssl genrsa -out ca/intermediate/private/intermediate.key.pem 4096 }
Invoke-Checked { openssl req -config ca/openssl-intermediate.cnf -new -sha256 `
  -key ca/intermediate/private/intermediate.key.pem `
  -subj "/C=CN/ST=Shanghai/O=Koal/OU=Training/CN=Koal Intermediate CA" `
  -out ca/intermediate/csr/intermediate.csr.pem }

Invoke-Checked { openssl ca -batch -config ca/openssl-root.cnf -extensions v3_ca -days 1825 -notext -md sha256 `
  -in ca/intermediate/csr/intermediate.csr.pem `
  -out ca/intermediate/certs/intermediate.cert.pem }

Invoke-Checked { openssl verify -CAfile ca/root/certs/ca.cert.pem ca/intermediate/certs/intermediate.cert.pem }

Get-Content ca/intermediate/certs/intermediate.cert.pem,ca/root/certs/ca.cert.pem |
  Out-File -FilePath ca/intermediate/certs/ca-chain.cert.pem -Encoding ascii

Write-Host "Root/Intermediate CA build completed."
