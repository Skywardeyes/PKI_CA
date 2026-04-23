param()

$ErrorActionPreference = "Stop"

$dirs = @(
  "ca/root/certs",
  "ca/root/crl",
  "ca/root/newcerts",
  "ca/root/private",
  "ca/root/csr",
  "ca/intermediate/certs",
  "ca/intermediate/crl",
  "ca/intermediate/newcerts",
  "ca/intermediate/private",
  "ca/intermediate/csr",
  "server",
  "client",
  "artifacts/logs"
)

foreach ($dir in $dirs) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

if (!(Test-Path "ca/root/index.txt")) { New-Item -ItemType File -Path "ca/root/index.txt" | Out-Null }
if (!(Test-Path "ca/intermediate/index.txt")) { New-Item -ItemType File -Path "ca/intermediate/index.txt" | Out-Null }
if (!(Test-Path "ca/root/serial")) { "1000" | Out-File -FilePath "ca/root/serial" -Encoding ascii -NoNewline }
if (!(Test-Path "ca/intermediate/serial")) { "2000" | Out-File -FilePath "ca/intermediate/serial" -Encoding ascii -NoNewline }
if (!(Test-Path "ca/intermediate/crlnumber")) { "2000" | Out-File -FilePath "ca/intermediate/crlnumber" -Encoding ascii -NoNewline }

Write-Host "PKI directory initialization completed."
