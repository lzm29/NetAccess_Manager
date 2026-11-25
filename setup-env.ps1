$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (Test-Path .env) { Write-Host 'Existing .env preserved.'; exit 0 }
function New-Secret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}
@("MYSQL_ROOT_PASSWORD=$(New-Secret)", "DB_PASSWORD=$(New-Secret)", "SECRET_KEY=$(New-Secret)") | Set-Content -Encoding ascii .env
Write-Host 'Created .env with random secrets. Keep it private.'
