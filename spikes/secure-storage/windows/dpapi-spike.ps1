param(
    [ValidateSet('test', 'attack')]
    [string]$Mode = 'test',
    [string]$CiphertextPath
)

$ErrorActionPreference = 'Stop'
$synthetic = [Text.Encoding]::UTF8.GetBytes('synthetic-agent-identity-not-production')
$entropy = [Text.Encoding]::UTF8.GetBytes('palladin-runtime-spike-v1')

if ($Mode -eq 'attack') {
    $ciphertext = [IO.File]::ReadAllBytes($CiphertextPath)
    $plaintext = [Security.Cryptography.ProtectedData]::Unprotect(
        $ciphertext,
        $entropy,
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
    if (-not [Security.Cryptography.CryptographicOperations]::FixedTimeEquals($plaintext, $synthetic)) {
        throw 'DPAPI returned unexpected bytes.'
    }
    Write-Output 'result=NOT_ISOLATED attacker-decrypt=success scope=CurrentUser'
    exit 10
}

$path = Join-Path ([IO.Path]::GetTempPath()) ("palladin-dpapi-{0}.bin" -f [Guid]::NewGuid())
try {
    $ciphertext = [Security.Cryptography.ProtectedData]::Protect(
        $synthetic,
        $entropy,
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
    [IO.File]::WriteAllBytes($path, $ciphertext)

    & pwsh -NoProfile -File $PSCommandPath -Mode attack -CiphertextPath $path
    $attackStatus = $LASTEXITCODE
    if ($attackStatus -ne 10) {
        throw "Expected same-user attacker to decrypt DPAPI CurrentUser ciphertext; exit=$attackStatus"
    }
    Write-Output 'expected=NOT_ISOLATED reason=DPAPI-CurrentUser-is-not-process-scoped'
} finally {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
}
