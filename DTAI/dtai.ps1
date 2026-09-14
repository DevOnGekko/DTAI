[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigurationPath,
    [Parameter(Mandatory)][string]$AttestationCommand,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Context,
    [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Dtai.psm1') -Force

if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite existing DEK output '$OutputPath'."
}

$configuration = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json
$attestationProvider = {
    param($Authority, $Challenge)
    $evidence = ($Challenge | ConvertTo-Json -Depth 8 -Compress) |
        & $AttestationCommand $Authority.Name
    if ($LASTEXITCODE -ne 0) {
        throw "Attestation command failed for authority '$($Authority.Name)'."
    }
    return $evidence
}
$dek = Invoke-DtaiKeyRelease -Configuration $configuration -Context $Context `
    -AttestationProvider $attestationProvider

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    throw "Output directory '$parent' does not exist."
}

$temporaryPath = "$OutputPath.$([Guid]::NewGuid().ToString('N')).tmp"
try {
    if ($IsWindows) {
        [IO.File]::WriteAllBytes($temporaryPath, $dek)
    }
    else {
        $options = [IO.FileStreamOptions]@{
            Access = [IO.FileAccess]::Write
            Mode = [IO.FileMode]::CreateNew
            Share = [IO.FileShare]::None
            UnixCreateMode = [IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite
        }
        $stream = [IO.FileStream]::new($temporaryPath, $options)
        try {
            $stream.Write($dek)
        }
        finally {
            $stream.Dispose()
        }
    }
    Move-Item -LiteralPath $temporaryPath -Destination $OutputPath
}
finally {
    [Array]::Clear($dek)
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}
