[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigurationPath,
    [Parameter(Mandatory)][string]$AttestationEvidencePath,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Context,
    [Parameter(Mandatory)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Dtai.psm1') -Force

if (Test-Path -LiteralPath $OutputPath) {
    throw "Refusing to overwrite existing DEK output '$OutputPath'."
}

$configuration = Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json
$evidence = Get-Content -LiteralPath $AttestationEvidencePath -Raw | ConvertFrom-Json
$dek = Invoke-DtaiKeyRelease -Configuration $configuration -AttestationEvidence $evidence -Context $Context

$parent = Split-Path -Parent $OutputPath
if ($parent -and -not (Test-Path -LiteralPath $parent)) {
    throw "Output directory '$parent' does not exist."
}

$temporaryPath = "$OutputPath.$([Guid]::NewGuid().ToString('N')).tmp"
try {
    [IO.File]::WriteAllBytes($temporaryPath, $dek)
    if (-not $IsWindows) {
        chmod 600 -- $temporaryPath
        if ($LASTEXITCODE -ne 0) { throw 'Unable to restrict DEK output permissions.' }
    }
    Move-Item -LiteralPath $temporaryPath -Destination $OutputPath
}
finally {
    [Array]::Clear($dek)
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}
