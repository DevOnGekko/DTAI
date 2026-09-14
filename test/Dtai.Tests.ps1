$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../DTAI/Dtai.psm1') -Force

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -cne $Actual) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

function Assert-Throws {
    param([scriptblock]$Action, [string]$Pattern)
    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike $Pattern) {
            throw "Expected error '$Pattern', got '$($_.Exception.Message)'."
        }
        return
    }
    throw "Expected action to throw '$Pattern'."
}

function New-TestConfiguration {
    return [pscustomobject]@{
        SchemaVersion = 1
        DerivationSalt = [Convert]::ToBase64String([byte[]](1..16))
        Security = [pscustomobject]@{
            MaxReleaseAgeSeconds = 120
            AllowedTeeTypes = @('IntelTDX', 'AMD-SEV-SNP', 'AzureConfidentialVM')
        }
        Authorities = @(
            [pscustomobject]@{
                Name = 'authority-azure'
                Provider = 'azure-key-vault'
                Sku = 'Premium'
                Endpoint = 'https://azure-authority.example/release'
                KeyId = 'https://vault.vault.azure.net/keys/k1/version'
            },
            [pscustomobject]@{
                Name = 'authority-secondary'
                Provider = 'google-cloud-kms'
                Endpoint = 'https://google-authority.example/release'
                GoogleAudience = 'https://google-authority.example'
                KeyId = 'projects/example/locations/us-central1/keyRings/dtai/cryptoKeys/k2/cryptoKeyVersions/1'
            }
        )
    }
}

function ConvertFrom-TestBase64Url {
    param([string]$Value)
    $padded = $Value.Replace('-', '+').Replace('_', '/')
    if ($padded.Length % 4 -eq 2) { $padded += '==' }
    if ($padded.Length % 4 -eq 3) { $padded += '=' }
    return [Convert]::FromBase64String($padded)
}

function ConvertTo-TestBase64Url {
    param([byte[]]$Value)
    return [Convert]::ToBase64String($Value).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-TestThumbprint {
    param($Jwk)
    $canonical = '{"e":"' + $Jwk.e + '","kty":"RSA","n":"' + $Jwk.n + '"}'
    return ConvertTo-TestBase64Url ([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($canonical)
    ))
}

$configuration = New-TestConfiguration
Assert-DtaiConfiguration $configuration

# RFC 5869 test case 1
$ikm = [byte[]]::new(22)
[Array]::Fill[byte]($ikm, 0x0b)
$salt = [byte[]](0x00..0x0c)
$info = [byte[]](0xf0..0xf9)
$okm = Invoke-DtaiHkdfSha256 -InputKeyMaterial $ikm -Salt $salt -Info $info -Length 42
Assert-Equal `
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865' `
    ([Convert]::ToHexString($okm).ToLowerInvariant()) `
    'HKDF output did not match RFC 5869.'

$contributions = @{
    'authority-azure' = [byte[]](1..32)
    'authority-secondary' = [byte[]](33..64)
}
$releaseClient = {
    param($Authority, $Request)
    $expectedEvidence = "attestation:$($Authority.Name):$($Request.nonce):$(Get-TestThumbprint $Request.recipient)"
    if ($Request.attestationEvidence -cne $expectedEvidence) {
        throw 'Attestation evidence was not bound to the release challenge.'
    }
    $rsa = [Security.Cryptography.RSA]::Create()
    try {
        $rsa.ImportParameters([Security.Cryptography.RSAParameters]@{
            Modulus = ConvertFrom-TestBase64Url $Request.recipient.n
            Exponent = ConvertFrom-TestBase64Url $Request.recipient.e
        })
        $ciphertext = $rsa.Encrypt(
            $contributions[$Authority.Name],
            [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
        )
        return [pscustomobject]@{
            protocol = 'DTAI-SKR-v1'
            authority = $Authority.Name
            provider = $Authority.Provider
            keyId = $Authority.KeyId
            nonce = $Request.nonce
            recipientThumbprint = Get-TestThumbprint $Request.recipient
            issuedAt = [DateTimeOffset]::UtcNow.ToString('o')
            ciphertext = ConvertTo-TestBase64Url $ciphertext
        }
    }
    finally {
        $rsa.Dispose()
    }
}

$attestationProvider = {
    param($Authority, $Challenge)
    return "attestation:$($Authority.Name):$($Challenge.nonce):$(Get-TestThumbprint $Challenge.recipient)"
}
$dek1 = Invoke-DtaiKeyRelease $configuration 'model://example/v1' $attestationProvider $releaseClient
$dek2 = Invoke-DtaiKeyRelease $configuration 'model://example/v1' $attestationProvider $releaseClient
Assert-Equal 32 $dek1.Length 'DEK length was incorrect.'
Assert-Equal ([Convert]::ToHexString($dek1)) ([Convert]::ToHexString($dek2)) 'Derivation was not deterministic.'
if ([Convert]::ToHexString($dek1) -eq [Convert]::ToHexString($contributions['authority-azure'])) {
    throw 'Derived DEK must not equal an individual contribution.'
}

$nonPremium = New-TestConfiguration
$nonPremium.Authorities[0].Sku = 'Standard'
Assert-Throws { Assert-DtaiConfiguration $nonPremium } '*Azure Key Vault Premium*'

$sameProvider = New-TestConfiguration
$sameProvider.Authorities[1].Provider = 'azure-key-vault'
Assert-Throws { Assert-DtaiConfiguration $sameProvider } '*distinct names, providers*'

$invalidGoogleKey = New-TestConfiguration
$invalidGoogleKey.Authorities[1].KeyId = 'projects/example/keys/k2'
Assert-Throws { Assert-DtaiConfiguration $invalidGoogleKey } '*Google Cloud KMS KeyId*'

$missingGoogleAudience = New-TestConfiguration
$missingGoogleAudience.Authorities[1].PSObject.Properties.Remove('GoogleAudience')
Assert-Throws { Assert-DtaiConfiguration $missingGoogleAudience } '*GoogleAudience*'

$googleFirst = New-TestConfiguration
[Array]::Reverse($googleFirst.Authorities)
Assert-Throws {
    Invoke-DtaiKeyRelease $googleFirst 'model://example/v1' $attestationProvider $null {
        param($Authority)
        return ''
    }
} '*Google identity token provider returned no token*'

$staleClient = {
    param($Authority, $Request)
    $response = & $releaseClient $Authority $Request
    $response.issuedAt = [DateTimeOffset]::UtcNow.AddMinutes(-10).ToString('o')
    return $response
}
Assert-Throws {
    Invoke-DtaiKeyRelease $configuration 'model://example/v1' $attestationProvider $staleClient
} '*stale release envelope*'

$unboundClient = {
    param($Authority, $Request)
    $response = & $releaseClient $Authority $Request
    $response.nonce = 'different-nonce'
    return $response
}
Assert-Throws {
    Invoke-DtaiKeyRelease $configuration 'model://example/v1' $attestationProvider $unboundClient
} '*invalid or unbound release envelope*'

Write-Host 'All DTAI tests passed.'
