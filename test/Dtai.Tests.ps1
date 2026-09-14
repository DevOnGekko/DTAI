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
                Provider = 'secondary-cloud-kms'
                Endpoint = 'https://secondary-authority.example/release'
                KeyId = 'projects/example/keys/k2'
            }
        )
    }
}

function New-TestAwsConfiguration {
    $configuration = New-TestConfiguration
    $configuration.Authorities[1] = [pscustomobject]@{
        Name = 'authority-aws'
        Provider = 'aws-kms'
        Region = 'us-east-1'
        Endpoint = 'https://aws-authority.example/v1/release'
        KeyId = 'arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555'
    }
    return $configuration
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

# AWS secondary trust authority
$awsConfiguration = New-TestAwsConfiguration
Assert-DtaiConfiguration $awsConfiguration

$contributions['authority-aws'] = [byte[]](65..96)
$awsDek = Invoke-DtaiKeyRelease $awsConfiguration 'model://example/v1' $attestationProvider $releaseClient
Assert-Equal 32 $awsDek.Length 'AWS authority DEK length was incorrect.'
if ([Convert]::ToHexString($awsDek) -eq [Convert]::ToHexString($dek1)) {
    throw 'Authority binding must change the derived DEK.'
}

$badRegion = New-TestAwsConfiguration
$badRegion.Authorities[1].Region = 'useast1'
Assert-Throws { Assert-DtaiConfiguration $badRegion } '*valid Region*'

$badArn = New-TestAwsConfiguration
$badArn.Authorities[1].KeyId = 'alias/dtai-k2'
Assert-Throws { Assert-DtaiConfiguration $badArn } '*KMS key or alias ARN*'

$mismatchedRegion = New-TestAwsConfiguration
$mismatchedRegion.Authorities[1].KeyId =
    'arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555'
Assert-Throws { Assert-DtaiConfiguration $mismatchedRegion } '*KeyId region must match*'

$badSigningService = New-TestAwsConfiguration
$badSigningService.Authorities[1] |
    Add-Member -NotePropertyName SigningService -NotePropertyValue 'Execute API'
Assert-Throws { Assert-DtaiConfiguration $badSigningService } '*SigningService is invalid*'

# AWS Signature Version 4 vector cross-checked against the AWS SDK signer
$signed = Get-DtaiAwsSigV4Headers -Method 'POST' `
    -Uri ([Uri]'https://kms.us-east-1.amazonaws.com/') -Region 'us-east-1' -Service 'kms' `
    -AccessKeyId 'AKIDEXAMPLE' -SecretAccessKey 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' `
    -Payload ([Text.Encoding]::UTF8.GetBytes('{"a":1}')) `
    -Timestamp ([DateTimeOffset]::new(2026, 9, 14, 16, 27, 20, [TimeSpan]::Zero))
Assert-Equal '20260914T162720Z' $signed['X-Amz-Date'] 'SigV4 request date was incorrect.'
Assert-Equal `
    ('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260914/us-east-1/kms/aws4_request, ' +
     'SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, ' +
     'Signature=0278237eae5d08c2474a50b9f7936e84e1188dcd611f33280f054078d5cec75c') `
    $signed['Authorization'] `
    'SigV4 authorization header did not match the expected signature.'
if ($signed.Contains('X-Amz-Security-Token')) {
    throw 'SigV4 headers must omit the security token when no session token is used.'
}

$sessionSigned = Get-DtaiAwsSigV4Headers -Method 'POST' `
    -Uri ([Uri]'https://api.example.com/v1/release') -Region 'eu-west-2' -Service 'execute-api' `
    -AccessKeyId 'AKIDEXAMPLE' -SecretAccessKey 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY' `
    -SessionToken 'session-token-value' `
    -Payload ([Text.Encoding]::UTF8.GetBytes('{"protocol":"DTAI-SKR-v1"}')) `
    -Timestamp ([DateTimeOffset]::new(2026, 9, 14, 16, 27, 20, [TimeSpan]::Zero))
Assert-Equal 'session-token-value' $sessionSigned['X-Amz-Security-Token'] `
    'SigV4 headers must forward the session token.'
Assert-Equal `
    ('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260914/eu-west-2/execute-api/aws4_request, ' +
     'SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, ' +
     'Signature=fbff628d14207784e8c02eb9c5988b7e2068ab4749c9090ad52c0f7116893b70') `
    $sessionSigned['Authorization'] `
    'SigV4 authorization header with a session token was incorrect.'

$previousAccessKeyId = $env:AWS_ACCESS_KEY_ID
$previousSecretAccessKey = $env:AWS_SECRET_ACCESS_KEY
try {
    $env:AWS_ACCESS_KEY_ID = ''
    $env:AWS_SECRET_ACCESS_KEY = ''
    Assert-Throws {
        Invoke-DtaiAuthorityRelease -Authority $awsConfiguration.Authorities[1] `
            -Request ([ordered]@{ protocol = 'DTAI-SKR-v1' })
    } '*AWS_ACCESS_KEY_ID*'
}
finally {
    $env:AWS_ACCESS_KEY_ID = $previousAccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = $previousSecretAccessKey
}

$nonPremium = New-TestConfiguration
$nonPremium.Authorities[0].Sku = 'Standard'
Assert-Throws { Assert-DtaiConfiguration $nonPremium } '*Azure Key Vault Premium*'

$sameProvider = New-TestConfiguration
$sameProvider.Authorities[1].Provider = 'azure-key-vault'
Assert-Throws { Assert-DtaiConfiguration $sameProvider } '*distinct names, providers*'

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
