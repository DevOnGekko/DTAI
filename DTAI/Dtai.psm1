Set-StrictMode -Version Latest

$script:SupportedTeeTypes = @('IntelTDX', 'AMD-SEV-SNP', 'AzureConfidentialVM')

function ConvertTo-DtaiBase64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-DtaiBase64Url {
    param([Parameter(Mandatory)][string]$Value)

    $padded = $Value.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += '==' }
        3 { $padded += '=' }
        1 { throw 'Invalid base64url value.' }
    }
    return [Convert]::FromBase64String($padded)
}

function Get-DtaiPublicKeyThumbprint {
    param([Parameter(Mandatory)]$Jwk)

    $canonical = '{"e":"' + $Jwk.e + '","kty":"RSA","n":"' + $Jwk.n + '"}'
    $hash = [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($canonical))
    return ConvertTo-DtaiBase64Url $hash
}

function Assert-DtaiConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Configuration)

    if ($Configuration.SchemaVersion -ne 1) {
        throw 'Configuration SchemaVersion must be 1.'
    }
    if (@($Configuration.Authorities).Count -ne 2) {
        throw 'DTAI requires exactly two key authorities.'
    }

    $names = @{}
    $providers = @{}
    $hosts = @{}
    foreach ($authority in $Configuration.Authorities) {
        foreach ($property in @('Name', 'Provider', 'Endpoint', 'KeyId')) {
            if ([string]::IsNullOrWhiteSpace([string]$authority.$property)) {
                throw "Authority property '$property' is required."
            }
        }

        $uri = [Uri]$authority.Endpoint
        if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https') {
            throw "Authority '$($authority.Name)' must use an HTTPS endpoint."
        }
        if ($names.ContainsKey($authority.Name) -or $providers.ContainsKey($authority.Provider) -or
            $hosts.ContainsKey($uri.DnsSafeHost)) {
            throw 'Authorities must have distinct names, providers, and endpoint hosts.'
        }
        $names[$authority.Name] = $true
        $providers[$authority.Provider] = $true
        $hosts[$uri.DnsSafeHost] = $true
    }

    $azure = @($Configuration.Authorities | Where-Object Provider -eq 'azure-key-vault')
    if ($azure.Count -ne 1 -or $azure[0].Sku -ne 'Premium') {
        throw "Exactly one authority must use an Azure Key Vault Premium key."
    }

    if ($Configuration.Security.MaxReleaseAgeSeconds -lt 30 -or
        $Configuration.Security.MaxReleaseAgeSeconds -gt 900) {
        throw 'MaxReleaseAgeSeconds must be between 30 and 900.'
    }
    if (@($Configuration.Security.AllowedTeeTypes).Count -eq 0) {
        throw 'At least one allowed TEE type is required.'
    }
    foreach ($teeType in $Configuration.Security.AllowedTeeTypes) {
        if ($teeType -notin $script:SupportedTeeTypes) {
            throw "Unsupported TEE type '$teeType'."
        }
    }

    $salt = [Convert]::FromBase64String($Configuration.DerivationSalt)
    if ($salt.Length -lt 16) {
        throw 'DerivationSalt must contain at least 16 random bytes.'
    }
}

function Invoke-DtaiHkdfSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$InputKeyMaterial,
        [Parameter(Mandatory)][byte[]]$Salt,
        [Parameter(Mandatory)][byte[]]$Info,
        [ValidateRange(1, 8160)][int]$Length = 32
    )

    $extractor = [Security.Cryptography.HMACSHA256]::new($Salt)
    try {
        $prk = $extractor.ComputeHash($InputKeyMaterial)
    }
    finally {
        $extractor.Dispose()
    }

    $result = [byte[]]::new($Length)
    $previous = [byte[]]::new(0)
    $offset = 0
    $counter = 1
    try {
        while ($offset -lt $Length) {
            $expand = [Security.Cryptography.HMACSHA256]::new($prk)
            try {
                $blockInput = [byte[]]::new($previous.Length + $Info.Length + 1)
                [Array]::Copy($previous, 0, $blockInput, 0, $previous.Length)
                [Array]::Copy($Info, 0, $blockInput, $previous.Length, $Info.Length)
                $blockInput[$blockInput.Length - 1] = [byte]$counter
                $next = $expand.ComputeHash($blockInput)
            }
            finally {
                $expand.Dispose()
                if ($null -ne $blockInput) { [Array]::Clear($blockInput) }
            }
            if ($previous.Length -gt 0) { [Array]::Clear($previous) }
            $previous = $next
            $take = [Math]::Min($previous.Length, $Length - $offset)
            [Array]::Copy($previous, 0, $result, $offset, $take)
            $offset += $take
            $counter++
        }
        return ,$result
    }
    finally {
        [Array]::Clear($prk)
        if ($previous.Length -gt 0) { [Array]::Clear($previous) }
    }
}

function Invoke-DtaiKeyRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Configuration,
        [Parameter(Mandatory)]$AttestationEvidence,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Context,
        [scriptblock]$ReleaseClient
    )

    Assert-DtaiConfiguration $Configuration
    if ($Context.Length -gt 1024) {
        throw 'Context must not exceed 1024 characters.'
    }
    if ($null -eq $ReleaseClient) {
        $ReleaseClient = {
            param($Authority, $Request)
            Invoke-RestMethod -Method Post -Uri $Authority.Endpoint -ContentType 'application/json' `
                -Body ($Request | ConvertTo-Json -Depth 8 -Compress) -TimeoutSec 30
        }
    }

    $rsa = [Security.Cryptography.RSA]::Create(3072)
    $contributions = [Collections.Generic.List[byte[]]]::new()
    try {
        $parameters = $rsa.ExportParameters($false)
        $jwk = [ordered]@{
            kty = 'RSA'
            n = ConvertTo-DtaiBase64Url $parameters.Modulus
            e = ConvertTo-DtaiBase64Url $parameters.Exponent
            alg = 'RSA-OAEP-256'
        }
        $thumbprint = Get-DtaiPublicKeyThumbprint $jwk

        foreach ($authority in $Configuration.Authorities) {
            $evidence = $AttestationEvidence.($authority.Name)
            if ([string]::IsNullOrWhiteSpace([string]$evidence)) {
                throw "Attestation evidence for authority '$($authority.Name)' is required."
            }

            $nonceBytes = [byte[]]::new(32)
            [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
            $nonce = ConvertTo-DtaiBase64Url $nonceBytes
            [Array]::Clear($nonceBytes)
            $request = [ordered]@{
                protocol = 'DTAI-SKR-v1'
                keyId = $authority.KeyId
                nonce = $nonce
                context = $Context
                attestationEvidence = $evidence
                recipient = $jwk
            }
            $response = & $ReleaseClient $authority $request

            if ($response.protocol -ne 'DTAI-SKR-v1' -or
                $response.authority -ne $authority.Name -or
                $response.provider -ne $authority.Provider -or
                $response.keyId -ne $authority.KeyId -or
                $response.nonce -cne $nonce -or
                $response.recipientThumbprint -cne $thumbprint) {
                throw "Authority '$($authority.Name)' returned an invalid or unbound release envelope."
            }
            $issuedAt = [DateTimeOffset]::Parse(
                $response.issuedAt,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal
            )
            $age = [DateTimeOffset]::UtcNow - $issuedAt
            if ($age.TotalSeconds -lt -30 -or
                $age.TotalSeconds -gt $Configuration.Security.MaxReleaseAgeSeconds) {
                throw "Authority '$($authority.Name)' returned a stale release envelope."
            }

            $ciphertext = ConvertFrom-DtaiBase64Url $response.ciphertext
            try {
                $contribution = $rsa.Decrypt(
                    $ciphertext,
                    [Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
                )
            }
            finally {
                [Array]::Clear($ciphertext)
            }
            if ($contribution.Length -ne 32) {
                [Array]::Clear($contribution)
                throw "Authority '$($authority.Name)' contribution must be exactly 32 bytes."
            }
            $contributions.Add($contribution)
        }

        $ikm = [byte[]]::new(64)
        [Array]::Copy($contributions[0], 0, $ikm, 0, 32)
        [Array]::Copy($contributions[1], 0, $ikm, 32, 32)
        $authorityBinding = ($Configuration.Authorities | ForEach-Object {
            "$($_.Provider):$($_.KeyId)"
        }) -join '|'
        $info = [Text.Encoding]::UTF8.GetBytes("DTAI-DEK-v1`0$Context`0$authorityBinding")
        $salt = [Convert]::FromBase64String($Configuration.DerivationSalt)
        try {
            return ,(Invoke-DtaiHkdfSha256 -InputKeyMaterial $ikm -Salt $salt -Info $info -Length 32)
        }
        finally {
            [Array]::Clear($ikm)
            [Array]::Clear($info)
            [Array]::Clear($salt)
        }
    }
    finally {
        foreach ($contribution in $contributions) { [Array]::Clear($contribution) }
        $rsa.Dispose()
    }
}

Export-ModuleMember -Function Assert-DtaiConfiguration, Invoke-DtaiHkdfSha256, Invoke-DtaiKeyRelease
