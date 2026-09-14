Set-StrictMode -Version Latest

$script:SupportedTeeTypes = @('IntelTDX', 'AMD-SEV-SNP', 'AzureConfidentialVM')
$script:AwsProvider = 'aws-kms'
$script:AwsRegionPattern = '^[a-z]{2}(-[a-z]+)+-\d$'
$script:AwsKeyArnPattern = '^arn:aws[a-z-]*:kms:(?<region>[a-z0-9-]+):\d{12}:(key/|alias/).+$'

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

function Get-DtaiProperty {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($InputObject -is [Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Assert-DtaiAwsAuthority {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Authority)

    $region = [string](Get-DtaiProperty $Authority 'Region')
    if ($region -notmatch $script:AwsRegionPattern) {
        throw "AWS authority '$($Authority.Name)' requires a valid Region such as 'us-east-1'."
    }
    $keyArn = [regex]::Match([string]$Authority.KeyId, $script:AwsKeyArnPattern)
    if (-not $keyArn.Success) {
        throw "AWS authority '$($Authority.Name)' KeyId must be an AWS KMS key or alias ARN."
    }
    if ($keyArn.Groups['region'].Value -cne $region) {
        throw "AWS authority '$($Authority.Name)' KeyId region must match Region '$region'."
    }

    $service = Get-DtaiProperty $Authority 'SigningService'
    if ($null -ne $service -and [string]$service -notmatch '^[a-z0-9-]{2,32}$') {
        throw "AWS authority '$($Authority.Name)' SigningService is invalid."
    }
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

        if ($authority.Provider -eq $script:AwsProvider) {
            Assert-DtaiAwsAuthority $authority
        }
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

function Get-DtaiAwsSigV4Headers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Method,
        [Parameter(Mandatory)][Uri]$Uri,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Region,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Service,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$AccessKeyId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SecretAccessKey,
        [string]$SessionToken,
        [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Payload,
        [ValidateNotNullOrEmpty()][string]$ContentType = 'application/json',
        [DateTimeOffset]$Timestamp = [DateTimeOffset]::UtcNow
    )

    $amzDate = $Timestamp.ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $dateStamp = $Timestamp.ToUniversalTime().ToString('yyyyMMdd')
    $payloadHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Payload)
    ).ToLowerInvariant()

    $canonicalPath = '/'
    if ($Uri.AbsolutePath -ne '/' -and -not [string]::IsNullOrEmpty($Uri.AbsolutePath)) {
        $canonicalPath = ($Uri.AbsolutePath.Split('/') | ForEach-Object {
            [Uri]::EscapeDataString([Uri]::UnescapeDataString($_))
        }) -join '/'
    }

    $canonicalQuery = ''
    if ($Uri.Query.Length -gt 1) {
        $pairs = foreach ($part in $Uri.Query.TrimStart('?').Split('&')) {
            if ($part.Length -eq 0) { continue }
            $split = $part.Split('=', 2)
            $name = [Uri]::EscapeDataString([Uri]::UnescapeDataString($split[0]))
            $value = ''
            if ($split.Count -eq 2) {
                $value = [Uri]::EscapeDataString([Uri]::UnescapeDataString($split[1]))
            }
            , @($name, $value)
        }
        $canonicalQuery = (@($pairs) | Sort-Object { $_[0] }, { $_[1] } | ForEach-Object {
            "$($_[0])=$($_[1])"
        }) -join '&'
    }

    $headers = [ordered]@{
        'content-type' = $ContentType
        'host' = $Uri.IdnHost + $(if ($Uri.IsDefaultPort) { '' } else { ":$($Uri.Port)" })
        'x-amz-content-sha256' = $payloadHash
        'x-amz-date' = $amzDate
    }
    if (-not [string]::IsNullOrWhiteSpace($SessionToken)) {
        $headers['x-amz-security-token'] = $SessionToken
    }

    $signedHeaders = ($headers.Keys | Sort-Object) -join ';'
    $canonicalHeaders = (($headers.Keys | Sort-Object | ForEach-Object {
        "${_}:$($headers[$_].Trim())"
    }) -join "`n") + "`n"

    $canonicalRequest = @(
        $Method.ToUpperInvariant()
        $canonicalPath
        $canonicalQuery
        $canonicalHeaders
        $signedHeaders
        $payloadHash
    ) -join "`n"

    $scope = "$dateStamp/$Region/$Service/aws4_request"
    $stringToSign = @(
        'AWS4-HMAC-SHA256'
        $amzDate
        $scope
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
            [Text.Encoding]::UTF8.GetBytes($canonicalRequest)
        )).ToLowerInvariant()
    ) -join "`n"

    $key = [Text.Encoding]::UTF8.GetBytes("AWS4$SecretAccessKey")
    try {
        foreach ($element in @($dateStamp, $Region, $Service, 'aws4_request', $stringToSign)) {
            $hmac = [Security.Cryptography.HMACSHA256]::new($key)
            try {
                $next = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($element))
            }
            finally {
                $hmac.Dispose()
            }
            [Array]::Clear($key)
            $key = $next
        }
        $signature = [Convert]::ToHexString($key).ToLowerInvariant()
    }
    finally {
        [Array]::Clear($key)
    }

    $result = [ordered]@{
        'X-Amz-Date' = $amzDate
        'X-Amz-Content-Sha256' = $payloadHash
        'Authorization' = "AWS4-HMAC-SHA256 Credential=$AccessKeyId/$scope, " +
            "SignedHeaders=$signedHeaders, Signature=$signature"
    }
    if ($headers.Contains('x-amz-security-token')) {
        $result['X-Amz-Security-Token'] = $SessionToken
    }
    return $result
}

function Get-DtaiAwsCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Authority)

    $accessKeyId = $env:AWS_ACCESS_KEY_ID
    $secretAccessKey = $env:AWS_SECRET_ACCESS_KEY
    if ([string]::IsNullOrWhiteSpace($accessKeyId) -or
        [string]::IsNullOrWhiteSpace($secretAccessKey)) {
        throw "AWS authority '$($Authority.Name)' requires AWS_ACCESS_KEY_ID and " +
            'AWS_SECRET_ACCESS_KEY in the environment.'
    }
    return [ordered]@{
        AccessKeyId = $accessKeyId
        SecretAccessKey = $secretAccessKey
        SessionToken = $env:AWS_SESSION_TOKEN
    }
}

function Invoke-DtaiAuthorityRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Authority,
        [Parameter(Mandatory)]$Request
    )

    $body = $Request | ConvertTo-Json -Depth 8 -Compress
    $headers = @{}
    if ($Authority.Provider -eq $script:AwsProvider) {
        $payload = [Text.Encoding]::UTF8.GetBytes($body)
        $credential = Get-DtaiAwsCredential $Authority
        $service = [string](Get-DtaiProperty $Authority 'SigningService')
        if ([string]::IsNullOrWhiteSpace($service)) { $service = 'execute-api' }
        $headers = Get-DtaiAwsSigV4Headers -Method 'POST' -Uri ([Uri]$Authority.Endpoint) `
            -Region ([string](Get-DtaiProperty $Authority 'Region')) -Service $service `
            -AccessKeyId $credential.AccessKeyId -SecretAccessKey $credential.SecretAccessKey `
            -SessionToken $credential.SessionToken -Payload $payload
    }
    return Invoke-RestMethod -Method Post -Uri $Authority.Endpoint -Headers $headers `
        -ContentType 'application/json' -Body $body -TimeoutSec 30
}

function Invoke-DtaiKeyRelease {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Configuration,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Context,
        [Parameter(Mandatory)][scriptblock]$AttestationProvider,
        [scriptblock]$ReleaseClient
    )

    Assert-DtaiConfiguration $Configuration
    if ($Context.Length -gt 1024) {
        throw 'Context must not exceed 1024 characters.'
    }
    if ($null -eq $ReleaseClient) {
        $ReleaseClient = {
            param($Authority, $Request)
            Invoke-DtaiAuthorityRelease -Authority $Authority -Request $Request
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
            $nonceBytes = [byte[]]::new(32)
            [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
            $nonce = ConvertTo-DtaiBase64Url $nonceBytes
            [Array]::Clear($nonceBytes)
            $challenge = [ordered]@{
                protocol = 'DTAI-SKR-v1'
                keyId = $authority.KeyId
                nonce = $nonce
                context = $Context
                recipient = $jwk
            }
            $evidence = & $AttestationProvider $authority $challenge
            if ([string]::IsNullOrWhiteSpace([string]$evidence)) {
                throw "Attestation provider returned no evidence for authority '$($authority.Name)'."
            }
            if ([Text.Encoding]::UTF8.GetByteCount([string]$evidence) -gt 1MB) {
                throw "Attestation evidence for authority '$($authority.Name)' exceeds 1 MiB."
            }
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

            if ([string]$response.ciphertext -notmatch '^[A-Za-z0-9_-]{512}$') {
                throw "Authority '$($authority.Name)' returned invalid ciphertext."
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

Export-ModuleMember -Function Assert-DtaiConfiguration, Get-DtaiAwsSigV4Headers, Invoke-DtaiAuthorityRelease,
    Invoke-DtaiHkdfSha256, Invoke-DtaiKeyRelease
