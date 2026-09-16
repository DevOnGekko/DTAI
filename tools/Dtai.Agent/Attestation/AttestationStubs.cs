namespace Dtai.Agent.Attestation;

using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

// The MAA-path providers below perform a real, config-driven attestation ->
// Azure Key Vault Secure Key Release when a vault and key are configured
// (attestation.settings(.local).json or DTAI_ATTESTATION_* env vars). The TEE
// type is selected by AttestationType; SevSnpVm is implemented today and other
// types (TdxVm, AzureGuest) plug in at the marked dispatch points. When
// unconfigured the providers return demo markers and make no network calls.
// The ITA/Hashicorp providers are still stubs. Test-only: the bundled SEV-SNP
// evidence is Azure's public sample.

public sealed class TeeEvidenceProvider : ITeeEvidenceProvider
{
    private readonly AttestationSettings settings;

    public TeeEvidenceProvider(AttestationSettings? settings = null) =>
        this.settings = settings ?? AttestationSettings.Load();

    public TeeEvidence FetchEvidence()
    {
        if (!settings.Enabled)
        {
            return new TeeEvidence("demo-only-tee-evidence");
        }

        // Load evidence for the configured TEE type. Add other types here.
        var dir = Path.Combine(AppContext.BaseDirectory, "Evidence");
        return settings.AttestationType switch
        {
            AttestationTypes.SevSnpVm => new TeeEvidence(JsonSerializer.Serialize(new
            {
                kind = AttestationTypes.SevSnpVm,
                snpReport = File.ReadAllText(Path.Combine(dir, "snp-report.b64url")).Trim(),
                vcekCertChain = File.ReadAllText(Path.Combine(dir, "vcek-cert-chain.b64url")).Trim(),
                runtimeData = File.ReadAllText(Path.Combine(dir, "runtime-data.json")).Trim(),
            })),
            AttestationTypes.TdxVm => new TeeEvidence(JsonSerializer.Serialize(new
            {
                kind = AttestationTypes.TdxVm,
                quote = File.ReadAllText(Path.Combine(dir, "tdx-quote.b64url")).Trim(),
                runtimeData = File.ReadAllText(Path.Combine(dir, "tdx-runtime-data.b64url")).Trim(),
            })),
            _ => throw new NotSupportedException(
                $"No bundled TEE evidence for attestation type '{settings.AttestationType}'. Implemented: {AttestationTypes.SevSnpVm}, {AttestationTypes.TdxVm}."),
        };
    }
}

public sealed class MaaAttestationService : IMaaAttestationService
{
    private static readonly HttpClient Http = new();
    private readonly AttestationSettings settings;

    public MaaAttestationService(AttestationSettings? settings = null) =>
        this.settings = settings ?? AttestationSettings.Load();

    public AttestationToken Attest(TeeEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (!settings.Enabled)
        {
            return new AttestationToken("demo-only-maa-token");
        }

        using var packed = JsonDocument.Parse(evidence.Value);
        var request = BuildMaaRequest(settings.AttestationType, packed.RootElement);

        var url = $"https://{settings.MaaEndpoint}/attest/{settings.AttestationType}" +
            $"?api-version={settings.AttestationApiVersion}";
        Console.WriteLine($"  [maa] attesting {settings.AttestationType} at {url}");
        using var content = new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json");
        using var response = Http.PostAsync(url, content).GetAwaiter().GetResult();
        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"MAA attestation failed ({(int)response.StatusCode}): {body}");
        }

        using var document = JsonDocument.Parse(body);
        var token = document.RootElement.GetProperty("token").GetString()!;
        VerifyAndLog(token);
        return new AttestationToken(token);
    }

    // Build the MAA request body for the configured TEE type. Each MAA attest
    // path expects a different shape (SevSnpVm: { report, runtimeData }; TdxVm:
    // { quote, runtimeData }; ...). Add other types here.
    private static object BuildMaaRequest(string attestationType, JsonElement evidence)
    {
        switch (attestationType)
        {
            case AttestationTypes.SevSnpVm:
                var snpReport = evidence.GetProperty("snpReport").GetString()!;
                var vcekCertChain = evidence.GetProperty("vcekCertChain").GetString()!;
                var runtimeData = evidence.GetProperty("runtimeData").GetString()!;

                // MAA "report" is base64url(JSON{ SnpReport, VcekCertChain });
                // runtimeData is hashed into report_data and carries the transfer key.
                var quoteJson = JsonSerializer.Serialize(new { SnpReport = snpReport, VcekCertChain = vcekCertChain });
                return new
                {
                    report = Base64UrlEncode(quoteJson),
                    runtimeData = new { data = Base64UrlEncode(runtimeData), dataType = "JSON" },
                };

            case AttestationTypes.TdxVm:
                // TDX carries no in-band cert chain; the quote and runtimeData are
                // already base64url and pass through unchanged.
                return new
                {
                    quote = evidence.GetProperty("quote").GetString()!,
                    runtimeData = new { data = evidence.GetProperty("runtimeData").GetString()!, dataType = "JSON" },
                };

            default:
                throw new NotSupportedException(
                    $"MAA request building for attestation type '{attestationType}' is not implemented. Implemented: {AttestationTypes.SevSnpVm}, {AttestationTypes.TdxVm}.");
        }
    }

    private static string Base64UrlEncode(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // Verify the MAA token the way Key Vault will (signature via MAA's JWKS,
    // issuer, lifetime) and log the outcome so the flow can be checked.
    private void VerifyAndLog(string token)
    {
        var certsUrl = $"https://{settings.MaaEndpoint}/certs";
        Console.WriteLine($"  [maa] fetching signing keys (JWKS): {certsUrl}");
        var jwks = Http.GetStringAsync(certsUrl).GetAwaiter().GetResult();
        var signingKeys = new JsonWebKeySet(jwks).GetSigningKeys();

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = $"https://{settings.MaaEndpoint}",
            ValidateAudience = false,
            ValidateLifetime = true,
            IssuerSigningKeys = signingKeys,
        };

        var result = new JsonWebTokenHandler().ValidateTokenAsync(token, parameters).GetAwaiter().GetResult();
        if (!result.IsValid)
        {
            throw new InvalidOperationException($"MAA token verification failed: {result.Exception?.Message}");
        }

        var jwt = (JsonWebToken)result.SecurityToken;
        var attestationType = jwt.TryGetClaim("x-ms-attestation-type", out var type) ? type.Value : "(none)";
        Console.WriteLine($"  [maa] token verified: signature OK, issuer {jwt.Issuer}, expires {jwt.ValidTo:u}");
        Console.WriteLine($"  [maa] x-ms-attestation-type: {attestationType}");
    }
}

public sealed class KeyVaultKeyProvider : IKeyVaultKeyProvider
{
    private static readonly HttpClient Http = new();
    private readonly AttestationSettings settings;

    public KeyVaultKeyProvider(AttestationSettings? settings = null) =>
        this.settings = settings ?? AttestationSettings.Load();

    public KeyReference GetK1(AttestationToken token)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (!settings.Enabled)
        {
            return new KeyReference("demo-only-k1-reference");
        }

        // AAD bearer authenticates the caller; the MAA token in the body authorizes release.
        var credentialOptions = new DefaultAzureCredentialOptions { ExcludeInteractiveBrowserCredential = false };
        if (!string.IsNullOrWhiteSpace(settings.TenantId))
        {
            credentialOptions.TenantId = settings.TenantId;
            credentialOptions.InteractiveBrowserTenantId = settings.TenantId;
        }

        var credential = new DefaultAzureCredential(credentialOptions);
        var accessToken = credential.GetToken(
            new TokenRequestContext(new[] { "https://vault.azure.net/.default" }));

        var versionSegment = string.IsNullOrWhiteSpace(settings.KeyVersion) ? string.Empty : $"/{settings.KeyVersion}";
        var url = $"https://{settings.KeyVaultName}.vault.azure.net/keys/{settings.KeyName}{versionSegment}/release" +
            $"?api-version={settings.KeyVaultApiVersion}";

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { target = token.Value }),
                Encoding.UTF8,
                "application/json"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken.Token);

        Console.WriteLine($"  [kv] releasing key '{settings.KeyName}' from {settings.KeyVaultName} (MAA token as release target)");
        using var response = Http.SendAsync(request).GetAwaiter().GetResult();
        var body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Key release failed ({(int)response.StatusCode}): {body}");
        }

        using var document = JsonDocument.Parse(body);
        var releasedValue = document.RootElement.GetProperty("value").GetString()!;
        Console.WriteLine($"  [kv] release authorized by MAA token; received wrapped key ({releasedValue.Length}-char JWE)");
        return new KeyReference(releasedValue);
    }
}

// The ITA (Intel Trust Authority) / Hashicorp K2 path remains a stub.
public sealed class ItaAttestationService : IItaAttestationService
{
    public AttestationToken Attest(TeeEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        // TODO: Implement a separate service that submits evidence to ITA and validates the returned token.
        return new AttestationToken("demo-only-ita-token");
    }
}

public sealed class HashicorpKeyProvider : IHashicorpKeyProvider
{
    public KeyReference GetK2(AttestationToken token)
    {
        ArgumentNullException.ThrowIfNull(token);
        // TODO: Implement a separate provider that requests authorized access to K2 using the ITA token.
        return new KeyReference("demo-only-k2-reference");
    }
}
