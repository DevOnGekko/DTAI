using System.Security.Cryptography;
using Dtai;

namespace Dtai.Tests;

/// <summary>Dependency-free focused tests mirroring test/Dtai.Tests.ps1.</summary>
public static class Program
{
    public static async Task<int> Main()
    {
        var configuration = NewTestConfiguration();
        configuration.Validate();

        AssertHkdfMatchesRfc5869();
        await AssertDerivationIsDeterministicAndBoundAsync().ConfigureAwait(false);
        AssertConfigurationRules();
        await AssertEnvelopeChecksAsync().ConfigureAwait(false);

        Console.WriteLine("All DTAI tests passed.");
        return 0;
    }

    private static readonly Dictionary<string, byte[]> Contributions = new()
    {
        ["authority-azure"] = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray(),
        ["authority-secondary"] = Enumerable.Range(33, 32).Select(value => (byte)value).ToArray()
    };

    private static DtaiConfiguration NewTestConfiguration() => new()
    {
        SchemaVersion = 1,
        DerivationSalt = Convert.ToBase64String(Enumerable.Range(1, 16).Select(value => (byte)value).ToArray()),
        Security = new DtaiSecurity
        {
            MaxReleaseAgeSeconds = 120,
            AllowedTeeTypes = new[] { "IntelTDX", "AMD-SEV-SNP", "AzureConfidentialVM" }
        },
        Authorities = new[]
        {
            new DtaiAuthority
            {
                Name = "authority-azure",
                Provider = "azure-key-vault",
                Sku = "Premium",
                Endpoint = "https://azure-authority.example/release",
                KeyId = "https://vault.vault.azure.net/keys/k1/version"
            },
            new DtaiAuthority
            {
                Name = "authority-secondary",
                Provider = "secondary-cloud-kms",
                Endpoint = "https://secondary-authority.example/release",
                KeyId = "projects/example/keys/k2"
            }
        }
    };

    private static Task<string> AttestationProviderAsync(
        DtaiAuthority authority,
        DtaiReleaseChallenge challenge,
        CancellationToken cancellationToken) =>
        Task.FromResult(
            $"attestation:{authority.Name}:{challenge.Nonce}:{challenge.Recipient.ComputeThumbprint()}");

    private static Task<DtaiReleaseResponse> ReleaseClientAsync(
        DtaiAuthority authority,
        DtaiReleaseRequest request,
        CancellationToken cancellationToken)
    {
        var thumbprint = request.Recipient.ComputeThumbprint();
        var expectedEvidence = $"attestation:{authority.Name}:{request.Nonce}:{thumbprint}";
        if (!string.Equals(request.AttestationEvidence, expectedEvidence, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Attestation evidence was not bound to the release challenge.");
        }

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = Base64Url.Decode(request.Recipient.N),
            Exponent = Base64Url.Decode(request.Recipient.E)
        });
        var ciphertext = rsa.Encrypt(Contributions[authority.Name!], RSAEncryptionPadding.OaepSHA256);

        return Task.FromResult(new DtaiReleaseResponse
        {
            Protocol = "DTAI-SKR-v1",
            Authority = authority.Name,
            Provider = authority.Provider,
            KeyId = authority.KeyId,
            Nonce = request.Nonce,
            RecipientThumbprint = thumbprint,
            IssuedAt = DateTimeOffset.UtcNow.ToString("o"),
            Ciphertext = Base64Url.Encode(ciphertext)
        });
    }

    private static void AssertHkdfMatchesRfc5869()
    {
        var ikm = new byte[22];
        Array.Fill(ikm, (byte)0x0b);
        var salt = Enumerable.Range(0x00, 13).Select(value => (byte)value).ToArray();
        var info = Enumerable.Range(0xf0, 10).Select(value => (byte)value).ToArray();
        var okm = DtaiHkdf.DeriveKey(ikm, salt, info, 42);
        AssertEqual(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            Convert.ToHexString(okm).ToLowerInvariant(),
            "HKDF output did not match RFC 5869.");
    }

    private static async Task AssertDerivationIsDeterministicAndBoundAsync()
    {
        var configuration = NewTestConfiguration();
        var dek1 = await DtaiKeyRelease.ReleaseAsync(
            configuration, "model://example/v1", AttestationProviderAsync, ReleaseClientAsync)
            .ConfigureAwait(false);
        var dek2 = await DtaiKeyRelease.ReleaseAsync(
            configuration, "model://example/v1", AttestationProviderAsync, ReleaseClientAsync)
            .ConfigureAwait(false);

        AssertEqual("32", dek1.Length.ToString(), "DEK length was incorrect.");
        AssertEqual(Convert.ToHexString(dek1), Convert.ToHexString(dek2), "Derivation was not deterministic.");
        if (Convert.ToHexString(dek1) == Convert.ToHexString(Contributions["authority-azure"]))
        {
            throw new InvalidOperationException("Derived DEK must not equal an individual contribution.");
        }

        var otherContext = await DtaiKeyRelease.ReleaseAsync(
            configuration, "model://example/v2", AttestationProviderAsync, ReleaseClientAsync)
            .ConfigureAwait(false);
        if (Convert.ToHexString(dek1) == Convert.ToHexString(otherContext))
        {
            throw new InvalidOperationException("Derived DEK must be bound to the model context.");
        }
    }

    private static void AssertConfigurationRules()
    {
        var nonPremium = NewTestConfiguration();
        nonPremium.Authorities[0].Sku = "Standard";
        AssertThrows(() => nonPremium.Validate(), "Azure Key Vault Premium");

        var sameProvider = NewTestConfiguration();
        sameProvider.Authorities[1].Provider = "azure-key-vault";
        AssertThrows(() => sameProvider.Validate(), "distinct names, providers");

        var httpEndpoint = NewTestConfiguration();
        httpEndpoint.Authorities[1].Endpoint = "http://secondary-authority.example/release";
        AssertThrows(() => httpEndpoint.Validate(), "HTTPS endpoint");

        var shortSalt = NewTestConfiguration();
        shortSalt.DerivationSalt = Convert.ToBase64String(new byte[15]);
        AssertThrows(() => shortSalt.Validate(), "at least 16 random bytes");
    }

    private static async Task AssertEnvelopeChecksAsync()
    {
        var configuration = NewTestConfiguration();

        await AssertThrowsAsync(
            () => DtaiKeyRelease.ReleaseAsync(
                configuration,
                "model://example/v1",
                AttestationProviderAsync,
                async (authority, request, cancellationToken) =>
                {
                    var response = await ReleaseClientAsync(authority, request, cancellationToken)
                        .ConfigureAwait(false);
                    response.IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-10).ToString("o");
                    return response;
                }),
            "stale release envelope").ConfigureAwait(false);

        await AssertThrowsAsync(
            () => DtaiKeyRelease.ReleaseAsync(
                configuration,
                "model://example/v1",
                AttestationProviderAsync,
                async (authority, request, cancellationToken) =>
                {
                    var response = await ReleaseClientAsync(authority, request, cancellationToken)
                        .ConfigureAwait(false);
                    response.Nonce = "different-nonce";
                    return response;
                }),
            "invalid or unbound release envelope").ConfigureAwait(false);

        await AssertThrowsAsync(
            () => DtaiKeyRelease.ReleaseAsync(
                configuration,
                "model://example/v1",
                AttestationProviderAsync,
                async (authority, request, cancellationToken) =>
                {
                    var response = await ReleaseClientAsync(authority, request, cancellationToken)
                        .ConfigureAwait(false);
                    response.Ciphertext = "not-base64url-ciphertext";
                    return response;
                }),
            "invalid ciphertext").ConfigureAwait(false);

        await AssertThrowsAsync(
            () => DtaiKeyRelease.ReleaseAsync(
                configuration,
                "model://example/v1",
                (authority, challenge, cancellationToken) => Task.FromResult(string.Empty),
                ReleaseClientAsync),
            "returned no evidence").ConfigureAwait(false);
    }

    private static void AssertEqual(string expected, string actual, string message)
    {
        if (!string.Equals(expected, actual, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{message} Expected '{expected}', got '{actual}'.");
        }
    }

    private static void AssertThrows(Action action, string expected)
    {
        try
        {
            action();
        }
        catch (Exception exception)
        {
            AssertMessageContains(exception, expected);
            return;
        }
        throw new InvalidOperationException($"Expected action to throw '{expected}'.");
    }

    private static async Task AssertThrowsAsync(Func<Task> action, string expected)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            AssertMessageContains(exception, expected);
            return;
        }
        throw new InvalidOperationException($"Expected action to throw '{expected}'.");
    }

    private static void AssertMessageContains(Exception exception, string expected)
    {
        if (!exception.Message.Contains(expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Expected error '{expected}', got '{exception.Message}'.");
        }
    }
}
