using System.Security.Cryptography;
using System.Text;
using Dtai;

namespace Dtai.Tests;

/// <summary>Dependency-free focused tests for the DTAI C# library.</summary>
public static class Program
{
    public static async Task<int> Main()
    {
        var configuration = NewTestConfiguration();
        configuration.Validate();

        AssertHkdfMatchesRfc5869();
        await AssertFileEncryptionAsync().ConfigureAwait(false);
        await AssertDerivationIsDeterministicAndBoundAsync().ConfigureAwait(false);
        AssertConfigurationRules();
        AssertAzureConfigurationRules();
        await AssertEnvelopeChecksAsync().ConfigureAwait(false);
        await AssertAwsAuthorityAsync().ConfigureAwait(false);
        AssertAwsConfigurationRules();
        AssertGoogleConfigurationRules();
        await AssertGoogleAuthorityAsync().ConfigureAwait(false);
        AssertAwsSigV4Vectors();
        AssertAwsSigV4SignsRequestMessages();
        AssertAwsCredentialsAreRequired();

        Console.WriteLine("All DTAI tests passed.");
        return 0;
    }

    private static readonly Dictionary<string, byte[]> Contributions = new()
    {
        ["authority-azure"] = Enumerable.Range(1, 32).Select(value => (byte)value).ToArray(),
        ["authority-secondary"] = Enumerable.Range(33, 32).Select(value => (byte)value).ToArray(),
        ["authority-aws"] = Enumerable.Range(65, 32).Select(value => (byte)value).ToArray(),
        ["authority-google"] = Enumerable.Range(97, 32).Select(value => (byte)value).ToArray()
    };

    private const string AwsKeyArn =
        "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555";

    private static DtaiConfiguration NewAwsTestConfiguration(
        string region = "us-east-1",
        string keyId = AwsKeyArn,
        string? signingService = null)
    {
        var configuration = NewTestConfiguration();
        configuration.Authorities = new[]
        {
            configuration.Authorities[0],
            new DtaiAuthority
            {
                Name = "authority-aws",
                Provider = "aws-kms",
                Region = region,
                SigningService = signingService,
                Endpoint = "https://aws-authority.example/v1/release",
                KeyId = keyId
            }
        };
        return configuration;
    }

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

    private static DtaiConfiguration NewGoogleTestConfiguration(
        string keyId =
            "projects/example/locations/us-central1/keyRings/dtai/cryptoKeys/contribution/cryptoKeyVersions/1",
        string audience = "https://google-authority.example")
    {
        var configuration = NewTestConfiguration();
        configuration.Authorities = new[]
        {
            configuration.Authorities[0],
            new DtaiAuthority
            {
                Name = "authority-google",
                Provider = DtaiGoogleAuthority.Provider,
                Endpoint = "https://google-authority.example/v1/release",
                GoogleAudience = audience,
                KeyId = keyId
            }
        };
        return configuration;
    }

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

    private static async Task AssertFileEncryptionAsync()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var expected = RandomNumberGenerator.GetBytes(150_000);
        await using var input = new MemoryStream(expected);
        await using var encrypted = new MemoryStream();
        await DtaiFileEncryption
            .EncryptAsync(input, encrypted, key, "model://example/v1")
            .ConfigureAwait(false);

        encrypted.Position = 0;
        await using var decrypted = new MemoryStream();
        await DtaiFileEncryption
            .DecryptAsync(encrypted, decrypted, key, "model://example/v1")
            .ConfigureAwait(false);
        AssertEqual(
            Convert.ToHexString(expected),
            Convert.ToHexString(decrypted.ToArray()),
            "File encryption did not round trip.");

        var tampered = encrypted.ToArray();
        tampered[^1] ^= 1;
        await AssertThrowsAsync(
                async () =>
                {
                    await using var tamperedInput = new MemoryStream(tampered);
                    await using var output = new MemoryStream();
                    await DtaiFileEncryption
                        .DecryptAsync(tamperedInput, output, key, "model://example/v1")
                        .ConfigureAwait(false);
                },
                "authentication tag")
            .ConfigureAwait(false);

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(expected);
        CryptographicOperations.ZeroMemory(tampered);
    }

    private static void AssertAzureConfigurationRules()
    {
        NewTestConfiguration().Validate();

        var invalidHost = NewTestConfiguration();
        invalidHost.Authorities[0].KeyId = "https://example.com/keys/k1/version";
        AssertThrows(() => invalidHost.Validate(), "Azure Key Vault HTTPS URL");

        var unversioned = NewTestConfiguration();
        unversioned.Authorities[0].KeyId = "https://vault.vault.azure.net/keys/k1";
        AssertThrows(() => unversioned.Validate(), "versioned key");
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

    private static async Task AssertAwsAuthorityAsync()
    {
        var configuration = NewAwsTestConfiguration();
        configuration.Validate();

        var dek = await DtaiKeyRelease.ReleaseAsync(
            configuration, "model://example/v1", AttestationProviderAsync, ReleaseClientAsync)
            .ConfigureAwait(false);
        AssertEqual("32", dek.Length.ToString(), "AWS authority DEK length was incorrect.");

        var secondary = await DtaiKeyRelease.ReleaseAsync(
            NewTestConfiguration(), "model://example/v1", AttestationProviderAsync, ReleaseClientAsync)
            .ConfigureAwait(false);
        if (Convert.ToHexString(dek) == Convert.ToHexString(secondary))
        {
            throw new InvalidOperationException("Authority binding must change the derived DEK.");
        }
    }

    private static void AssertAwsConfigurationRules()
    {
        AssertThrows(
            () => NewAwsTestConfiguration(region: "useast1").Validate(),
            "valid Region");

        AssertThrows(
            () => NewAwsTestConfiguration(keyId: "alias/dtai-k2").Validate(),
            "KMS key or alias ARN");

        AssertThrows(
            () => NewAwsTestConfiguration(
                keyId: "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555")
                .Validate(),
            "KeyId region must match");

        AssertThrows(
            () => NewAwsTestConfiguration(signingService: "Execute API").Validate(),
            "SigningService is invalid");
    }

    private static void AssertGoogleConfigurationRules()
    {
        NewGoogleTestConfiguration().Validate();

        AssertThrows(
            () => NewGoogleTestConfiguration(keyId: "projects/example/keys/k2").Validate(),
            "crypto key version");

        AssertThrows(
            () => NewGoogleTestConfiguration(audience: "http://google-authority.example").Validate(),
            "HTTPS GoogleAudience");
    }

    private static async Task AssertGoogleAuthorityAsync()
    {
        var authority = NewGoogleTestConfiguration().Authorities[1];
        var handler = new TestHttpMessageHandler(_ => new HttpResponseMessage
        {
            Content = new StringContent(" identity-token \n")
        });
        using var httpClient = new HttpClient(handler);
        var token = await DtaiGoogleAuthority
            .GetIdentityTokenAsync(authority, httpClient, CancellationToken.None)
            .ConfigureAwait(false);

        AssertEqual("identity-token", token, "Google identity token was incorrect.");
        AssertEqual(
            "Google",
            handler.Request!.Headers.GetValues("Metadata-Flavor").Single(),
            "Google metadata request header was missing.");
        AssertEqual(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https%3A%2F%2Fgoogle-authority.example&format=full",
            handler.Request.RequestUri!.AbsoluteUri,
            "Google metadata request URI was incorrect.");

        using var request = new HttpRequestMessage();
        DtaiGoogleAuthority.AddBearerToken(request, token);
        AssertEqual("Bearer", request.Headers.Authorization!.Scheme, "Google release request scheme was incorrect.");
        AssertEqual(token, request.Headers.Authorization.Parameter!, "Google release request token was missing.");
    }

    private static void AssertAwsSigV4Vectors()
    {
        var timestamp = new DateTimeOffset(2026, 9, 14, 16, 27, 20, TimeSpan.Zero);
        var credentials = new AwsCredentials(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

        var signed = AwsSigV4.CreateSignedHeaders(
            "POST",
            new Uri("https://kms.us-east-1.amazonaws.com/"),
            "us-east-1",
            "kms",
            credentials,
            Encoding.UTF8.GetBytes("{\"a\":1}"),
            timestamp: timestamp);
        AssertEqual("20260914T162720Z", signed[AwsSigV4.DateHeader], "SigV4 request date was incorrect.");
        AssertEqual(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260914/us-east-1/kms/aws4_request, " +
            "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, " +
            "Signature=0278237eae5d08c2474a50b9f7936e84e1188dcd611f33280f054078d5cec75c",
            signed["Authorization"],
            "SigV4 authorization header did not match the expected signature.");
        if (signed.ContainsKey(AwsSigV4.SecurityTokenHeader))
        {
            throw new InvalidOperationException(
                "SigV4 headers must omit the security token when no session token is used.");
        }

        var sessionSigned = AwsSigV4.CreateSignedHeaders(
            "POST",
            new Uri("https://api.example.com/v1/release"),
            "eu-west-2",
            "execute-api",
            credentials with { SessionToken = "session-token-value" },
            Encoding.UTF8.GetBytes("{\"protocol\":\"DTAI-SKR-v1\"}"),
            timestamp: timestamp);
        AssertEqual(
            "session-token-value",
            sessionSigned[AwsSigV4.SecurityTokenHeader],
            "SigV4 headers must forward the session token.");
        AssertEqual(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260914/eu-west-2/execute-api/aws4_request, " +
            "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, " +
            "Signature=fbff628d14207784e8c02eb9c5988b7e2068ab4749c9090ad52c0f7116893b70",
            sessionSigned["Authorization"],
            "SigV4 authorization header with a session token was incorrect.");
    }

    private static void AssertAwsSigV4SignsRequestMessages()
    {
        var payload = Encoding.UTF8.GetBytes("{\"protocol\":\"DTAI-SKR-v1\"}");
        var timestamp = new DateTimeOffset(2026, 9, 14, 16, 27, 20, TimeSpan.Zero);
        var credentials = new AwsCredentials(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "session-token-value");

        using var message = new HttpRequestMessage(
            HttpMethod.Post,
            "https://api.example.com/v1/release");
        AwsSigV4.Sign(message, "eu-west-2", "execute-api", credentials, payload, timestamp: timestamp);

        var expected = AwsSigV4.CreateSignedHeaders(
            "POST",
            new Uri("https://api.example.com/v1/release"),
            "eu-west-2",
            "execute-api",
            credentials,
            payload,
            timestamp: timestamp);
        foreach (var (name, value) in expected)
        {
            if (!message.Headers.TryGetValues(name, out var values) ||
                !string.Equals(string.Join(string.Empty, values), value, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Signed request message is missing header '{name}'.");
            }
        }
    }

    private static void AssertAwsCredentialsAreRequired()
    {
        var accessKeyId = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
        var secretAccessKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
        try
        {
            Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", null);
            Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", null);
            AssertThrows(
                () => AwsCredentials.FromEnvironment("authority-aws"),
                "AWS_ACCESS_KEY_ID");
        }
        finally
        {
            Environment.SetEnvironmentVariable("AWS_ACCESS_KEY_ID", accessKeyId);
            Environment.SetEnvironmentVariable("AWS_SECRET_ACCESS_KEY", secretAccessKey);
        }
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

    private sealed class TestHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> responseFactory;

        public TestHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory) =>
            this.responseFactory = responseFactory;

        public HttpRequestMessage? Request { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(responseFactory(request));
        }
    }
}
