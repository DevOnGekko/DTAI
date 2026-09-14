using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Dtai;

/// <summary>Orchestrates a two-authority DTAI secure key release inside a TEE.</summary>
public static class DtaiKeyRelease
{
    private const int ContributionLength = 32;

    private static readonly Regex CiphertextPattern =
        new("^[A-Za-z0-9_-]{512}$", RegexOptions.CultureInvariant);

    private static readonly HttpClient SharedHttpClient = new()
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    /// <summary>
    /// Requests both contributions, validates their release envelopes, unwraps them with the
    /// ephemeral recipient key, and derives the 256-bit model DEK.
    /// </summary>
    public static async Task<byte[]> ReleaseAsync(
        DtaiConfiguration configuration,
        string context,
        DtaiAttestationProvider attestationProvider,
        DtaiReleaseClient? releaseClient = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);
        ArgumentNullException.ThrowIfNull(attestationProvider);

        configuration.Validate();
        if (context.Length > 1024)
        {
            throw new DtaiException("Context must not exceed 1024 characters.");
        }
        releaseClient ??= PostReleaseRequestAsync;

        using var rsa = RSA.Create(3072);
        var contributions = new List<byte[]>();
        try
        {
            var parameters = rsa.ExportParameters(false);
            var recipient = new DtaiRecipientJwk
            {
                N = Base64Url.Encode(parameters.Modulus!),
                E = Base64Url.Encode(parameters.Exponent!)
            };
            var thumbprint = recipient.ComputeThumbprint();

            foreach (var authority in configuration.Authorities)
            {
                var nonceBytes = RandomNumberGenerator.GetBytes(32);
                var nonce = Base64Url.Encode(nonceBytes);
                CryptographicOperations.ZeroMemory(nonceBytes);

                var challenge = new DtaiReleaseChallenge
                {
                    KeyId = authority.KeyId!,
                    Nonce = nonce,
                    Context = context,
                    Recipient = recipient
                };
                var evidence = await attestationProvider(authority, challenge, cancellationToken)
                    .ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(evidence))
                {
                    throw new DtaiException(
                        $"Attestation provider returned no evidence for authority '{authority.Name}'.");
                }
                if (Encoding.UTF8.GetByteCount(evidence) > 1024 * 1024)
                {
                    throw new DtaiException(
                        $"Attestation evidence for authority '{authority.Name}' exceeds 1 MiB.");
                }

                var request = new DtaiReleaseRequest
                {
                    KeyId = authority.KeyId!,
                    Nonce = nonce,
                    Context = context,
                    AttestationEvidence = evidence,
                    Recipient = recipient
                };
                var response = await releaseClient(authority, request, cancellationToken)
                    .ConfigureAwait(false);

                ValidateEnvelope(configuration, authority, response, nonce, thumbprint);
                contributions.Add(Unwrap(rsa, authority, response!.Ciphertext!));
            }

            return DeriveKey(configuration, context, contributions);
        }
        finally
        {
            foreach (var contribution in contributions)
            {
                CryptographicOperations.ZeroMemory(contribution);
            }
        }
    }

    private static void ValidateEnvelope(
        DtaiConfiguration configuration,
        DtaiAuthority authority,
        DtaiReleaseResponse? response,
        string nonce,
        string thumbprint)
    {
        if (response is null ||
            !string.Equals(response.Protocol, DtaiProtocol.Version, StringComparison.Ordinal) ||
            !string.Equals(response.Authority, authority.Name, StringComparison.Ordinal) ||
            !string.Equals(response.Provider, authority.Provider, StringComparison.Ordinal) ||
            !string.Equals(response.KeyId, authority.KeyId, StringComparison.Ordinal) ||
            !string.Equals(response.Nonce, nonce, StringComparison.Ordinal) ||
            !string.Equals(response.RecipientThumbprint, thumbprint, StringComparison.Ordinal))
        {
            throw new DtaiException(
                $"Authority '{authority.Name}' returned an invalid or unbound release envelope.");
        }

        if (!DateTimeOffset.TryParse(
                response.IssuedAt,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var issuedAt))
        {
            throw new DtaiException(
                $"Authority '{authority.Name}' returned an invalid or unbound release envelope.");
        }

        var age = DateTimeOffset.UtcNow - issuedAt;
        if (age.TotalSeconds < -30 || age.TotalSeconds > configuration.Security!.MaxReleaseAgeSeconds)
        {
            throw new DtaiException($"Authority '{authority.Name}' returned a stale release envelope.");
        }

        if (response.Ciphertext is null || !CiphertextPattern.IsMatch(response.Ciphertext))
        {
            throw new DtaiException($"Authority '{authority.Name}' returned invalid ciphertext.");
        }
    }

    private static byte[] Unwrap(RSA rsa, DtaiAuthority authority, string ciphertextValue)
    {
        var ciphertext = Base64Url.Decode(ciphertextValue);
        byte[] contribution;
        try
        {
            contribution = rsa.Decrypt(ciphertext, RSAEncryptionPadding.OaepSHA256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }

        if (contribution.Length != ContributionLength)
        {
            CryptographicOperations.ZeroMemory(contribution);
            throw new DtaiException(
                $"Authority '{authority.Name}' contribution must be exactly 32 bytes.");
        }
        return contribution;
    }

    private static byte[] DeriveKey(
        DtaiConfiguration configuration,
        string context,
        List<byte[]> contributions)
    {
        var ikm = new byte[ContributionLength * 2];
        var authorityBinding = string.Join(
            "|",
            configuration.Authorities.Select(authority => $"{authority.Provider}:{authority.KeyId}"));
        var info = Encoding.UTF8.GetBytes($"DTAI-DEK-v1\0{context}\0{authorityBinding}");
        var salt = Convert.FromBase64String(configuration.DerivationSalt!);
        try
        {
            contributions[0].CopyTo(ikm, 0);
            contributions[1].CopyTo(ikm, ContributionLength);
            return DtaiHkdf.DeriveKey(ikm, salt, info, ContributionLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikm);
            CryptographicOperations.ZeroMemory(info);
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    private static async Task<DtaiReleaseResponse> PostReleaseRequestAsync(
        DtaiAuthority authority,
        DtaiReleaseRequest request,
        CancellationToken cancellationToken)
    {
        using var response = await SharedHttpClient
            .PostAsJsonAsync(authority.Endpoint, request, cancellationToken)
            .ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await response.Content
            .ReadFromJsonAsync<DtaiReleaseResponse>(cancellationToken)
            .ConfigureAwait(false)
            ?? throw new DtaiException($"Authority '{authority.Name}' returned an empty response.");
    }
}
