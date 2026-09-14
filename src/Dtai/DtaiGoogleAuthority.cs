using System.Net.Http.Headers;
using System.Text.RegularExpressions;

namespace Dtai;

/// <summary>Google Cloud KMS-specific authority operations for the secondary trust authority.</summary>
public static partial class DtaiGoogleAuthority
{
    /// <summary>Provider value selecting the Google Cloud KMS authority operations.</summary>
    public const string Provider = "google-cloud-kms";

    [GeneratedRegex(
        @"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[^/]+$",
        RegexOptions.CultureInvariant)]
    private static partial Regex KeyIdPattern();

    /// <summary>Throws when a <c>google-cloud-kms</c> authority is not deployable.</summary>
    public static void Validate(DtaiAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        if (!KeyIdPattern().IsMatch(authority.KeyId ?? string.Empty))
        {
            throw new DtaiException(
                $"Google Cloud KMS authority '{authority.Name}' KeyId must identify a crypto key version.");
        }
        if (!Uri.TryCreate(authority.GoogleAudience, UriKind.Absolute, out var audience) ||
            audience.Scheme != Uri.UriSchemeHttps)
        {
            throw new DtaiException(
                $"Google Cloud KMS authority '{authority.Name}' requires an HTTPS GoogleAudience.");
        }
    }

    /// <summary>Obtains a Google workload identity token for the authority release service.</summary>
    public static async Task<string> GetIdentityTokenAsync(
        DtaiAuthority authority,
        HttpClient httpClient,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(httpClient);

        var audience = Uri.EscapeDataString(authority.GoogleAudience!);
        var metadataUri = new Uri(
            $"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={audience}&format=full");
        using var request = new HttpRequestMessage(HttpMethod.Get, metadataUri);
        request.Headers.Add("Metadata-Flavor", "Google");
        using var response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var token = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new DtaiException(
                $"Google identity token provider returned no token for authority '{authority.Name}'.");
        }
        return token;
    }

    /// <summary>Adds the Google workload identity token as bearer authentication.</summary>
    public static void AddBearerToken(HttpRequestMessage request, string token)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }
}
