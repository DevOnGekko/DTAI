using System.Text.RegularExpressions;

namespace Dtai;

/// <summary>Google Cloud-specific operations for the secondary trust authority.</summary>
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
                $"Google Cloud KMS authority '{authority.Name}' must specify an HTTPS GoogleAudience.");
        }
    }
}
