using System.Text.RegularExpressions;

namespace Dtai;

/// <summary>AWS-specific authority operations for the secondary trust authority.</summary>
public static partial class DtaiAwsAuthority
{
    /// <summary>Provider value selecting the AWS KMS authority operations.</summary>
    public const string Provider = "aws-kms";

    /// <summary>Signing service used when an authority does not specify one.</summary>
    public const string DefaultSigningService = "execute-api";

    [GeneratedRegex(@"^[a-z]{2}(-[a-z]+)+-\d$", RegexOptions.CultureInvariant)]
    private static partial Regex RegionPattern();

    [GeneratedRegex(
        @"^arn:aws[a-z-]*:kms:(?<region>[a-z0-9-]+):\d{12}:(key/|alias/).+$",
        RegexOptions.CultureInvariant)]
    private static partial Regex KeyArnPattern();

    [GeneratedRegex("^[a-z0-9-]{2,32}$", RegexOptions.CultureInvariant)]
    private static partial Regex SigningServicePattern();

    /// <summary>Throws when an <c>aws-kms</c> authority is not deployable.</summary>
    public static void Validate(DtaiAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        var region = authority.Region;
        if (string.IsNullOrWhiteSpace(region) || !RegionPattern().IsMatch(region))
        {
            throw new DtaiException(
                $"AWS authority '{authority.Name}' requires a valid Region such as 'us-east-1'.");
        }

        var keyArn = KeyArnPattern().Match(authority.KeyId ?? string.Empty);
        if (!keyArn.Success)
        {
            throw new DtaiException(
                $"AWS authority '{authority.Name}' KeyId must be an AWS KMS key or alias ARN.");
        }
        if (!string.Equals(keyArn.Groups["region"].Value, region, StringComparison.Ordinal))
        {
            throw new DtaiException(
                $"AWS authority '{authority.Name}' KeyId region must match Region '{region}'.");
        }

        if (authority.SigningService is not null &&
            !SigningServicePattern().IsMatch(authority.SigningService))
        {
            throw new DtaiException(
                $"AWS authority '{authority.Name}' SigningService is invalid.");
        }
    }

    /// <summary>Returns the signing service for an authority, defaulting to API Gateway.</summary>
    public static string GetSigningService(DtaiAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        return string.IsNullOrWhiteSpace(authority.SigningService)
            ? DefaultSigningService
            : authority.SigningService;
    }
}
