using System.Text.Json;

namespace Dtai;

/// <summary>A single independently administered key release authority.</summary>
public sealed class DtaiAuthority
{
    public string? Name { get; set; }

    public string? Provider { get; set; }

    public string? Sku { get; set; }

    public string? Endpoint { get; set; }

    public string? KeyId { get; set; }

    /// <summary>AWS region, required when <see cref="Provider"/> is <c>aws-kms</c>.</summary>
    public string? Region { get; set; }

    /// <summary>
    /// AWS SigV4 signing service name fronting the release endpoint. Optional; defaults to
    /// <c>execute-api</c>.
    /// </summary>
    public string? SigningService { get; set; }

    /// <summary>
    /// Google workload identity token audience, required when <see cref="Provider"/> is
    /// <c>google-cloud-kms</c>.
    /// </summary>
    public string? GoogleAudience { get; set; }
}

/// <summary>Security constraints applied to every release.</summary>
public sealed class DtaiSecurity
{
    public int MaxReleaseAgeSeconds { get; set; }

    public IReadOnlyList<string> AllowedTeeTypes { get; set; } = Array.Empty<string>();
}

/// <summary>Two-authority DTAI configuration.</summary>
public sealed class DtaiConfiguration
{
    public int SchemaVersion { get; set; }

    public string? DerivationSalt { get; set; }

    public DtaiSecurity? Security { get; set; }

    public IReadOnlyList<DtaiAuthority> Authorities { get; set; } = Array.Empty<DtaiAuthority>();

    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>Reads and validates a configuration document.</summary>
    public static DtaiConfiguration Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var configuration = JsonSerializer.Deserialize<DtaiConfiguration>(File.ReadAllText(path), ReadOptions)
            ?? throw new DtaiException("Configuration document is empty.");
        configuration.Validate();
        return configuration;
    }

    /// <summary>Throws when the configuration violates a DTAI deployment requirement.</summary>
    public void Validate() => DtaiConfigurationValidator.Validate(this);
}

/// <summary>Error raised when a DTAI requirement is violated.</summary>
public class DtaiException : Exception
{
    public DtaiException(string message)
        : base(message)
    {
    }

    public DtaiException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>Validates DTAI configuration against the deployment requirements.</summary>
public static class DtaiConfigurationValidator
{
    public static readonly IReadOnlyList<string> SupportedTeeTypes =
        new[] { "IntelTDX", "AMD-SEV-SNP", "AzureConfidentialVM" };

    public static void Validate(DtaiConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        if (configuration.SchemaVersion != 1)
        {
            throw new DtaiException("Configuration SchemaVersion must be 1.");
        }
        if (configuration.Authorities.Count != 2)
        {
            throw new DtaiException("DTAI requires exactly two key authorities.");
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        var providers = new HashSet<string>(StringComparer.Ordinal);
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var authority in configuration.Authorities)
        {
            foreach (var (property, value) in new[]
                     {
                         ("Name", authority.Name),
                         ("Provider", authority.Provider),
                         ("Endpoint", authority.Endpoint),
                         ("KeyId", authority.KeyId)
                     })
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new DtaiException($"Authority property '{property}' is required.");
                }
            }

            if (!Uri.TryCreate(authority.Endpoint, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                throw new DtaiException($"Authority '{authority.Name}' must use an HTTPS endpoint.");
            }
            if (!names.Add(authority.Name!) || !providers.Add(authority.Provider!) || !hosts.Add(uri.DnsSafeHost))
            {
                throw new DtaiException("Authorities must have distinct names, providers, and endpoint hosts.");
            }

            if (authority.Provider == DtaiAwsAuthority.Provider)
            {
                DtaiAwsAuthority.Validate(authority);
            }
            if (authority.Provider == DtaiGoogleAuthority.Provider)
            {
                DtaiGoogleAuthority.Validate(authority);
            }
        }

        var azure = configuration.Authorities
            .Where(authority => authority.Provider == "azure-key-vault")
            .ToList();
        if (azure.Count != 1 || azure[0].Sku != "Premium")
        {
            throw new DtaiException("Exactly one authority must use an Azure Key Vault Premium key.");
        }

        var security = configuration.Security
            ?? throw new DtaiException("Configuration Security section is required.");
        if (security.MaxReleaseAgeSeconds < 30 || security.MaxReleaseAgeSeconds > 900)
        {
            throw new DtaiException("MaxReleaseAgeSeconds must be between 30 and 900.");
        }
        if (security.AllowedTeeTypes.Count == 0)
        {
            throw new DtaiException("At least one allowed TEE type is required.");
        }
        foreach (var teeType in security.AllowedTeeTypes)
        {
            if (!SupportedTeeTypes.Contains(teeType, StringComparer.Ordinal))
            {
                throw new DtaiException($"Unsupported TEE type '{teeType}'.");
            }
        }

        byte[] salt;
        try
        {
            salt = Convert.FromBase64String(configuration.DerivationSalt ?? string.Empty);
        }
        catch (FormatException exception)
        {
            throw new DtaiException("DerivationSalt must be valid Base64.", exception);
        }
        if (salt.Length < 16)
        {
            throw new DtaiException("DerivationSalt must contain at least 16 random bytes.");
        }
    }
}
