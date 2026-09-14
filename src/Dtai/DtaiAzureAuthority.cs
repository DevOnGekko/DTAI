namespace Dtai;

/// <summary>Azure Key Vault-specific authority validation.</summary>
public static class DtaiAzureAuthority
{
    public const string Provider = "azure-key-vault";

    public static void Validate(DtaiAuthority authority)
    {
        ArgumentNullException.ThrowIfNull(authority);

        if (!string.Equals(authority.Sku, "Premium", StringComparison.Ordinal))
        {
            throw new DtaiException(
                $"Azure Key Vault Premium authority '{authority.Name}' requires the Premium SKU.");
        }

        if (!Uri.TryCreate(authority.KeyId, UriKind.Absolute, out var keyUri) ||
            keyUri.Scheme != Uri.UriSchemeHttps ||
            !keyUri.DnsSafeHost.EndsWith(".vault.azure.net", StringComparison.OrdinalIgnoreCase))
        {
            throw new DtaiException(
                $"Azure authority '{authority.Name}' KeyId must be an Azure Key Vault HTTPS URL.");
        }

        var segments = keyUri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length != 3 ||
            !string.Equals(segments[0], "keys", StringComparison.Ordinal) ||
            segments[1].Length == 0 ||
            segments[2].Length == 0)
        {
            throw new DtaiException(
                $"Azure authority '{authority.Name}' KeyId must identify a versioned key.");
        }
    }
}
