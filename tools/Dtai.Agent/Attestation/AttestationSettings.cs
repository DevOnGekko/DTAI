namespace Dtai.Agent.Attestation;

using System.Text.Json;

// Test-only configuration for the real MAA + Azure Key Vault Secure Key Release
// path. Committed defaults contain NO subscription, tenant, or vault names.
// Put real values in attestation.settings.local.json (git-ignored) or environment
// variables (DTAI_ATTESTATION_*). When no vault/key is set, providers stay in
// demo mode and make no network calls.
public sealed class AttestationSettings
{
    public string MaaEndpoint { get; set; } = "sharedwus.wus.attest.azure.net";

    public string AttestationType { get; set; } = "TdxVm";

    public string KeyVaultName { get; set; } = string.Empty;

    public string KeyName { get; set; } = string.Empty;

    public string KeyVersion { get; set; } = string.Empty;

    public string KeyVaultApiVersion { get; set; } = "7.4";

    public string TenantId { get; set; } = string.Empty;

    public string AttestationApiVersion { get; set; } = "2025-06-01";

    // Real MAA/Key Vault calls run only when a vault and key are configured.
    public bool Enabled =>
        !string.IsNullOrWhiteSpace(KeyVaultName) && !string.IsNullOrWhiteSpace(KeyName);

    public static AttestationSettings Load()
    {
        var settings = new AttestationSettings();

        // Optional local override (git-ignored); base defaults live in this class.
        var path = Path.Combine(AppContext.BaseDirectory, "attestation.settings.local.json");
        if (File.Exists(path))
        {
            var loaded = JsonSerializer.Deserialize<AttestationSettings>(
                File.ReadAllText(path),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (loaded is not null)
            {
                settings.MergeFrom(loaded);
            }
        }

        settings.ApplyEnvironmentOverrides();
        return settings;
    }

    private void MergeFrom(AttestationSettings other)
    {
        if (!string.IsNullOrWhiteSpace(other.MaaEndpoint)) { MaaEndpoint = other.MaaEndpoint; }
        if (!string.IsNullOrWhiteSpace(other.AttestationType)) { AttestationType = other.AttestationType; }
        if (!string.IsNullOrWhiteSpace(other.AttestationApiVersion)) { AttestationApiVersion = other.AttestationApiVersion; }
        if (!string.IsNullOrWhiteSpace(other.KeyVaultName)) { KeyVaultName = other.KeyVaultName; }
        if (!string.IsNullOrWhiteSpace(other.KeyName)) { KeyName = other.KeyName; }
        if (!string.IsNullOrWhiteSpace(other.KeyVersion)) { KeyVersion = other.KeyVersion; }
        if (!string.IsNullOrWhiteSpace(other.KeyVaultApiVersion)) { KeyVaultApiVersion = other.KeyVaultApiVersion; }
        if (!string.IsNullOrWhiteSpace(other.TenantId)) { TenantId = other.TenantId; }
    }

    private void ApplyEnvironmentOverrides()
    {
        MaaEndpoint = EnvOrDefault("DTAI_ATTESTATION_MAAENDPOINT", MaaEndpoint);
        AttestationType = EnvOrDefault("DTAI_ATTESTATION_TYPE", AttestationType);
        KeyVaultName = EnvOrDefault("DTAI_ATTESTATION_KEYVAULTNAME", KeyVaultName);
        KeyName = EnvOrDefault("DTAI_ATTESTATION_KEYNAME", KeyName);
        KeyVersion = EnvOrDefault("DTAI_ATTESTATION_KEYVERSION", KeyVersion);
        TenantId = EnvOrDefault("DTAI_ATTESTATION_TENANTID", TenantId);
    }

    private static string EnvOrDefault(string variable, string fallback)
    {
        var value = Environment.GetEnvironmentVariable(variable);
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }
}

// MAA attest path segments per TEE type (the {type} in /attest/{type}). Only
// SevSnpVm has bundled evidence and a request builder today; the others are the
// documented extension points for the TEE types DTAI targets.
public static class AttestationTypes
{
    public const string SevSnpVm = "SevSnpVm";
    public const string TdxVm = "TdxVm";
    public const string AzureGuest = "AzureGuest";
}

