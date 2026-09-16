namespace Dtai.Agent.Tests;

using Dtai.Agent.Attestation;
using Xunit;

// Only the safety-critical, deterministic logic is covered: the config gate
// that decides demo vs. real, and that the default (unconfigured) state makes
// no real MAA/Key Vault calls. The networked release path is exercised by the
// end-to-end run documented in the README, not by unit tests.

public sealed class AttestationSettingsTests
{
    [Fact]
    public void Enabled_IsFalse_WhenUnconfigured()
    {
        var settings = new AttestationSettings();
        Assert.False(settings.Enabled);
    }

    [Fact]
    public void Enabled_IsTrue_WhenVaultAndKeySet()
    {
        var settings = new AttestationSettings { KeyVaultName = "v", KeyName = "k" };
        Assert.True(settings.Enabled);
    }

    [Theory]
    [InlineData("v", "")]
    [InlineData("", "k")]
    [InlineData("", "")]
    public void Enabled_IsFalse_WhenVaultOrKeyMissing(string vault, string key)
    {
        var settings = new AttestationSettings { KeyVaultName = vault, KeyName = key };
        Assert.False(settings.Enabled);
    }
}

public sealed class DemoModeProviderTests
{
    // Force demo mode by injecting an unconfigured settings object, so the test
    // is deterministic regardless of ambient config files or environment.
    private static readonly AttestationSettings Disabled = new();

    [Fact]
    public void Providers_ReturnDemoMarkers_AndMakeNoCalls()
    {
        var evidence = new TeeEvidenceProvider(Disabled).FetchEvidence();
        Assert.Equal("demo-only-tee-evidence", evidence.Value);

        var maaToken = new MaaAttestationService(Disabled).Attest(evidence);
        Assert.Equal("demo-only-maa-token", maaToken.Value);

        var k1 = new KeyVaultKeyProvider(Disabled).GetK1(maaToken);
        Assert.Equal("demo-only-k1-reference", k1.Value);

        var itaToken = new ItaAttestationService().Attest(evidence);
        Assert.Equal("demo-only-ita-token", itaToken.Value);

        var k2 = new HashicorpKeyProvider().GetK2(itaToken);
        Assert.Equal("demo-only-k2-reference", k2.Value);
    }
}

public sealed class AttestationTypeDispatchTests
{
    private static AttestationSettings Enabled(string attestationType) =>
        new() { KeyVaultName = "v", KeyName = "k", AttestationType = attestationType };

    [Fact]
    public void FetchEvidence_PacksTdxEvidence()
    {
        var evidence = new TeeEvidenceProvider(Enabled(AttestationTypes.TdxVm)).FetchEvidence();
        Assert.Contains("\"kind\":\"TdxVm\"", evidence.Value);
        Assert.Contains("\"quote\":", evidence.Value);
        Assert.Contains("\"runtimeData\":", evidence.Value);
    }

    [Fact]
    public void FetchEvidence_Throws_ForUnsupportedType()
    {
        var provider = new TeeEvidenceProvider(Enabled(AttestationTypes.AzureGuest));
        Assert.Throws<NotSupportedException>(() => provider.FetchEvidence());
    }

    [Fact]
    public void Attest_Throws_ForUnsupportedType()
    {
        var service = new MaaAttestationService(Enabled(AttestationTypes.AzureGuest));
        Assert.Throws<NotSupportedException>(() => service.Attest(new TeeEvidence("{}")));
    }

    [Fact]
    public void AttestationApiVersion_DefaultsTo_2025_06_01()
    {
        Assert.Equal("2025-06-01", new AttestationSettings().AttestationApiVersion);
    }
}
