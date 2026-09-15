namespace Dtai.Agent.Attestation;

// These stubs perform no service calls. Their results are demo markers, not valid evidence, tokens, or keys.
public sealed class TeeEvidenceProvider : ITeeEvidenceProvider
{
    public TeeEvidence FetchEvidence()
    {
        // TODO: Implement a separate provider that collects actual evidence from the CVM's TEE.
        return new TeeEvidence("demo-only-tee-evidence");
    }
}

public sealed class MaaAttestationService : IMaaAttestationService
{
    public AttestationToken Attest(TeeEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        // TODO: Implement a separate service that submits evidence to MAA and validates the returned token.
        return new AttestationToken("demo-only-maa-token");
    }
}

public sealed class KeyVaultKeyProvider : IKeyVaultKeyProvider
{
    public KeyReference GetK1(AttestationToken token)
    {
        ArgumentNullException.ThrowIfNull(token);
        // TODO: Implement a separate provider that requests authorized access to K1 using the MAA token.
        return new KeyReference("demo-only-k1-reference");
    }
}

public sealed class ItaAttestationService : IItaAttestationService
{
    public AttestationToken Attest(TeeEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        // TODO: Implement a separate service that submits evidence to ITA and validates the returned token.
        return new AttestationToken("demo-only-ita-token");
    }
}

public sealed class HashicorpKeyProvider : IHashicorpKeyProvider
{
    public KeyReference GetK2(AttestationToken token)
    {
        ArgumentNullException.ThrowIfNull(token);
        // TODO: Implement a separate provider that requests authorized access to K2 using the ITA token.
        return new KeyReference("demo-only-k2-reference");
    }
}
