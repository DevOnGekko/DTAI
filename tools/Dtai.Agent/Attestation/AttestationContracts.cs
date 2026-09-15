namespace Dtai.Agent.Attestation;

public sealed record TeeEvidence(string Value);

public sealed record AttestationToken(string Value);

public sealed record KeyReference(string Value);

public sealed record KeyRetrievalResult(KeyReference K1, KeyReference K2);

public interface ITeeEvidenceProvider
{
    TeeEvidence FetchEvidence();
}

public interface IMaaAttestationService
{
    AttestationToken Attest(TeeEvidence evidence);
}

public interface IKeyVaultKeyProvider
{
    KeyReference GetK1(AttestationToken token);
}

public interface IItaAttestationService
{
    AttestationToken Attest(TeeEvidence evidence);
}

public interface IHashicorpKeyProvider
{
    KeyReference GetK2(AttestationToken token);
}
