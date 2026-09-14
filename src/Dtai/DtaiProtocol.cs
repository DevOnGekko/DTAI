using System.Text.Json.Serialization;

namespace Dtai;

/// <summary>Challenge handed to the attestation provider for signing.</summary>
public sealed class DtaiReleaseChallenge
{
    [JsonPropertyName("protocol")]
    public string Protocol { get; init; } = DtaiProtocol.Version;

    [JsonPropertyName("keyId")]
    public string KeyId { get; init; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; init; } = string.Empty;

    [JsonPropertyName("context")]
    public string Context { get; init; } = string.Empty;

    [JsonPropertyName("recipient")]
    public DtaiRecipientJwk Recipient { get; init; } = new();
}

/// <summary>Release request sent to an authority.</summary>
public sealed class DtaiReleaseRequest
{
    [JsonPropertyName("protocol")]
    public string Protocol { get; init; } = DtaiProtocol.Version;

    [JsonPropertyName("keyId")]
    public string KeyId { get; init; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; init; } = string.Empty;

    [JsonPropertyName("context")]
    public string Context { get; init; } = string.Empty;

    [JsonPropertyName("attestationEvidence")]
    public string AttestationEvidence { get; init; } = string.Empty;

    [JsonPropertyName("recipient")]
    public DtaiRecipientJwk Recipient { get; init; } = new();
}

/// <summary>Normalized release response returned by an authority.</summary>
public sealed class DtaiReleaseResponse
{
    [JsonPropertyName("protocol")]
    public string? Protocol { get; set; }

    [JsonPropertyName("authority")]
    public string? Authority { get; set; }

    [JsonPropertyName("provider")]
    public string? Provider { get; set; }

    [JsonPropertyName("keyId")]
    public string? KeyId { get; set; }

    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    [JsonPropertyName("recipientThumbprint")]
    public string? RecipientThumbprint { get; set; }

    [JsonPropertyName("issuedAt")]
    public string? IssuedAt { get; set; }

    [JsonPropertyName("ciphertext")]
    public string? Ciphertext { get; set; }
}

/// <summary>DTAI protocol constants.</summary>
public static class DtaiProtocol
{
    public const string Version = "DTAI-SKR-v1";
}

/// <summary>Produces signed attestation evidence binding a release challenge.</summary>
public delegate Task<string> DtaiAttestationProvider(
    DtaiAuthority authority,
    DtaiReleaseChallenge challenge,
    CancellationToken cancellationToken);

/// <summary>Sends a release request to an authority and returns its response.</summary>
public delegate Task<DtaiReleaseResponse> DtaiReleaseClient(
    DtaiAuthority authority,
    DtaiReleaseRequest request,
    CancellationToken cancellationToken);
