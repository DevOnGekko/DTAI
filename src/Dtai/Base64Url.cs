using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace Dtai;

/// <summary>Base64url (RFC 7515) encoding helpers used by the DTAI protocol.</summary>
public static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var padded = value.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2:
                padded += "==";
                break;
            case 3:
                padded += "=";
                break;
            case 1:
                throw new FormatException("Invalid base64url value.");
        }

        return Convert.FromBase64String(padded);
    }
}

/// <summary>RSA public key in JWK form, as sent to a DTAI authority.</summary>
public sealed class DtaiRecipientJwk
{
    [JsonPropertyName("kty")]
    public string Kty { get; init; } = "RSA";

    [JsonPropertyName("n")]
    public string N { get; init; } = string.Empty;

    [JsonPropertyName("e")]
    public string E { get; init; } = string.Empty;

    [JsonPropertyName("alg")]
    public string Alg { get; init; } = "RSA-OAEP-256";

    /// <summary>Computes the RFC 7638 thumbprint of the key.</summary>
    public string ComputeThumbprint()
    {
        var canonical = $"{{\"e\":\"{E}\",\"kty\":\"RSA\",\"n\":\"{N}\"}}";
        return Base64Url.Encode(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(canonical)));
    }
}
