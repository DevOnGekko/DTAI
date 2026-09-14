using System.Security.Cryptography;

namespace Dtai;

/// <summary>HKDF-SHA-256 (RFC 5869) derivation used for the DTAI DEK.</summary>
public static class DtaiHkdf
{
    public static byte[] DeriveKey(
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int length = 32)
    {
        if (length < 1 || length > 8160)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Length must be between 1 and 8160 bytes.");
        }

        var output = new byte[length];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, output, salt, info);
        return output;
    }
}
