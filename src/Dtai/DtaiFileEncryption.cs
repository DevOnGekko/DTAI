using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Dtai;

/// <summary>Authenticated, chunked encryption for data protected by a DTAI DEK.</summary>
public static class DtaiFileEncryption
{
    private static readonly byte[] Magic = "DTAIENC1"u8.ToArray();
    private const int ChunkSize = 64 * 1024;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int HeaderSize = 8 + 4 + NonceSize;

    public static async Task EncryptAsync(
        Stream plaintext,
        Stream ciphertext,
        ReadOnlyMemory<byte> key,
        string context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);
        ValidateKey(key);

        var header = new byte[HeaderSize];
        Magic.CopyTo(header, 0);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(8, 4), ChunkSize);
        RandomNumberGenerator.Fill(header.AsSpan(12, NonceSize - sizeof(uint)));
        await ciphertext.WriteAsync(header, cancellationToken).ConfigureAwait(false);

        var input = new byte[ChunkSize];
        var encrypted = new byte[ChunkSize];
        var tag = new byte[TagSize];
        using var aes = new AesGcm(key.Span, TagSize);
        try
        {
            uint counter = 0;
            while (true)
            {
                var length = await ReadChunkAsync(plaintext, input, cancellationToken).ConfigureAwait(false);
                var recordHeader = new byte[4];
                BinaryPrimitives.WriteInt32BigEndian(recordHeader, length);
                var nonce = CreateNonce(header, counter);
                var associatedData = CreateAssociatedData(header, recordHeader, counter, context);
                try
                {
                    aes.Encrypt(
                        nonce,
                        input.AsSpan(0, length),
                        encrypted.AsSpan(0, length),
                        tag,
                        associatedData);
                    await ciphertext.WriteAsync(recordHeader, cancellationToken).ConfigureAwait(false);
                    await ciphertext.WriteAsync(encrypted.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                    await ciphertext.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nonce);
                    CryptographicOperations.ZeroMemory(associatedData);
                }

                if (length == 0)
                {
                    break;
                }
                if (counter == uint.MaxValue)
                {
                    throw new DtaiException("Input is too large to encrypt safely.");
                }
                counter++;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(encrypted);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    public static async Task DecryptAsync(
        Stream ciphertext,
        Stream plaintext,
        ReadOnlyMemory<byte> key,
        string context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        ArgumentNullException.ThrowIfNull(plaintext);
        ArgumentException.ThrowIfNullOrWhiteSpace(context);
        ValidateKey(key);

        var header = new byte[HeaderSize];
        await ReadExactlyAsync(ciphertext, header, cancellationToken).ConfigureAwait(false);
        if (!header.AsSpan(0, Magic.Length).SequenceEqual(Magic) ||
            BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(8, 4)) != ChunkSize)
        {
            throw new DtaiException("Encrypted input has an invalid DTAI header.");
        }

        var encrypted = new byte[ChunkSize];
        var decrypted = new byte[ChunkSize];
        var tag = new byte[TagSize];
        using var aes = new AesGcm(key.Span, TagSize);
        try
        {
            uint counter = 0;
            while (true)
            {
                var recordHeader = new byte[4];
                await ReadExactlyAsync(ciphertext, recordHeader, cancellationToken).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadInt32BigEndian(recordHeader);
                if (length < 0 || length > ChunkSize)
                {
                    throw new DtaiException("Encrypted input has an invalid chunk length.");
                }

                await ReadExactlyAsync(ciphertext, encrypted.AsMemory(0, length), cancellationToken)
                    .ConfigureAwait(false);
                await ReadExactlyAsync(ciphertext, tag, cancellationToken).ConfigureAwait(false);
                var nonce = CreateNonce(header, counter);
                var associatedData = CreateAssociatedData(header, recordHeader, counter, context);
                try
                {
                    aes.Decrypt(
                        nonce,
                        encrypted.AsSpan(0, length),
                        tag,
                        decrypted.AsSpan(0, length),
                        associatedData);
                    await plaintext.WriteAsync(decrypted.AsMemory(0, length), cancellationToken)
                        .ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nonce);
                    CryptographicOperations.ZeroMemory(associatedData);
                }

                if (length == 0)
                {
                    if (await ciphertext.ReadAsync(new byte[1], cancellationToken).ConfigureAwait(false) != 0)
                    {
                        throw new DtaiException("Encrypted input contains data after its final chunk.");
                    }
                    break;
                }
                if (counter == uint.MaxValue)
                {
                    throw new DtaiException("Encrypted input contains too many chunks.");
                }
                counter++;
            }
        }
        catch (EndOfStreamException exception)
        {
            throw new DtaiException("Encrypted input is truncated.", exception);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encrypted);
            CryptographicOperations.ZeroMemory(decrypted);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    private static void ValidateKey(ReadOnlyMemory<byte> key)
    {
        if (key.Length != 32)
        {
            throw new ArgumentException("A DTAI DEK must be exactly 32 bytes.", nameof(key));
        }
    }

    private static async Task<int> ReadChunkAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total += read;
        }
        return total;
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            total += read;
        }
    }

    private static byte[] CreateNonce(byte[] header, uint counter)
    {
        var nonce = header.AsSpan(12, NonceSize).ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(NonceSize - sizeof(uint)), counter);
        return nonce;
    }

    private static byte[] CreateAssociatedData(
        byte[] header,
        byte[] recordHeader,
        uint counter,
        string context)
    {
        var contextBytes = Encoding.UTF8.GetBytes(context);
        var associatedData = new byte[header.Length + recordHeader.Length + sizeof(uint) + contextBytes.Length];
        header.CopyTo(associatedData, 0);
        recordHeader.CopyTo(associatedData, header.Length);
        BinaryPrimitives.WriteUInt32BigEndian(
            associatedData.AsSpan(header.Length + recordHeader.Length, sizeof(uint)),
            counter);
        contextBytes.CopyTo(associatedData, header.Length + recordHeader.Length + sizeof(uint));
        CryptographicOperations.ZeroMemory(contextBytes);
        return associatedData;
    }
}
