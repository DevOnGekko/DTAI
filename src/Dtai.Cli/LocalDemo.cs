using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dtai;

namespace Dtai.Cli;

public static class LocalDemo
{
    private const string Context = "dtai://local-file-demo/v1";
    private const string DefaultPfxPassword = "dtai-demo-only";
    private static readonly RSAEncryptionPadding Padding = RSAEncryptionPadding.OaepSHA256;

    public static async Task<int> RunAsync(string[] args)
    {
        var values = Parse(args);
        if (args[0].Equals("encrypt", StringComparison.OrdinalIgnoreCase))
        {
            await EncryptAsync(values).ConfigureAwait(false);
        }
        else
        {
            await DecryptAsync(values).ConfigureAwait(false);
        }

        return 0;
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        var encrypt = args[0].Equals("encrypt", StringComparison.OrdinalIgnoreCase);
        var expected = encrypt
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "-Model", "-DEK" }
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "-EncryptedDEK", "-EncryptedModel" };
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 1; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length)
            {
                throw new DtaiException($"Missing value for '{args[index]}'.");
            }

            if (!expected.Contains(args[index]))
            {
                throw new DtaiException($"'{args[index]}' is not valid for {args[0]}.");
            }

            if (!values.TryAdd(args[index], args[index + 1]) || string.IsNullOrWhiteSpace(args[index + 1]))
            {
                throw new DtaiException($"'{args[index]}' must be supplied exactly once with a nonempty value.");
            }
        }

        if (values.Count != expected.Count)
        {
            throw new DtaiException(encrypt
                ? "Usage: DTAI encrypt -Model <model> -DEK <dek-file>"
                : "Usage: DTAI decrypt -EncryptedDEK <encrypted-dek> -EncryptedModel <encrypted-model>");
        }

        return values;
    }

    private static async Task EncryptAsync(IReadOnlyDictionary<string, string> values)
    {
        var model = FullFile(values["-Model"]);
        var dekFile = FullFile(values["-DEK"]);
        var directory = Path.GetDirectoryName(model)!;
        var encryptedModel = Path.Combine(directory, $"e-{Path.GetFileName(model)}");
        var encryptedDek = Path.Combine(directory, "encrypted-dek.txt");
        var k1Path = Path.Combine(Environment.CurrentDirectory, "K1-public.pem");
        var k2Path = Path.Combine(Environment.CurrentDirectory, "K2-public.pem");
        EnsureFiles(model, dekFile, k1Path, k2Path);
        EnsureOutputs(encryptedModel, encryptedDek);

        using var k1 = LoadPublic(k1Path);
        using var k2 = LoadPublic(k2Path);
        var k1Capacity = Capacity(k1);
        var k2Capacity = Capacity(k2);
        if (new FileInfo(dekFile).Length > k1Capacity)
        {
            throw new DtaiException($"DEK file exceeds K1 OAEP-SHA256 capacity ({k1Capacity} bytes).");
        }
        if (k1.KeySize / 8 > k2Capacity)
        {
            throw new DtaiException(
                $"K2 OAEP-SHA256 capacity ({k2Capacity} bytes) cannot wrap K1 ciphertext ({k1.KeySize / 8} bytes).");
        }

        var dekBytes = await File.ReadAllBytesAsync(dekFile).ConfigureAwait(false);
        var dek = DecodeDek(dekBytes);
        try
        {
            try
            {
                Green("Inputs validated.");
                await EncryptFileAsync(model, encryptedModel, dek).ConfigureAwait(false);
                Green($"Model encrypted and written to '{Path.GetFileName(encryptedModel)}'.");
                var k1Ciphertext = k1.Encrypt(dekBytes, Padding);
                try
                {
                    Green("DEK wrapped with K1 public key.");
                    var k2Ciphertext = k2.Encrypt(k1Ciphertext, Padding);
                    try
                    {
                        await WriteStagedAsync(encryptedDek, Convert.ToBase64String(k2Ciphertext)).ConfigureAwait(false);
                        Green($"DEK wrapped with K2 public key and written to '{Path.GetFileName(encryptedDek)}'.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(k2Ciphertext);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(k1Ciphertext);
                }
            }
            catch
            {
                DeleteOutput(encryptedModel);
                DeleteOutput(encryptedDek);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(dekBytes);
        }
    }

    private static async Task DecryptAsync(IReadOnlyDictionary<string, string> values)
    {
        var encryptedDek = FullFile(values["-EncryptedDEK"]);
        var encryptedModel = FullFile(values["-EncryptedModel"]);
        var directory = Path.GetDirectoryName(encryptedModel)!;
        var dekOutput = Path.Combine(directory, "result-dek.txt");
        var modelOutput = Path.Combine(directory, $"result-{RemoveEncryptedPrefix(Path.GetFileName(encryptedModel))}");
        var k1Path = Path.Combine(Environment.CurrentDirectory, "K1.pfx");
        var k2Path = Path.Combine(Environment.CurrentDirectory, "K2.pfx");
        EnsureFiles(encryptedDek, encryptedModel, k1Path, k2Path);
        EnsureOutputs(dekOutput, modelOutput);

        using var k1 = LoadPrivate(k1Path, "DTAI_K1_PFX_PASSWORD");
        using var k2 = LoadPrivate(k2Path, "DTAI_K2_PFX_PASSWORD");
        var outer = Convert.FromBase64String(await File.ReadAllTextAsync(encryptedDek).ConfigureAwait(false));
        if (outer.Length != k2.KeySize / 8)
        {
            CryptographicOperations.ZeroMemory(outer);
            throw new DtaiException("Encrypted DEK does not have the expected K2 ciphertext size.");
        }

        try
        {
            Green("Inputs validated.");
            var k1Ciphertext = k2.Decrypt(outer, Padding);
            try
            {
                Green("DEK unwrapped with K2 private key.");
                if (k1Ciphertext.Length != k1.KeySize / 8)
                {
                    throw new DtaiException("K2 output does not have the expected K1 ciphertext size.");
                }

                var dekBytes = k1.Decrypt(k1Ciphertext, Padding);
                try
                {
                    Green("DEK unwrapped with K1 private key.");
                    var dek = DecodeDek(dekBytes);
                    try
                    {
                        await WriteStagedAsync(dekOutput, dekBytes).ConfigureAwait(false);
                        Green($"Recovered DEK saved to '{Path.GetFileName(dekOutput)}'.");
                        await DecryptFileAsync(encryptedModel, modelOutput, dek).ConfigureAwait(false);
                        Green($"Model decrypted and saved to '{Path.GetFileName(modelOutput)}'.");
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(dek);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(dekBytes);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(k1Ciphertext);
            }
        }
        catch
        {
            DeleteOutput(dekOutput);
            DeleteOutput(modelOutput);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(outer);
        }
    }

    private static async Task EncryptFileAsync(string input, string output, byte[] dek) =>
        await StageFileAsync(output, async stream =>
        {
            await using var source = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read);
            await DtaiFileEncryption.EncryptAsync(source, stream, dek, Context).ConfigureAwait(false);
        }).ConfigureAwait(false);

    private static async Task DecryptFileAsync(string input, string output, byte[] dek) =>
        await StageFileAsync(output, async stream =>
        {
            await using var source = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read);
            await DtaiFileEncryption.DecryptAsync(source, stream, dek, Context).ConfigureAwait(false);
        }).ConfigureAwait(false);

    private static async Task WriteStagedAsync(string output, string value) =>
        await WriteStagedAsync(output, System.Text.Encoding.UTF8.GetBytes(value)).ConfigureAwait(false);

    private static async Task WriteStagedAsync(string output, byte[] value) =>
        await StageFileAsync(output, stream => stream.WriteAsync(value).AsTask()).ConfigureAwait(false);

    private static async Task StageFileAsync(string output, Func<FileStream, Task> write)
    {
        var temporary = $"{output}.{Guid.NewGuid():N}.tmp";
        try
        {
            var options = new FileStreamOptions { Access = FileAccess.Write, Mode = FileMode.CreateNew, Share = FileShare.None };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            await using (var stream = new FileStream(temporary, options))
            {
                await write(stream).ConfigureAwait(false);
            }
            File.Move(temporary, output);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    private static RSA LoadPublic(string path)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        return rsa;
    }

    private static RSA LoadPrivate(string path, string environmentVariable)
    {
        var password = Environment.GetEnvironmentVariable(environmentVariable) ?? DefaultPfxPassword;
        using var certificate = new X509Certificate2(
            path,
            password,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        return certificate.GetRSAPrivateKey()
            ?? throw new DtaiException($"PFX '{path}' does not contain an RSA private key.");
    }

    private static int Capacity(RSA rsa) => rsa.KeySize / 8 - (2 * 32) - 2;

    private static byte[] DecodeDek(byte[] value)
    {
        byte[] dek;
        try
        {
            var text = System.Text.Encoding.UTF8.GetString(value);
            dek = Convert.FromBase64String(text.StartsWith('\uFEFF') ? text[1..] : text);
        }
        catch (FormatException exception)
        {
            throw new DtaiException("DEK file must contain Base64 text.", exception);
        }
        if (dek.Length != 32)
        {
            CryptographicOperations.ZeroMemory(dek);
            throw new DtaiException("DEK Base64 must decode to exactly 32 bytes.");
        }
        return dek;
    }

    private static string FullFile(string path)
    {
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            throw new DtaiException($"Input file '{path}' does not exist.");
        }
        return fullPath;
    }

    private static void EnsureFiles(params string[] paths)
    {
        foreach (var path in paths)
        {
            if (!File.Exists(path))
            {
                throw new DtaiException($"Required input '{path}' does not exist.");
            }
        }
    }

    private static void EnsureOutputs(params string[] paths)
    {
        foreach (var path in paths)
        {
            if (File.Exists(path) || Directory.Exists(path))
            {
                throw new DtaiException($"Refusing to overwrite existing output '{path}'.");
            }
        }
    }

    private static void DeleteOutput(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string RemoveEncryptedPrefix(string filename) =>
        filename.StartsWith("e-", StringComparison.Ordinal) ? filename[2..] : filename;

    private static void Green(string message)
    {
        var color = Console.ForegroundColor;
        try
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(message);
        }
        finally
        {
            Console.ForegroundColor = color;
        }
    }
}
