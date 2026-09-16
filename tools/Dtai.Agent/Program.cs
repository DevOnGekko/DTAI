using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dtai.Agent.Attestation;

const string Password = "dtai-demo-only";
const string K1PublicName = "K1-public.pem";
const string K2PublicName = "K2-public.pem";
const string K1PrivateName = "K1.pfx";
const string K2PrivateName = "K2.pfx";
const string EncryptedDekName = "encrypted-dek.txt";
const string ResultDekName = "result-dek.txt";
const int DekLength = 32;
const int NonceLength = 12;
const int TagLength = 16;
const int HeaderLength = 20;
const byte ContainerVersion = 1;
const byte ContainerAlgorithmAes256Gcm = 1;
byte[] ContainerMagic = "DTAIEMOD"u8.ToArray();

try
{
    if (args.Length == 0)
    {
        return RunInteractive();
    }

    var command = args[0];
    if (string.Equals(command, "generate", StringComparison.OrdinalIgnoreCase))
    {
        if (args.Length > 2)
        {
            ShowUsage();
            return 2;
        }

        return GenerateFixtures(args.Length == 1 ? Environment.CurrentDirectory : Path.GetFullPath(args[1]));
    }

    if (string.Equals(command, "encrypt", StringComparison.OrdinalIgnoreCase))
    {
        return EncryptCommand(args[1..]);
    }

    if (string.Equals(command, "decrypt", StringComparison.OrdinalIgnoreCase))
    {
        return DecryptCommand(args[1..]);
    }

    if (args.Length == 1)
    {
        return GenerateFixtures(Path.GetFullPath(args[0]));
    }

    ShowUsage();
    return 2;
}
catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or FormatException or InvalidDataException or ArgumentException)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

int GenerateFixtures(string directory)
{
    Directory.CreateDirectory(directory);
    var dek = RandomNumberGenerator.GetBytes(DekLength);
    try
    {
        File.WriteAllText(Path.Combine(directory, "dek-plain.txt"), Convert.ToBase64String(dek));
        File.WriteAllBytes(Path.Combine(directory, "model001.safetensors"), CreateSafetensorsFile());
        CreateKeyPair(directory, "K1", 3072);
        CreateKeyPair(directory, "K2", 4096);
        WriteSuccessLine("Generated demo-only fixtures. NEVER use them for real models.");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(dek);
    }
}

int RunInteractive()
{
    Console.WriteLine("DTAI interactive mode");
    Console.WriteLine("Use a single letter for operation:");
    Console.WriteLine("  g = generate fixtures");
    Console.WriteLine("  e = encrypt model + DEK");
    Console.WriteLine("  d = decrypt model + DEK");
    Console.WriteLine("  x = exit");

    while (true)
    {
        try
        {
            Console.Write("Operation (g/e/d/x): ");
            var operation = (Console.ReadLine() ?? string.Empty).Trim();
            if (string.IsNullOrEmpty(operation))
            {
                continue;
            }

            if (string.Equals(operation, "x", StringComparison.OrdinalIgnoreCase))
            {
                return 0;
            }

            int exitCode;
            if (string.Equals(operation, "g", StringComparison.OrdinalIgnoreCase))
            {
                var defaultDirectory = Environment.CurrentDirectory;
                var directory = Path.GetFullPath(PromptWithDefault("Output directory", defaultDirectory));
                exitCode = GenerateFixtures(directory);
            }
            else if (string.Equals(operation, "e", StringComparison.OrdinalIgnoreCase))
            {
                var modelPath = PromptWithDefault("Model path", Path.Combine(Environment.CurrentDirectory, "model001.safetensors"));
                var dekPath = PromptWithDefault("DEK path", Path.Combine(Environment.CurrentDirectory, "dek-plain.txt"));
                exitCode = EncryptCommand(new[] { "-Model", modelPath, "-DEK", dekPath });
            }
            else if (string.Equals(operation, "d", StringComparison.OrdinalIgnoreCase))
            {
                var encryptedDekPath = PromptWithDefault("Encrypted DEK path", Path.Combine(Environment.CurrentDirectory, EncryptedDekName));
                var encryptedModelPath = PromptWithDefault("Encrypted model path", Path.Combine(Environment.CurrentDirectory, "e-model001.safetensors"));
                exitCode = DecryptCommand(new[] { "-EncryptedDEK", encryptedDekPath, "-EncryptedModel", encryptedModelPath });
            }
            else
            {
                Console.Error.WriteLine("Unknown operation. Expected: g, e, d, or x.");
                continue;
            }

            if (exitCode != 0)
            {
                Console.Error.WriteLine($"Operation failed with exit code {exitCode}.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or FormatException or InvalidDataException or ArgumentException)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
        }
    }
}

string PromptWithDefault(string prompt, string defaultValue)
{
    Console.Write($"{prompt} [{defaultValue}]: ");
    var value = Console.ReadLine();
    return string.IsNullOrWhiteSpace(value) ? defaultValue : value;
}

int EncryptCommand(string[] commandArgs)
{
    var options = ParseOptions(commandArgs, "-Model", "-DEK");
    var modelPath = Path.GetFullPath(options["-Model"]);
    var dekPath = Path.GetFullPath(options["-DEK"]);
    var encryptedModelPath = Path.Combine(Path.GetDirectoryName(modelPath) ?? Environment.CurrentDirectory, "e-" + Path.GetFileName(modelPath));
    var encryptedDekPath = Path.Combine(Environment.CurrentDirectory, EncryptedDekName);

    var modelBytes = File.ReadAllBytes(modelPath);
    var dekFileBytes = File.ReadAllBytes(dekPath);
    var dek = DecodeDek(dekFileBytes, "DEK file");
    try
    {
        var encryptedModel = EncryptModelContainer(modelBytes, dek);
        var encryptedDekText = EncryptDekFileBytes(dekFileBytes);
        WriteStaged(encryptedModelPath, encryptedModel);
        WriteStaged(encryptedDekPath, Encoding.ASCII.GetBytes(encryptedDekText));
        WriteSuccessLine($"Wrote encrypted model container: {Path.GetFileName(encryptedModelPath)}");
        WriteSuccessLine($"Wrote nested RSA-encrypted DEK: {Path.GetFileName(encryptedDekPath)}");
        Console.WriteLine("Demo-only warning: bundled keys, PFX files, and password are public and must never be used for real models.");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(dek);
    }
}

int DecryptCommand(string[] commandArgs)
{
    var options = ParseOptions(commandArgs, "-EncryptedDEK", "-EncryptedModel");
    var encryptedDekPath = Path.GetFullPath(options["-EncryptedDEK"]);
    var encryptedModelPath = Path.GetFullPath(options["-EncryptedModel"]);
    var resultModelPath = Path.Combine(
        Path.GetDirectoryName(encryptedModelPath) ?? Environment.CurrentDirectory,
        "result-" + RemoveEncryptedPrefix(Path.GetFileName(encryptedModelPath)));
    var resultDekPath = Path.Combine(Environment.CurrentDirectory, ResultDekName);

    var recoveredDekFileBytes = DecryptDekFileBytes(File.ReadAllText(encryptedDekPath));
    var recoveredDek = DecodeDek(recoveredDekFileBytes, "recovered DEK");
    try
    {
        var recoveredModel = DecryptModelContainer(File.ReadAllBytes(encryptedModelPath), recoveredDek);

        var attestation = Dtai.Agent.Attestation.AttestationSettings.Load();
        Console.WriteLine(attestation.Enabled
            ? $"Test mode: performing real {attestation.AttestationType} attestation and Key Vault release; local PFX files still do the decryption."
            : "Demo-only simulation: no attestation or remote key retrieval is performed; decryption uses local PFX files.");
        var workflow = new AttestationWorkflow(
            new TeeEvidenceProvider(attestation),
            new MaaAttestationService(attestation),
            new KeyVaultKeyProvider(attestation),
            new ItaAttestationService(),
            new HashicorpKeyProvider());
        // Demo key references are placeholders and are not used for local decryption.
        // The attestation leg is illustrative here; a failure (e.g. TDX needing a
        // collateral-provisioned provider) warns but does not block decryption.
        try
        {
            _ = workflow.Run(WriteDecryptProgress);
        }
        catch (InvalidOperationException ex)
        {
            Console.Error.WriteLine($"Warning: attestation/release step failed: {ex.Message}");
        }

        WriteStaged(resultDekPath, recoveredDekFileBytes);
        WriteStaged(resultModelPath, recoveredModel);
        WriteSuccessLine($"Wrote recovered DEK bytes: {Path.GetFileName(resultDekPath)}");
        WriteSuccessLine($"Wrote authenticated decrypted model: {Path.GetFileName(resultModelPath)}");
        Console.WriteLine("Demo-only warning: bundled keys, PFX files, and password are public and must never be used for real models.");
        return 0;
    }
    finally
    {
        CryptographicOperations.ZeroMemory(recoveredDek);
        CryptographicOperations.ZeroMemory(recoveredDekFileBytes);
    }
}

Dictionary<string, string> ParseOptions(string[] commandArgs, params string[] requiredNames)
{
    if (commandArgs.Length != requiredNames.Length * 2)
    {
        ShowUsage();
        throw new ArgumentException("Missing or extra command arguments.");
    }

    var allowed = new HashSet<string>(requiredNames, StringComparer.OrdinalIgnoreCase);
    var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < commandArgs.Length; i += 2)
    {
        var name = commandArgs[i];
        if (!allowed.Contains(name) || options.ContainsKey(name))
        {
            ShowUsage();
            throw new ArgumentException($"Unexpected or duplicate option '{name}'.");
        }

        var value = commandArgs[i + 1];
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"Option '{name}' requires a path.");
        }

        options[name] = value;
    }

    foreach (var requiredName in requiredNames)
    {
        if (!options.ContainsKey(requiredName))
        {
            ShowUsage();
            throw new ArgumentException($"Missing required option '{requiredName}'.");
        }
    }

    return options;
}

byte[] DecodeDek(byte[] dekFileBytes, string description)
{
    var text = Encoding.UTF8.GetString(dekFileBytes);
    if (text.Length > 0 && text[0] == '\uFEFF')
    {
        text = text[1..];
    }

    byte[] dek;
    try
    {
        dek = Convert.FromBase64String(text);
    }
    catch (FormatException ex)
    {
        throw new FormatException($"{description} must be Base64 text for exactly 32 bytes.", ex);
    }

    if (dek.Length != DekLength)
    {
        CryptographicOperations.ZeroMemory(dek);
        throw new FormatException($"{description} must decode to exactly 32 bytes, but decoded to {dek.Length} bytes.");
    }

    return dek;
}

byte[] EncryptModelContainer(byte[] plaintext, byte[] dek)
{
    var nonce = RandomNumberGenerator.GetBytes(NonceLength);
    var tag = new byte[TagLength];
    var ciphertext = new byte[plaintext.Length];
    var header = CreateContainerHeader(ciphertext.Length);
    try
    {
        using var aes = new AesGcm(dek, TagLength);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, header);
        return Combine(header, nonce, tag, ciphertext);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(tag);
    }
}

byte[] DecryptModelContainer(byte[] container, byte[] dek)
{
    if (container.Length < HeaderLength + NonceLength + TagLength)
    {
        throw new InvalidDataException("Encrypted model container is truncated.");
    }

    var header = container.AsSpan(0, HeaderLength);
    if (!header[..ContainerMagic.Length].SequenceEqual(ContainerMagic))
    {
        throw new InvalidDataException("Encrypted model container has an unsupported magic value.");
    }

    if (header[8] != ContainerVersion || header[9] != ContainerAlgorithmAes256Gcm)
    {
        throw new InvalidDataException("Encrypted model container version or algorithm is unsupported.");
    }

    var nonceLength = header[10];
    var tagLength = header[11];
    if (nonceLength != NonceLength || tagLength != TagLength)
    {
        throw new InvalidDataException("Encrypted model container has unsupported nonce or tag length.");
    }

    var ciphertextLength = BinaryPrimitives.ReadUInt64LittleEndian(header[12..20]);
    if (ciphertextLength > int.MaxValue)
    {
        throw new InvalidDataException("Encrypted model container ciphertext is too large for this demo.");
    }

    var expectedLength = HeaderLength + nonceLength + tagLength + (int)ciphertextLength;
    if (container.Length != expectedLength)
    {
        throw new InvalidDataException("Encrypted model container length does not match its header.");
    }

    var offset = HeaderLength;
    var nonce = container.AsSpan(offset, nonceLength);
    offset += nonceLength;
    var tag = container.AsSpan(offset, tagLength);
    offset += tagLength;
    var ciphertext = container.AsSpan(offset, (int)ciphertextLength);
    var plaintext = new byte[ciphertext.Length];
    using var aes = new AesGcm(dek, TagLength);
    aes.Decrypt(nonce, ciphertext, tag, plaintext, header);
    return plaintext;
}

byte[] CreateContainerHeader(int ciphertextLength)
{
    var header = new byte[HeaderLength];
    ContainerMagic.CopyTo(header, 0);
    header[8] = ContainerVersion;
    header[9] = ContainerAlgorithmAes256Gcm;
    header[10] = NonceLength;
    header[11] = TagLength;
    BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(12), (ulong)ciphertextLength);
    return header;
}

string EncryptDekFileBytes(byte[] dekFileBytes)
{
    using var k1 = LoadPublicRsa(K1PublicName);
    using var k2 = LoadPublicRsa(K2PublicName);
    EnsureRsaCapacity(k1, dekFileBytes.Length, "K1", "DEK file bytes");
    var k1Ciphertext = k1.Encrypt(dekFileBytes, RSAEncryptionPadding.OaepSHA256);
    try
    {
        EnsureRsaCapacity(k2, k1Ciphertext.Length, "K2", "raw K1 RSA ciphertext");
        var k2Ciphertext = k2.Encrypt(k1Ciphertext, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(k2Ciphertext);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(k1Ciphertext);
    }
}

byte[] DecryptDekFileBytes(string encryptedDekText)
{
    byte[] k2Ciphertext;
    try
    {
        k2Ciphertext = Convert.FromBase64String(encryptedDekText);
    }
    catch (FormatException ex)
    {
        throw new FormatException("Encrypted DEK file must be Base64 text.", ex);
    }

    using var k2 = LoadPrivateRsa(K2PrivateName);
    using var k1 = LoadPrivateRsa(K1PrivateName);
    var k1Ciphertext = k2.Decrypt(k2Ciphertext, RSAEncryptionPadding.OaepSHA256);
    try
    {
        return k1.Decrypt(k1Ciphertext, RSAEncryptionPadding.OaepSHA256);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(k2Ciphertext);
        CryptographicOperations.ZeroMemory(k1Ciphertext);
    }
}

RSA LoadPublicRsa(string fileName)
{
    var path = Path.Combine(Environment.CurrentDirectory, fileName);
    var rsa = RSA.Create();
    try
    {
        rsa.ImportFromPem(File.ReadAllText(path));
        return rsa;
    }
    catch
    {
        rsa.Dispose();
        throw;
    }
}

RSA LoadPrivateRsa(string fileName)
{
    var path = Path.Combine(Environment.CurrentDirectory, fileName);
    var certificate = new X509Certificate2(File.ReadAllBytes(path), Password, X509KeyStorageFlags.EphemeralKeySet);
    var rsa = certificate.GetRSAPrivateKey();
    certificate.Dispose();
    return rsa ?? throw new CryptographicException($"{fileName} does not contain an RSA private key.");
}

void EnsureRsaCapacity(RSA rsa, int inputLength, string keyName, string payloadDescription)
{
    var keyBytes = rsa.KeySize / 8;
    var maxInput = keyBytes - (2 * SHA256.HashSizeInBytes) - 2;
    if (inputLength > maxInput)
    {
        throw new InvalidDataException($"{keyName} RSA-OAEP-SHA256 cannot encrypt {payloadDescription}: {inputLength} bytes exceeds its {maxInput}-byte limit.");
    }
}

void WriteStaged(string path, byte[] bytes)
{
    var directory = Path.GetDirectoryName(path);
    if (!string.IsNullOrEmpty(directory))
    {
        Directory.CreateDirectory(directory);
    }

    var temp = path + ".tmp-" + Guid.NewGuid().ToString("N");
    try
    {
        File.WriteAllBytes(temp, bytes);
        File.Move(temp, path, true);
    }
    finally
    {
        if (File.Exists(temp))
        {
            File.Delete(temp);
        }
    }
}

string RemoveEncryptedPrefix(string fileName) => fileName.StartsWith("e-", StringComparison.OrdinalIgnoreCase) ? fileName[2..] : fileName;

void WriteSuccessLine(string message)
{
    var priorColor = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine(message);
    Console.ForegroundColor = priorColor;
}

void WriteDecryptProgress(string message)
{
    Console.WriteLine(message);
    Thread.Sleep(1000);
}

byte[] Combine(params byte[][] parts)
{
    var length = parts.Sum(part => part.Length);
    var result = new byte[length];
    var offset = 0;
    foreach (var part in parts)
    {
        part.CopyTo(result, offset);
        offset += part.Length;
    }

    return result;
}

void ShowUsage()
{
    Console.Error.WriteLine("Usage:");
    Console.Error.WriteLine("  DTAI  (interactive mode)");
    Console.Error.WriteLine("  DTAI generate [output-directory]");
    Console.Error.WriteLine("  DTAI [output-directory]");
    Console.Error.WriteLine("  DTAI encrypt -Model model001.safetensors -DEK dek-plain.txt");
    Console.Error.WriteLine("  DTAI decrypt -EncryptedDEK encrypted-dek.txt -EncryptedModel e-model001.safetensors");
}

void CreateKeyPair(string directory, string name, int keySize)
{
    using var rsa = RSA.Create(keySize);
    var request = new CertificateRequest(
        $"CN=DTAI {name} demo only",
        rsa,
        HashAlgorithmName.SHA256,
        RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
    using var certificate = request.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddYears(1));
    File.WriteAllText(Path.Combine(directory, $"{name}-public.pem"), rsa.ExportSubjectPublicKeyInfoPem());
    File.WriteAllBytes(Path.Combine(directory, $"{name}.pfx"), certificate.Export(X509ContentType.Pfx, Password));
}

byte[] CreateSafetensorsFile()
{
    var header = Encoding.UTF8.GetBytes("""{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}""");
    var file = new byte[sizeof(long) + header.Length + sizeof(float)];
    BinaryPrimitives.WriteInt64LittleEndian(file, header.Length);
    header.CopyTo(file, sizeof(long));
    BinaryPrimitives.WriteSingleLittleEndian(file.AsSpan(sizeof(long) + header.Length), 1.0f);
    return file;
}
