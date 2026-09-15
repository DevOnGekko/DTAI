using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

const string Password = "dtai-demo-only";
var directory = args.Length == 0 ? Environment.CurrentDirectory : Path.GetFullPath(args[0]);
if (args.Length > 1)
{
    Console.Error.WriteLine("Usage: dotnet run --project tools/Dtai.DemoGenerator -- [output-directory]");
    return 2;
}

Directory.CreateDirectory(directory);
var names = new[] { "model001.safetensors", "dek-plain.txt", "K1-public.pem", "K1.pfx", "K2-public.pem", "K2.pfx" };
if (names.Any(name => File.Exists(Path.Combine(directory, name))))
{
    Console.Error.WriteLine("Refusing to overwrite an existing demo fixture.");
    return 1;
}

var dek = RandomNumberGenerator.GetBytes(32);
try
{
    await File.WriteAllTextAsync(Path.Combine(directory, "dek-plain.txt"), Convert.ToBase64String(dek));
    await File.WriteAllBytesAsync(Path.Combine(directory, "model001.safetensors"), CreateSafetensorsFile());
    CreateKeyPair(directory, "K1", 3072);
    CreateKeyPair(directory, "K2", 4096);
    Console.WriteLine("Generated demo-only fixtures. NEVER use them for real models.");
    return 0;
}
finally
{
    CryptographicOperations.ZeroMemory(dek);
}

static void CreateKeyPair(string directory, string name, int keySize)
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

static byte[] CreateSafetensorsFile()
{
    var header = Encoding.UTF8.GetBytes("""{"tensor":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}""");
    var file = new byte[sizeof(long) + header.Length + sizeof(float)];
    BinaryPrimitives.WriteInt64LittleEndian(file, header.Length);
    header.CopyTo(file, sizeof(long));
    BinaryPrimitives.WriteSingleLittleEndian(file.AsSpan(sizeof(long) + header.Length), 1.0f);
    return file;
}
