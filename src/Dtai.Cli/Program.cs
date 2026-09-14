using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Dtai;

namespace Dtai.Cli;

/// <summary>CLI wrapper that writes a raw 32-byte DEK for tools that cannot host the library.</summary>
public static class Program
{
    private const string Usage = """
        Usage: dtai --configuration <path> --attestation-command <path> \
                    --context <model-context> --output <path>
        """;

    public static async Task<int> Main(string[] args)
    {
        string? configurationPath = null;
        string? attestationCommand = null;
        string? context = null;
        string? outputPath = null;

        for (var index = 0; index < args.Length; index += 2)
        {
            if (index + 1 >= args.Length)
            {
                Console.Error.WriteLine($"Missing value for '{args[index]}'.\n{Usage}");
                return 2;
            }

            var value = args[index + 1];
            switch (args[index])
            {
                case "--configuration":
                    configurationPath = value;
                    break;
                case "--attestation-command":
                    attestationCommand = value;
                    break;
                case "--context":
                    context = value;
                    break;
                case "--output":
                    outputPath = value;
                    break;
                default:
                    Console.Error.WriteLine($"Unknown argument '{args[index]}'.\n{Usage}");
                    return 2;
            }
        }

        if (string.IsNullOrWhiteSpace(configurationPath) ||
            string.IsNullOrWhiteSpace(attestationCommand) ||
            string.IsNullOrWhiteSpace(context) ||
            string.IsNullOrWhiteSpace(outputPath))
        {
            Console.Error.WriteLine(Usage);
            return 2;
        }

        try
        {
            await RunAsync(configurationPath, attestationCommand, context, outputPath)
                .ConfigureAwait(false);
            return 0;
        }
        catch (Exception exception) when (exception is DtaiException or IOException or
                                              UnauthorizedAccessException or FormatException or
                                              JsonException or CryptographicException or
                                              HttpRequestException or OperationCanceledException)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }

    private static async Task RunAsync(
        string configurationPath,
        string attestationCommand,
        string context,
        string outputPath)
    {
        if (File.Exists(outputPath) || Directory.Exists(outputPath))
        {
            throw new DtaiException($"Refusing to overwrite existing DEK output '{outputPath}'.");
        }

        var parent = Path.GetDirectoryName(Path.GetFullPath(outputPath));
        if (!string.IsNullOrEmpty(parent) && !Directory.Exists(parent))
        {
            throw new DtaiException($"Output directory '{parent}' does not exist.");
        }

        var configuration = DtaiConfiguration.Load(configurationPath);
        var dek = await DtaiKeyRelease
            .ReleaseAsync(
                configuration,
                context,
                (authority, challenge, cancellationToken) =>
                    InvokeAttestationCommandAsync(attestationCommand, authority, challenge, cancellationToken))
            .ConfigureAwait(false);

        try
        {
            WriteDek(outputPath, dek);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    private static async Task<string> InvokeAttestationCommandAsync(
        string attestationCommand,
        DtaiAuthority authority,
        DtaiReleaseChallenge challenge,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(attestationCommand)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        startInfo.ArgumentList.Add(authority.Name!);

        using var process = Process.Start(startInfo)
            ?? throw new DtaiException($"Failed to start attestation command '{attestationCommand}'.");

        await process.StandardInput
            .WriteAsync(JsonSerializer.Serialize(challenge).AsMemory(), cancellationToken)
            .ConfigureAwait(false);
        process.StandardInput.Close();

        var evidence = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var diagnostics = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            Console.Error.Write(diagnostics);
            throw new DtaiException($"Attestation command failed for authority '{authority.Name}'.");
        }

        return evidence.Trim();
    }

    private static void WriteDek(string outputPath, byte[] dek)
    {
        var temporaryPath = $"{outputPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            var options = new FileStreamOptions
            {
                Access = FileAccess.Write,
                Mode = FileMode.CreateNew,
                Share = FileShare.None
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var stream = new FileStream(temporaryPath, options))
            {
                stream.Write(dek);
            }
            File.Move(temporaryPath, outputPath);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }
}
