using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Dtai;

/// <summary>AWS credentials used to sign release requests.</summary>
/// <param name="AccessKeyId">Access key identifier.</param>
/// <param name="SecretAccessKey">Secret access key.</param>
/// <param name="SessionToken">Optional session token for temporary credentials.</param>
public sealed record AwsCredentials(string AccessKeyId, string SecretAccessKey, string? SessionToken = null)
{
    /// <summary>
    /// Reads credentials from the standard AWS environment variables supplied by an
    /// instance, task, or enclave parent role.
    /// </summary>
    public static AwsCredentials FromEnvironment(string authorityName)
    {
        var accessKeyId = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID");
        var secretAccessKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY");
        if (string.IsNullOrWhiteSpace(accessKeyId) || string.IsNullOrWhiteSpace(secretAccessKey))
        {
            throw new DtaiException(
                $"AWS authority '{authorityName}' requires AWS_ACCESS_KEY_ID and " +
                "AWS_SECRET_ACCESS_KEY in the environment.");
        }

        var sessionToken = Environment.GetEnvironmentVariable("AWS_SESSION_TOKEN");
        return new AwsCredentials(
            accessKeyId,
            secretAccessKey,
            string.IsNullOrWhiteSpace(sessionToken) ? null : sessionToken);
    }
}

/// <summary>AWS Signature Version 4 signing for DTAI release requests.</summary>
public static class AwsSigV4
{
    private const string Algorithm = "AWS4-HMAC-SHA256";

    /// <summary>Header carrying the signed payload hash.</summary>
    public const string ContentSha256Header = "X-Amz-Content-Sha256";

    /// <summary>Header carrying the signing timestamp.</summary>
    public const string DateHeader = "X-Amz-Date";

    /// <summary>Header carrying a temporary credential session token.</summary>
    public const string SecurityTokenHeader = "X-Amz-Security-Token";

    /// <summary>
    /// Computes the SigV4 headers, including <c>Authorization</c>, for a request with the
    /// supplied payload. The payload is signed exactly as it will be transmitted.
    /// </summary>
    public static IReadOnlyDictionary<string, string> CreateSignedHeaders(
        string method,
        Uri uri,
        string region,
        string service,
        AwsCredentials credentials,
        ReadOnlySpan<byte> payload,
        string contentType = "application/json",
        DateTimeOffset? timestamp = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentException.ThrowIfNullOrWhiteSpace(region);
        ArgumentException.ThrowIfNullOrWhiteSpace(service);
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);

        var signedAt = (timestamp ?? DateTimeOffset.UtcNow).ToUniversalTime();
        var amzDate = signedAt.ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        var dateStamp = signedAt.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var payloadHash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

        var headersToSign = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["content-type"] = contentType,
            ["host"] = uri.IsDefaultPort ? uri.IdnHost : $"{uri.IdnHost}:{uri.Port}",
            ["x-amz-content-sha256"] = payloadHash,
            ["x-amz-date"] = amzDate
        };
        if (!string.IsNullOrWhiteSpace(credentials.SessionToken))
        {
            headersToSign["x-amz-security-token"] = credentials.SessionToken;
        }

        var signedHeaders = string.Join(";", headersToSign.Keys);
        var canonicalHeaders = new StringBuilder();
        foreach (var (name, value) in headersToSign)
        {
            canonicalHeaders.Append(name).Append(':').Append(value.Trim()).Append('\n');
        }

        var canonicalRequest = string.Join(
            "\n",
            method.ToUpperInvariant(),
            CanonicalPath(uri),
            CanonicalQuery(uri),
            canonicalHeaders.ToString(),
            signedHeaders,
            payloadHash);

        var scope = $"{dateStamp}/{region}/{service}/aws4_request";
        var stringToSign = string.Join(
            "\n",
            Algorithm,
            amzDate,
            scope,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalRequest))).ToLowerInvariant());

        var signingKey = Encoding.UTF8.GetBytes($"AWS4{credentials.SecretAccessKey}");
        string signature;
        try
        {
            foreach (var element in new[] { dateStamp, region, service, "aws4_request", stringToSign })
            {
                var next = HMACSHA256.HashData(signingKey, Encoding.UTF8.GetBytes(element));
                CryptographicOperations.ZeroMemory(signingKey);
                signingKey = next;
            }
            signature = Convert.ToHexString(signingKey).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingKey);
        }

        var signed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [DateHeader] = amzDate,
            [ContentSha256Header] = payloadHash,
            ["Authorization"] =
                $"{Algorithm} Credential={credentials.AccessKeyId}/{scope}, " +
                $"SignedHeaders={signedHeaders}, Signature={signature}"
        };
        if (!string.IsNullOrWhiteSpace(credentials.SessionToken))
        {
            signed[SecurityTokenHeader] = credentials.SessionToken;
        }
        return signed;
    }

    /// <summary>Adds the computed SigV4 headers to an outgoing request message.</summary>
    public static void Sign(
        HttpRequestMessage request,
        string region,
        string service,
        AwsCredentials credentials,
        ReadOnlySpan<byte> payload,
        string contentType = "application/json",
        DateTimeOffset? timestamp = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.RequestUri is null)
        {
            throw new ArgumentException("Request must have an absolute URI.", nameof(request));
        }

        var headers = CreateSignedHeaders(
            request.Method.Method,
            request.RequestUri,
            region,
            service,
            credentials,
            payload,
            contentType,
            timestamp);

        foreach (var (name, value) in headers)
        {
            // SigV4 Authorization values use comma-separated parameters that the strict
            // authentication header parser rejects, so add every header unvalidated.
            request.Headers.TryAddWithoutValidation(name, value);
        }
    }

    private static string CanonicalPath(Uri uri)
    {
        var path = uri.AbsolutePath;
        if (string.IsNullOrEmpty(path) || path == "/")
        {
            return "/";
        }

        var segments = path.Split('/');
        for (var index = 0; index < segments.Length; index++)
        {
            segments[index] = Uri.EscapeDataString(Uri.UnescapeDataString(segments[index]));
        }
        return string.Join("/", segments);
    }

    private static string CanonicalQuery(Uri uri)
    {
        var query = uri.Query;
        if (query.Length <= 1)
        {
            return string.Empty;
        }

        var pairs = new List<(string Name, string Value)>();
        foreach (var part in query.TrimStart('?').Split('&'))
        {
            if (part.Length == 0)
            {
                continue;
            }

            var separator = part.IndexOf('=');
            var name = separator < 0 ? part : part[..separator];
            var value = separator < 0 ? string.Empty : part[(separator + 1)..];
            pairs.Add((
                Uri.EscapeDataString(Uri.UnescapeDataString(name)),
                Uri.EscapeDataString(Uri.UnescapeDataString(value))));
        }

        return string.Join(
            "&",
            pairs
                .OrderBy(pair => pair.Name, StringComparer.Ordinal)
                .ThenBy(pair => pair.Value, StringComparer.Ordinal)
                .Select(pair => $"{pair.Name}={pair.Value}"));
    }
}
