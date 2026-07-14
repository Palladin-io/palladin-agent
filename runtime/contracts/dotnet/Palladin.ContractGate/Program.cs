using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

return ContractGate.Run(args);

internal static partial class ContractGate
{
    private const string SourceManifest = "source-manifest.json";
    private static readonly IReadOnlyDictionary<string, string> ContractIds =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["cli.json"] = "native-cli-v2",
            ["credential-blobs.json"] = "credential-blobs",
            ["encrypted-envelope.json"] = "encrypted-credential-envelope-v1",
            ["grant-access.json"] = "grant-access",
            ["mcp-tools.json"] = "palladin-agent-mcp-tools",
            ["request-signing.json"] = "agent-request-signing-v1",
            [SourceManifest] = "palladin-agent-runtime",
        };
    private static readonly IReadOnlyDictionary<string, string> PinnedDigests =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["cli.json"] = "5930da5ef9fda13a09898f99d38a53065c3704b9d3d11f24b5b037be94a390a9",
            ["credential-blobs.json"] = "af7424d14ff869b6a35fedeea6e3795dad5c831a50d81f2d52fecb15cd9a3ca7",
            ["encrypted-envelope.json"] = "98f288511c590e1bc983a0c299748f2ae2f183d056f3b7b182fe6338d97481ee",
            ["grant-access.json"] = "825efb7d3d34b05f6d32b1f4166c0606acf105cd550eef393e1f435fc3e0122f",
            ["mcp-tools.json"] = "c673d367cbd15d9692fc277000fa77d3efb69824851f1c12efedb241788da2c0",
            ["request-signing.json"] = "364a87c2dce913cb470057c548f1ded55fd26ee63209bffddc9d16b2371f563a",
            [SourceManifest] = "348dd4400392b6a6a94aebf68a67497ffc87743809310f3a526f3105b8c8c94c",
        };

    public static int Run(string[] args)
    {
        try
        {
            if (args.Length != 1)
            {
                throw new InvalidOperationException("expected one contract directory argument");
            }

            var root = Path.GetFullPath(args[0]);
            var manifestPath = BoundedPath(root, SourceManifest);
            using var manifest = ParseObject(manifestPath);
            var contract = manifest.RootElement;
            RequireString(contract, "contract", "palladin-agent-runtime");
            RequireString(contract, "version", "1.0.0");
            RequireString(contract, "status", "frozen");
            if (!contract.TryGetProperty("syntheticOnly", out var syntheticOnly)
                || syntheticOnly.ValueKind != JsonValueKind.True)
            {
                throw new InvalidDataException("source manifest must be synthetic-only");
            }

            var consumers = StringArray(contract, "consumers");
            if (!consumers.SequenceEqual(["typescript", "rust", "dotnet"], StringComparer.Ordinal))
            {
                throw new InvalidDataException("unexpected contract consumers");
            }

            var fixtures = StringArray(contract, "fixtures");
            if (fixtures.Count == 0 || fixtures.Count != fixtures.Distinct(StringComparer.Ordinal).Count())
            {
                throw new InvalidDataException("contract fixture list is empty or duplicated");
            }

            var expectedFiles = fixtures.Append(SourceManifest).ToArray();
            if (!expectedFiles.Order(StringComparer.Ordinal).SequenceEqual(
                    ContractIds.Keys.Order(StringComparer.Ordinal),
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException("contract file set is not the frozen v1 set");
            }
            var actualJsonFiles = Directory.EnumerateFiles(root, "*.json", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileName)
                .Where(file => file is not null)
                .Cast<string>()
                .Order(StringComparer.Ordinal);
            if (!actualJsonFiles.SequenceEqual(expectedFiles.Order(StringComparer.Ordinal), StringComparer.Ordinal))
            {
                throw new InvalidDataException("contract directory contains undeclared JSON files");
            }
            var hashes = ReadHashes(BoundedPath(root, "SOURCE.sha256"));
            if (!hashes.Keys.Order(StringComparer.Ordinal).SequenceEqual(
                    expectedFiles.Order(StringComparer.Ordinal),
                    StringComparer.Ordinal))
            {
                throw new InvalidDataException("hash manifest does not exactly cover contract fixtures");
            }

            foreach (var file in expectedFiles)
            {
                var path = BoundedPath(root, file);
                var actual = Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
                if (!string.Equals(actual, PinnedDigests[file], StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"frozen .NET contract pin mismatch for {file}");
                }
                if (!CryptographicOperations.FixedTimeEquals(
                        Convert.FromHexString(actual),
                        Convert.FromHexString(hashes[file])))
                {
                    throw new InvalidDataException($"hash mismatch for {file}");
                }

                using var fixture = ParseObject(path);
                if (!fixture.RootElement.TryGetProperty("contract", out var fixtureContract)
                    || fixtureContract.ValueKind != JsonValueKind.String
                    || !string.Equals(fixtureContract.GetString(), ContractIds[file], StringComparison.Ordinal))
                {
                    throw new InvalidDataException($"unexpected contract identifier in {file}");
                }
                if (!fixture.RootElement.TryGetProperty("syntheticOnly", out var fixtureSynthetic)
                    || fixtureSynthetic.ValueKind != JsonValueKind.True)
                {
                    throw new InvalidDataException($"contract fixture is not marked synthetic-only: {file}");
                }
            }

            SemanticVectors.Validate(root);

            Console.WriteLine($"Validated {expectedFiles.Length} synthetic contract files for .NET.");
            return 0;
        }
        catch (Exception error) when (error is IOException
                                      or UnauthorizedAccessException
                                      or JsonException
                                      or FormatException
                                      or InvalidDataException
                                      or InvalidOperationException)
        {
            Console.Error.WriteLine($"Contract gate failed: {error.Message}");
            return 1;
        }
    }

    private static JsonDocument ParseObject(string path)
    {
        var document = JsonDocument.Parse(
            File.ReadAllBytes(path),
            new JsonDocumentOptions { AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow, MaxDepth = 64 });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            document.Dispose();
            throw new InvalidDataException($"contract file is not an object: {Path.GetFileName(path)}");
        }

        return document;
    }

    private static string BoundedPath(string root, string file)
    {
        if (!string.Equals(file, "SOURCE.sha256", StringComparison.Ordinal)
            && !SafeFileName().IsMatch(file))
        {
            throw new InvalidDataException("contract filename is invalid");
        }

        var path = Path.GetFullPath(file, root);
        if (!string.Equals(Path.GetDirectoryName(path), root, StringComparison.Ordinal))
        {
            throw new InvalidDataException("contract path escaped its root");
        }

        return path;
    }

    private static Dictionary<string, string> ReadHashes(string path)
    {
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in File.ReadLines(path))
        {
            var match = HashLine().Match(line);
            if (!match.Success || !hashes.TryAdd(match.Groups[2].Value, match.Groups[1].Value))
            {
                throw new InvalidDataException("invalid or duplicate hash manifest entry");
            }
        }

        return hashes;
    }

    private static List<string> StringArray(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException($"missing {property} array");
        }

        var values = new List<string>();
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(item.GetString()))
            {
                throw new InvalidDataException($"invalid {property} entry");
            }

            values.Add(item.GetString()!);
        }

        return values;
    }

    private static void RequireString(JsonElement root, string property, string expected)
    {
        if (!root.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.String
            || !string.Equals(value.GetString(), expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"unexpected {property}");
        }
    }

    [GeneratedRegex("^[a-z0-9-]+\\.json$", RegexOptions.CultureInvariant)]
    private static partial Regex SafeFileName();

    [GeneratedRegex("^([0-9a-f]{64})  ([a-z0-9-]+\\.json)$", RegexOptions.CultureInvariant)]
    private static partial Regex HashLine();
}
