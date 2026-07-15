using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NSec.Cryptography;
using Sodium;

internal static class SemanticVectors
{
    public static void Validate(string root)
    {
        ValidateCli(Path.Combine(root, "cli.json"));
        ValidateMcpTools(Path.Combine(root, "mcp-tools.json"));
        ValidateRequestSigning(Path.Combine(root, "request-signing.json"));
        ValidateEnvelope(Path.Combine(root, "encrypted-envelope.json"));
        ValidateGrantRules(Path.Combine(root, "grant-access.json"));
        ValidateCredentialRules(Path.Combine(root, "credential-blobs.json"));
    }

    private static void ValidateCli(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        RequireEqual(root.GetProperty("status").GetString(), "frozen", ".NET CLI status");
        RequireEqual(root.GetProperty("sourceOfTruth").GetString(), "native-runtime", ".NET CLI source");

        var exitCodes = root.GetProperty("exitCodes");
        var expectedExitCodes = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["success"] = 0,
            ["failure"] = 1,
            ["usage"] = 2,
            ["pendingOrUnavailable"] = 75,
            ["notPermitted"] = 77,
            ["unsafeEnvironment"] = 78,
        };
        RequireExactProperties(exitCodes, expectedExitCodes.Keys, ".NET CLI exit codes");
        foreach (var expected in expectedExitCodes)
        {
            if (exitCodes.GetProperty(expected.Key).GetInt32() != expected.Value)
            {
                throw new InvalidDataException(".NET CLI exit-code semantics diverged");
            }
        }

        var identity = root.GetProperty("identityModel");
        RequireEqual(identity.GetProperty("apiKeyOwner").GetString(), "organization", ".NET API-key ownership");
        if (!identity.GetProperty("organizationKeyMayBeSharedByAgents").GetBoolean())
        {
            throw new InvalidDataException(".NET rejected shared organization API keys");
        }
        RequireStringSequence(
            identity.GetProperty("agentIdentity"),
            ["agentId", "x25519", "ed25519"],
            ".NET Agent identity");

        var expectedCommands = new[]
        {
            "init", "doctor", "connect", "connect", "status", "disconnect", "search", "get", "get", "get",
            "get", "exec", "inject", "report-stale", "mcp", "agents", "security", "security",
            "security", "security", "purge",
        };
        var commands = root.GetProperty("commands").EnumerateArray().ToArray();
        if (commands.Length != expectedCommands.Length)
        {
            throw new InvalidDataException(".NET CLI command set diverged");
        }
        for (var index = 0; index < commands.Length; index++)
        {
            var command = commands[index];
            RequireEqual(command.GetProperty("name").GetString(), expectedCommands[index], ".NET CLI command");
            var argv = command.GetProperty("argv").EnumerateArray().Select(value => value.GetString()!).ToArray();
            if (argv.Length == 0 || argv.Any(value => value.Any(char.IsControl)))
            {
                throw new InvalidDataException(".NET CLI argv contract is invalid");
            }
            var secretOutput = command.GetProperty("secretOutput").GetBoolean();
            if (secretOutput != (command.GetProperty("name").GetString() == "get"))
            {
                throw new InvalidDataException(".NET CLI secret-output classification diverged");
            }
        }

        var processExitCodes = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["version"] = 0,
            ["unknown-command"] = 2,
            ["deprecated-connect-id"] = 1,
            ["unsafe-terminal-argument"] = 1,
            ["inject-fake-cdp-fails-before-profile-open"] = 78,
            ["unsafe-environment"] = 78,
        };
        var processCases = root.GetProperty("processCases").EnumerateArray().ToArray();
        if (processCases.Length != processExitCodes.Count)
        {
            throw new InvalidDataException(".NET CLI process-case set diverged");
        }
        foreach (var processCase in processCases)
        {
            var name = processCase.GetProperty("name").GetString()!;
            if (!processExitCodes.TryGetValue(name, out var exitCode)
                || processCase.GetProperty("exitCode").GetInt32() != exitCode)
            {
                throw new InvalidDataException(".NET CLI process-case semantics diverged");
            }
            _ = processCase.GetProperty("stdoutExact").GetString()
                ?? throw new InvalidDataException("missing .NET CLI stdout snapshot");
            _ = processCase.GetProperty("stderrExact").GetString()
                ?? throw new InvalidDataException("missing .NET CLI stderr snapshot");
        }

        var outputRules = root.GetProperty("outputRules");
        RequireStringSequence(
            outputRules.GetProperty("stdoutMayContainPlaintextSecretOnlyFor"),
            ["get", "retrieve"],
            ".NET CLI plaintext-output rule");
        RequireEqual(outputRules.GetProperty("errorsAndProgress").GetString(), "stderr", ".NET CLI error stream");
        RequireEqual(outputRules.GetProperty("machineOutput").GetString(), "stdout", ".NET CLI machine stream");
        RequireEqual(outputRules.GetProperty("identifierDisplay").GetString(), "first8-ellipsis-last6", ".NET identifier display");
        RequireEqual(outputRules.GetProperty("apiKeyArgv").GetString(), "reject-before-parser-without-echo", ".NET API-key argv rule");

        foreach (var snapshot in root.GetProperty("credentialOutputSnapshots").EnumerateObject())
        {
            if (string.IsNullOrEmpty(snapshot.Value.GetString()))
            {
                throw new InvalidDataException(".NET CLI credential snapshot is empty");
            }
        }
        foreach (var snapshot in root.GetProperty("commandOutputSnapshots").EnumerateArray())
        {
            _ = snapshot.GetProperty("name").GetString()
                ?? throw new InvalidDataException("missing .NET CLI output snapshot name");
            _ = snapshot.GetProperty("exitCode").GetInt32();
            _ = snapshot.GetProperty("stdout").GetString()
                ?? throw new InvalidDataException("missing .NET CLI output snapshot stdout");
            _ = snapshot.GetProperty("stderr").GetString()
                ?? throw new InvalidDataException("missing .NET CLI output snapshot stderr");
        }
    }

    private static void ValidateMcpTools(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        var server = root.GetProperty("server");
        RequireEqual(server.GetProperty("name").GetString(), "Palladin Agents", ".NET MCP server name");
        RequireEqual(server.GetProperty("title").GetString(), "Palladin Agent Runtime", ".NET MCP server title");
        RequireStringSequence(
            root.GetProperty("supportedProtocolVersions"),
            ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"],
            ".NET MCP protocol versions");

        var compatibility = root.GetProperty("compatibility");
        var expectedCompatibility = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["contentType"] = "text",
            ["toolResultJson"] = "pretty",
            ["mcpWaitDefault"] = "one-shot",
            ["fieldSelectorPrecedence"] = "fieldId",
            ["stdout"] = "json-rpc-only",
            ["operatorOutput"] = "stderr",
        };
        RequireExactProperties(compatibility, expectedCompatibility.Keys, ".NET MCP compatibility");
        foreach (var expected in expectedCompatibility)
        {
            RequireEqual(compatibility.GetProperty(expected.Key).GetString(), expected.Value, ".NET MCP compatibility");
        }

        var expectedTools = new Dictionary<string, (string? Method, string[] Required)>(StringComparer.Ordinal)
        {
            ["search_entries"] = (null, ["query"]),
            ["get_credential"] = ("Get", ["vaultId", "entryId"]),
            ["exec_with_credential"] = ("Exec", ["vaultId", "entryId"]),
            ["inject_credential"] = (null, ["vaultId", "entryId", "cdp"]),
            ["report_credential_stale"] = (null, ["vaultId", "entryId"]),
        };
        var tools = root.GetProperty("tools").EnumerateArray().ToArray();
        if (tools.Length != expectedTools.Count)
        {
            throw new InvalidDataException(".NET MCP tool set diverged");
        }
        foreach (var tool in tools)
        {
            var name = tool.GetProperty("name").GetString()!;
            if (!expectedTools.TryGetValue(name, out var expected))
            {
                throw new InvalidDataException(".NET MCP contains an unknown tool");
            }
            var method = tool.GetProperty("requiredMethod");
            var actualMethod = method.ValueKind == JsonValueKind.Null ? null : method.GetString();
            RequireEqual(actualMethod, expected.Method, ".NET MCP grant method");
            if (string.IsNullOrWhiteSpace(tool.GetProperty("description").GetString()))
            {
                throw new InvalidDataException(".NET MCP tool description is empty");
            }
            var schema = tool.GetProperty("inputSchema");
            RequireEqual(schema.GetProperty("type").GetString(), "object", ".NET MCP schema type");
            if (schema.GetProperty("additionalProperties").GetBoolean())
            {
                throw new InvalidDataException(".NET MCP schema permits undeclared input");
            }
            var properties = schema.GetProperty("properties");
            RequireStringSequence(schema.GetProperty("required"), expected.Required, ".NET MCP required fields");
            foreach (var required in expected.Required)
            {
                if (!properties.TryGetProperty(required, out _))
                {
                    throw new InvalidDataException(".NET MCP required field is undeclared");
                }
            }
            foreach (var property in properties.EnumerateObject())
            {
                if (string.IsNullOrWhiteSpace(property.Value.GetProperty("type").GetString())
                    || string.IsNullOrWhiteSpace(property.Value.GetProperty("description").GetString()))
                {
                    throw new InvalidDataException(".NET MCP property contract is incomplete");
                }
            }
        }
    }

    private static void ValidateRequestSigning(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        var input = root.GetProperty("input");
        var expected = root.GetProperty("expected");
        var body = Encoding.UTF8.GetBytes(input.GetProperty("bodyUtf8").GetString()!);
        var bodyHash = Convert.ToBase64String(SHA256.HashData(body));
        RequireEqual(bodyHash, expected.GetProperty("bodySha256Base64").GetString(), "request body digest");
        var canonical = string.Join('\n',
            input.GetProperty("method").GetString()!.ToUpperInvariant(),
            input.GetProperty("pathWithQuery").GetString(),
            input.GetProperty("timestamp").GetInt64().ToString(CultureInfo.InvariantCulture),
            input.GetProperty("nonceBase64").GetString(),
            bodyHash);
        RequireEqual(canonical, expected.GetProperty("canonicalUtf8").GetString(), "request canonicalization");

        var keyVector = root.GetProperty("key");
        var seed = Convert.FromHexString(keyVector.GetProperty("privateSeedHex").GetString()!);
        var publicBytes = Convert.FromBase64String(keyVector.GetProperty("publicKeyBase64").GetString()!);
        var signature = Convert.FromBase64String(expected.GetProperty("signatureBase64").GetString()!);
        var canonicalBytes = Encoding.UTF8.GetBytes(canonical);
        try
        {
            using var privateKey = Key.Import(
                SignatureAlgorithm.Ed25519,
                seed,
                KeyBlobFormat.RawPrivateKey,
                new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var derivedPublic = privateKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            if (!CryptographicOperations.FixedTimeEquals(derivedPublic, publicBytes))
            {
                throw new InvalidDataException(".NET derived an unexpected signing public key");
            }

            var generatedSignature = SignatureAlgorithm.Ed25519.Sign(privateKey, canonicalBytes);
            if (!CryptographicOperations.FixedTimeEquals(generatedSignature, signature))
            {
                throw new InvalidDataException(".NET generated an unexpected request signature");
            }

            if (!SignatureAlgorithm.Ed25519.Verify(privateKey.PublicKey, canonicalBytes, signature))
            {
                throw new InvalidDataException(".NET rejected the request-signing vector");
            }

            canonicalBytes[0] ^= 1;
            if (SignatureAlgorithm.Ed25519.Verify(privateKey.PublicKey, canonicalBytes, signature))
            {
                throw new InvalidDataException(".NET accepted a tampered request-signing vector");
            }

            CryptographicOperations.ZeroMemory(derivedPublic);
            CryptographicOperations.ZeroMemory(generatedSignature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(canonicalBytes);
        }
    }

    private static void ValidateEnvelope(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        var keys = root.GetProperty("keyFixture");
        var envelope = root.GetProperty("envelope");
        var privateKey = Convert.FromBase64String(keys.GetProperty("privateKeyBase64").GetString()!);
        var publicKey = Convert.FromBase64String(keys.GetProperty("publicKeyBase64").GetString()!);
        var wrappedDek = Convert.FromBase64String(envelope.GetProperty("agentWrappedDek").GetString()!);
        var nonce = Convert.FromBase64String(envelope.GetProperty("nonce").GetString()!);
        var cipherText = Convert.FromBase64String(envelope.GetProperty("reEncryptedBlob").GetString()!);
        byte[]? dek = null;
        byte[]? plaintext = null;
        try
        {
            dek = SealedPublicKeyBox.Open(wrappedDek, privateKey, publicKey);
            var expectedDek = Convert.FromBase64String(root.GetProperty("dekBase64").GetString()!);
            if (!CryptographicOperations.FixedTimeEquals(dek, expectedDek))
            {
                throw new InvalidDataException(".NET unwrapped an unexpected DEK");
            }

            plaintext = SecretBox.Open(cipherText, nonce, dek);
            var expectedPlaintext = Encoding.UTF8.GetBytes(root.GetProperty("plaintextUtf8").GetString()!);
            if (!CryptographicOperations.FixedTimeEquals(plaintext, expectedPlaintext))
            {
                throw new InvalidDataException(".NET decrypted an unexpected credential payload");
            }

            var tampered = cipherText.ToArray();
            tampered[^1] ^= 1;
            try
            {
                _ = SecretBox.Open(tampered, nonce, dek);
                throw new InvalidDataException(".NET accepted a tampered credential envelope");
            }
            catch (CryptographicException)
            {
                // Expected fail-closed behavior.
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            if (dek is not null) CryptographicOperations.ZeroMemory(dek);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private static void ValidateGrantRules(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        foreach (var state in root.GetProperty("states").EnumerateArray())
        {
            var access = state.GetProperty("access").GetString()!;
            var expectedExit = state.GetProperty("exitCode").GetInt32();
            var actualExit = access switch
            {
                "granted" => 0,
                "pending" or "unavailable" => 75,
                "denied" or "revoked" or "expired" or "consumed" or "method-not-allowed"
                    or "script-exec-only" or "blocked" => 77,
                _ => throw new InvalidDataException("unknown grant state in contract"),
            };
            if (actualExit != expectedExit || state.GetProperty("retryable").GetBoolean() != (actualExit == 75))
            {
                throw new InvalidDataException(".NET grant exit classification diverged");
            }
        }

        foreach (var duration in root.GetProperty("durations").EnumerateArray())
        {
            var actual = ParseDuration(duration.GetProperty("input").GetString()!);
            if (actual != duration.GetProperty("expectedMs").GetInt64())
            {
                throw new InvalidDataException(".NET duration parsing diverged");
            }
        }

        foreach (var policy in root.GetProperty("waitPolicies").EnumerateArray())
        {
            var options = policy.GetProperty("options");
            var hints = policy.GetProperty("hints");
            var expected = policy.GetProperty("expected");
            var wait = OptionalInt(options, "waitMs") ?? OptionalInt(hints, "maxWaitMs") ?? 180_000;
            var poll = Math.Clamp(OptionalInt(options, "pollMs") ?? OptionalInt(hints, "pollIntervalMs") ?? 30_000, 5_000, 60_000);
            var heartbeat = Math.Min(10_000, poll);
            var pollTimeout = Math.Min(10_000, poll);
            if (wait != expected.GetProperty("waitMs").GetInt32()
                || poll != expected.GetProperty("pollMs").GetInt32()
                || heartbeat != expected.GetProperty("heartbeatMs").GetInt32()
                || pollTimeout != expected.GetProperty("pollTimeoutMs").GetInt32())
            {
                throw new InvalidDataException(".NET wait policy diverged");
            }
        }

        foreach (var scenario in root.GetProperty("waitScenarios").EnumerateArray())
        {
            ValidateWaitScenario(scenario);
        }
    }

    private static void ValidateCredentialRules(string path)
    {
        using var document = JsonDocument.Parse(File.ReadAllBytes(path));
        var root = document.RootElement;
        var totpUnixSeconds = root.GetProperty("totpUnixSeconds").GetInt64();
        foreach (var vector in root.GetProperty("cases").EnumerateArray())
        {
            var plaintext = vector.GetProperty("plaintext").GetString()!;
            var parsed = TryParseCredential(plaintext);
            var expectedParseError = OptionalBool(vector, "parseError") ?? false;
            if (expectedParseError == parsed.Success)
            {
                throw new InvalidDataException(".NET credential parse classification diverged");
            }
            if (!parsed.Success) continue;

            if (vector.TryGetProperty("primary", out var primary)
                && !string.Equals(parsed.Primary, primary.GetString(), StringComparison.Ordinal))
            {
                throw new InvalidDataException(".NET credential primary selection diverged");
            }
            if (vector.TryGetProperty("customFieldCount", out var fieldCount)
                && parsed.Fields.Count != fieldCount.GetInt32())
            {
                throw new InvalidDataException(".NET credential field filtering diverged");
            }
            if (vector.TryGetProperty("scriptRefCount", out var refCount)
                && parsed.ScriptRefCount != refCount.GetInt32())
            {
                throw new InvalidDataException(".NET script reference parsing diverged");
            }
            if (vector.TryGetProperty("totpCode", out var expectedCode))
            {
                var descriptor = ResolveTotp(parsed, vector);
                var actualCode = Totp(descriptor, totpUnixSeconds);
                RequireEqual(actualCode, expectedCode.GetString(), ".NET TOTP vector");
            }

            if (vector.TryGetProperty("redactionForbidden", out var forbidden)
                || vector.TryGetProperty("redactionContains", out _))
            {
                var redacted = RedactTotpSecrets(plaintext, totpUnixSeconds);
                if (forbidden.ValueKind == JsonValueKind.String
                    && redacted.Contains(forbidden.GetString()!, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(".NET TOTP redaction retained a forbidden value");
                }
                if (vector.TryGetProperty("redactionContains", out var required)
                    && required.ValueKind == JsonValueKind.String
                    && !redacted.Contains(required.GetString()!, StringComparison.Ordinal))
                {
                    throw new InvalidDataException(".NET TOTP redaction omitted its safe marker");
                }
            }

            ValidateSelection(parsed, vector, totpUnixSeconds);
        }
    }

    private static ParsedCredential TryParseCredential(string plaintext)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(plaintext);
        }
        catch (JsonException)
        {
            return new ParsedCredential(true, plaintext, [], null, 0);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return new ParsedCredential(true, plaintext, [], null, 0);
            }
            var root = document.RootElement;
            var primary = OptionalString(root, "password") ?? OptionalString(root, "value") ?? string.Empty;
            var fields = new List<CredentialField>();
            if (root.TryGetProperty("fields", out var fieldArray) && fieldArray.ValueKind == JsonValueKind.Array)
            {
                foreach (var field in fieldArray.EnumerateArray())
                {
                    var type = OptionalString(field, "type");
                    if (type is not ("text" or "concealed" or "multiline" or "totp")) continue;
                    var id = OptionalString(field, "id") ?? string.Empty;
                    var label = OptionalString(field, "label") ?? string.Empty;
                    fields.Add(new CredentialField(id, label, type!, field.GetProperty("value").Clone()));
                }
            }

            var scriptRefs = 0;
            if (root.TryGetProperty("script", out _)
                && root.TryGetProperty("refs", out var refs)
                && refs.ValueKind == JsonValueKind.Array)
            {
                foreach (var reference in refs.EnumerateArray())
                {
                    if (string.IsNullOrWhiteSpace(OptionalString(reference, "entryId")))
                    {
                        return new ParsedCredential(false, string.Empty, [], null, 0);
                    }
                    scriptRefs++;
                }
            }

            JsonElement? legacyTotp = root.TryGetProperty("totp", out var totp) ? totp.Clone() : null;
            return new ParsedCredential(true, primary, fields, legacyTotp, scriptRefs);
        }
    }

    private static void ValidateSelection(ParsedCredential parsed, JsonElement vector, long timestamp)
    {
        var selectorId = OptionalString(vector, "selectorFieldId");
        var selectorLabel = OptionalString(vector, "selectorField");
        if (selectorId is null && selectorLabel is null) return;
        var selectionError = OptionalBool(vector, "selectionError") ?? false;
        string? selected = null;
        var failed = false;
        if (selectorId is not null)
        {
            var matches = parsed.Fields.Where(field => string.Equals(field.Id, selectorId, StringComparison.Ordinal)).ToArray();
            failed = matches.Length != 1;
            if (!failed) selected = FieldValue(matches[0], timestamp);
        }
        else if (string.Equals(selectorLabel, "totp", StringComparison.OrdinalIgnoreCase)
                 && parsed.LegacyTotp is not null)
        {
            try { selected = Totp(ParseTotp(parsed.LegacyTotp.Value), timestamp); }
            catch (InvalidDataException) { failed = true; }
        }
        else
        {
            var matches = parsed.Fields.Where(field => string.Equals(field.Label.Trim(), selectorLabel?.Trim(), StringComparison.OrdinalIgnoreCase)).ToArray();
            failed = matches.Length != 1;
            if (!failed) selected = FieldValue(matches[0], timestamp);
        }

        if (failed != selectionError)
        {
            throw new InvalidDataException(".NET field selection classification diverged");
        }
        if (!failed && vector.TryGetProperty("expectedFieldValue", out var expected))
        {
            RequireEqual(selected, expected.GetString(), ".NET field selection");
        }
    }

    private static string FieldValue(CredentialField field, long timestamp) =>
        field.Type == "totp" ? Totp(ParseTotp(field.Value), timestamp) : field.Value.GetString() ?? string.Empty;

    private static TotpDescriptor ResolveTotp(ParsedCredential parsed, JsonElement vector)
    {
        var id = OptionalString(vector, "totpFieldId");
        if (id is not null)
        {
            var field = parsed.Fields.Single(candidate => string.Equals(candidate.Id, id, StringComparison.Ordinal));
            return ParseTotp(field.Value);
        }
        if (parsed.LegacyTotp is null) throw new InvalidDataException("missing .NET TOTP vector");
        return ParseTotp(parsed.LegacyTotp.Value);
    }

    private static void ValidateWaitScenario(JsonElement scenario)
    {
        var policy = scenario.GetProperty("policy");
        var waitMs = policy.GetProperty("waitMs").GetInt32();
        var pollMs = policy.GetProperty("pollMs").GetInt32();
        var heartbeatMs = policy.GetProperty("heartbeatMs").GetInt32();
        var cancelDuringPoll = OptionalString(scenario, "cancelDuring") == "poll";
        var hungPoll = OptionalBool(scenario, "hangPoll") ?? false;
        var responses = scenario.TryGetProperty("responses", out var responseArray)
            ? responseArray.EnumerateArray().Select(value => value.GetString()!).ToArray()
            : [];
        var sleeps = new List<int>();
        var heartbeats = new List<int>();
        var responseIndex = 0;
        var waited = 0;
        var nextPoll = pollMs;
        var nextHeartbeat = heartbeatMs;
        var access = "pending";
        string? error = null;

        while (waited < waitMs)
        {
            var nextEvent = Math.Min(Math.Min(nextPoll, nextHeartbeat), waitMs);
            sleeps.Add(nextEvent - waited);
            waited = nextEvent;
            if (waited >= nextHeartbeat)
            {
                heartbeats.Add(waited);
                nextHeartbeat += heartbeatMs;
            }
            if (waited < nextPoll) continue;
            if (cancelDuringPoll)
            {
                error = "cancelled";
                break;
            }
            if (hungPoll)
            {
                heartbeats.Add(waited);
                nextPoll += pollMs;
                continue;
            }
            if (responseIndex >= responses.Length)
            {
                throw new InvalidDataException(".NET wait scenario exhausted its responses");
            }
            access = responses[responseIndex++];
            if (access != "pending") break;
            nextPoll += pollMs;
        }

        if (scenario.TryGetProperty("expectedSleepMs", out var expectedSleeps))
        {
            RequireSequence(sleeps, IntArray(expectedSleeps), ".NET wait sleep schedule");
        }
        if (scenario.TryGetProperty("expectedHeartbeatMs", out var expectedHeartbeats))
        {
            RequireSequence(heartbeats, IntArray(expectedHeartbeats), ".NET wait heartbeat schedule");
        }
        RequireEqual(access, OptionalString(scenario, "expectedAccess") ?? "pending", ".NET wait result");
        RequireEqual(error, OptionalString(scenario, "expectedError"), ".NET wait cancellation");
    }

    private static string RedactTotpSecrets(string plaintext, long timestamp)
    {
        JsonNode? node;
        try { node = JsonNode.Parse(plaintext); }
        catch (JsonException) { return plaintext; }
        if (node is not JsonObject root) return plaintext;

        var redacted = false;
        if (root.TryGetPropertyValue("totp", out var legacy) && legacy is not null)
        {
            root["totp"] = TotpReplacement(legacy, timestamp);
            redacted = true;
        }
        if (root["fields"] is JsonArray fields)
        {
            foreach (var item in fields)
            {
                if (item is not JsonObject field
                    || field["type"]?.GetValue<string>() != "totp"
                    || !field.TryGetPropertyValue("value", out var value)
                    || value is null)
                {
                    continue;
                }
                field["value"] = TotpReplacement(value, timestamp);
                redacted = true;
            }
        }
        return redacted ? root.ToJsonString() : plaintext;
    }

    private static JsonObject TotpReplacement(JsonNode descriptor, long timestamp)
    {
        try
        {
            var element = JsonSerializer.SerializeToElement(descriptor);
            var value = element.ValueKind == JsonValueKind.String
                ? JsonSerializer.SerializeToElement(element.GetString())
                : element;
            var parsed = ParseTotp(value);
            var code = Totp(parsed, timestamp);
            var expiresIn = parsed.Period - (timestamp % parsed.Period);
            return new JsonObject
            {
                ["code"] = code,
                ["expiresIn"] = expiresIn,
                ["note"] = "TOTP secret withheld - use --field to get a fresh code",
            };
        }
        catch (Exception error) when (error is InvalidDataException or FormatException or UriFormatException)
        {
            return new JsonObject { ["error"] = "TOTP descriptor is invalid and was withheld" };
        }
    }

    private static TotpDescriptor ParseTotp(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var objectSecret = OptionalString(value, "secret") ?? throw new InvalidDataException("missing TOTP secret");
            var objectAlgorithm = (OptionalString(value, "algorithm") ?? "SHA1").ToUpperInvariant();
            var objectDigits = OptionalInt(value, "digits") ?? 6;
            var objectPeriod = OptionalInt(value, "period") ?? 30;
            return ValidatedTotp(objectSecret, objectAlgorithm, objectDigits, objectPeriod);
        }
        if (value.ValueKind != JsonValueKind.String) throw new InvalidDataException("invalid TOTP descriptor");
        var uri = new Uri(value.GetString()!, UriKind.Absolute);
        if (!string.Equals(uri.Scheme, "otpauth", StringComparison.OrdinalIgnoreCase)
            || !string.Equals(uri.Host, "totp", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(uri.AbsolutePath.Trim('/')))
        {
            throw new InvalidDataException("invalid TOTP URI");
        }
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .ToDictionary(
                part => Uri.UnescapeDataString(part[0]),
                part => part.Length == 2 ? Uri.UnescapeDataString(part[1]) : string.Empty,
                StringComparer.OrdinalIgnoreCase);
        if (!query.TryGetValue("secret", out var secret)) throw new InvalidDataException("missing TOTP secret");
        var algorithm = query.GetValueOrDefault("algorithm", "SHA1").ToUpperInvariant();
        var digits = ParsePositiveInt(query.GetValueOrDefault("digits", "6"));
        var period = ParsePositiveInt(query.GetValueOrDefault("period", "30"));
        return ValidatedTotp(secret, algorithm, digits, period);
    }

    private static TotpDescriptor ValidatedTotp(string secret, string algorithm, int digits, int period)
    {
        if (algorithm is not ("SHA1" or "SHA256" or "SHA512") || digits is < 6 or > 8 || period <= 0)
        {
            throw new InvalidDataException("unsupported TOTP parameters");
        }
        return new TotpDescriptor(secret, algorithm, digits, period);
    }

    private static string Totp(TotpDescriptor descriptor, long timestamp)
    {
        var key = Base32(descriptor.Secret);
        Span<byte> counter = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(counter, timestamp / descriptor.Period);
        using HMAC hmac = descriptor.Algorithm switch
        {
            "SHA1" => new HMACSHA1(key),
            "SHA256" => new HMACSHA256(key),
            "SHA512" => new HMACSHA512(key),
            _ => throw new InvalidDataException("unsupported TOTP algorithm"),
        };
        var digest = hmac.ComputeHash(counter.ToArray());
        var offset = digest[^1] & 0x0f;
        var binary = ((digest[offset] & 0x7f) << 24)
                     | (digest[offset + 1] << 16)
                     | (digest[offset + 2] << 8)
                     | digest[offset + 3];
        return (binary % (int)Math.Pow(10, descriptor.Digits)).ToString(
            new string('0', descriptor.Digits), CultureInfo.InvariantCulture);
    }

    private static byte[] Base32(string input)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var normalized = input.Trim().TrimEnd('=').ToUpperInvariant();
        var output = new List<byte>();
        var buffer = 0;
        var bits = 0;
        foreach (var character in normalized)
        {
            var value = alphabet.IndexOf(character);
            if (value < 0) throw new InvalidDataException("invalid base32 TOTP secret");
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits < 8) continue;
            bits -= 8;
            output.Add((byte)(buffer >> bits));
            buffer &= (1 << bits) - 1;
        }
        return output.ToArray();
    }

    private static long ParseDuration(string value)
    {
        var suffix = value.EndsWith("ms", StringComparison.Ordinal) ? "ms" : value[^1..];
        var number = double.Parse(value[..^suffix.Length], CultureInfo.InvariantCulture);
        var multiplier = suffix switch { "ms" => 1d, "s" => 1_000d, "m" => 60_000d, _ => throw new InvalidDataException("invalid duration") };
        return checked((long)(number * multiplier));
    }

    private static int ParsePositiveInt(string value) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed > 0
            ? parsed
            : throw new InvalidDataException("invalid positive integer");

    private static int? OptionalInt(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.Number ? value.GetInt32() : null;

    private static bool? OptionalBool(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : null;

    private static string? OptionalString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static int[] IntArray(JsonElement values) =>
        values.ValueKind == JsonValueKind.Array
            ? values.EnumerateArray().Select(value => value.GetInt32()).ToArray()
            : throw new InvalidDataException("expected integer array");

    private static void RequireSequence(IReadOnlyList<int> actual, IReadOnlyList<int> expected, string field)
    {
        if (!actual.SequenceEqual(expected))
        {
            throw new InvalidDataException($"{field} diverged");
        }
    }

    private static void RequireStringSequence(JsonElement actual, IReadOnlyList<string> expected, string field)
    {
        if (actual.ValueKind != JsonValueKind.Array
            || !actual.EnumerateArray().Select(value => value.GetString()).SequenceEqual(expected))
        {
            throw new InvalidDataException($"{field} diverged");
        }
    }

    private static void RequireExactProperties(JsonElement actual, IEnumerable<string> expected, string field)
    {
        if (actual.ValueKind != JsonValueKind.Object
            || !actual.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)
                .SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal))
        {
            throw new InvalidDataException($"{field} diverged");
        }
    }

    private static void RequireEqual(string? actual, string? expected, string field)
    {
        if (!string.Equals(actual, expected, StringComparison.Ordinal))
        {
            throw new InvalidDataException($"{field} diverged");
        }
    }

    private sealed record ParsedCredential(
        bool Success,
        string Primary,
        List<CredentialField> Fields,
        JsonElement? LegacyTotp,
        int ScriptRefCount);

    private sealed record CredentialField(string Id, string Label, string Type, JsonElement Value);
    private sealed record TotpDescriptor(string Secret, string Algorithm, int Digits, int Period);
}
