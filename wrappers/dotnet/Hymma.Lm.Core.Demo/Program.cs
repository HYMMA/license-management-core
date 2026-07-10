// Offline smoke test of the .NET wrapper against the generated test vectors.
// Proves the whole P/Invoke chain: C# -> hymmalm.dll -> portable crypto.
// (No network calls — online flows are exercised against the sandbox server.)
using System.Text.Json;
using Hymma.Lm.Core;

if (args.Length != 1)
{
    Console.Error.WriteLine("usage: demo <path-to-vectors.json>");
    return 2;
}

var doc = JsonDocument.Parse(File.ReadAllText(args[0]));
var root = doc.RootElement;

string rsaJwk = root.GetProperty("RsaJwk").GetRawText();
string ecJwk = root.GetProperty("EcJwk").GetRawText();
string jwks = "[" + rsaJwk + "," + ecJwk + "]";

Console.WriteLine($"MachineId (native): {LicenseClient.GetMachineId()}");

int pass = 0, fail = 0;
foreach (var c in root.GetProperty("Cases").EnumerateArray())
{
    string name = c.GetProperty("Name").GetString()!;
    string jws = c.GetProperty("Jws").GetString()!;
    bool valid = c.GetProperty("Valid").GetBoolean();
    DateTime? now = c.TryGetProperty("NowUtc", out var n) && n.ValueKind == JsonValueKind.String
        ? DateTime.Parse(n.GetString()!, null, System.Globalization.DateTimeStyles.AdjustToUniversal)
        : null;

    try
    {
        var status = LicenseClient.Verify(jws, jwks, nowUtc: now);
        string? expected = c.TryGetProperty("ExpectedStatus", out var e) && e.ValueKind == JsonValueKind.String
            ? e.GetString() : null;

        bool ok = valid && (expected == null || status.ToString() == expected);
        Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}: {status}");
        if (ok) pass++; else fail++;
    }
    catch (LicenseException ex)
    {
        bool ok = !valid;
        Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}: rejected ({ex.Message})");
        if (ok) pass++; else fail++;
    }
}

Console.WriteLine($"{pass} passed, {fail} failed");
return fail == 0 ? 0 : 1;
