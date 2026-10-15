// Offline smoke test of the .NET wrapper against the generated test vectors.
// Proves the whole P/Invoke chain: C# -> hymmalm.dll -> portable crypto.
// (No network calls — online flows are exercised against the sandbox server.)
using System.Text.Json;
using LicenseManagement.Core;

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

void Expect(bool ok, string name)
{
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")} {name}");
    if (ok) pass++; else fail++;
}

// ---- license file installed by hand --------------------------------------
const string Product = "PRD_01KWWPEPM0N070BDAHJ7G09RGV";
const string Machine = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG";
string Case(string name) => root.GetProperty("Cases").EnumerateArray()
    .First(c => c.GetProperty("Name").GetString() == name).GetProperty("Jws").GetString()!;

var dir = Path.Combine(Path.GetTempPath(), "hlm-dotnet-import-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dir);
try
{
    var cache = Path.Combine(dir, "cache.lic");
    File.WriteAllText(cache, Case("rs256-trial-valid"));
    LicenseClient NewClient(string machine) => new(new LicenseClientOptions
    {
        BaseUrl = "http://127.0.0.1:1/api/", ProductId = Product, ClientApiKey = "PUB_TEST",
        JwksJson = jwks, MachineId = machine, MachineName = "SHOP-FLOOR-01", LicensePath = cache,
    });

    using (var client = NewClient(Machine))
    {
        Expect(client.LicensePath == cache, "import: license path exposed");

        var r = client.ImportLicense(Case("rs256-tampered-payload"));
        Expect(r.Outcome == LicenseImportOutcome.SignatureInvalid && !r.Succeeded, "import tampered: refused");
        Expect(File.ReadAllText(cache) == Case("rs256-trial-valid"), "import tampered: cache untouched");

        r = client.ImportLicense("not a license");
        Expect(r.Outcome == LicenseImportOutcome.NotALicenseFile, "import garbage: not a license");

        r = client.ImportLicenseFile(Path.Combine(dir, "missing.lic"));
        Expect(r.Outcome == LicenseImportOutcome.NotALicenseFile && r.Message.StartsWith("The file could not be read"),
               "import missing file: not a license, says why");

        var good = Path.Combine(dir, "downloaded.lic");
        File.WriteAllText(good, Case("rs256-paid-valid") + "\r\n");
        r = client.ImportLicenseFile(good);
        Expect(r.Succeeded && r.InstalledPath == cache && r.Message == "License file installed.", "import genuine: installed");
        Expect(File.ReadAllText(cache) == Case("rs256-paid-valid"), "import genuine: cache replaced");
        Expect(client.LicenseId == "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0", "import genuine: license adopted");
    }

    using (var other = NewClient("OTHERMACHINE0000000000000000000000000000000000000000"))
    {
        var r = other.ImportLicense(Case("rs256-trial-valid"));
        Expect(r.Outcome == LicenseImportOutcome.WrongComputer &&
               r.Message == "This license file is for the computer SHOP-FLOOR-01. Download the file for this computer.",
               "import other computer: refused with the computer's name");
        Expect(File.ReadAllText(cache) == Case("rs256-paid-valid"), "import other computer: cache untouched");
    }

    // ---- network failure says what failed ---------------------------------
    File.Delete(cache);
    using (var offline = NewClient(Machine))
    {
        try
        {
            offline.Check();
            Expect(false, "network: refused connection raises");
        }
        catch (LicenseException ex)
        {
            Expect(ex.Error == LicenseError.NetworkFailure && ex.NetworkFailure == NetworkFailure.Connection,
                   $"network: refused connection -> Connection ({ex.NetworkFailure})");
            Expect(ex.Detail.StartsWith("Could not connect to 127.0.0.1."), "network: message names the host");
        }
    }
}
finally
{
    Directory.Delete(dir, true);
}

Console.WriteLine($"{pass} passed, {fail} failed");
return fail == 0 ? 0 : 1;
