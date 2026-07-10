// Generates tests/vectors/vectors.json for the C core test suite.
//
// The JWS builder below is a byte-for-byte copy of the license server's
// JwsLicenseSigner.BuildCompactJws (Hymma.LM), and the payloads are shaped
// like LicenseGetApiModel serialized with the server's PayloadOptions
// (PascalCase, nulls omitted). If the C core verifies these vectors it
// verifies what production signs.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

const string Usage = "usage: vectorgen <output.json>";
if (args.Length != 1) { Console.Error.WriteLine(Usage); return 1; }

var payloadOptions = new JsonSerializerOptions
{
    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
};

// ---- keys -----------------------------------------------------------------
using var rsa = RSA.Create(2048);
using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);

var rsaParams = rsa.ExportParameters(false);
var ecParams = ec.ExportParameters(false);

static string B64Url(ReadOnlySpan<byte> bytes) =>
    Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

// Same as JwsLicenseSigner.BuildCompactJws.
static string BuildCompactJws(string algorithm, ReadOnlySpan<byte> payloadJson, Func<byte[], byte[]> sign)
{
    var header = Encoding.UTF8.GetBytes($$"""{"alg":"{{algorithm}}","typ":"JWT"}""");
    var signingInput = B64Url(header) + "." + B64Url(payloadJson);
    var signature = sign(Encoding.ASCII.GetBytes(signingInput));
    return signingInput + "." + B64Url(signature);
}

string SignRs256(object payload)
{
    var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, payload.GetType(), payloadOptions);
    return BuildCompactJws("RS256", bytes,
        input => rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
}

string SignEs256(object payload)
{
    var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, payload.GetType(), payloadOptions);
    return BuildCompactJws("ES256", bytes,
        input => ec.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
}

// ---- license payloads (shape of LicenseGetApiModel) ------------------------
object Product() => new
{
    Id = "PRD_01KWWPEPM0N070BDAHJ7G09RGV",
    Name = "CADshift Nesting",
    Vendor = new { Id = "VDR_01JYR1K9S59A71Z7PHE64TE6CX", Name = "Hymma" },
};

object Computer() => new
{
    Id = "PC_01KWVTRYM7AXBT1V56M2N3E3AB",
    MacAddress = "KS8E9QAZBQTE92M8XKPX8A7KT3SDK2V8AV65AM4VKRBSX5T7S8GG",
    Name = "SHOP-FLOOR-01",
};

object TrialLicense() => new
{
    Created = "2026-07-01T09:15:00",
    Id = "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0",
    Status = "ValidTrial",
    LiveMode = false,
    TrialEndDate = "2026-07-20T13:44:38.2833333",
    Expires = "2026-10-08T01:17:58.115645Z",
    Product = Product(),
    Computer = Computer(),
};

object PaidLicense() => new
{
    Created = "2026-05-11T08:00:00",
    Updated = "2026-06-01T10:30:00",
    Id = "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0",
    Status = "Valid",
    LiveMode = true,
    TrialEndDate = "2026-05-25T08:00:00",
    FirstPaidOn = "2026-06-01T10:30:00",
    Expires = "2026-12-01T00:00:00Z",
    Receipt = new
    {
        Id = "RCP_01KWWQZZZZN070BDAHJ7G09AAA",
        Code = "",
        Qty = 10,
        BuyerEmail = "jane@example.com",
        Expires = "2027-06-01T00:00:00Z",
    },
    Product = Product(),
    Computer = Computer(),
    Metadata = new[] { new { Key = "seat", Value = "floor-1" } },
};

object LegacyNoStatusTrial() => new
{
    Id = "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0",
    TrialEndDate = "2026-08-01T00:00:00",
    Expires = "2026-10-01T00:00:00Z",
    Product = Product(),
    Computer = Computer(),
};

object ReceiptExpiredLicense() => new
{
    Updated = "2025-06-01T10:30:00",
    Id = "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0",
    Status = "ReceiptExpired",
    LiveMode = true,
    TrialEndDate = "2025-05-25T08:00:00",
    Expires = "2026-12-01T00:00:00Z",
    Receipt = new
    {
        Id = "RCP_01KWWQZZZZN070BDAHJ7G09AAA",
        Code = "",
        Qty = 1,
        BuyerEmail = "jane@example.com",
        Expires = "2026-06-01T00:00:00Z",
    },
    Product = Product(),
    Computer = Computer(),
};

// ---- cases ------------------------------------------------------------------
var cases = new List<object>();

void AddCase(string name, string jws, bool valid, string? nowUtc = null,
             string? expectedStatus = null, string? licenseId = null)
    => cases.Add(new { Name = name, Jws = jws, Valid = valid, NowUtc = nowUtc,
                       ExpectedStatus = expectedStatus, LicenseId = licenseId });

var rsTrial = SignRs256(TrialLicense());
AddCase("rs256-trial-valid", rsTrial, true, "2026-07-10T00:00:00Z",
        "ValidTrial", "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0");
AddCase("rs256-trial-lapsed", rsTrial, true, "2026-07-25T00:00:00Z",
        "ValidTrial", null); // server status trusted until FILE expiry...
AddCase("rs256-file-expired", rsTrial, true, "2026-11-01T00:00:00Z",
        "Expired", null);

var rsPaid = SignRs256(PaidLicense());
AddCase("rs256-paid-valid", rsPaid, true, "2026-07-10T00:00:00Z",
        "Valid", "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0");

var esPaid = SignEs256(PaidLicense());
AddCase("es256-paid-valid", esPaid, true, "2026-07-10T00:00:00Z", "Valid", null);

var esReceiptExpired = SignEs256(ReceiptExpiredLicense());
AddCase("es256-receipt-expired", esReceiptExpired, true, "2026-07-10T00:00:00Z",
        "ReceiptExpired", null);

var rsLegacy = SignRs256(LegacyNoStatusTrial());
AddCase("rs256-legacy-trial", rsLegacy, true, "2026-07-10T00:00:00Z",
        "ValidTrial", null);
AddCase("rs256-legacy-trial-over", rsLegacy, true, "2026-08-15T00:00:00Z",
        "InvalidTrial", null);

object UnregisteredLicense() => new
{
    Updated = "2026-06-01T10:30:00",
    Id = "LIC_01KWVTRYMCAGWHTCVBYFGNJDA0",
    Status = "ReceiptUnregistered",
    LiveMode = true,
    TrialEndDate = "2026-05-25T08:00:00",
    Expires = "2026-12-01T00:00:00Z",
    Product = Product(),
    Computer = Computer(),
};

var rsUnregistered = SignRs256(UnregisteredLicense());
AddCase("rs256-receipt-unregistered", rsUnregistered, true, "2026-07-10T00:00:00Z",
        "ReceiptUnregistered", null);

// Tampering: bump a character inside the payload segment.
static string TamperPayload(string jws)
{
    var parts = jws.Split('.');
    var chars = parts[1].ToCharArray();
    var i = chars.Length / 2;
    chars[i] = chars[i] == 'A' ? 'B' : 'A';
    return parts[0] + "." + new string(chars) + "." + parts[2];
}

// Signature from one token pasted onto another.
static string SwapSignature(string jws, string donor)
    => jws[..jws.LastIndexOf('.')] + donor[donor.LastIndexOf('.')..];

AddCase("rs256-tampered-payload", TamperPayload(rsPaid), false);
AddCase("rs256-swapped-signature", SwapSignature(rsPaid, rsTrial), false);
AddCase("es256-tampered-payload", TamperPayload(esPaid), false);
AddCase("es256-truncated-signature",
        esPaid[..(esPaid.LastIndexOf('.') + 40)], false);
AddCase("garbage-not-a-jws", "hello.world", false);

// ---- auxiliary vectors -------------------------------------------------------
static string Sha256Hex(string s) =>
    Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(s)));

var sha = new[]
{
    new { Input = "abc", Hex = Sha256Hex("abc") },
    new { Input = "The quick brown fox jumps over the lazy dog", Hex = Sha256Hex("The quick brown fox jumps over the lazy dog") },
    new { Input = new string('a', 200), Hex = Sha256Hex(new string('a', 200)) },
    new { Input = "W1KS03Z106A,BFEBFBFF000906EA", Hex = Sha256Hex("W1KS03Z106A,BFEBFBFF000906EA") },
};

// DeviceId's Base32ByteArrayEncoder: Crockford alphabet, big-endian 5-bit
// groups, no padding — reimplemented here to pin the C port.
static string CrockfordBase32(byte[] data)
{
    const string alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    var sb = new StringBuilder((data.Length * 8 + 4) / 5);
    int bits = data.Length * 8;
    for (int i = 0; i < bits; i += 5)
    {
        int byteI = i / 8, bitOff = i % 8;
        int chunk = data[byteI] << 8;
        if (byteI + 1 < data.Length) chunk |= data[byteI + 1];
        chunk = (chunk >> (11 - bitOff)) & 0x1f;
        sb.Append(alphabet[chunk]);
    }
    return sb.ToString();
}

static string Fingerprint(params string[] components) =>
    CrockfordBase32(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(",", components))));

var fingerprints = new[]
{
    new { Components = new[] { "W1KS03Z106A", "BFEBFBFF000906EA" },
          Expected = Fingerprint("W1KS03Z106A", "BFEBFBFF000906EA") },
    new { Components = new[] { "stm32-uid-0123456789abcdef" },
          Expected = Fingerprint("stm32-uid-0123456789abcdef") },
};

// ---- output -------------------------------------------------------------------
var doc = new
{
    RsaJwk = new { kty = "RSA", n = B64Url(rsaParams.Modulus!), e = B64Url(rsaParams.Exponent!) },
    EcJwk = new { kty = "EC", crv = "P-256", x = B64Url(ecParams.Q.X!), y = B64Url(ecParams.Q.Y!) },
    Sha256 = sha,
    Fingerprint = fingerprints,
    Cases = cases,
};

var json = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
File.WriteAllText(args[0], json + "\n");
Console.WriteLine($"wrote {args[0]} ({cases.Count} cases)");
return 0;
