# LicenseManagement.Core

Cross-platform [License-Management.com](https://license-management.com) client
for .NET — a thin binding over the open-source native core
([HYMMA/license-management-core](https://github.com/HYMMA/license-management-core)).
All licensing logic (signature verification, status rules, machine
fingerprinting, retry policy, clock-tamper resistance) lives in the shared
native library, so behavior is identical across every platform and every
language wrapper.

Use this package for console apps, services, Unity, or cross-platform work.
For desktop apps that want ready-made activation dialogs, see
`LicenseManagement.EndUser.Wpf` / `LicenseManagement.EndUser.Avalonia`.

```csharp
using LicenseManagement.Core;

using var client = new LicenseClient(new LicenseClientOptions
{
    ProductId    = "PRD_your_product",
    ClientApiKey = "PUB_your_client_key",     // never a MST_ key
    JwksJson     = signingKeysJson,           // GET /api/signingkeys.json
    Format       = SignedFormat.Es256,
    LicensePath  = licenseCachePath,
});

var status = client.Check();                  // silent check + trial bootstrap
if (status == LicenseStatus.InvalidTrial)
    client.Activate(receiptCodeFromUser);
```

Refusals surface as typed exceptions with the server's own explanation:

```csharp
catch (LicenseException ex) when (ex.Error == LicenseError.PaidFormatRequired)
{
    Show("A purchased key is required.", ex.Detail);
}
```

Native libraries for win-x64, linux-x64 and osx-arm64 are included under
`runtimes/`. .NET Framework consumers should copy the matching `hymmalm`
library next to the executable.
