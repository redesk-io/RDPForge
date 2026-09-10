# Support matrix

States: `Supported` = AutoFind + full VM validation done. `Discovery-supported` = AutoFind passes, VM pending. `Unsupported` = out of contract.

| OS | Arch | Discovery | Runtime | Status |
|---|---|---|---|---|
| Windows 8 (6.2, Win8SL path) | x86/x64 | ✓ | ✓ | Supported |
| Windows 8.1 (6.3, SLInit) | x86/x64 | ✓ | ✓ | Supported |
| Windows 10 1507–22H2 | x86/x64 | ✓ | ✓ | Supported |
| Windows 11 21H2+ | x64/ARM64 | ✓ | ✓ | Supported (primary) |
| Server 2012/2012R2 | x64 | ✓ | ✓ | Supported |
| Server 2016–2025 | x64/ARM64 | ✓ | ✓ | Supported |
| Windows 7 / Vista / XP / 2003 | any | — | — | Unsupported |
| New Insider builds | x64/ARM64 | ✓ | pending | Discovery-supported until VM gate passes |

UmHook (camera/USB): opt-in, x64+ARM64, Home/Server only. EndpWrap (audio): deferred, off by default (app-compat risk).
