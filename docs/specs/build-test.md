# Spec: Build and test

Toolchains: Zig `0.13+` (`x86/x86_64/aarch64-windows-msvc`, Zydis static, no MSVC project for Zig parts); .NET 4.7.2 SDK + MSBuild for GUI (WinForms, Costura single-file Release; no .NET 8 — breaks Win8/2012). PDBs as CI artifacts; live debug via WinDbg + `OutputDebugStringA`.

## Requirement → test traceability

| Requirement | Unit | Corpus | VM | Manual |
|---|---|---|---|---|
| R1 no disk patch (hash unchanged) | | | ✓ | |
| LocalOnly discovery+patch | ✓ | ✓ | | |
| DefPolicy discovery+patch | ✓ | ✓ | | |
| SingleUser (both locations) | ✓ | ✓ | ✓ | |
| SLInit / Win8SL era paths | ✓ | ✓ | | |
| Concurrent sessions (2 users) | | | ✓ | |
| Console + RDP same user | | | ✓ | |
| Shadow | | | ✓ | |
| Uninstall restores + restarts (R6) | ✓ | | ✓ | |
| ThirdParty ServiceDll refused w/o `-o` | ✓ | | ✓ | |
| Modified termsrv rejected | ✓ | | ✓ | |
| ARM64 discovery parity (R5) | ✓ | ✓ | | |
| Partial-patch visible in GUI | ✓ | | ✓ | |
| No network/creds/proc in hook (R4) | ✓ | | | ✓ (review) |

## Gates

1. `zig build test` (HookTest VEH + `DONT_RESOLVE_DLL_REFERENCES`): all required sites `FOUND`, lens ≤16, zero `ERROR`.
2. Arch parity on corpus (ARM64 file-based, not executed).
3. VM matrix per `support-matrix.md`: install → reboot → GUI green → loopback → concurrency + shadow. Fail = crash loop or enforcement intact.
4. Size: hook `<200KB`/arch, installer `<1MB`.

## Corpus

Hashes only checked in; CI fetches pinned `termsrv.dll` set. Community uploads quarantined until HookTest passes.
