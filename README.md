# RDPForge

Concurrent Remote Desktop enabler for Windows 8+ and Server 2012+. See `docs/support-matrix.md` for the authoritative OS/arch states.

## Design guarantees

- `termsrv.dll` is never modified on disk (R1).
- Patch locations are discovered from the loaded image; no version-specific offset tables ship or are consulted (R2/R2a).
- No runtime symbols, PDB downloads, network access, or config files in the hook (R4).
- Failed discovery fails closed per site and never crashes the service; partial-patch states are explicit and visible (R3).
- Installation is transactional with rollback; uninstall restores `ServiceDll` and restarts the service without requiring reboot (R6).
- Responsibilities are separated: ForgeHook patches; InstallerCli installs/configures; ManagerGui observes/configures/tests (R7).

## Components

- `ForgeHook.dll` (Zig, x86/x64/ARM64) — runs inside `svchost termsvcs`.
- `InstallerCli.exe` (Zig, static) — admin install/uninstall/health, Server-Core safe.
- `ManagerGui.exe` (C# WinForms, net472) — status, settings, loopback test.

## Quickstart (dev)

```
zig build -Dtarget=x86_64-windows-msvc
zig build test
msbuild src/ManagerGui/ManagerGui.csproj
InstallerCli.exe -i
ManagerGui.exe
```

## Docs (contracts)

- `docs/requirements.md` — constitution (read first)
- `docs/architecture.md` — ownership, loader-lock contract, atomicity
- `docs/state-machine.md` — install/runtime/failure states
- `docs/specs/hook.md`, `autofind.md`, `installer.md`, `gui.md`, `build-test.md`
- `docs/support-matrix.md`, `docs/security.md`, `docs/glossary.md`
