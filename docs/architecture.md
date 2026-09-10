# Architecture

See `requirements.md` (constitution). This doc owns system structure, runtime flow, and cross-cutting contracts.

## Context

TermService (shared `svchost.exe -k termsvcs`) enforces SKU policy in `termsrv.dll`. RDPForge relaxes enforcement in memory at service start.

## Ownership

```
┌───────────────┐
│ InstallerCli  │  ServiceDll, files, ACLs, firewall, TS config, schtask
└───────┬───────┘
        ▼
┌───────────────┐
│ ForgeHook     │  termsrv loading, discovery, patching, forwarding — nothing else (R4,R7)
└───────▲───────┘
        │ read-only
┌───────┴───────┐
│ ManagerGui    │  observes SCM/listener/log, edits TS settings, launches mstsc (R7)
└───────────────┘
```

GUI never installs, patches, discovers, or modifies executable code.

## Version-independence invariant (R2a)

No version → offset table exists anywhere. Version strings are log/diagnostic labels only.

## Runtime flow

1. Trigger: SCM loads `ForgeHook.dll` per `ServiceDll`. Input: on-disk `termsrv.dll` + process context. Owner: ForgeHook.
2. Init handoff (see Loader-lock contract below): resolve + load real `termsrv.dll`, capture entry points.
3. Suspend service threads (self excluded). On `SUSPEND_FAIL` after retries: abort patching, boot unpatched.
4. AutoFind → per-site emissions (see `specs/autofind.md`).
5. Patch apply per site-independent rule below. `FlushInstructionCache`. Resume threads. Tail-call real `ServiceMain`.

## Loader-lock contract (decision, must hold for v1)

Rationale: heavy work inside `DLL_PROCESS_ATTACH` risks loader-lock deadlock. v1 keeps the TermWrap-proven in-DllMain sequence but bounds it explicitly; a future `ServiceMain`-deferred init is reserved if VM validation shows hangs.

- MUST: `DisableThreadLibraryCalls`, `AlreadyHooked` atomic guard, bounded time (abort + boot unpatched on timeout), no heap growth beyond fixed arenas, log + continue on any single-site failure.
- MUST NOT: COM, threads, network, non-system DLL loads, UI, registry writes (log-file append only), unbounded scans (windows capped 128/256B, function-iteration capped).
- Allowed: `GetSystemDirectoryW`, `LoadLibraryExW(SYSTEM32\termsrv.dll)`, `GetProcAddress`, Toolhelp snapshot + `Suspend/ResumeThread`, PE header + section traversal, Zydis decode of capped windows, in-process write + `FlushInstructionCache`, `OutputDebugStringA` + log append.
- Forbidden: `LoadLibrary` of hook-owned DLLs, `CreateThread`, `CoInitialize`, sockets, `RegSetValue`, `CreateProcess`, `MessageBox`.
- Observability: `HOOK_INIT`, `TERMSRV_LOAD`, `SUSPEND_FAIL` events (see `specs/hook.md` logging schema).

## Patch atomicity (Model A — site-independent, intentional)

Patch application is site-independent. A failed required/optional site does not roll back successfully applied sites. A runtime may enter a partially patched state. This is intentional and visible via per-site `PATCH_OK/SKIPPED` events consumed by the GUI. Required vs optional per `specs/autofind.md`; even required-site failure boots (unpatched for that check) rather than crashing (R3).

## Key invariants

- R1, R2/R2a, R4 per requirements. Hook has zero config files and zero third-party DLL dependencies.
