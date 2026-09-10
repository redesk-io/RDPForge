# Spec: ForgeHook

Authority: termsrv loading, discovery orchestration, patching, forwarding (R4,R7). Applies to Win8+ x86/x64/ARM64. Observability: event schema below, consumed by GUI log pane.

## 1. Exports (`Export.def`)

Trigger: SCM `svchost` load. Input: none. Output: `ServiceMain`, `SvchostPushServiceGlobals` forwarders resolved via `GetProcAddress(real_termsrv)`. Failure: missing real export → log `TERMSRV_LOAD_FAIL`, return error to SCM (no fallback). Invariant: exactly two exports, no COM.

## 2. DllMain / init handoff

Trigger: `DLL_PROCESS_ATTACH`. Input: loader context. Output: real entry points stored + patch attempt completed or skipped. Failure: any step fails → boot unpatched, never fail load (except `TERMSRV_LOAD_FAIL`). Invariant: Loader-lock contract in `architecture.md` (allowed/forbidden lists, bounded time, `AlreadyHooked` guard). Compatibility: all supported OS/arch. Observability: `HOOK_INIT`, `TERMSRV_LOAD`.

- `DLL_PROCESS_DETACH`: no-op.
- `DisableThreadLibraryCalls` + atomic guard mandatory.

## 3. Thread control

Trigger: post-load, pre-patch. Input: current PID threads. Output: all non-self threads suspended (then resumed post-patch). Failure: `SUSPEND_FAIL` after N retries → abort patching, boot unpatched, resume any suspended. Invariant: never suspend self; always resume on all paths. Observability: `SUSPEND_FAIL` with thread count.

## 4. Logging schema (stable, GUI-consumed)

Fields: `timestamp, component=hook, level, event, arch, termsrv_version, site, rva, length, result, reason`. Version is informational only (R2a). Event IDs: `HOOK_INIT, TERMSRV_LOAD, TERMSRV_LOAD_FAIL, AUTOFIND_BEGIN, SITE_FOUND, SITE_MISS, SITE_VALIDATION_FAIL, PATCH_OK, PATCH_SKIPPED, SUSPEND_FAIL, UNSUPPORTED_OS, TERMSRV_MODIFIED`. Never log user/SID/session data. Sinks: `OutputDebugStringA` + `%ProgramData%\RDPForge\forge.log` (fallback `%ProgramFiles%\RDP Wrapper\forge.log`).

## 5. Size and linkage

Zig DynamicLib per-arch, static Zydis, stripped Release, PDB as CI artifact. Target `<200KB` per DLL.
