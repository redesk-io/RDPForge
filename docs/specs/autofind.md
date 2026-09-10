# Spec: AutoFind (offset discovery, no INI)

Authority: ForgeHook discovery stage. Trigger: post-`TERMSRV_LOAD`, pre-patch, threads suspended. Input: in-memory `termsrv.dll` image + arch. Output: per-site `(rva, len≤16, bytes)` emissions or MISS/SKIP. Failure: per-site skip, never abort service (R3, Model A). Compatibility: Win8+ per site table; 6.0/6.1 → `UNSUPPORTED_OS`. Observability: `AUTOFIND_BEGIN/SITE_FOUND/SITE_MISS/SITE_VALIDATION_FAIL/PATCH_OK/PATCH_SKIPPED`. Version log-only (R2a).

## Pipeline

1. Anchors: `.rdata` 4-byte-stepped scan (UTF-8/16) + IAT (`memset`, `VerifyVersionInfoW`).
2. Function starts: x64/ARM64 pdata + xref (`LEA RIP` / `ADRP+ADD`) + `CHAININFO` backtrace; x86 prologue `8B FF 55 8B EC` + branch worklist.
3. Zydis validation in capped windows (128/256B) → emission. Strict predicates; mismatch → `SITE_VALIDATION_FAIL` → `PATCH_SKIPPED`.

## Site: LocalOnly (Required)

Purpose: disable license-type-local-only enforcement. Supported: Win8+ x86/x64/ARM64.
Discovery: anchor `IsLicenseTypeLocalOnly` via `GetInstanceOfTSLicense` caller; function: xref backtrace.
Expected: `CALL IsLicenseTypeLocalOnly; MOV*; TEST; JS/JNS; CMP; JZ==target`.
Accepted: `JZ`-to-common-target converging with `CMP`; x86 `TEST+JZ` short form.
Rejected: missing CALL, non-converging JZ, window overrun.
Patch: orig ≤16, emit `EB rel8 (jmpshort)` or `90 E9 rel32 (nopjmp)`; semantics: force branch taken.
Failure: MISS → SKIPPED (boot unpatched for license check); VALIDATION_FAIL → SKIPPED; PATCH_FAILURE → SKIPPED. Safety: patch only if all predicates match.

## Site: DefPolicy (Required)

Purpose: neutralize `CDefPolicy::Query` session denial. Supported: Win8+ x86/x64/ARM64.
Discovery: anchor `CDefPolicy::Query`; function: xref/pdata.
Expected: `CMP [base+0x63C(x64)/0x320(x86)]` (ARM64: MOV-derived base + `0x63C/0x638`) + `JZ/JNZ`.
Accepted: register variants (ECX/ESI/RCX/RDI...), recorded in log; short/long jmp forms.
Rejected: unknown displacement, missing conditional, cross-function target.
Patch: `B8 00010000 89 … 90/EB… (mov dword, mov r32, nop/jmp)`; semantics: return policy-allow.
Failure/safety: as LocalOnly.

## Site: SingleUser (Required)

Purpose: disable single-session-per-user arbitration. Supported: Win8+ x86/x64/ARM64.
Discovery: anchors `IsSingleSessionPerUser[Enabled]` + IAT `memset` thunk + `VerifyVersionInfoW`; function: memset-caller search.
Expected: `CALL memset-thunk (JMP [RIP]/[DS])` then `CALL VerifyVersionInfoW` or `CMP [rbp/rsp/ebp+..],1`.
Accepted: `mov eax,1+nop*`, `nop*`, `pop eax; add esp,12` forms; both locations patched when present.
Rejected: neither VerifyVersion call nor CMP found.
Patch semantics: force multi-session allowed. Failure/safety: as LocalOnly.

## Site: NonRDP (Optional)

Purpose: allow non-RDP stack where applicable. Supported: Win8+ x64/ARM64 (x86 best-effort).
Discovery: anchor `IsAllowNonRDPStack`/`AppServer`; miss tolerated.
Expected: `CALL AppServer(5B)` → emit `FF01 31C0 90`. Failure: MISS → SKIPPED silently (feature-gated).

## Site: SLInit (Required on 6.3+; Win8 6.2 uses SLPolicyInternal path instead)

Purpose: initialize SKU policy globals to permissive values. Supported: 6.3+ x86/x64/ARM64.
Discovery: `CSLQuery::Initialize` via `bRemoteConnAllowed` xref; find `LEA bRemoteConnAllowed/bFUSEnabled/bAppServerAllowed/bMultimonAllowed` + `MOV [mem],1 (bInitialized)`.
Expected: LEA set + terminal MOV; Accepted: RIP- vs DS-relative forms. Rejected: short `len≤0x100` without JMP-follow confirmation.
Patch semantics: globals `=1 (allowed) / 0 (unlimited)` per policy table. Failure/safety: as LocalOnly.
