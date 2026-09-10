# Spec: InstallerCli (Zig static)

Authority: ServiceDll, files, ACLs, firewall, TS config, schtask (R7). Compatibility: Win8+ x86/x64/ARM64, admin/SYSTEM only. Observability: stdout exit codes + `install.log`; GUI reads resulting state, never drives installer.

## CLI

`-l` (diagnose only, no changes) / `-i [-s] [-o]` / `-u [-k]` / `-r` / `-w` (health verify: files present, ServiceDll correct, service running — no INI concept).

## Installation transaction

Trigger: `-i` as admin. Input: arch-matched DLLs. Output: valid installed config OR pre-install state restored. Invariant: MUST NOT leave ServiceDll→missing DLL, TermService permanently stopped, partial files, orphaned task. Rollback order (reverse): delete task → restore ServiceDll → restore service start mode/state → remove copied files → report `InstallFailed` (see `state-machine.md`).

Steps: arch gate → `ImagePath` contains `svchost.exe` (else refuse; `-o` overrides ThirdParty) → `TERMSRV_MODIFIED` integrity check → stop TermService/UmRdpService (10s) → copy DLLs + ACLs (`S-1-5-18/6` FullControl) → set `ServiceDll` (`REG_EXPAND_SZ`) → TS registry (`fDenyTSConnections=0`, `EnableConcurrentSessions=1`, `AllowMultipleTSSessions=1`) → firewall TCP 3389 (`FwPolicy2` COM, `netsh` fallback) → restart services → create `RDPForgeHealth` schtask → Defender-exclusion prompt (manual `Add-MpPreference` if declined). H264 `.pol` documented, not automatic.

## Uninstall (precise)

Uninstall does not require reboot. It restores `ServiceDll` → `%SystemRoot%\System32\termsrv.dll`, restarts TermService, deletes install dir + health task, and reports completion only after the restart succeeds. `-k` preserves firewall/registry tweaks. Failure mid-way → roll forward to a safe state (service running on original DLL) and report which step failed.
