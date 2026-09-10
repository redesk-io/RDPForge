# Spec: ManagerGui (C# WinForms, net472)

Authority: observe + configure TS settings + test (R7). MUST NOT install, patch, discover, or modify executable code. Compatibility: Win8+ (net472 in-box). Observability: renders hook event schema + SCM/listener state.

## Source-of-truth precedence (disagreements resolved here, not invented per view)

- `Installed`: `ServiceDll` basename == `ForgeHook.dll` (64-bit view, `Sysnative` handling).
- `Running`: SCM `TermService == RUNNING`.
- `RDP ready`: Running + `RDP-Tcp` listener present via `winsta.dll!WinStationEnumerateW`.
- `Patched`: last boot log shows `PATCH_OK` for all required sites → `FullyPatched`; any required `PATCH_SKIPPED` → `PartiallyPatched` (site named); no log → `Unknown (reboot to observe)`.
- Example: `ServiceDll=ForgeHook + SCM=stopped + listener=absent` → `Installed, not running` (not an error state).

## Diagnostics (1s timer)

Wrapper / service / listener / `FileVersionInfo` (hook + termsrv). Support label derives from state model, not a version list: `RDPForge (auto-find)` when installed, else `not installed`. No version-gated logic.

## Editors (TS registry + policy mirrors)

`fDenyTSConnections` (inverted), `fSingleSessionPerUser` (+ policy mirror), `HonorLegacySettings`; `RDP-Tcp`: `PortNumber` (updates firewall), `SecurityLayer`/`UserAuthentication` (`0/0, 1/0, 2/1`), `Shadow` (+ mirror), `MaxInstanceCount`; policy client toggles (camera/audio/PnP/USB inverted), `fUsbRedirectionEnableMode`, `dontdisplaylastusername`. All edits are registry-only.

## Loopback test + users

`mstsc /v:127.0.0.2:<port> /w:<W> /h:<H>` presets, Restart-Service button, log pane (renders stable event IDs, never parses free text). User mgmt via `PrincipalContext` + Remote Desktop Users; `lusrmgr`/`netplwiz` shortcuts; Defender-exclusion helper.
