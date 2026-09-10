# Security

## Trust boundaries

```
User → ManagerGui → Windows config / SCM → TermService/svchost (SYSTEM) → ForgeHook → termsrv.dll
```

InstallerCli crosses the admin boundary (requires Administrator/SYSTEM): modifies ServiceDll, firewall, TS policy, schtask.

## Security objectives

ForgeHook: no remote input, no network, no child processes, no credentials, no persisted user data, no disk modification of system binaries (R1,R4). GUI handles credentials only via OS dialogs.

## AV compatibility (distinct from security properties)

Enabler behavior (ServiceDll swap, thread suspend, memory patch) triggers Defender/AV heuristics — expected, not a vulnerability. Mitigations: exclusion for `%ProgramFiles%\RDP Wrapper\`, self-sign dev, EV cert tracked for releases, published hashes. HVCI/SmartScreen (Win11 24H2+) may block unsigned svchost DLLs: installer surfaces `SIGNING_UNTRUSTED` guidance, never silently bypasses. Original `termsrv.dll` must be Authenticode-intact; installer aborts `TERMSRV_MODIFIED` otherwise.
