# Glossary

- `TermService`: Windows service hosting Terminal Services in shared `svchost.exe -k termsvcs`.
- `ServiceDll`: registry value selecting which DLL `svchost` loads for `TermService`. The single indirection RDPForge uses.
- `termsrv.dll`: Microsoft RDP server implementation. Never modified on disk by RDPForge.
- `ForgeHook.dll`: RDPForge shim, the `ServiceDll` target.
- `AutoFind`: runtime discovery of patch sites by disassembly + signature search.
- `LocalOnly/SingleUser/DefPolicy/NonRDP/SLInit`: patch sites — license-type check, single-session arbitration, connection-policy query, non-RDP stack gate, SKU-policy initializer.
- `UmRdpService/umrdp.dll`: device (PnP/camera) redirection service, wrapped optionally by UmHook.
- `RDP-Tcp`: WinStation listener name for RDP; enumerated via `winsta.dll`.
- `NLA`: Network Level Authentication (`SecurityLayer`/`UserAuthentication` pair).
- `Zydis`: embedded x86/x64 (+ ARM64 tables) disassembler used for discovery.
