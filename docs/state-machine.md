# State machine

GUI maps directly onto these states (precedence in `specs/gui.md`).

```
              ┌──────────────┐
              │ NotInstalled │  ServiceDll == termsrv.dll
              └──────┬───────┘
                     │ install (transactional)
                     ▼
              ┌──────────────┐      ┌──────────────┐
              │  Installed   │─────▶│ InstallFailed│ (rolled back, see installer.md)
              └──────┬───────┘      └──────────────┘
                     │ service start
                     ▼
              ┌──────────────┐
              │ Initializing │  HOOK_INIT..AUTOFIND_BEGIN
              └──────┬───────┘
                     ▼
        ┌───────────┴───────────┐
        ▼                       ▼
 ┌─────────────┐        ┌─────────────────┐
 │ FullyPatched│        │ PartiallyPatched│  ≥1 required site SKIPPED (intentional)
 └──────┬──────┘        └────────┬────────┘
        │                        │
        └───────────┬────────────┘
                    ▼
               ┌─────────┐
               │ Running │  service RUNNING (RDP-ready needs listener too)
               └─────────┘
```

Failure/lateral states: `DiscoveryFailed` (all required sites MISS → Running unpatched), `PatchSkipped` (per-site, not global), `ServiceStartFailed`, `Unsupported` (6.0/6.1 or unknown era → `UNSUPPORTED_OS`), `ThirdPartyServiceDll` (installer refuses without `-o`), `TermsrvModified` (integrity fail, install aborted).
