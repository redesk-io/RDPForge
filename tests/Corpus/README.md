# Corpus

`tests/Corpus/manifest.json` pins known `termsrv.dll` builds by SHA-256 with expected discovery results.

## Rules

- Binaries are never checked in. CI downloads them (pinned manifest workflow) or contributors supply a local copy at the well-known path (`/mnt/c/Windows/System32/termsrv.dll` on dev WSL, `C:\Windows\System32\termsrv.dll` on Windows).
- Live tests (`HookTest` cases reading the real DLL) MUST skip cleanly when the file is absent (`catch return`), and MUST assert exact site RVAs when present.
- Adding a new Windows build: append an entry with hash + observed sites. `local_only_jz` stays explicitly heuristic until symbol-confirmed.
- `expected` fields use hex strings (`0x...`) matching `AutoFind.discover()` emissions.
