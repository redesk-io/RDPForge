# RDPForge Requirements (constitution)

Project-level invariants. Specs explain how each is satisfied; no spec may weaken these.

## R1 — No disk modification

RDPForge MUST NOT modify `termsrv.dll` or any Microsoft system binary on disk. Verified by corpus + VM gate (no hash change post-install).

## R2 — Runtime discovery, no offset table

Patch locations MUST be discovered from the loaded image at service start. A version-specific offset table MUST NOT be required, shipped, or consulted.

## R2a — Version-independence invariant

OS/version metadata MAY be used for logging, diagnostics, test reporting. It MUST NOT select patch offsets. Patch sites are selected by structural discovery + validation only.

## R3 — Failure safety

Failure to discover or validate a site MUST NOT crash TermService. Failed sites boot unpatched for that check (see patch-atomicity rule in `architecture.md`).

## R4 — Hook isolation

ForgeHook MUST NOT use network, credentials, child processes, COM, script hosts, or config files. It owns termsrv loading, discovery, patching, forwarding — nothing else.

## R5 — Architecture parity

Supported archs (x86/x64/ARM64) MUST use the same discovery model (anchors → function starts → Zydis validation → emission). Arch differences are confined to `autofind.md` per-site validation tables.

## R6 — Reversibility

Uninstall MUST restore the original `ServiceDll` and MUST NOT require reboot to claim completion: TermService is restarted after restore (see `installer.md`). It MUST NOT leave ServiceDll pointing at a missing DLL, TermService permanently stopped, or an orphaned health task.

## R7 — Component ownership

ForgeHook patches. InstallerCli installs/configures. ManagerGui observes/configures/tests and MUST NOT install, patch, discover, or modify executable code.
