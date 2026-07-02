# Skittermouse — Unimplemented Work

Derived from [spec.md](spec.md); section refs (§) point there. This file lists **only what
is not yet built** — as each item lands, delete it from here.

## Status

- Native C++ only (product), **870 checks green**, Windows + macOS CI green at every commit.
- **The full app loop is validated headlessly in-process** by the mocked-systems e2e set
  (`tests/e2e_full_system_tests.cpp` + `tests/mock_systems.h`): every OS boundary is faked
  (MockInjector, MockClipboard, an in-process network Switchboard) so pairing → stored PSK →
  ConnectionService dial/accept → AES-256-GCM secure link → mesh switch → forwarded input reaching
  the injector → clipboard sync all run in one process. The mocks live ONLY in `tests/`, never in
  the product exe.
- **The entire data plane is validated over real TCP** by a two-container Docker rig
  (`tests/docker/`, run `pwsh tests/docker/run.ps1`): (1) ECDH numeric-comparison **pairing** →
  both nodes derive the same 6-digit code + PSK; (2) **encrypted input** — secure link →
  coordinator election → ownership switch → a forwarded keystroke decrypted + injected; (3)
  **file transfer** — a 500 KB file chunked → reassembled by offset → byte-verified. All exercise
  the SAME product logic (secure_link → ConnectionService/ConnectionManager → MeshNode →
  EncryptedTransport / FileChannel) over the real POSIX WS transport.
- Implemented + unit-tested: all core logic + crypto (AES-256-GCM / ECDH P-256 / SHA / HMAC /
  HKDF / base64, KAT-verified), pairing + secure-link handshake, the protocol/codec layer, the
  mesh brain (N-peer switch, coordinator failover, heartbeat fail-safe, clipboard sync, input
  forwarding, one-time drop/return/unavailable/version toasts), `ConnectionService`, the
  file-transfer session + `FileChannel`, WoL `WakeFlow`, and the config store. Both Windows
  (Shell_NotifyIcon) and macOS (NSStatusBar) are real tray apps; the Windows tray has the mesh,
  hotkey+fallback, picker, clipboard, WoL, an opt-in run-on-startup toggle, a working Settings
  item, **auto-discovery pairing** (LAN beacon → pick device by name+IP, no manual IP typing),
  **native file copy/paste** (delay-render IDataObject → on-demand encrypted /files channel), and
  a **file debug log** (`%APPDATA%\Skittermouse\log.txt`); macOS has the Carbon hotkey + NSPanel
  picker. **Windows WS transport is now wss (Schannel TLS)**; POSIX WS transport for macOS/Linux.
- Remaining items are **macOS-only** and share one hard blocker (see "macOS product" below);
  the **Windows product is feature-complete**. Two field bugs were just fixed + CI-green:
  (1) one-way discovery when a **VPN** is up — the beacon now sends to every interface's directed
  broadcast, so the LAN NIC is always covered regardless of the default route; (2) the installer
  now opens the app's firewall ports, stops a running instance before reinstall, and the app has a
  single-instance guard so two copies never fight over the fixed ports.

---

## VERY IMPORTANT — native C++ only (product); OpenSSL only in the Linux test rig

Every SHIPPED item must use **native, system-provided C++ APIs only** — Win32, WinSock2,
CNG/BCrypt, Schannel, Core Graphics, AppKit, CommonCrypto, Security.framework, BSD sockets, and
the C++ standard library. **No third-party dependencies in the product** (spec §16). The ONE
exception is `src/platform/crypto_posix.cpp` + `tools/net*.cpp`: they link OpenSSL, but they are
the Linux two-container TEST RIG only (`tests/docker/`) and are never compiled into the
Windows/macOS product (guarded by the CMake `else()`/`UNIX AND NOT APPLE` branches).

---

## By build order (spec §17)

### macOS product — the one blocker behind every remaining item

All unchecked items below are macOS. They are gated on a single hard problem: **SecureTransport
(the native TLS API) requires a server *certificate identity*, and macOS has no API to mint a
self-signed identity without either hand-rolling X.509 ASN.1 DER + ECDSA signing, or importing a
PKCS#12 into the *keychain*.** Both touch the keychain/filesystem and are cryptographically
unforgiving (one wrong DER length byte = a silently invalid cert), so they must be written **on a
Mac where they can actually be run and validated** — writing them blind would leave code that
looks done but may not connect. The Windows side interops only over `wss`, so a plain-ws macOS
shortcut won't talk to it either. Everything *above* the transport (mesh, pairing, discovery,
file channel, clipboard) is already cross-platform + tested and will light up the moment the
macOS transport exists. A Mac session should, in order: (1) `ws_transport_mac.mm` — BSD sockets +
SecureTransport, ephemeral self-signed identity via a temporary keychain, mirroring the validated
OpenSSL/Schannel structure; (2) wire the tray connect/accept + auto-discovery in `tray_mac.mm`
(a direct port of the done Windows tray); (3) `filepromise_mac.mm` (`NSFilePromiseProvider`).

### Step 4 — Input channel: TLS / wss (§5)

- [x] **wss PROVEN end-to-end**: the POSIX WS transport does a real TLS handshake (OpenSSL,
      ephemeral self-signed cert, encryption-only — the PSK secure link stays the trust gate), and
      the two-container Docker rig now runs the FULL stack (pairing + encrypted input + file
      transfer) over TLS, all PASS. (TCP → TLS → WebSocket → app-layer AES-256-GCM.)
- [x] `platform/ws_transport_win.cpp` — **Schannel** TLS: the Windows product is now wss too
      (SSPI handshake loop, EncryptMessage/DecryptMessage stream I/O, ephemeral self-signed server
      cert via CryptoAPI, encryption-only). Compiles + links (secur32/crypt32); the WS handshake +
      frames ride over TLS. Runtime SSPI edge cases still want the two-Windows-machine loop to
      shake out — the `[tls]` lines in `%APPDATA%\Skittermouse\log.txt` are there for that.
- [ ] macOS: TLS via Security.framework (SecureTransport) once the macOS transport lands — blocked
      on the server-identity/keychain problem described in "macOS product" above; do it on a Mac.

### Step 9 — Peer mesh: macOS connection thread

- [ ] macOS tray: run the same background connect/accept -> secure-link -> mesh I/O thread over
      the (written) POSIX transport, plus an "Add device" pairing flow. The **Windows tray is
      done**: a background I/O thread dials paired peers (bounded connect timeout) + accepts
      inbound on port 47800, runs the secure link off the UI thread, and hands sealed links to
      the UI thread (mesh stays single-threaded); **"Add device" is auto-discovery** — a LAN
      presence beacon (broadcast + listen on UDP 47802) feeds a live picker where the user selects
      the target by name + IP (no manual IP typing), then the ECDH numeric-comparison
      (`PairingExchange` + confirm dialog, port 47801) stores the PSK in an encrypted-at-rest
      keystore. Runtime check is in Manual validation below.

### Step 10 — File transfer: OS delay-render (§9)

- [x] **Windows file transfer DONE (code-complete, Explorer-gated for runtime)**: a native
      delay-render `IDataObject` advertises `CFSTR_FILEDESCRIPTORW` + promised `CFSTR_FILECONTENTS`,
      each backed by a read-only `IStream` that pulls bytes through an injected byte source only
      on paste (`filepromise_win.cpp`, unit-tested headlessly incl. the mid-stream error path).
      Wired into the tray: copying files (CF_HDROP) broadcasts a `FilePromiseAnnounce` over the
      mesh + remembers the paths; the destination puts a matching promise on its clipboard whose
      byte source dials the source's on-demand `/files` channel (secure link, port 47803) and
      drives the (done) `net/FileChannel` — so a paste in Explorer materialises the files with its
      OWN native copy-progress + error UI. Multi-file; no staging temp. Needs two Windows machines + Explorer to validate the last mile.
- [ ] `platform/filepromise_mac.mm` — `NSFilePromiseProvider`; native Finder progress (§9.2).
      (The mesh announce, the `/files` secure channel, and `net/FileChannel` are cross-platform and
      done; only the macOS OS-provider glue remains, and it needs a Mac + Finder.)

### Step 11 — Lock/unlock finish (§14)

- [ ] Unlock = switch-then-type only; **verify Secure Desktop / `LogonUI` behavior on a real
      locked machine** (open question). (lock_win/lock_mac, autostart_win/mac: done. WoL
      **"Waking…" flow** — bounded-timeout state machine (`core/WakeFlow`, unit-tested) + magic
      packet + guided-fallback toast, wired into the tray on switch-to-unreachable with a
      per-device MAC (config round-tripped): done.)

### Step 12 — Failure & edge-state UI (§15)

- [x] File-transfer mid-stream failure surfaced via native `IStream` error (Windows): the promised
      stream returns `STG_E_READFAULT` when the byte source fails, so Explorer shows its own error
      UI (unit-tested). (macOS equivalent lands with `filepromise_mac.mm`.)
      (heartbeat fail-safe, discovery staleness, simultaneous-claim resolution, codec version
      gate, one-time connection-dropped/return toast, switch-to-unreachable "unavailable" flash,
      **protocol-version-mismatch "update Skittermouse on <machine>" toast** (throttled per peer,
      e2e-tested) — all via MeshNode callbacks wired into the Windows tray: done.)

---

## Manual validation (needs real hardware — the code is built + CI-green, but these paths can't

## be runtime-tested from the dev box; validate on your machines)

### Two Windows machines — pair, connect, forward input (Step 9, built)

1. Install the same nightly on both PCs; both show the tray icon.
2. Same LAN. The installer now **auto-adds the Windows Firewall rules** (TCP 47800-47803, UDP
   47802); on a corp/domain PC where policy blocks that, allow Skittermouse manually.
3. On BOTH PCs: tray → **Add device**. Each PC broadcasts its presence (now out **every** network
   interface, so a VPN on one PC no longer hides it) and shows a live list of devices (name + IP).
4. On ONE PC, select the other from the list → **Pair**. (The other PC just needs its Add-device
   window open; it accepts automatically.)
5. Both show a **6-digit code** — confirm they MATCH and click Yes on both → toast "Paired with …".
6. Within a few seconds → toast "Connected to <PC>"; the peer appears in the tray menu.
7. Click the peer (or hotkey → pick it) to switch input, then type/move → it appears on the other
   PC; switch back with the hotkey/menu. (This is exactly the flow the Docker rig proves headless.)

- Not connecting? Check the firewall, that both are on the same LAN, and that both run the same
  build. The `%APPDATA%\Skittermouse\log.txt` file logs each dial/accept/pair/TLS step.

### Two Windows machines — copy/paste a file (Step 10, built)

1. Pair + connect two PCs as above; allow TCP 47803 (the /files channel) through the firewall.
2. On PC-A: copy a file (or several) in Explorer (Ctrl+C).
3. On PC-B: paste (Ctrl+V) into any folder → Explorer shows its own copy-progress dialog while the
   bytes stream from PC-A over the encrypted /files channel; the files land byte-for-byte.
4. Mid-transfer failure (e.g. PC-A goes offline) surfaces as Explorer's own native copy-error
   dialog. `log.txt` logs `[file] announced/serving/pulling` on each side.

- Directories are skipped in v1 (files only). One transfer at a time.

### Run-on-startup installer checkbox (Step 13)

- Install with "Run Skittermouse on startup" ticked → after reboot the tray reappears.
- Default (unticked) → no autostart; enable later via tray "Run on startup" or Settings.
- "Run Skittermouse" on the installer's finish page launches it immediately (elevated, from the
   elevated installer). If a previous copy was running, the reinstall now stops it first and the
   single-instance guard prevents two copies fighting over the ports.

### Lock-screen unlock (Step 14, open question)

- Switch to a LOCKED PC and type its password through forwarded input. Verify whether SendInput
  crosses the Secure Desktop (LogonUI) boundary on your Windows build; if not, unlock needs
  physical presence (documented limitation, not a bug).

---

## Do NOT build (spec §1 non-goals — listed so they aren't accidentally added)

- Linux support in the PRODUCT (the Linux build is a TEST RIG only, never shipped).
- Edge-of-screen crossing as a primary/load-bearing switch trigger.
- Remote desktop, screen streaming, video capture.
- A Bluetooth backend now (keep only the `transport.h` abstraction).

## Evaluate the below - don't implement yet

- Rich clipboard formats (images/RTF/HTML) — plain text only v1.
- Resumable/queued file transfers — one at a time, fail cleanly.
- Any unattended/scripted credential injection into a lock screen.
