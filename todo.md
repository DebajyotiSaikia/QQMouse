# Skittermouse — Unimplemented Work

Derived from [spec.md](spec.md); section refs (§) point there. This file lists **only what
is not yet built** — as each item lands, delete it from here.

## Status

- Native C++ only, **624 checks green**, Windows + macOS CI green. Implemented + unit-tested:
  all core logic + crypto (AES-256-GCM / ECDH P-256 / SHA / HMAC / HKDF / base64, KAT-verified),
  pairing, the full protocol/codec layer, the **mesh coordination brain** (`app/MeshNode`:
  N-peer switch broadcast, coordinator election/failover, heartbeat fail-safe, clipboard sync,
  input forwarding) with a 3-node headless e2e, and the file-transfer session. **Both** the
  Windows (Shell_NotifyIcon) and macOS (NSStatusBar) builds are real tray apps, with MeshNode
  wired into the Windows tray (menu-switch, clipboard, injection, heartbeat pump). The WS
  transport has client + server/listener sides. All Windows + macOS platform backends compile
  on their CI runners.
- Remaining: TLS-wrap the transport (Schannel), the network connection-management thread
  (connect/accept feeding MeshNode), OS file-promise (IStream / NSFilePromiseProvider), the
  macOS hotkey/picker, and hardware / two-machine / macOS validation.

---

## VERY IMPORTANT — native C++ only

Every item below must be built with **native, system-provided C++ APIs only** — Win32,
WinSock2, CNG/BCrypt, Schannel, Core Graphics, AppKit, CommonCrypto, Security.framework,
BSD sockets, and the C++ standard library. **No third-party dependencies** (no Boost, no
OpenSSL, no Qt, no JSON/networking/crypto library). If any task seems to "need" a library,
re-check against [spec.md](spec.md) §16 — the native path exists for all of it.

---

## By build order (spec §17)

### Step 4 — Input channel: transport finish (§5)

- [ ] TLS-wrap (Schannel) the (done) client + server WebSocket transport for full `wss://`.
- [x] Milestone: two real machines forwarding encrypted input end-to-end. **VALIDATED** via a
      two-container Docker rig (tests/docker/): two isolated Linux nodes connect over real
      TCP/WebSocket, run the clear-id-hint -> per-device-PSK -> AES-256-GCM secure link, do the
      encrypted peer-hello handshake, elect a coordinator, switch input ownership, and forward
      a keystroke that the sink decrypts + injects (RESULT PASS). Exercises the SAME product
      logic (secure_link -> ConnectionManager -> MeshNode -> EncryptedTransport) over a real
      POSIX WS transport (`platform/ws_transport_posix.cpp`, which is also the macOS transport).

### Step 9 — Peer mesh: remaining

- [ ] Wire the (done, Docker-proven) `app/ConnectionService` into the Windows tray on a
      background I/O thread: the thread dials/accepts + runs the secure link (blocking socket
      work, lock-free), and hands each sealed link to the UI thread (which owns the mesh) via a
      queue, so all `MeshNode`/`ConnectionManager` access stays single-threaded. Needs a dial
      `connect()` timeout and **two-Windows-machine runtime validation** before shipping (the
      threading can't be proven from one machine). `ConnectionService` itself (factory-injected
      dial/accept -> secure_link -> ConnectionManager) is built, unit-tested, and validated
      end-to-end over real TCP by the two-container rig (tests/docker/), which drives it through
      `tools/netcheck`. macOS needs the same thread over the (now-written) POSIX transport.

### Step 10 — File transfer: OS delay-render (§9)

- [ ] `platform/filepromise_win.cpp` — `IDataObject` delay-render: `CFSTR_FILEDESCRIPTORW` +
      `CFSTR_FILECONTENTS` (`IStream::Read` pulls bytes on paste) over the (done) file session;
      multi-file; native Explorer progress + error UI (§9.1).
- [ ] `platform/filepromise_mac.mm` — `NSFilePromiseProvider`; native Finder progress (§9.2).
- [ ] `net/ws_file_channel` glue — open the on-demand file transport per transfer (WS
      client to `/files` + session token) and hand it to the (done, tested)
      `net/FileChannel` driver, which streams FilePromiseMeta + FileChunks and reassembles
      by offset over any Transport (multi-file + zero-byte + partial-delivery e2e-tested).
      Bidirectional (§9.3).

### Step 11 — WoL / lock-unlock finish (§12, §14)

- [ ] Unlock = switch-then-type only; **verify Secure Desktop / `LogonUI` behavior on a real
      locked machine** (open question). (lock_win/lock_mac, autostart_win/mac: done. WoL
      **"Waking…" flow** — bounded-timeout state machine (`core/WakeFlow`, unit-tested) + magic
      packet + guided-fallback toast, wired into the tray on switch-to-unreachable with a
      per-device MAC (config round-tripped): done.)

### Step 12 — Failure & edge-state UI (§15)

- [ ] File-transfer mid-stream failure surfaced via native `IStream`/promise error
      (lands with the file-promise work in Step 10).
      (heartbeat fail-safe, discovery staleness, simultaneous-claim resolution, codec version
      gate, one-time connection-dropped/return toast, switch-to-unreachable "unavailable" flash,
      **protocol-version-mismatch "update Skittermouse on <machine>" toast** (throttled per peer,
      e2e-tested) — all via MeshNode callbacks wired into the Windows tray: done.)

---

## Tests — 100% coverage (all steps)

- [~] **735 checks**, native harness: all core logic, crypto (KAT + OpenSSL cross-check),
  pairing, session token, WS handshake/framing/assembler, message + ownership + file codecs,
  file session, WoL, beacon, discovery table, heartbeat, input pipeline, hotkey, menu model,
  config, key_translation. Extend as new pure logic lands.
- [~] Headless e2e through the real Transport (loopback): a 2-node full flow AND a 3-node mesh
  (switch broadcast, coordinator failover/failback, input forward, clipboard loop-prevent,
  owner-drop fail-safe, version reject). Extend with file transfer + TLS as those land.
- [~] Windows + macOS CI green at every step (735/735).

---

## Do NOT build (spec §1 non-goals — listed so they aren't accidentally added)

- Linux support (any form).
- Edge-of-screen crossing as a primary/load-bearing switch trigger.
- Remote desktop, screen streaming, video capture.
- A Bluetooth backend now (keep only the `transport.h` abstraction).

## Evaluate the below - don't implement yet

- Rich clipboard formats (images/RTF/HTML) — plain text only v1.
- Resumable/queued file transfers — one at a time, fail cleanly.
- Any unattended/scripted credential injection into a lock screen.
