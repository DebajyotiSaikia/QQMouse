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
- [ ] Milestone: two real machines forwarding encrypted input end-to-end. (transport interface,
      WS handshake/framing/assembler, **client + server** transport, message codec, the
      **AES-256-GCM per-message `Transport` decorator** (strict nonce counter + anti-replay,
      3-node e2e through it), MeshNode routing wired into the tray, 3-node loopback e2e: done.)

### Step 9 — Peer mesh: remaining

- [ ] OS network thread: run the WS client `connect()` to each paired peer and
      `wsAcceptOne()` for inbound sockets, handing each Transport to the (done, tested)
      `app/ConnectionManager`. (peer-hello handshake, link identification/lifecycle, dedup,
      disconnect reaping, mesh registration + pump via `ConnectionManager`; config layout,
      N-peer ownership broadcast, race resolution, coordinator election/failover/failback,
      priority list, MeshNode wired into the tray app: done.)

### Step 10 — File transfer: OS delay-render (§9)

- [ ] `platform/filepromise_win.cpp` — `IDataObject` delay-render: `CFSTR_FILEDESCRIPTORW` +
      `CFSTR_FILECONTENTS` (`IStream::Read` pulls bytes on paste) over the (done) file session;
      multi-file; native Explorer progress + error UI (§9.1).
- [ ] `platform/filepromise_mac.mm` — `NSFilePromiseProvider`; native Finder progress (§9.2).
- [ ] `net/ws_file_channel` — open the on-demand file transport per transfer, driving the
      (done) `net/file_session` sender/receiver. Bidirectional (§9.3).

### Step 11 — WoL / lock-unlock finish (§12, §14)

- [ ] "Waking…" state + 30–60 s timeout + guided fallback flow around the (done) magic-packet
      sender + (done) `wol_diag`.
- [ ] Unlock = switch-then-type only; **verify Secure Desktop / `LogonUI` behavior on a real
      locked machine** (open question). (lock_win/lock_mac, autostart_win/mac: done.)

### Step 12 — Failure & edge-state UI (§15)

- [ ] File-transfer mid-stream failure surfaced via native `IStream`/promise error.
- [ ] Surface protocol-version mismatch ("update Skittermouse on <machine>") in the UI.
      (heartbeat fail-safe, discovery staleness, simultaneous-claim resolution, codec version
      gate, **one-time connection-dropped/return toast + switch-to-unreachable "unavailable"
      flash** via MeshNode transition callbacks (e2e-tested) wired into the Windows tray: done.)

---

## Tests — 100% coverage (all steps)

- [~] **619 checks**, native harness: all core logic, crypto (KAT + OpenSSL cross-check),
  pairing, session token, WS handshake/framing/assembler, message + ownership + file codecs,
  file session, WoL, beacon, discovery table, heartbeat, input pipeline, hotkey, menu model,
  config, key_translation. Extend as new pure logic lands.
- [~] Headless e2e through the real Transport (loopback): a 2-node full flow AND a 3-node mesh
  (switch broadcast, coordinator failover/failback, input forward, clipboard loop-prevent,
  owner-drop fail-safe, version reject). Extend with file transfer + TLS as those land.
- [~] Windows + macOS CI green at every step (619/619).

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
