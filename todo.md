# Skittermouse — Unimplemented Work

Derived from [spec.md](spec.md); section refs (§) point there. This file lists **only what
is not yet built** — as each item lands, delete it from here.

## Status

- Native C++ only, **619 checks green**, Windows + macOS CI green. Implemented + unit-tested:
  all core logic + crypto (AES-256-GCM / ECDH P-256 / SHA / HMAC / HKDF / base64, KAT-verified),
  pairing, the full protocol/codec layer, the **mesh coordination brain** (`app/MeshNode`:
  N-peer switch broadcast, coordinator election/failover, heartbeat fail-safe, clipboard sync,
  input forwarding) with a 3-node headless e2e, and the file-transfer session. The Windows
  build is a **real tray app**. Windows platform (capture/inject/WS transport/clipboard/lock/
  autostart/wol-diag/pairing-dialog) and the macOS backends (crypto/capture/inject/clipboard/
  lock/autostart/pairing-dialog) all compile on their CI runners.
- Remaining: the transport's TLS wrap + listener side, the picker/tray-menu switch wiring, the
  macOS Cocoa UI (tray/hotkey/picker), OS file-promise (IStream / NSFilePromiseProvider),
  wiring MeshNode onto real sockets, and hardware / two-machine / macOS validation.

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

- [ ] TLS-wrap (Schannel) the (done) TCP+WebSocket client transport for full `wss://`, and add
      the server/listener side (accept + server handshake); differentiate `/input` vs `/files`.
- [ ] `net/ws_input_channel` — persistent channel with AES-256-GCM per message
      (strictly-incrementing nonce) over the transport; wire `MeshNode` onto it.
- [ ] Milestone: two real machines forwarding encrypted input end-to-end. (transport interface,
      WS handshake/framing/assembler, client transport, message codec, MeshNode routing,
      3-node loopback e2e: done.)

### Step 5 — Switching UX finish (§4, §10)

- [ ] Wire the tray menu's per-device click + `WM_HOTKEY` to `MeshNode::requestSwitchTo` once
      the mesh is connected; add the fallback-combo path if `RegisterHotKey` fails.
- [ ] `ui/picker_window_win.cpp` — topmost focus-stealing list over the (done) `ui/menu_model`;
      Up/Down/Enter/Esc; local keyboard hook while open; offline greyed; clean dismiss (§4.2).
- [ ] `ui/toast_notify` — connection/transfer status notifications (§15).
      (hotkey parser, menu model, tray shell, hotkey registration: done.)

### Step 6 — macOS Cocoa UI parity (§4, §10)

- [ ] `platform/hotkey_mac.mm` — `RegisterEventHotKey` / filtering `CGEventTap` (§4.1).
- [ ] `ui/picker_window_mac.mm` — topmost key-focus-stealing NSPanel (§4.2).
- [ ] `platform/tray_mac.mm` — `NSStatusBar` status item + menu (§10); the macOS app main().
      (macOS crypto/capture/inject/clipboard/lock/autostart/pairing-dialog: done and compiling.)

### Step 9 — Peer mesh: remaining (§11.4)

- [ ] `core/config` layout config — monitor-level spatial arrangement, forward-compat data
      only, **no** edge-crossing.
- [ ] Wire `MeshNode` into the app with real per-peer transports (connect/accept on pairing).
      (N-peer ownership broadcast, over-the-wire race resolution, coordinator election/
      failover/failback, priority list: done and e2e-tested.)

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

- [ ] Connection-dropped tray state + one-time (non-repeating) notification.
- [ ] Switch-to-unreachable = no-op / brief "unavailable" flash in the picker/tray.
- [ ] File-transfer mid-stream failure surfaced via native `IStream`/promise error.
- [ ] Surface protocol-version mismatch ("update Skittermouse on <machine>") in the UI.
      (heartbeat fail-safe, discovery staleness, simultaneous-claim resolution, codec version
      gate: done and e2e-tested.)

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
