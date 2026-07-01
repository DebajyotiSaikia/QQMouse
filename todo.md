# Skittermouse — Pending Work (audit against the original build spec)

Source of truth: [.github/copilot-instructions.md](.github/copilot-instructions.md)
(identical to the original `janus-build-spec.md`). Section refs below (§) point there.

## Status at a glance

- **Build-order steps (spec §17): 1 of 12 complete.** Step 1 (pure-logic core) is done;
  **steps 2–12 are pending.**
- **User-facing features (§1, 13 listed): 0 working end-to-end.** The ownership/election
  logic that underpins switching exists as pure logic, but nothing is wired to real
  input, network, or UI yet.
- **Spec'd source files: ~3 of ~51 created — ~48 pending.**
  (core 3/7 · platform 0/19 · net 0/11 · pairing 0/8 · ui 0/6)
- The shipped app is a **console stub** ([src/main.cpp](src/main.cpp)) that prints and
  exits. No capture, no injection, no network, no tray, no window.

---

## DONE (for context)

- [x] `core/event_types.h` — wire protocol structs (§5.3); `InputEvent` packs to 12 bytes (static_assert).
- [x] `core/ownership_state.h/.cpp` — peer-mesh input-owner state machine (§11); Lamport-clock race resolution (§11.3).
- [x] `core/server_election.h/.cpp` — priority-failover elected coordinator / "primary" (§11.5).
- [x] `core/peer_id.h` — shared `PeerId` alias (project addition).
- [x] `tests/` — hand-rolled harness; 115 checks (event_types, ownership_state, server_election, e2e_mesh + mesh_simulator).
- [x] Infra (not app features): CMake + per-OS source gating (§16), CPack NSIS/ZIP/DMG + EULA + icon + shortcuts, website, Cloudflare Pages, nightly-release CI.

---

## PENDING — by build order (spec §17)

### Step 1 remainder — pure-logic core gaps
- [ ] `core/config.h/.cpp` — flat-file paired-device list, layout config, settings; no DB (§2.2, §16).
- [ ] `core/key_translation.h/.cpp` — cross-OS modifier remap table by physical key position (§4.4/§4.5).

### Step 2 — Capture + injection (primary platform first)
- [ ] `platform/capture_win.cpp` — `SetWindowsHookEx` `WH_MOUSE_LL` + `WH_KEYBOARD_LL` (§3.1); install hook **only** while this machine is owner; track "currently down" keys/buttons explicitly (for §4.4).
- [ ] `platform/inject_win.cpp` — `SendInput` (§3.2); runs continuously on non-owner, event-driven, ~zero idle cost.
- [ ] Local hook → local inject sanity loop before any networking exists.

### Step 3 — Pairing (§7)
- [ ] `platform/crypto_win.cpp` (+ `crypto_mac.mm` later) — AES-256-GCM + ECDH wrappers (§5.4, §7): CNG/BCrypt GCM; **nonce = strict incrementing counter, never reused**.
- [ ] `pairing/ecdh_handshake.h/.cpp` — ephemeral ECDH P-256, `BCryptSecretAgreement` (§7.1).
- [ ] `pairing/verification_code.h/.cpp` — 6-digit code = `HMAC-SHA256(shared, "pairing")` truncated (§7.1).
- [ ] `pairing/pairing_dialog_win.cpp` — native confirm/reject dialog showing the code (§7.1).
- [ ] HKDF long-term PSK derivation, salt = device_ids → 256-bit; discard ephemeral keys (§7.1).
- [ ] `pairing/key_store.h/.cpp` — per-device PSK encrypted at rest (AES-256-GCM machine-local key) (§7.2).

### Step 4 — Input channel (§5)
- [ ] `net/transport.h` — abstract `Transport` (send/recv/connect/close); one WSS backend now, Bluetooth-ready (§5.5).
- [ ] WSS-over-TLS backend — hand-rolled WS upgrade + native TLS; path `/input` vs `/files` or `role` field (§5.1).
- [ ] `net/ws_input_channel.h/.cpp` — persistent channel: MouseMove/MouseButton/KeyEvent/SwitchOwner/Heartbeat/ClipboardUpdate (§5.1).
- [ ] AES-256-GCM per-message (§5.4); `protocol_version` byte checked on connect (§5.3, §15).
- [ ] Milestone: two machines forwarding real mouse/keyboard end-to-end, encrypted.

### Step 5 — Switching UX (§4, §10, §15)
- [ ] `platform/hotkey_win.cpp` — `RegisterHotKey` (default `Ctrl+Alt+Space`), loud-fail → fallback combo, surface active combo (§4.1).
- [ ] `ui/picker_window_win.cpp` — topmost focus-stealing list; Up/Down/Enter/Esc; local keyboard hook while open; unreachable machines greyed not omitted; always-clean dismiss (§4.2).
- [ ] `platform/tray_win.cpp` + `ui/tray_menu.h/.cpp` — `Shell_NotifyIcon`; owner marked; per-machine online/offline; Connect…/Add device/settings; no IP/port/"server" language (§10, §4.3).
- [ ] **Stuck-key release on every switch-out** — synthetic key-up/button-up for all tracked-down keys before handoff (§4.4).
- [ ] Apply `key_translation` at injection when target OS differs (§4.5).
- [ ] `ui/toast_notify.h/.cpp` — connection/transfer status notifications (§15).
- [ ] Turn `main.cpp` into the real app: WIN32 subsystem, message loop, subsystem wiring, config load.

### Step 6 — Second platform (macOS) parity
- [ ] `platform/capture_mac.mm` — `CGEventTapCreate`; explicit Accessibility permission prompt + denial/revocation handling (§3.1).
- [ ] `platform/inject_mac.mm` — `CGEventPost` (§3.2).
- [ ] `platform/hotkey_mac.mm` — filtering `CGEventTap` / `RegisterEventHotKey` (§4.1).
- [ ] `ui/picker_window_mac.mm` — topmost key-focus-stealing panel (§4.2).
- [ ] `platform/tray_mac.mm` — `NSStatusBar` (§10).
- [ ] `platform/crypto_mac.mm` — CommonCrypto AES-GCM + Security.framework ECDH (§5.4, §7.1).
- [ ] `pairing/pairing_dialog_mac.mm` — `NSAlert` code confirm (§7.1).

### Step 7 — Discovery (§6)
- [ ] `net/discovery_beacon.h/.cpp` — UDP broadcast beacon `{machine_name, machine_id, ip, port}`; last-seen timeout drops stale entries; per-network "don't broadcast" toggle for untrusted Wi-Fi.

### Step 8 — Clipboard sync (§8)
- [ ] `platform/clipboard_win.cpp` — `AddClipboardFormatListener` / `WM_CLIPBOARDUPDATE` (event-driven).
- [ ] `platform/clipboard_mac.mm` — poll `NSPasteboard.changeCount` 200–500 ms.
- [ ] Loop prevention (hash/source tag on synced writes).
- [ ] Plain text only v1 (`CF_UNICODETEXT` / `NSPasteboardTypeString`).
- [ ] Password-manager exclusion (`CFSTR_EXCLUDECLIPBOARDCONTENTFROMMONITORPROCESSING`).

### Step 9 — Peer mesh, generalized to N (§2.1, §11)
- [x] Core convergence/broadcast/race **logic** (ownership_state + server_election + e2e sim).
- [ ] Wire to real N-1 persistent connections per machine.
- [ ] `SwitchOwner` broadcasts to **all** peers (never a private 2-party handshake) (§11.2).
- [ ] Over-the-wire race handling per §11.3; pair-individually join (no transitive trust).
- [ ] `core/config` layout config — monitor-level spatial arrangement, forward-compat data only, **no** edge-crossing (§11.4).

### Step 10 — File transfer (§9)
- [ ] `net/session_token.h/.cpp` — short-lived token correlating the file channel to the authenticated input channel (§5.2).
- [ ] `net/ws_file_channel.h/.cpp` — on-demand WSS, chunked bytes, opened per transfer, closed after (§5.1).
- [ ] `platform/filepromise_win.cpp` — `IDataObject` delay-render: `CFSTR_FILEDESCRIPTORW` (meta now) + `CFSTR_FILECONTENTS` (`IStream` pulls bytes only on `GetData`); multi-file from the start; native Explorer progress + error UI (§9.1).
- [ ] `platform/filepromise_mac.mm` — `NSFilePromiseProvider`; native Finder progress (§9.2).
- [ ] Bidirectional: every machine is both promise-provider and consumer (§9.3).

### Step 11 — Wake-on-LAN, auto-start, lock/unlock (§12–14)
- [ ] `platform/wol_diag_win.cpp` — NIC WoL (`powercfg /deviceenablewake`) + OS wake (WMI `MSPower_DeviceWakeEnable`); cannot check BIOS — never claim certainty (§12).
- [ ] `net/wol_sender.h/.cpp` — magic-packet UDP broadcast; "Waking…" state + 30–60 s timeout; guided fallback message (§12).
- [ ] `platform/autostart_win.cpp` — Task Scheduler, **run elevated** (UIPI injection into elevated windows) (§13).
- [ ] `platform/autostart_mac.mm` — `LaunchAgent` plist (§13).
- [ ] `platform/lock_win.cpp` — `LockWorkStation`; opt-in per machine (§14).
- [ ] `platform/lock_mac.mm` — equivalent lock call (§14).
- [ ] Unlock = switch-then-type only (no scripted credentials); **verify Secure Desktop/`LogonUI` behavior on a real locked machine** (§14 open question).

### Step 12 — Failure & edge-state hardening (§15)
- [ ] Fail-safe local control on owner drop; heartbeat watchdog ~1–2 s (design for silent death, not clean goodbye).
- [ ] Connection-dropped tray state + one-time (non-repeating) notification.
- [ ] Switch-to-unreachable = no-op / brief "unavailable" flash, never hang/crash.
- [ ] File-transfer mid-stream failure surfaced via native `IStream`/promise error (verify in testing).
- [ ] Discovery staleness timeout (drop offline machines from "Connect to…").
- [ ] Protocol-version mismatch rejected cleanly: "update Skittermouse on <machine>".
- [ ] Simultaneous switch claims resolved per §11.3, not undefined.

---

## Do NOT build (spec §1 non-goals — listed so they aren't accidentally added)

- Linux support (any form).
- Edge-of-screen crossing as a primary/load-bearing switch trigger.
- Remote desktop, screen streaming, video capture.
- A Bluetooth backend now (keep only the `transport.h` abstraction).
- Rich clipboard formats (images/RTF/HTML) — plain text only v1.
- Resumable/queued file transfers — one at a time, fail cleanly.
- Any unattended/scripted credential injection into a lock screen.
