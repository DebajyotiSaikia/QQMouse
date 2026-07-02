# Skittermouse — Unimplemented Work

Derived from [spec.md](spec.md); section refs (§) point there. This file lists **only what
is not yet built** — as each item lands, delete it from here.

## Status

- Foundation landed and unit-tested (native C++ only, **438 checks green**): core logic
  (config, key_translation, ownership, election, stuck-key tracker, clipboard loop-prevention),
  crypto (AES-256-GCM + ECDH P-256 + SHA/HMAC/HKDF, KAT-verified), pairing (ECDH handshake,
  6-digit code, encrypted key store), and net primitives (WS framing, version-checked message
  codec, session token, WoL magic packet, discovery beacon codec). Windows capture/injection
  compile.
- Remaining: the WSS-over-TLS transport, the switching UX (hotkey/picker/tray), the OS
  clipboard/file-promise/lock/autostart/wol-diag glue, all macOS `.mm` backends, the real
  `main.cpp` app wiring, and hardware / two-machine / macOS validation.
- The shipped app is still a console stub — no UI/tray/network wired yet.

---

## VERY IMPORTANT — native C++ only

Every item below must be built with **native, system-provided C++ APIs only** — Win32,
WinSock2, CNG/BCrypt, Schannel, Core Graphics, AppKit, CommonCrypto, Security.framework,
BSD sockets, and the C++ standard library. **No third-party dependencies** (no Boost, no
OpenSSL, no Qt, no JSON/networking/crypto library). If any task seems to "need" a library,
re-check against [spec.md](spec.md) §16 — the native path exists for all of it.

---

## By build order (spec §17)

### Step 2 — Capture + injection

- [ ] Wire capture → stuck-key tracker → forward, and inject on the sink; run the local
      hook→inject sanity loop. (`platform/capture_win.cpp` + `inject_win.cpp` exist and
      compile; the wiring and real-hardware validation remain.)

### Step 3 — Pairing (§7)

- [ ] `pairing/pairing_dialog_win.cpp` — native confirm/reject dialog showing the 6-digit
      code (§7.1). (crypto, ECDH handshake, verification code, HKDF PSK, key store: done.)

### Step 4 — Input channel (§5)

- [ ] WSS-over-TLS backend (Schannel) implementing `Transport` — WS upgrade handshake + native
      TLS; differentiate `/input` vs `/files` (§5.1, §5.5).
- [ ] `net/ws_input_channel.h/.cpp` — persistent channel carrying the hot-path messages;
      AES-256-GCM per message with a strictly-incrementing nonce; version check on connect.
- [ ] Milestone: two machines forwarding encrypted input end-to-end.
      (transport interface + version-checked message codec: done.)

### Step 5 — Switching UX (§4, §10, §15)

- [ ] `platform/hotkey_win.cpp` — `RegisterHotKey` (default `Ctrl+Alt+Space`), loud-fail → fallback combo, surface active combo (§4.1).
- [ ] `ui/picker_window_win.cpp` — topmost focus-stealing list; Up/Down/Enter/Esc; local keyboard hook while open; unreachable machines greyed not omitted; always-clean dismiss (§4.2).
- [ ] `platform/tray_win.cpp` + `ui/tray_menu.h/.cpp` — `Shell_NotifyIcon`; owner marked; per-machine online/offline; Connect…/Add device/settings; no IP/port/"server" language (§10, §4.3).
- [ ] Apply `key_translation` at injection when target OS differs (§4.5). (remap table: done.)
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

- [ ] UDP broadcast/listen sockets around the beacon codec; per-machine last-seen timeout
      drops stale entries; "don't broadcast on this network" toggle. (beacon packet codec: done.)

### Step 8 — Clipboard sync (§8)

- [ ] `platform/clipboard_win.cpp` — `AddClipboardFormatListener` / `WM_CLIPBOARDUPDATE` (event-driven).
- [ ] `platform/clipboard_mac.mm` — poll `NSPasteboard.changeCount` 200–500 ms.
- [ ] Plain text only v1 (`CF_UNICODETEXT` / `NSPasteboardTypeString`). (loop-prevention logic: done.)
- [ ] Password-manager exclusion (`CFSTR_EXCLUDECLIPBOARDCONTENTFROMMONITORPROCESSING`).

### Step 9 — Peer mesh, generalized to N (§2.1, §11)

- [ ] Wire to real N-1 persistent connections per machine.
- [ ] `SwitchOwner` broadcasts to **all** peers (never a private 2-party handshake) (§11.2).
- [ ] Over-the-wire race handling per §11.3; pair-individually join (no transitive trust).
- [ ] `core/config` layout config — monitor-level spatial arrangement, forward-compat data only, **no** edge-crossing (§11.4).

#### Coordinator failover — priority-ordered "server" fallback

- [ ] User designates paired machines in a **priority order** (1, 2, 3, 4, 5, …). The current
      coordinator ("server") is the highest-priority machine currently online; for machine 5
      to act as server, all of 1–4 must be offline. Fails over down the list automatically,
      and **fails back** preemptively when a higher-priority machine returns.
- [ ] The coordinator has **no special permissions** — it is only a deterministic, mesh-wide
      agreed reference computed identically on every machine from (priority list, online set).
- [ ] **All paired machines are on the list by default**; the user may remove a machine so it
      is never eligible. New pairings append at lowest priority.
- [ ] Wire the (done) `core/server_election` logic to the live online set from the mesh,
      persist the priority list in `core/config` (done), and surface it as "primary" (never
      "server") in the settings UI (§10 wording).

### Step 10 — File transfer (§9)

- [ ] `net/ws_file_channel.h/.cpp` — on-demand WSS, chunked bytes, opened per transfer, closed after (§5.1). (session_token: done.)
- [ ] `platform/filepromise_win.cpp` — `IDataObject` delay-render: `CFSTR_FILEDESCRIPTORW` (meta now) + `CFSTR_FILECONTENTS` (`IStream` pulls bytes only on `GetData`); multi-file from the start; native Explorer progress + error UI (§9.1).
- [ ] `platform/filepromise_mac.mm` — `NSFilePromiseProvider`; native Finder progress (§9.2).
- [ ] Bidirectional: every machine is both promise-provider and consumer (§9.3).

### Step 11 — Wake-on-LAN, auto-start, lock/unlock (§12–14)

- [ ] `platform/wol_diag_win.cpp` — NIC WoL (`powercfg /deviceenablewake`) + OS wake (WMI `MSPower_DeviceWakeEnable`); cannot check BIOS — never claim certainty (§12).
- [ ] "Waking…" state + 30–60 s timeout + guided fallback flow around the (done) magic-packet UDP sender (§12).
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
- [ ] Surface protocol-version mismatch cleanly ("update Skittermouse on <machine>") at connect. (codec-level version gate: done.)
- [ ] Simultaneous switch claims resolved per §11.3, not undefined.

---

## Tests — 100% coverage (all steps)

- [~] Unit tests for every pure-logic module landed so far (**438 checks**, native harness):
  core logic, crypto (KAT + OpenSSL cross-check), pairing, session token, WS framing,
  message codec, WoL, beacon, config, key_translation. Extend to 100% as new modules land.
- [ ] **Comprehensive e2e automation covering 100% of scenarios** — extend the mesh simulator
      to a full flow: pairing → connect → switch (all triggers) → clipboard sync → file
      transfer → coordinator failover/failback → owner-drop fail-safe → protocol-mismatch
      reject → switch-to-unreachable → stuck-key release, through the app seams, headless.
- [~] Keep the Windows CI build green and all tests passing at every step. (currently 438/438.)

---

## Do NOT build (spec §1 non-goals — listed so they aren't accidentally added)

- Linux support (any form).
- Edge-of-screen crossing as a primary/load-bearing switch trigger.
- Remote desktop, screen streaming, video capture.
- A Bluetooth backend now (keep only the `transport.h` abstraction).
- Rich clipboard formats (images/RTF/HTML) — plain text only v1.
- Resumable/queued file transfers — one at a time, fail cleanly.
- Any unattended/scripted credential injection into a lock screen.
