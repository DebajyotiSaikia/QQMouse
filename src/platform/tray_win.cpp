// Windows tray application shell (spec 10). A message-only window hosts the tray
// icon (Shell_NotifyIcon), the global hotkey (RegisterHotKey via the tested
// core/hotkey parser), and the clipboard listener (AddClipboardFormatListener ->
// WM_CLIPBOARDUPDATE) feeding the tested clipboard loop-prevention. The paired-
// machine menu is built from the tested ui/menu_model. Native Win32, zero
// third-party. Input capture is NOT installed here -- it is owner-only and wired
// once a peer connection exists (spec 3.1); the tray shell is always safe to run.

#include "platform/tray_app.h"

#include "app/connection_manager.h"
#include "app/mesh_node.h"
#include "app/secure_link.h"
#include "core/config.h"
#include "core/event_types.h"
#include "core/hotkey.h"
#include "core/wake_flow.h"
#include "crypto/crypto.h"
#include "net/wol_sender.h"
#include "net/ws_transport.h"
#include "pairing/key_store.h"
#include "pairing/pairing_dialog.h"
#include "pairing/pairing_exchange.h"
#include "platform/autostart.h"
#include "platform/clipboard.h"
#include "platform/injector.h"
#include "ui/menu_model.h"
#include "ui/picker_window.h"
#include "ui/settings_window.h"

#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>

#include <array>
#include <atomic>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace sm::platform {

namespace {

constexpr UINT kTrayCallback = WM_APP + 1;
constexpr UINT kIdQuit = 40001;
constexpr UINT kIdSettings = 40002;
constexpr UINT kIdStartup = 40003;
constexpr UINT kIdAddDevice = 40004;
constexpr UINT kIdDeviceBase = 41000;
constexpr int kHotkeyId = 1;
constexpr uint16_t kMeshPort = 47800; // input + clipboard channel
constexpr uint16_t kPairPort = 47801; // pairing exchange

struct PendingLink {
    sm::app::SecureLink link;
    bool outbound;
};

struct AppState {
    sm::core::Config config;
    std::unique_ptr<sm::app::MeshNode> mesh;
    std::unique_ptr<sm::app::ConnectionManager> cm;
    std::unique_ptr<sm::platform::Injector> injector;
    sm::core::WakeFlow wake; // Wake-on-LAN "Waking…" flow (spec 12)
    NOTIFYICONDATAW nid{};
    std::string self;

    // Networking (spec 5.1): a background I/O thread dials/accepts and hands sealed
    // links to the UI thread, which owns the mesh -- so all MeshNode/ConnectionManager
    // access stays single-threaded.
    sm::pairing::KeyStore keys;
    std::string keyStorePath;
    std::array<uint8_t, 32> protKey{};
    std::thread netThread;
    std::thread pairThread;
    std::atomic<bool> netRunning{false};
    std::atomic<bool> pairingActive{false};
    std::mutex stateMutex;                         // guards config.devices + keys
    std::mutex linkMutex;                          // guards pendingLinks
    std::deque<PendingLink> pendingLinks;          // bg -> UI handoff
    std::mutex connMutex;                          // guards connectedIds
    std::set<sm::core::PeerId> connectedIds;       // UI writes, bg reads (dial dedup)
    std::map<sm::core::PeerId, uint64_t> lastDial; // bg-thread only
};

AppState* g_app = nullptr;

std::wstring toWide(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? static_cast<std::size_t>(n - 1) : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

std::string configPath() {
    wchar_t appdata[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) return {};
    std::wstring dir = std::wstring(appdata) + L"\\Skittermouse";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring cfg = dir + L"\\config.txt";
    int n = WideCharToMultiByte(CP_UTF8, 0, cfg.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? static_cast<std::size_t>(n - 1) : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, cfg.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

// A tray balloon notification (spec 15: connection/transfer status).
void showToast(const std::wstring& title, const std::wstring& message) {
    if (!g_app) return;
    NOTIFYICONDATAW n = g_app->nid;
    n.uFlags = NIF_INFO;
    wcsncpy_s(n.szInfoTitle, title.c_str(), _TRUNCATE);
    wcsncpy_s(n.szInfo, message.c_str(), _TRUNCATE);
    n.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &n);
}

std::string keyStorePath() {
    wchar_t appdata[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) return {};
    std::wstring ks = std::wstring(appdata) + L"\\Skittermouse\\keys.dat";
    int n = WideCharToMultiByte(CP_UTF8, 0, ks.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? static_cast<std::size_t>(n - 1) : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, ks.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

// Machine-local key protecting the PSK store at rest (spec 7.2): HKDF over the OS
// MachineGuid so the keys.dat is only usable on this machine.
std::array<uint8_t, 32> machineProtectionKey() {
    std::array<uint8_t, 32> key{};
    wchar_t guid[128] = L"skittermouse-fallback-guid";
    DWORD sz = sizeof(guid);
    RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid",
                 RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, guid, &sz);
    int n = WideCharToMultiByte(CP_UTF8, 0, guid, -1, nullptr, 0, nullptr, nullptr);
    std::string g(n > 0 ? static_cast<std::size_t>(n - 1) : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, guid, -1, g.data(), n, nullptr, nullptr);
    static const char salt[] = "skittermouse-keystore-v1";
    static const char info[] = "psk-at-rest";
    auto okm = sm::crypto::hkdfSha256(reinterpret_cast<const uint8_t*>(g.data()), g.size(),
                                      reinterpret_cast<const uint8_t*>(salt), sizeof(salt) - 1,
                                      reinterpret_cast<const uint8_t*>(info), sizeof(info) - 1, 32);
    if (okm.size() == 32) std::copy(okm.begin(), okm.end(), key.begin());
    return key;
}

// --- Minimal one-field input dialog (peer IP entry for pairing) -------------------
struct PromptState {
    HWND edit = nullptr;
    std::wstring label;
    std::wstring* out = nullptr;
    bool ok = false;
    bool done = false;
};
PromptState* g_prompt = nullptr;

LRESULT CALLBACK promptProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_CREATE: {
            HINSTANCE hi = GetModuleHandleW(nullptr);
            HFONT font = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            HWND lab = CreateWindowExW(0, L"STATIC", g_prompt->label.c_str(), WS_CHILD | WS_VISIBLE,
                                       14, 12, 344, 20, h, nullptr, hi, nullptr);
            g_prompt->edit = CreateWindowExW(
                0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP, 14,
                38, 344, 24, h, reinterpret_cast<HMENU>(static_cast<INT_PTR>(100)), hi, nullptr);
            HWND ok = CreateWindowExW(0, L"BUTTON", L"OK",
                                      WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP, 194, 74,
                                      78, 26, h, reinterpret_cast<HMENU>(IDOK), hi, nullptr);
            HWND cancel = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                          280, 74, 78, 26, h, reinterpret_cast<HMENU>(IDCANCEL), hi,
                                          nullptr);
            for (HWND c : {lab, g_prompt->edit, ok, cancel})
                if (c) SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SetFocus(g_prompt->edit);
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(w) == IDOK) {
                wchar_t b[256];
                GetWindowTextW(g_prompt->edit, b, 256);
                if (g_prompt->out) *g_prompt->out = b;
                g_prompt->ok = true;
                g_prompt->done = true;
                DestroyWindow(h);
            } else if (LOWORD(w) == IDCANCEL) {
                g_prompt->done = true;
                DestroyWindow(h);
            }
            return 0;
        case WM_CLOSE:
            g_prompt->done = true;
            DestroyWindow(h);
            return 0;
        default:
            return DefWindowProcW(h, m, w, l);
    }
}

bool promptText(const wchar_t* title, const wchar_t* label, std::wstring& out) {
    PromptState st;
    st.label = label;
    st.out = &out;
    g_prompt = &st;
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = promptProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SkittermousePrompt";
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
    RegisterClassW(&wc);
    int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
    const int wdt = 376, hgt = 150;
    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, wc.lpszClassName, title,
                             WS_POPUP | WS_CAPTION | WS_SYSMENU, (sx - wdt) / 2, (sy - hgt) / 2, wdt,
                             hgt, nullptr, nullptr, hInst, nullptr);
    if (!h) {
        g_prompt = nullptr;
        return false;
    }
    ShowWindow(h, SW_SHOW);
    SetForegroundWindow(h);
    MSG msg;
    while (!st.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (IsDialogMessageW(h, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_prompt = nullptr;
    return st.ok;
}

// --- Background network I/O thread (spec 5.1) -------------------------------------
// Dials paired peers we have a PSK for and accepts inbound sockets, running the
// secure link (blocking socket work stays OFF the UI thread). Sealed links are handed
// to the UI thread, which owns the mesh. No MeshNode/ConnectionManager access here.
void netThreadProc() {
    while (g_app && g_app->netRunning.load()) {
        const uint64_t now = GetTickCount64();

        struct Dialable {
            std::string id, host;
            uint16_t port;
            sm::pairing::Psk psk;
            bool hasKey;
        };
        std::vector<Dialable> toDial;
        {
            std::lock_guard<std::mutex> lk(g_app->stateMutex);
            for (const auto& d : g_app->config.devices) {
                if (d.id == g_app->self || d.last_ip.empty()) continue;
                const sm::pairing::Psk* psk = g_app->keys.getPsk(d.id);
                Dialable dd;
                dd.id = d.id;
                dd.host = d.last_ip;
                dd.port = d.port ? d.port : kMeshPort;
                dd.hasKey = (psk != nullptr);
                if (psk) dd.psk = *psk;
                toDial.push_back(std::move(dd));
            }
        }
        for (auto& dd : toDial) {
            if (!g_app->netRunning.load()) break;
            if (!dd.hasKey) continue;
            {
                std::lock_guard<std::mutex> lk(g_app->connMutex);
                if (g_app->connectedIds.count(dd.id)) continue;
            }
            auto it = g_app->lastDial.find(dd.id);
            if (it != g_app->lastDial.end() && now - it->second < 3000) continue;
            g_app->lastDial[dd.id] = now;

            std::unique_ptr<sm::net::Transport> raw(sm::net::createWsClientTransport());
            if (raw && raw->connect(dd.host, dd.port)) {
                sm::pairing::KeyStore tmp;
                tmp.setPsk(dd.id, dd.psk);
                sm::app::SecureLink link =
                    sm::app::secureOutbound(std::move(raw), tmp, g_app->self, dd.id);
                if (link.transport) {
                    std::lock_guard<std::mutex> lk(g_app->linkMutex);
                    g_app->pendingLinks.push_back(PendingLink{std::move(link), true});
                }
            }
        }

        // Accept one inbound; the caller's identity + PSK come from the secure link.
        std::unique_ptr<sm::net::Transport> in(sm::net::wsAcceptOne(kMeshPort, 200));
        if (in) {
            sm::pairing::KeyStore keysCopy;
            {
                std::lock_guard<std::mutex> lk(g_app->stateMutex);
                for (const auto& id : g_app->keys.devices()) {
                    const sm::pairing::Psk* p = g_app->keys.getPsk(id);
                    if (p) keysCopy.setPsk(id, *p);
                }
            }
            sm::app::InboundHandshake hs(std::move(in), keysCopy, g_app->self);
            for (int i = 0; i < 200 && g_app->netRunning.load(); ++i) {
                auto st = hs.poll();
                if (st == sm::app::InboundHandshake::Status::Ok) {
                    sm::app::SecureLink link = hs.take();
                    std::lock_guard<std::mutex> lk(g_app->linkMutex);
                    g_app->pendingLinks.push_back(PendingLink{std::move(link), false});
                    break;
                }
                if (st != sm::app::InboundHandshake::Status::NeedMore) break;
                Sleep(5);
            }
        }
        Sleep(50);
    }
}

// --- Pairing thread (spec 7.1) ----------------------------------------------------
// If `host` is non-empty we initiate (connect to the peer's pairing port); otherwise
// we wait for an inbound pairing connection. Runs the ECDH exchange, shows the 6-digit
// code for the human to compare, and on confirm stores the PSK + device.
void pairThreadProc(std::string host) {
    while (!host.empty() && (host.back() == ' ' || host.back() == '\r' || host.back() == '\n'))
        host.pop_back();
    while (!host.empty() && host.front() == ' ') host.erase(host.begin());

    std::unique_ptr<sm::net::Transport> t;
    const uint64_t deadline = GetTickCount64() + 30000;
    while (!t && GetTickCount64() < deadline && g_app->pairingActive.load()) {
        if (!host.empty()) {
            std::unique_ptr<sm::net::Transport> raw(sm::net::createWsClientTransport());
            if (raw && raw->connect(host, kPairPort)) t = std::move(raw);
            else Sleep(300);
        } else {
            t.reset(sm::net::wsAcceptOne(kPairPort, 500));
        }
    }
    if (!t) {
        showToast(L"Skittermouse", L"Pairing timed out (no connection).");
        g_app->pairingActive.store(false);
        return;
    }

    sm::pairing::PairingExchange ex(*t, g_app->self);
    if (!ex.start()) {
        showToast(L"Skittermouse", L"Pairing failed to start.");
        g_app->pairingActive.store(false);
        return;
    }
    sm::pairing::PairingExchange::Status st = sm::pairing::PairingExchange::Status::NeedMore;
    while (st == sm::pairing::PairingExchange::Status::NeedMore && GetTickCount64() < deadline) {
        st = ex.poll();
        if (st == sm::pairing::PairingExchange::Status::NeedMore) Sleep(20);
    }
    if (st != sm::pairing::PairingExchange::Status::Ok) {
        showToast(L"Skittermouse", L"Pairing exchange failed.");
        g_app->pairingActive.store(false);
        return;
    }

    if (!confirmPairingCode(ex.code(), ex.peerId())) { // human numeric comparison (spec 7.1)
        showToast(L"Skittermouse", L"Pairing rejected.");
        g_app->pairingActive.store(false);
        return;
    }

    {
        std::lock_guard<std::mutex> lk(g_app->stateMutex);
        g_app->keys.setPsk(ex.peerId(), ex.psk());
        if (!g_app->keyStorePath.empty())
            g_app->keys.saveToFile(g_app->keyStorePath, g_app->protKey.data());
        sm::core::PairedDevice dev;
        dev.id = ex.peerId();
        dev.name = ex.peerId();
        dev.last_ip = host; // set only if we initiated; the peer dials us otherwise
        dev.port = kMeshPort;
        dev.os = "windows";
        g_app->config.addDevice(dev);
        std::string cpath = configPath();
        if (!cpath.empty()) g_app->config.saveToFile(cpath);
    }
    showToast(L"Skittermouse", L"Paired with " + toWide(ex.peerId()));
    g_app->pairingActive.store(false);
}

void showMenu(HWND hwnd) {
    POINT pt;
    GetCursorPos(&pt);
    HMENU menu = CreatePopupMenu();

    std::vector<sm::core::PeerId> online;
    for (const auto& d : g_app->config.devices)
        if (g_app->mesh && g_app->mesh->isPeerOnline(d.id)) online.push_back(d.id);
    sm::core::PeerId owner = g_app->mesh ? g_app->mesh->owner() : g_app->self;
    auto items = sm::ui::buildMachineMenu(g_app->config.devices, g_app->self, owner, online);
    if (items.empty()) {
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, L"No devices paired");
    } else {
        UINT id = kIdDeviceBase;
        for (const auto& it : items) {
            UINT flags = MF_STRING;
            if (it.is_owner) flags |= MF_CHECKED;
            if (!it.is_online) flags |= MF_GRAYED;
            AppendMenuW(menu, flags, id++, toWide(it.name).c_str());
        }
    }
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdAddDevice, L"Add device\u2026");
    AppendMenuW(menu, MF_STRING | (isAutostartEnabled() ? MF_CHECKED : MF_UNCHECKED), kIdStartup,
                L"Run on startup");
    AppendMenuW(menu, MF_STRING, kIdSettings, L"Settings\u2026");
    AppendMenuW(menu, MF_STRING, kIdQuit, L"Quit Skittermouse");

    SetForegroundWindow(hwnd); // so the menu dismisses on click-away
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case kTrayCallback:
            if (LOWORD(l) == WM_RBUTTONUP || LOWORD(l) == WM_CONTEXTMENU) showMenu(hwnd);
            return 0;

        case WM_COMMAND: {
            UINT id = LOWORD(w);
            if (id == kIdQuit) {
                PostQuitMessage(0);
            } else if (id == kIdSettings) {
                // Native settings window (spec 10/16) -- replaces opening the raw
                // config file. On Save, persist and apply run-on-startup immediately
                // (the hotkey re-registers on next launch).
                const bool wasStartup = g_app->config.settings.run_on_startup;
                if (sm::ui::showSettingsWindow(g_app->config)) {
                    std::string path = configPath();
                    if (!path.empty()) g_app->config.saveToFile(path);
                    const bool nowStartup = g_app->config.settings.run_on_startup;
                    if (nowStartup != wasStartup) {
                        const bool ok = nowStartup ? enableAutostart() : disableAutostart();
                        if (!ok) {
                            g_app->config.settings.run_on_startup = wasStartup; // revert
                            if (!path.empty()) g_app->config.saveToFile(path);
                            showToast(L"Skittermouse",
                                      L"Startup change needs administrator approval.");
                        }
                    }
                    showToast(L"Skittermouse", L"Settings saved (hotkey applies after restart).");
                }
            } else if (id == kIdStartup) {
                // Opt-in auto-start (spec 13), OFF by default so a reboot always
                // recovers. Enabling/disabling the elevated login task needs admin,
                // so this prompts UAC; a declined prompt leaves the setting unchanged.
                const bool wasEnabled = isAutostartEnabled();
                const bool ok = wasEnabled ? disableAutostart() : enableAutostart();
                if (ok) {
                    g_app->config.settings.run_on_startup = !wasEnabled;
                    std::string path = configPath();
                    if (!path.empty()) g_app->config.saveToFile(path);
                    showToast(L"Skittermouse", wasEnabled
                                                   ? L"Skittermouse will no longer run on startup."
                                                   : L"Skittermouse will run on startup.");
                } else {
                    showToast(L"Skittermouse",
                              L"Startup setting unchanged (administrator approval declined).");
                }
            } else if (id == kIdAddDevice) {
                // Pairing (spec 7.1): prompt for the peer IP (or blank to wait), then
                // run the ECDH numeric-comparison on a background thread.
                if (g_app->pairingActive.load()) {
                    showToast(L"Skittermouse", L"Pairing already in progress\u2026");
                } else {
                    std::wstring hostW;
                    if (promptText(L"Add device",
                                   L"Enter the other PC's IP address (or leave blank to wait for "
                                   L"it), then click Add device on that PC too:",
                                   hostW)) {
                        std::string host;
                        int n = WideCharToMultiByte(CP_UTF8, 0, hostW.c_str(), -1, nullptr, 0,
                                                    nullptr, nullptr);
                        host.resize(n > 0 ? static_cast<std::size_t>(n - 1) : 0);
                        if (n > 0)
                            WideCharToMultiByte(CP_UTF8, 0, hostW.c_str(), -1, host.data(), n,
                                                nullptr, nullptr);
                        if (g_app->pairThread.joinable()) g_app->pairThread.join();
                        g_app->pairingActive.store(true);
                        showToast(L"Skittermouse", L"Pairing\u2026 compare the code on both PCs.");
                        g_app->pairThread = std::thread(pairThreadProc, host);
                    }
                }
            } else if (id >= kIdDeviceBase && g_app->mesh) {
                std::size_t idx = id - kIdDeviceBase;
                if (idx < g_app->config.devices.size())
                    g_app->mesh->requestSwitchTo(g_app->config.devices[idx].id);
            }
            return 0;
        }

        case WM_HOTKEY:
            if (g_app->mesh) {
                std::vector<sm::core::PeerId> online;
                for (const auto& d : g_app->config.devices)
                    if (g_app->mesh->isPeerOnline(d.id)) online.push_back(d.id);
                auto items = sm::ui::buildMachineMenu(g_app->config.devices, g_app->self,
                                                      g_app->mesh->owner(), online);
                std::string sel = sm::ui::showPicker(items);
                if (!sel.empty()) g_app->mesh->requestSwitchTo(sel);
            }
            return 0;

        case WM_TIMER: {
            if (g_app->cm) {
                uint64_t now = GetTickCount64();
                // Drain sealed links produced by the network thread into the mesh.
                {
                    std::lock_guard<std::mutex> lk(g_app->linkMutex);
                    for (auto& pl : g_app->pendingLinks) {
                        if (pl.outbound)
                            g_app->cm->addOutgoing(pl.link.peerId, std::move(pl.link.transport));
                        else
                            g_app->cm->addIncoming(std::move(pl.link.transport));
                    }
                    g_app->pendingLinks.clear();
                }
                g_app->cm->poll(now); // pumps mesh.poll + heartbeats

                // Resolve any in-progress Wake-on-LAN attempt (spec 12).
                if (g_app->wake.isWaking()) {
                    const sm::core::PeerId target = g_app->wake.target();
                    auto st = g_app->wake.update(now, g_app->mesh->isPeerOnline(target));
                    if (st == sm::core::WakeFlow::Status::Connected) {
                        showToast(L"Skittermouse", toWide(target) + L" is awake");
                        g_app->mesh->requestSwitchTo(target); // now reachable -> switch
                        g_app->wake.reset();
                    } else if (st == sm::core::WakeFlow::Status::TimedOut) {
                        showToast(L"Skittermouse",
                                  L"Could not wake " + toWide(target) +
                                      L". Check BIOS/UEFI Wake-on-LAN, the adapter's "
                                      L"\u201cAllow this device to wake the computer\u201d "
                                      L"setting, and disable Fast Startup.");
                        g_app->wake.reset();
                    }
                }
            }
            return 0;
        }

        case WM_CLIPBOARDUPDATE: {
            if (!clipboardExcludedFromMonitoring() && g_app->mesh) { // skip password-manager writes
                std::string text;
                if (getClipboardText(text)) g_app->mesh->onLocalClipboardChange(text);
            }
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            g_app->netRunning.store(false);
            g_app->pairingActive.store(false);
            if (g_app->netThread.joinable()) g_app->netThread.join();
            if (g_app->pairThread.joinable()) g_app->pairThread.join();
            RemoveClipboardFormatListener(hwnd);
            UnregisterHotKey(hwnd, kHotkeyId);
            Shell_NotifyIconW(NIM_DELETE, &g_app->nid);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

} // namespace

int runTrayApp() {
    AppState app;
    g_app = &app;

    std::string cfg = configPath();
    if (!cfg.empty()) app.config = sm::core::Config::loadFromFile(cfg);

    // Derive a stable self id from the machine name and build the mesh brain.
    char nameBuf[256];
    DWORD nameLen = sizeof(nameBuf);
    app.self = GetComputerNameA(nameBuf, &nameLen) ? std::string(nameBuf, nameLen)
                                                   : std::string("this-machine");
    app.injector.reset(sm::platform::createInjector());
    app.mesh = std::make_unique<sm::app::MeshNode>(app.self);
    app.mesh->setPriority(app.config.priority);
    sm::platform::Injector* inj = app.injector.get();
    app.mesh->onInject = [inj](const sm::core::InputEvent& e) {
        using MT = sm::core::MessageType;
        switch (static_cast<MT>(e.type)) {
            case MT::MouseMove:   inj->mouseMove(e.dx, e.dy); break;
            case MT::MouseButton: inj->mouseButton(e.code, e.down != 0); break;
            case MT::KeyEvent:    inj->key(e.code, e.down != 0); break;
            default: break;
        }
    };
    app.mesh->onRemoteClipboard = [](const std::string& t) { setClipboardText(t); };
    app.mesh->onOwnerChanged = [](const sm::core::PeerId& newOwner) {
        showToast(L"Skittermouse", L"Input owner is now " + toWide(newOwner));
    };
    // Connection state (spec 15): one-time balloon on drop/return, never repeating
    // (the transition callbacks fire exactly once per change).
    app.mesh->onPeerOffline = [](const sm::core::PeerId& id) {
        showToast(L"Skittermouse", L"Lost connection to " + toWide(id));
    };
    app.mesh->onPeerOnline = [](const sm::core::PeerId& id) {
        showToast(L"Skittermouse", L"Connected to " + toWide(id));
    };
    // Switch-to-unreachable (spec 15/12): if the target is WoL-plausible and has a
    // known MAC, send the magic packet and enter the bounded "Waking…" flow;
    // otherwise just flash "unavailable".
    app.mesh->onSwitchUnavailable = [](const sm::core::PeerId& id) {
        if (!g_app) return;
        const sm::core::PairedDevice* dev = nullptr;
        for (const auto& d : g_app->config.devices)
            if (d.id == id) { dev = &d; break; }

        sm::net::Mac mac;
        if (dev && dev->wol_capable && !dev->mac.empty() &&
            sm::net::parseMac(dev->mac, mac)) {
            sm::net::sendMagicPacket(mac, "255.255.255.255", 9); // WoL discard port
            g_app->wake.start(id, GetTickCount64(), 45000);      // 45 s window (spec 12)
            const std::wstring name = toWide(dev->name.empty() ? id : dev->name);
            showToast(L"Skittermouse", L"Waking " + name + L"\u2026");
        } else {
            showToast(L"Skittermouse", toWide(id) + L" is unavailable");
        }
    };
    // Protocol-version mismatch (spec 15): tell the user which machine to update.
    app.mesh->onVersionMismatch = [](const sm::core::PeerId& id) {
        showToast(L"Skittermouse", L"Update Skittermouse on " + toWide(id));
    };

    // Connection manager + encrypted-at-rest PSK store (spec 5.2/7.2). The network
    // thread produces sealed links; the UI thread (WM_TIMER) registers + pumps them.
    app.cm = std::make_unique<sm::app::ConnectionManager>(*app.mesh);
    app.cm->onPeerConnected = [](const sm::core::PeerId& id) {
        std::lock_guard<std::mutex> lk(g_app->connMutex);
        g_app->connectedIds.insert(id);
    };
    app.cm->onPeerDisconnected = [](const sm::core::PeerId& id) {
        std::lock_guard<std::mutex> lk(g_app->connMutex);
        g_app->connectedIds.erase(id);
    };
    app.keyStorePath = keyStorePath();
    app.protKey = machineProtectionKey();
    if (!app.keyStorePath.empty())
        app.keys.loadFromFile(app.keyStorePath, app.protKey.data()); // empty on first run

    HINSTANCE hInst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = wndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SkittermouseTray";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"Skittermouse", 0, 0, 0, 0, 0,
                                HWND_MESSAGE, nullptr, hInst, nullptr);
    if (!hwnd) return 1;

    // Tray icon -- reuse our embedded app icon (resource id 1 from skittermouse.rc).
    app.nid.cbSize = sizeof(app.nid);
    app.nid.hWnd = hwnd;
    app.nid.uID = 1;
    app.nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    app.nid.uCallbackMessage = kTrayCallback;
    app.nid.hIcon = static_cast<HICON>(LoadImageW(hInst, MAKEINTRESOURCEW(1), IMAGE_ICON,
                                                  GetSystemMetrics(SM_CXSMICON),
                                                  GetSystemMetrics(SM_CYSMICON),
                                                  LR_DEFAULTCOLOR));
    if (!app.nid.hIcon) {
        // IDI_APPLICATION is an ANSI resource macro; pass its numeric id to the W API.
        app.nid.hIcon = LoadIconW(nullptr, reinterpret_cast<LPCWSTR>(IDI_APPLICATION));
    }
    wcscpy_s(app.nid.szTip, L"Skittermouse");
    Shell_NotifyIconW(NIM_ADD, &app.nid);

    AddClipboardFormatListener(hwnd);
    SetTimer(hwnd, 1, 50, nullptr); // pump the mesh: heartbeats + incoming messages

    // Global hotkey from config (spec 4.1). MOD_NOREPEAT avoids auto-repeat storms.
    // If the configured combo is already owned by another process, RegisterHotKey
    // fails loudly -- fall back to a secondary combo and surface it in the tooltip.
    auto hk = sm::core::parseHotkey(app.config.settings.hotkey);
    bool hkOk = hk.valid && RegisterHotKey(hwnd, kHotkeyId, hk.modifiers | MOD_NOREPEAT, hk.key);
    if (!hkOk) {
        auto fb = sm::core::parseHotkey("Ctrl+Shift+Alt+Space");
        hkOk = fb.valid && RegisterHotKey(hwnd, kHotkeyId, fb.modifiers | MOD_NOREPEAT, fb.key);
        if (hkOk) {
            NOTIFYICONDATAW tip = app.nid;
            tip.uFlags = NIF_TIP;
            wcscpy_s(tip.szTip, L"Skittermouse (hotkey: Ctrl+Shift+Alt+Space)");
            Shell_NotifyIconW(NIM_MODIFY, &tip);
        }
    }

    // Start the background network I/O thread (dials paired peers + accepts inbound).
    app.netRunning.store(true);
    app.netThread = std::thread(netThreadProc);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_app = nullptr;
    return 0;
}

} // namespace sm::platform
