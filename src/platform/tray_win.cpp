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
#include "core/log.h"
#include "core/wake_flow.h"
#include "crypto/crypto.h"
#include "net/discovery_beacon.h"
#include "net/discovery_socket.h"
#include "net/discovery_table.h"
#include "net/file_channel.h"
#include "net/file_promise_announce.h"
#include "net/file_session.h"
#include "net/wol_sender.h"
#include "net/ws_transport.h"
#include "pairing/key_store.h"
#include "pairing/pairing_dialog.h"
#include "pairing/pairing_exchange.h"
#include "platform/autostart.h"
#include "platform/clipboard.h"
#include "platform/filepromise.h"
#include "platform/filepromise_win.h"
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
#include <fstream>
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
constexpr uint16_t kMeshPort = 47800;      // input + clipboard channel
constexpr uint16_t kPairPort = 47801;      // pairing exchange
constexpr uint16_t kDiscoveryPort = 47802; // LAN presence beacon during pairing (spec 6)
constexpr uint16_t kFilePort = 47803;      // on-demand file channel (spec 5.1/9)

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
    std::thread discoveryThread;  // broadcast + listen for beacons during pairing
    std::thread pairAcceptThread; // accept an inbound pairing while pairing mode is on
    std::atomic<bool> netRunning{false};
    std::atomic<bool> pairingActive{false};
    std::atomic<bool> pairEngaged{false}; // one exchange per session (init XOR accept)
    HWND discoveryDlg{nullptr};           // open discovery picker, so bg can dismiss it
    sm::net::DiscoveryTable discovered;   // live beacons seen this session
    std::mutex discMutex;                 // guards discovered
    std::mutex stateMutex;                         // guards config.devices + keys
    std::mutex linkMutex;                          // guards pendingLinks
    std::deque<PendingLink> pendingLinks;          // bg -> UI handoff
    std::mutex connMutex;                          // guards connectedIds
    std::set<sm::core::PeerId> connectedIds;       // UI writes, bg reads (dial dedup)
    std::map<sm::core::PeerId, uint64_t> lastDial; // bg-thread only
    std::map<sm::core::PeerId, std::string> peerIp; // last-known IP per peer (for /files dial)

    // File transfer (spec 9): the source remembers the paths it last copied so the
    // on-demand /files server can stream them when the destination pastes.
    std::vector<std::string> copiedPaths;
    std::mutex fileMutex;
    std::thread fileThread; // accepts + serves the /files channel
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

std::string logPath() {
    wchar_t appdata[MAX_PATH];
    if (!SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdata))) return {};
    std::wstring dir = std::wstring(appdata) + L"\\Skittermouse";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring lg = dir + L"\\log.txt";
    int n = WideCharToMultiByte(CP_UTF8, 0, lg.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? static_cast<std::size_t>(n - 1) : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, lg.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
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

// --- Auto-discovery pairing picker (spec 6/7) -------------------------------------
// A small live list of LAN devices found via the presence beacon: name + IP shown,
// no manual IP typing. The list refreshes on a timer from the discovery table that
// discoveryProc() fills. Picking a device initiates pairing to it.
struct DiscoveryPickState {
    HWND list = nullptr;
    std::vector<sm::net::Beacon> items; // parallel to the listbox rows
    std::string selectedIp;
    std::string selectedName;
    bool ok = false;
    bool done = false;
};
DiscoveryPickState* g_disco = nullptr;

void refreshDiscoveryList() {
    if (!g_disco || !g_disco->list || !g_app) return;
    std::vector<sm::net::Beacon> live;
    {
        std::lock_guard<std::mutex> lk(g_app->discMutex);
        live = g_app->discovered.live(GetTickCount64(), 6000); // drop entries >6 s stale
    }
    // Hide devices we're already paired with (nothing to add there).
    std::vector<sm::net::Beacon> shown;
    for (auto& b : live) {
        bool paired = false;
        for (auto& d : g_app->config.devices)
            if (d.id == b.machine_id) { paired = true; break; }
        if (!paired) shown.push_back(b);
    }
    // Preserve the current selection across the refresh by machine_id.
    LRESULT sel = SendMessageW(g_disco->list, LB_GETCURSEL, 0, 0);
    std::string selId;
    if (sel != LB_ERR && static_cast<std::size_t>(sel) < g_disco->items.size())
        selId = g_disco->items[static_cast<std::size_t>(sel)].machine_id;

    SendMessageW(g_disco->list, LB_RESETCONTENT, 0, 0);
    g_disco->items = shown;
    int newSel = -1;
    for (std::size_t i = 0; i < shown.size(); ++i) {
        std::wstring line = toWide(shown[i].machine_name + "   \u2014   " + shown[i].ip);
        SendMessageW(g_disco->list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line.c_str()));
        if (shown[i].machine_id == selId) newSel = static_cast<int>(i);
    }
    if (newSel >= 0)
        SendMessageW(g_disco->list, LB_SETCURSEL, newSel, 0);
    else if (!shown.empty() && selId.empty())
        SendMessageW(g_disco->list, LB_SETCURSEL, 0, 0);
}

LRESULT CALLBACK discoveryPickProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
        case WM_CREATE: {
            HINSTANCE hi = GetModuleHandleW(nullptr);
            HFONT font = reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            HWND lab = CreateWindowExW(
                0, L"STATIC",
                L"Devices found on your network. Open \u201cAdd device\u201d on the other PC too, "
                L"then select it here:",
                WS_CHILD | WS_VISIBLE, 14, 10, 396, 34, h, nullptr, hi, nullptr);
            g_disco->list = CreateWindowExW(
                WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP | LBS_NOTIFY, 14, 48, 396, 150, h,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(200)), hi, nullptr);
            HWND pair = CreateWindowExW(0, L"BUTTON", L"Pair",
                                        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP, 246,
                                        208, 78, 28, h, reinterpret_cast<HMENU>(IDOK), hi, nullptr);
            HWND cancel = CreateWindowExW(0, L"BUTTON", L"Cancel",
                                          WS_CHILD | WS_VISIBLE | WS_TABSTOP, 332, 208, 78, 28, h,
                                          reinterpret_cast<HMENU>(IDCANCEL), hi, nullptr);
            for (HWND c : {lab, g_disco->list, pair, cancel})
                if (c) SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
            SetTimer(h, 1, 600, nullptr); // live-refresh the discovered list
            refreshDiscoveryList();
            SetFocus(g_disco->list);
            return 0;
        }
        case WM_TIMER:
            refreshDiscoveryList();
            return 0;
        case WM_COMMAND:
            if (LOWORD(w) == IDOK || (LOWORD(w) == 200 && HIWORD(w) == LBN_DBLCLK)) {
                LRESULT sel = SendMessageW(g_disco->list, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR && static_cast<std::size_t>(sel) < g_disco->items.size()) {
                    g_disco->selectedIp = g_disco->items[static_cast<std::size_t>(sel)].ip;
                    g_disco->selectedName = g_disco->items[static_cast<std::size_t>(sel)].machine_name;
                    g_disco->ok = true;
                    g_disco->done = true;
                    DestroyWindow(h);
                }
            } else if (LOWORD(w) == IDCANCEL) {
                g_disco->done = true;
                DestroyWindow(h);
            }
            return 0;
        case WM_CLOSE:
            g_disco->done = true;
            DestroyWindow(h);
            return 0;
        case WM_DESTROY:
            KillTimer(h, 1);
            return 0;
        default:
            return DefWindowProcW(h, m, w, l);
    }
}

// Show the discovery picker (modal). Returns true and fills ip/name if the user picks
// a device. The window handle is published in g_app->discoveryDlg so a background
// pairing accept can dismiss it. The local message loop still dispatches the tray's
// WM_TIMER, so the mesh keeps pumping while the picker is open.
bool showDiscoveryPicker(std::string& ipOut, std::string& nameOut) {
    DiscoveryPickState st;
    g_disco = &st;
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = discoveryPickProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SkittermouseDiscovery";
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW));
    RegisterClassW(&wc);
    int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
    const int wdt = 442, hgt = 292;
    HWND h = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, wc.lpszClassName, L"Add device",
                             WS_POPUP | WS_CAPTION | WS_SYSMENU, (sx - wdt) / 2, (sy - hgt) / 2, wdt,
                             hgt, nullptr, nullptr, hInst, nullptr);
    if (!h) {
        g_disco = nullptr;
        return false;
    }
    if (g_app) g_app->discoveryDlg = h;
    ShowWindow(h, SW_SHOW);
    SetForegroundWindow(h);
    MSG msg;
    while (!st.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (IsDialogMessageW(h, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (g_app) g_app->discoveryDlg = nullptr;
    g_disco = nullptr;
    ipOut = st.selectedIp;
    nameOut = st.selectedName;
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
                sm::log::write("[net] dialed " + dd.id + " at " + dd.host + ":" +
                               std::to_string(dd.port) + " (wss up)");
                {
                    std::lock_guard<std::mutex> lk(g_app->connMutex);
                    g_app->peerIp[dd.id] = dd.host; // remember for the /files dial (spec 9)
                }
                sm::pairing::KeyStore tmp;
                tmp.setPsk(dd.id, dd.psk);
                sm::app::SecureLink link =
                    sm::app::secureOutbound(std::move(raw), tmp, g_app->self, dd.id);
                if (link.transport) {
                    std::lock_guard<std::mutex> lk(g_app->linkMutex);
                    g_app->pendingLinks.push_back(PendingLink{std::move(link), true});
                } else {
                    sm::log::write("[net] secure link to " + dd.id + " failed (PSK mismatch?)");
                }
            }
        }

        // Accept one inbound; the caller's identity + PSK come from the secure link.
        std::string inboundIp;
        std::unique_ptr<sm::net::Transport> in(sm::net::wsAcceptOne(kMeshPort, 200, &inboundIp));
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
            sm::log::write("[net] inbound wss accepted; running secure handshake");
            for (int i = 0; i < 200 && g_app->netRunning.load(); ++i) {
                auto st = hs.poll();
                if (st == sm::app::InboundHandshake::Status::Ok) {
                    sm::app::SecureLink link = hs.take();
                    sm::log::write("[net] inbound secure link established with " + link.peerId);
                    if (!inboundIp.empty()) {
                        std::lock_guard<std::mutex> lk(g_app->connMutex);
                        g_app->peerIp[link.peerId] = inboundIp; // for the /files dial (spec 9)
                    }
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

// --- Pairing (spec 7.1) -----------------------------------------------------------
// Shared exchange used by both the initiator and the acceptor: run the ECDH numeric-
// comparison over an already-connected transport, show the 6-digit code for the human
// to compare, and on confirm store the PSK + device. `initiatedHost` is the peer IP
// when we dialed (so we can seed last_ip); empty when the peer dialed us.
bool runPairingSession(sm::net::Transport& t, const std::string& initiatedHost) {
    const uint64_t deadline = GetTickCount64() + 30000;
    sm::log::write("[pair] connected; starting ECDH exchange");

    sm::pairing::PairingExchange ex(t, g_app->self);
    if (!ex.start()) {
        showToast(L"Skittermouse", L"Pairing failed to start.");
        return false;
    }
    sm::pairing::PairingExchange::Status st = sm::pairing::PairingExchange::Status::NeedMore;
    while (st == sm::pairing::PairingExchange::Status::NeedMore && GetTickCount64() < deadline) {
        st = ex.poll();
        if (st == sm::pairing::PairingExchange::Status::NeedMore) Sleep(20);
    }
    if (st != sm::pairing::PairingExchange::Status::Ok) {
        showToast(L"Skittermouse", L"Pairing exchange failed.");
        return false;
    }

    if (!confirmPairingCode(ex.code(), ex.peerId())) { // human numeric comparison (spec 7.1)
        showToast(L"Skittermouse", L"Pairing rejected.");
        return false;
    }

    {
        std::lock_guard<std::mutex> lk(g_app->stateMutex);
        g_app->keys.setPsk(ex.peerId(), ex.psk());
        if (!g_app->keyStorePath.empty())
            g_app->keys.saveToFile(g_app->keyStorePath, g_app->protKey.data());
        sm::core::PairedDevice dev;
        dev.id = ex.peerId();
        dev.name = ex.peerId();
        dev.last_ip = initiatedHost; // set only if we initiated; the peer dials us otherwise
        dev.port = kMeshPort;
        dev.os = "windows";
        g_app->config.addDevice(dev);
        std::string cpath = configPath();
        if (!cpath.empty()) g_app->config.saveToFile(cpath);
    }
    showToast(L"Skittermouse", L"Paired with " + toWide(ex.peerId()));
    sm::log::write("[pair] paired with " + ex.peerId());
    return true;
}

// End the current pairing session: stops the discovery + accept loops.
void endPairingSession() {
    g_app->pairingActive.store(false);
    if (g_app->discoveryDlg) PostMessageW(g_app->discoveryDlg, WM_CLOSE, 0, 0);
}

// Initiator: the user picked a discovered device; dial its pairing port and run the
// exchange. pairEngaged guards against also accepting an inbound pairing this session
// (which would derive a second, mismatched PSK).
void pairInitProc(std::string host) {
    while (!host.empty() && (host.back() == ' ' || host.back() == '\r' || host.back() == '\n'))
        host.pop_back();
    while (!host.empty() && host.front() == ' ') host.erase(host.begin());

    if (g_app->pairEngaged.exchange(true)) return; // an inbound pairing already won
    sm::log::write("[pair] initiating to " + host);

    std::unique_ptr<sm::net::Transport> t;
    const uint64_t deadline = GetTickCount64() + 15000;
    while (!t && GetTickCount64() < deadline && g_app->pairingActive.load()) {
        std::unique_ptr<sm::net::Transport> raw(sm::net::createWsClientTransport());
        if (raw && raw->connect(host, kPairPort)) t = std::move(raw);
        else Sleep(300);
    }
    if (!t) {
        sm::log::write("[pair] could not reach " + host);
        showToast(L"Skittermouse", L"Could not reach the selected PC.");
    } else {
        runPairingSession(*t, host);
    }
    endPairingSession();
}

// Acceptor: while pairing mode is on, wait for an inbound pairing connection. The
// first side to connect wins the pairEngaged race; the other becomes the acceptor.
void pairAcceptProc() {
    while (g_app->pairingActive.load() && !g_app->pairEngaged.load()) {
        std::unique_ptr<sm::net::Transport> t(sm::net::wsAcceptOne(kPairPort, 500));
        if (!t) continue;
        if (g_app->pairEngaged.exchange(true)) break; // we already initiated -> ignore
        sm::log::write("[pair] inbound pairing connection accepted");
        if (g_app->discoveryDlg) PostMessageW(g_app->discoveryDlg, WM_CLOSE, 0, 0);
        runPairingSession(*t, ""); // peer dialed us; it will dial the mesh port too
        break;
    }
    endPairingSession();
}

// Presence: broadcast our beacon and listen for others on the discovery port while
// pairing mode is on, feeding the live table the picker reads (spec 6). On receiving a
// beacon we ALSO unicast one straight back to the sender -- so a machine whose own
// broadcast can't reach us (VPN split routing / corp firewall dropping broadcast) still
// becomes visible the moment ONE direction's broadcast gets through. Throttled per peer.
void discoveryProc() {
    sm::net::Beacon self;
    self.machine_name = g_app->self;
    self.machine_id = g_app->self;
    self.port = kMeshPort;
    self.os = 0; // windows
    std::map<std::string, uint64_t> lastReply; // per-peer unicast-reply throttle
    uint64_t lastBroadcast = 0;
    while (g_app->pairingActive.load()) {
        const uint64_t now = GetTickCount64();
        if (now - lastBroadcast >= 400) { // broadcast ~2x/sec
            sm::net::broadcastBeacon(self, kDiscoveryPort);
            lastBroadcast = now;
        }
        sm::net::Beacon in;
        if (sm::net::receiveBeacon(kDiscoveryPort, 250, in) && in.machine_id != g_app->self) {
            {
                std::lock_guard<std::mutex> lk(g_app->discMutex);
                g_app->discovered.onBeacon(in, GetTickCount64());
            }
            const uint64_t t = GetTickCount64();
            uint64_t& lr = lastReply[in.machine_id];
            if (!in.ip.empty() && (lr == 0 || t - lr >= 700)) {
                sm::net::sendBeaconTo(self, in.ip, kDiscoveryPort); // let the sender see us
                lr = t;
            }
        }
    }
}

// --- File transfer glue (spec 9) --------------------------------------------------
// Read the file paths currently on the clipboard (CF_HDROP), i.e. what the user just
// copied in Explorer. Empty if the clipboard holds no files.
std::vector<std::wstring> clipboardFilePaths(HWND owner) {
    std::vector<std::wstring> paths;
    if (!IsClipboardFormatAvailable(CF_HDROP) || !OpenClipboard(owner)) return paths;
    if (HANDLE h = GetClipboardData(CF_HDROP)) {
        auto drop = static_cast<HDROP>(h);
        UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
        for (UINT i = 0; i < count; ++i) {
            wchar_t buf[MAX_PATH];
            if (DragQueryFileW(drop, i, buf, MAX_PATH)) paths.emplace_back(buf);
        }
    }
    CloseClipboard();
    return paths;
}

uint64_t fileSizeOf(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) return 0;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return 0; // v1: files only
    return (static_cast<uint64_t>(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
}

std::string baseNameUtf8(const std::wstring& path) {
    std::size_t slash = path.find_last_of(L"\\/");
    std::wstring name = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
    int n = WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? static_cast<std::size_t>(n - 1) : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, name.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

std::string wideToUtf8(const std::wstring& w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? static_cast<std::size_t>(n - 1) : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

bool isDirectory(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

bool readWholeFile(const std::wstring& path, sm::net::Bytes& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<std::size_t>(sz));
    if (sz > 0) f.read(reinterpret_cast<char*>(out.data()), sz);
    return static_cast<bool>(f) || f.eof();
}

// Secure an inbound socket by looking up the connector's PSK (mirrors the mesh
// acceptor). Returns a sealed link or an empty one on failure.
sm::app::SecureLink secureInboundLink(std::unique_ptr<sm::net::Transport> raw) {
    sm::pairing::KeyStore keysCopy;
    {
        std::lock_guard<std::mutex> lk(g_app->stateMutex);
        for (const auto& id : g_app->keys.devices())
            if (const sm::pairing::Psk* p = g_app->keys.getPsk(id)) keysCopy.setPsk(id, *p);
    }
    sm::app::InboundHandshake hs(std::move(raw), keysCopy, g_app->self);
    for (int i = 0; i < 400 && g_app->netRunning.load(); ++i) {
        auto st = hs.poll();
        if (st == sm::app::InboundHandshake::Status::Ok) return hs.take();
        if (st != sm::app::InboundHandshake::Status::NeedMore) break;
        Sleep(5);
    }
    return {};
}

// /files server (spec 5.1/9): accept a secure connection on kFilePort and stream the
// files the user last copied. A fresh connection per transfer keeps large file bytes
// entirely off the input channel, so a transfer never stalls mouse movement.
void fileServeThreadProc() {
    while (g_app->netRunning.load()) {
        std::unique_ptr<sm::net::Transport> in(sm::net::wsAcceptOne(kFilePort, 300));
        if (!in) continue;
        sm::app::SecureLink link = secureInboundLink(std::move(in));
        if (!link.transport) continue;

        std::vector<std::string> paths;
        {
            std::lock_guard<std::mutex> lk(g_app->fileMutex);
            paths = g_app->copiedPaths;
        }
        sm::net::FileSender snd;
        for (const auto& p : paths) {
            std::wstring wp = toWide(p);
            sm::net::Bytes bytes;
            if (readWholeFile(wp, bytes)) snd.addFile(baseNameUtf8(wp), std::move(bytes));
        }
        if (snd.fileCount() == 0) continue;
        sm::log::write("[file] serving " + std::to_string(snd.fileCount()) + " file(s)");
        sm::net::FileChannel::sendAll(*link.transport, snd, 64 * 1024);
        // Linger briefly so the peer drains before the socket closes.
        for (int i = 0; i < 40 && link.transport->isConnected(); ++i) {
            uint8_t b[64];
            if (link.transport->recv(b, sizeof(b)) < 0) break;
            Sleep(25);
        }
    }
}

// Destination pull: a shared, lazily-connected session that dials the source's /files
// port on first read and drives a FileReceiver. All promised streams of one paste
// share it, so the bytes are pulled once and served to Explorer by (index, offset).
struct FilePullSession {
    std::mutex mtx;
    std::string sourceIp;
    sm::core::PeerId sourceId;
    sm::pairing::Psk psk;
    bool hasKey = false;
    std::unique_ptr<sm::net::Transport> transport;
    sm::net::FileReceiver receiver;
    bool failed = false;
    bool dialed = false;

    // Open the secure /files link to the source (once).
    bool ensureConnected() {
        if (dialed) return transport != nullptr;
        dialed = true;
        if (sourceIp.empty() || !hasKey) { failed = true; return false; }
        std::unique_ptr<sm::net::Transport> raw(sm::net::createWsClientTransport());
        if (!raw || !raw->connect(sourceIp, kFilePort)) { failed = true; return false; }
        sm::pairing::KeyStore tmp;
        tmp.setPsk(sourceId, psk);
        sm::app::SecureLink link =
            sm::app::secureOutbound(std::move(raw), tmp, g_app->self, sourceId);
        if (!link.transport) { failed = true; return false; }
        transport = std::move(link.transport);
        sm::log::write("[file] pulling from " + sourceId + " at " + sourceIp);
        return true;
    }

    // Serve bytes of file `index` at `offset`. Blocks (draining the link) until the
    // bytes arrive; returns bytes copied, 0 at EOF, -1 on failure/timeout.
    int read(uint32_t index, uint64_t offset, uint8_t* buf, uint32_t cap) {
        std::lock_guard<std::mutex> lk(mtx);
        if (failed) return -1;
        if (!ensureConnected()) return -1;
        const uint64_t deadline = GetTickCount64() + 30000; // 30 s no-progress budget
        for (;;) {
            const bool haveFile = receiver.fileCount() > index;
            const std::size_t have = haveFile ? receiver.data(index).size() : 0;
            if (offset < have) {
                std::size_t avail = have - static_cast<std::size_t>(offset);
                std::size_t n = avail < cap ? avail : cap;
                std::memcpy(buf, receiver.data(index).data() + offset, n);
                return static_cast<int>(n);
            }
            if (haveFile && receiver.complete(index) && offset >= have) return 0; // EOF
            sm::net::FileChannel::receiveAvailable(*transport, receiver);
            if (!transport->isConnected() && !(receiver.fileCount() > index &&
                                               receiver.data(index).size() > offset)) {
                failed = true;
                return -1; // source closed before delivering the requested bytes
            }
            if (GetTickCount64() > deadline) { failed = true; return -1; }
            Sleep(2);
        }
    }
};

// Called on the UI thread when a peer announces copied files: build a delay-render
// promise whose bytes pull from that peer over the /files channel, and put it on the
// local clipboard so a paste in Explorer materialises them with native progress UI.
void onRemoteFilePromiseUi(const sm::core::PeerId& from,
                           const std::vector<sm::net::FilePromiseItem>& files) {
    if (files.empty()) return;
    auto session = std::make_shared<FilePullSession>();
    session->sourceId = from;
    {
        std::lock_guard<std::mutex> lk(g_app->connMutex);
        auto it = g_app->peerIp.find(from);
        if (it != g_app->peerIp.end()) session->sourceIp = it->second;
    }
    if (session->sourceIp.empty()) {
        for (const auto& d : g_app->config.devices)
            if (d.id == from) session->sourceIp = d.last_ip;
    }
    {
        std::lock_guard<std::mutex> lk(g_app->stateMutex);
        if (const sm::pairing::Psk* p = g_app->keys.getPsk(from)) {
            session->psk = *p;
            session->hasKey = true;
        }
    }

    std::vector<sm::platform::PromisedFile> promised;
    for (const auto& f : files) promised.push_back({f.name, f.size});

    sm::platform::FileByteSource source = [session](uint32_t index, uint64_t offset, uint8_t* buf,
                                                    uint32_t cap) -> int {
        return session->read(index, offset, buf, cap);
    };
    if (sm::platform::putFilePromiseOnClipboard(promised, std::move(source)))
        showToast(L"Skittermouse", L"Files from " + toWide(from) + L" ready to paste");
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
                // Auto-discovery pairing (spec 6/7.1): start broadcasting + listening
                // for LAN beacons and accepting an inbound pairing, then show a live
                // picker of discovered devices (name + IP -- no manual IP typing).
                if (g_app->pairingActive.load()) {
                    showToast(L"Skittermouse", L"Pairing already in progress\u2026");
                } else {
                    // Join any previous session's threads before starting a new one.
                    if (g_app->discoveryThread.joinable()) g_app->discoveryThread.join();
                    if (g_app->pairAcceptThread.joinable()) g_app->pairAcceptThread.join();
                    if (g_app->pairThread.joinable()) g_app->pairThread.join();
                    {
                        std::lock_guard<std::mutex> lk(g_app->discMutex);
                        g_app->discovered = sm::net::DiscoveryTable{};
                    }
                    g_app->pairEngaged.store(false);
                    g_app->pairingActive.store(true);
                    g_app->discoveryThread = std::thread(discoveryProc);
                    g_app->pairAcceptThread = std::thread(pairAcceptProc);

                    std::string ip, name;
                    const bool picked = showDiscoveryPicker(ip, name);
                    if (picked && !ip.empty()) {
                        if (g_app->pairThread.joinable()) g_app->pairThread.join();
                        showToast(L"Skittermouse",
                                  L"Pairing with " + toWide(name) + L"\u2026 compare the code.");
                        g_app->pairThread = std::thread(pairInitProc, ip);
                    } else if (!g_app->pairEngaged.load()) {
                        // Cancelled with no inbound pairing running -> end the session.
                        endPairingSession();
                    }
                    // If pairEngaged (an inbound pairing was accepted while the picker
                    // was open), the accept thread finishes and ends the session.
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
            if (g_app->mesh && !clipboardExcludedFromMonitoring()) { // skip password-mgr writes
                // Files copied in Explorer (CF_HDROP) -> announce a promise to peers so
                // the machine the user pastes on can pull them (spec 9). Otherwise fall
                // back to plain-text clipboard sync (spec 8).
                std::vector<std::wstring> paths = clipboardFilePaths(hwnd);
                std::vector<sm::net::FilePromiseItem> items;
                std::vector<std::string> utf8Paths;
                for (const auto& p : paths) {
                    if (isDirectory(p)) continue; // v1: files only
                    items.push_back({baseNameUtf8(p), fileSizeOf(p)});
                    utf8Paths.push_back(wideToUtf8(p));
                }
                if (!items.empty()) {
                    {
                        std::lock_guard<std::mutex> lk(g_app->fileMutex);
                        g_app->copiedPaths = std::move(utf8Paths);
                    }
                    g_app->mesh->announceFilePromise(items);
                    sm::log::write("[file] announced " + std::to_string(items.size()) +
                                   " copied file(s)");
                } else {
                    std::string text;
                    if (getClipboardText(text)) g_app->mesh->onLocalClipboardChange(text);
                }
            }
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            g_app->netRunning.store(false);
            g_app->pairingActive.store(false);
            if (g_app->netThread.joinable()) g_app->netThread.join();
            if (g_app->pairThread.joinable()) g_app->pairThread.join();
            if (g_app->discoveryThread.joinable()) g_app->discoveryThread.join();
            if (g_app->pairAcceptThread.joinable()) g_app->pairAcceptThread.join();
            if (g_app->fileThread.joinable()) g_app->fileThread.join();
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
    // Log first (before anything can early-return) so "did the finish-page Run launch
    // us?" is answerable from %APPDATA%\Skittermouse\log.txt.
    sm::log::init(logPath());
    sm::log::write("[app] runTrayApp entry");

    // Single-instance guard: if another copy is already running (e.g. the installer's
    // "Run" launched one while a prior instance from autostart/a reinstall lingers),
    // exit quietly so two instances never fight over the fixed ports. A NULL-DACL makes
    // the mutex visible across integrity levels, so an elevated (autostart) instance and
    // a de-elevated (finish-page / Start-menu) launch see each other. Logged so a
    // "nothing happened after Finish" report is diagnosable.
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa{};
    if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) &&
        SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE)) {
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = &sd;
    }
    HANDLE singleton =
        CreateMutexW(sa.lpSecurityDescriptor ? &sa : nullptr, TRUE, L"SkittermouseSingletonMutex");
    if (singleton && GetLastError() == ERROR_ALREADY_EXISTS) {
        sm::log::write("[app] another instance already running; exiting (tray already present)");
        return 0;
    }

    AppState app;
    g_app = &app;

    sm::log::write("[app] Skittermouse starting");
    OleInitialize(nullptr); // OLE clipboard for the delay-render file promise (spec 9.1)

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
    // A peer announced copied files (spec 9): offer them on the local clipboard so a
    // paste in Explorer pulls the bytes on demand with native progress UI.
    app.mesh->onRemoteFilePromise = [](const sm::core::PeerId& from,
                                       const std::vector<sm::net::FilePromiseItem>& files) {
        onRemoteFilePromiseUi(from, files);
    };
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
    app.fileThread = std::thread(fileServeThreadProc); // on-demand /files server (spec 9)

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    g_app = nullptr;
    return 0;
}

} // namespace sm::platform
