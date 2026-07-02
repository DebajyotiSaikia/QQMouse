// Windows hotkey picker window (spec 4.2). A topmost WS_POPUP that steals focus,
// lists paired machines (owner marked, offline greyed), and returns the chosen id.
// A local message loop runs while it is open; Esc / lost-focus dismiss it. Native
// Win32, zero third-party.

#include "ui/picker_window.h"

#include <windows.h>

#include <string>
#include <vector>

namespace sm::ui {

namespace {

struct PickerState {
    const std::vector<MenuItem>* items = nullptr;
    int sel = 0;
    std::string result;
    bool done = false;
};

PickerState* g_ps = nullptr;

std::wstring toW(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? static_cast<std::size_t>(n - 1) : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

void moveSel(int dir) {
    if (!g_ps) return;
    int n = static_cast<int>(g_ps->items->size());
    if (n == 0) return;
    int s = g_ps->sel;
    for (int i = 0; i < n; ++i) {
        s = (s + dir + n) % n;
        if ((*g_ps->items)[s].is_online) { // skip offline (unselectable) rows
            g_ps->sel = s;
            return;
        }
    }
}

LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
    switch (msg) {
        case WM_KEYDOWN:
            if (!g_ps) return 0;
            if (w == VK_ESCAPE) {
                g_ps->result.clear();
                g_ps->done = true;
                DestroyWindow(hwnd);
            } else if (w == VK_UP) {
                moveSel(-1);
                InvalidateRect(hwnd, nullptr, TRUE);
            } else if (w == VK_DOWN) {
                moveSel(1);
                InvalidateRect(hwnd, nullptr, TRUE);
            } else if (w == VK_RETURN) {
                int s = g_ps->sel;
                if (s >= 0 && s < static_cast<int>(g_ps->items->size()) &&
                    (*g_ps->items)[s].is_online) {
                    g_ps->result = (*g_ps->items)[s].id;
                }
                g_ps->done = true;
                DestroyWindow(hwnd);
            }
            return 0;

        case WM_KILLFOCUS: // click-away / focus loss dismisses
            if (g_ps) {
                g_ps->result.clear();
                g_ps->done = true;
            }
            DestroyWindow(hwnd);
            return 0;

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(dc, &rc, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
            SetBkMode(dc, TRANSPARENT);
            SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
            int y = 8;
            for (int i = 0; g_ps && i < static_cast<int>(g_ps->items->size()); ++i) {
                const MenuItem& it = (*g_ps->items)[i];
                RECT row = {8, y, rc.right - 8, y + 24};
                if (i == g_ps->sel) {
                    HBRUSH b = CreateSolidBrush(RGB(60, 90, 160));
                    FillRect(dc, &row, b);
                    DeleteObject(b);
                }
                SetTextColor(dc, it.is_online ? RGB(240, 240, 240) : RGB(120, 120, 120));
                std::wstring label = (it.is_owner ? L"\u25CF  " : L"    ") + toW(it.name);
                TextOutW(dc, 16, y + 4, label.c_str(), static_cast<int>(label.size()));
                y += 26;
            }
            EndPaint(hwnd, &ps);
            return 0;
        }

        default:
            return DefWindowProcW(hwnd, msg, w, l);
    }
}

} // namespace

std::string showPicker(const std::vector<MenuItem>& items) {
    PickerState st;
    st.items = &items;
    // Start on the current owner if it's online, else the first online machine.
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (items[i].is_owner && items[i].is_online) { st.sel = static_cast<int>(i); break; }
    }
    if (st.sel >= static_cast<int>(items.size()) ||
        (!items.empty() && !items[st.sel].is_online)) {
        for (std::size_t i = 0; i < items.size(); ++i)
            if (items[i].is_online) { st.sel = static_cast<int>(i); break; }
    }
    g_ps = &st;

    HINSTANCE hInst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = proc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"SkittermousePicker";
    wc.hCursor = LoadCursorW(nullptr, reinterpret_cast<LPCWSTR>(IDC_ARROW)); // IDC_ARROW id
    RegisterClassW(&wc);

    int height = static_cast<int>(items.size()) * 26 + 16;
    if (height < 60) height = 60;
    int width = 300;
    int sx = GetSystemMetrics(SM_CXSCREEN), sy = GetSystemMetrics(SM_CYSCREEN);
    HWND hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, wc.lpszClassName,
                                L"Switch to\u2026", WS_POPUP | WS_BORDER,
                                (sx - width) / 2, (sy - height) / 2, width, height,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) {
        g_ps = nullptr;
        return {};
    }
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    SetFocus(hwnd);

    MSG msg;
    while (!st.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_ps = nullptr;
    return st.result;
}

} // namespace sm::ui
