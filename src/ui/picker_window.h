#pragma once

// Hotkey-triggered machine picker (spec 4.2). A small, topmost, focus-stealing list
// of paired machines with the current owner marked; Up/Down to move, Enter to
// switch, Esc / click-away to dismiss. Offline machines are shown but greyed and not
// selectable. Implemented per-OS (Win32 popup; macOS NSPanel).

#include <string>
#include <vector>

#include "ui/menu_model.h"

namespace sm::ui {

// Blocks until the user selects (Enter) or dismisses. Returns the chosen machine id,
// or "" if dismissed.
std::string showPicker(const std::vector<MenuItem>& items);

} // namespace sm::ui
