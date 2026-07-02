#pragma once

// Flat-file configuration: paired devices, coordinator priority list, layout, and
// settings (spec Section 2.2 and Section 16 -- a flat file, no embedded database).
//
// serialize()/parse() are PURE LOGIC (only the C++ standard library). The parser
// is tolerant: unknown keys are ignored (so a config written by a newer build
// still loads on an older one), blank and '#' comment lines are skipped, and a
// missing file yields defaults. Free-text fields are backslash-escaped so device
// names may contain '|', '\', or newlines without corrupting the format.

#include <cstdint>
#include <string>
#include <vector>

#include "core/peer_id.h"

namespace sm::core {

struct PairedDevice {
    PeerId      id;                 // stable machine id (persisted UUID / machine name)
    std::string name;               // display name shown in the picker / tray
    std::string last_ip;            // last-known address (plumbing; never shown in UI)
    uint16_t    port = 0;
    std::string os;                 // "windows" | "macos"
    bool        wol_capable = false; // last self-diagnosed Wake-on-LAN status (Section 12)

    bool operator==(const PairedDevice& o) const;
    bool operator!=(const PairedDevice& o) const { return !(*this == o); }
};

// Spatial arrangement at the MONITOR level (spec 11.4) -- forward-compatible data
// only. Edge-of-screen switching is intentionally NOT built on this yet; it exists
// so adding edge-crossing later needs no data-model change. Coordinates are in the
// mesh's notional virtual-desktop space.
struct LayoutMonitor {
    PeerId  machine_id;
    int32_t monitor_index = 0;
    int32_t x = 0, y = 0, w = 0, h = 0;

    bool operator==(const LayoutMonitor& o) const;
    bool operator!=(const LayoutMonitor& o) const { return !(*this == o); }
};

struct Settings {
    std::string hotkey = "Ctrl+Alt+Space"; // Section 4.1 default combo
    bool broadcast_presence = true;         // Section 6 discovery beacon on/off
    bool lock_propagation_optin = false;    // Section 14 lock is opt-in per machine
};

class Config {
public:
    Settings                   settings;
    std::vector<PairedDevice>  devices;
    std::vector<PeerId>        priority;    // Section 11.5: index 0 = highest priority
    std::vector<PeerId>        ineligible;  // removed from coordinator election
    std::vector<LayoutMonitor> monitors;    // Section 11.4 monitor-level layout (forward-compat)

    // Text round-trip (pure, no I/O).
    std::string serialize() const;
    static Config parse(const std::string& text);

    // File I/O via std::fstream. loadFromFile returns defaults when the file is
    // absent or unreadable, never throws.
    bool saveToFile(const std::string& path) const;
    static Config loadFromFile(const std::string& path);

    // Pair a new device (Section 11.5): stored/updated, and -- unless the user has
    // explicitly removed it from election -- appended at lowest coordinator priority.
    void addDevice(const PairedDevice& d);
    const PairedDevice* findDevice(const PeerId& id) const;
};

} // namespace sm::core
