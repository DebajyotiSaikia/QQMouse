#include "test_framework.h"

#include "core/config.h"

#include <cstdio>
#include <filesystem>
#include <string>

using namespace sm::core;

namespace {

PairedDevice makeDevice(const std::string& id, const std::string& name) {
    PairedDevice d;
    d.id = id;
    d.name = name;
    d.last_ip = "192.168.1.42";
    d.port = 7777;
    d.os = "windows";
    d.wol_capable = true;
    return d;
}

} // namespace

void run_config_tests() {
    // --- Default round-trip -------------------------------------------------
    {
        Config def;
        Config r = Config::parse(def.serialize());
        SM_CHECK_EQ(r.settings.hotkey, std::string("Ctrl+Alt+Space"));
        SM_CHECK(r.settings.broadcast_presence);
        SM_CHECK(!r.settings.lock_propagation_optin);
        SM_CHECK(r.devices.empty());
        SM_CHECK(r.priority.empty());
        SM_CHECK(r.ineligible.empty());
    }

    // --- Settings booleans + hotkey round-trip ------------------------------
    {
        Config c;
        c.settings.hotkey = "Ctrl+Shift+Alt+Space";
        c.settings.broadcast_presence = false;
        c.settings.lock_propagation_optin = true;
        Config r = Config::parse(c.serialize());
        SM_CHECK_EQ(r.settings.hotkey, c.settings.hotkey);
        SM_CHECK(!r.settings.broadcast_presence);
        SM_CHECK(r.settings.lock_propagation_optin);
    }

    // --- Devices with special characters round-trip -------------------------
    {
        Config c;
        c.addDevice(makeDevice("id-1", "My|Weird\\Name"));
        c.addDevice(makeDevice("id-2", "Line1\nLine2\rEnd"));
        c.addDevice(makeDevice("id-3", ""));
        Config r = Config::parse(c.serialize());
        SM_CHECK_EQ(r.devices.size(), c.devices.size());
        for (std::size_t i = 0; i < c.devices.size(); ++i) {
            SM_CHECK(r.devices[i] == c.devices[i]);
        }
        // Priority auto-populated by addDevice, in pairing order.
        SM_CHECK_EQ(r.priority.size(), 3u);
        SM_CHECK_EQ(r.priority[0], std::string("id-1"));
        SM_CHECK_EQ(r.priority[2], std::string("id-3"));
    }

    // --- priority + ineligible round-trip, including empty -------------------
    {
        Config c;
        c.priority = {"a", "b", "c"};
        c.ineligible = {"z"};
        Config r = Config::parse(c.serialize());
        SM_CHECK_EQ(r.priority.size(), 3u);
        SM_CHECK_EQ(r.priority[1], std::string("b"));
        SM_CHECK_EQ(r.ineligible.size(), 1u);
        SM_CHECK_EQ(r.ineligible[0], std::string("z"));

        Config empty;
        Config re = Config::parse(empty.serialize());
        SM_CHECK(re.priority.empty());
        SM_CHECK(re.ineligible.empty());
    }

    // --- Monitor-level layout round-trip (spec 11.4) ------------------------
    {
        Config c;
        c.monitors.push_back(LayoutMonitor{"win-1", 0, 0, 0, 1920, 1080});
        c.monitors.push_back(LayoutMonitor{"mac-2", 1, 1920, -200, 2560, 1440});
        Config r = Config::parse(c.serialize());
        SM_CHECK_EQ(r.monitors.size(), 2u);
        SM_CHECK(r.monitors[0] == c.monitors[0]);
        SM_CHECK(r.monitors[1] == c.monitors[1]);
        SM_CHECK_EQ(r.monitors[1].x, 1920);
        SM_CHECK_EQ(r.monitors[1].y, -200); // negative coordinate survives
    }

    // --- Tolerant parser: unknown keys / comments / junk lines ignored ------
    {
        std::string text =
            "# a comment\n"
            "\n"
            "version=99\n"
            "futurekey=whatever\n"
            "no_equals_sign_here\n"
            "setting.hotkey=F9\n";
        Config r = Config::parse(text);
        SM_CHECK_EQ(r.settings.hotkey, std::string("F9"));
        SM_CHECK(r.devices.empty());
    }

    // --- Port parsing: valid, overflow clamps, non-numeric -> 0 -------------
    {
        Config r = Config::parse("device=id|name|ip|70000|windows|0\n");
        SM_CHECK_EQ(r.devices.size(), 1u);
        SM_CHECK_EQ(r.devices[0].port, static_cast<uint16_t>(65535));

        Config r2 = Config::parse("device=id|name|ip|abc|macos|1\n");
        SM_CHECK_EQ(r2.devices[0].port, static_cast<uint16_t>(0));
        SM_CHECK(r2.devices[0].wol_capable);
        SM_CHECK_EQ(r2.devices[0].os, std::string("macos"));
    }

    // --- addDevice: replace-by-id, no duplicate priority, respect ineligible -
    {
        Config c;
        c.addDevice(makeDevice("dup", "First"));
        c.addDevice(makeDevice("dup", "Second")); // same id -> replace, not append
        SM_CHECK_EQ(c.devices.size(), 1u);
        SM_CHECK_EQ(c.devices[0].name, std::string("Second"));
        SM_CHECK_EQ(c.priority.size(), 1u); // not double-added

        // A machine the user removed from election must not be re-added to priority.
        Config c2;
        c2.ineligible = {"nope"};
        c2.addDevice(makeDevice("nope", "Removed"));
        SM_CHECK_EQ(c2.devices.size(), 1u);
        SM_CHECK(c2.priority.empty());
    }

    // --- findDevice ---------------------------------------------------------
    {
        Config c;
        c.addDevice(makeDevice("find-me", "Here"));
        const PairedDevice* got = c.findDevice("find-me");
        SM_CHECK(got != nullptr);
        if (got) SM_CHECK_EQ(got->name, std::string("Here"));
        SM_CHECK(c.findDevice("absent") == nullptr);
    }

    // --- File I/O: save then load; missing file -> defaults -----------------
    {
        std::filesystem::path tmp =
            std::filesystem::temp_directory_path() / "skittermouse_cfg_test.cfg";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);

        Config c;
        c.settings.hotkey = "Ctrl+Alt+P";
        c.addDevice(makeDevice("disk-1", "Disk Device|X"));
        SM_CHECK(c.saveToFile(tmp.string()));

        Config loaded = Config::loadFromFile(tmp.string());
        SM_CHECK_EQ(loaded.settings.hotkey, std::string("Ctrl+Alt+P"));
        SM_CHECK_EQ(loaded.devices.size(), 1u);
        if (!loaded.devices.empty())
            SM_CHECK_EQ(loaded.devices[0].name, std::string("Disk Device|X"));

        std::filesystem::remove(tmp, ec);

        Config missing = Config::loadFromFile(
            (std::filesystem::temp_directory_path() / "sm_absent_xyz.cfg").string());
        SM_CHECK_EQ(missing.settings.hotkey, std::string("Ctrl+Alt+Space"));
        SM_CHECK(missing.devices.empty());
    }
}
