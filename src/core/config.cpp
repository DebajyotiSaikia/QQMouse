#include "core/config.h"

#include <fstream>
#include <sstream>

namespace sm::core {

namespace {

// --- Backslash escaping so free-text fields can hold '|', '\', and newlines ---
std::string esc(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '|':  out += "\\p";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

std::string unesc(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[++i];
            switch (n) {
                case '\\': out += '\\'; break;
                case 'p':  out += '|';  break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                default:   out += n;    break; // unknown escape: keep the char
            }
        } else {
            out += s[i];
        }
    }
    return out;
}

// Join already-known-safe id/text fields with an unescaped '|' separator; each
// field is escaped first, so the separator is never ambiguous.
std::string joinFields(const std::vector<std::string>& fields) {
    std::string out;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i) out += '|';
        out += esc(fields[i]);
    }
    return out;
}

std::vector<std::string> splitFields(const std::string& s) {
    std::vector<std::string> out;
    if (s.empty()) return out; // empty value -> zero fields
    std::string cur;
    for (char c : s) {
        if (c == '|') {
            out.push_back(unesc(cur));
            cur.clear();
        } else {
            cur += c;
        }
    }
    out.push_back(unesc(cur));
    return out;
}

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string cur;
    for (char c : text) {
        if (c == '\n') {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            lines.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty()) {
        if (cur.back() == '\r') cur.pop_back();
        lines.push_back(cur);
    }
    return lines;
}

uint16_t toU16(const std::string& s) {
    unsigned long v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') break;
        v = v * 10 + static_cast<unsigned long>(c - '0');
        if (v > 65535UL) return 65535;
    }
    return static_cast<uint16_t>(v);
}

int32_t toI32(const std::string& s) {
    long v = 0;
    bool neg = false;
    std::size_t i = 0;
    if (i < s.size() && (s[i] == '-' || s[i] == '+')) { neg = (s[i] == '-'); ++i; }
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') break;
        v = v * 10 + (s[i] - '0');
    }
    return static_cast<int32_t>(neg ? -v : v);
}

std::vector<std::string> toStrIds(const std::vector<PeerId>& ids) {
    return std::vector<std::string>(ids.begin(), ids.end());
}

} // namespace

bool PairedDevice::operator==(const PairedDevice& o) const {
    return id == o.id && name == o.name && last_ip == o.last_ip &&
           port == o.port && os == o.os && wol_capable == o.wol_capable;
}

bool LayoutMonitor::operator==(const LayoutMonitor& o) const {
    return machine_id == o.machine_id && monitor_index == o.monitor_index &&
           x == o.x && y == o.y && w == o.w && h == o.h;
}

std::string Config::serialize() const {
    std::ostringstream out;
    out << "# Skittermouse config\n";
    out << "version=1\n";
    out << "setting.hotkey=" << esc(settings.hotkey) << "\n";
    out << "setting.broadcast=" << (settings.broadcast_presence ? "1" : "0") << "\n";
    out << "setting.lock_optin=" << (settings.lock_propagation_optin ? "1" : "0") << "\n";
    for (const auto& d : devices) {
        out << "device=" << joinFields({d.id, d.name, d.last_ip,
                                         std::to_string(d.port), d.os,
                                         d.wol_capable ? "1" : "0"}) << "\n";
    }
    out << "priority=" << joinFields(toStrIds(priority)) << "\n";
    out << "ineligible=" << joinFields(toStrIds(ineligible)) << "\n";
    for (const auto& m : monitors) {
        out << "monitor=" << joinFields({m.machine_id, std::to_string(m.monitor_index),
                                         std::to_string(m.x), std::to_string(m.y),
                                         std::to_string(m.w), std::to_string(m.h)}) << "\n";
    }
    return out.str();
}

Config Config::parse(const std::string& text) {
    Config c;
    for (const std::string& line : splitLines(text)) {
        if (line.empty() || line[0] == '#') continue;
        std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if (key == "setting.hotkey") {
            c.settings.hotkey = unesc(val);
        } else if (key == "setting.broadcast") {
            c.settings.broadcast_presence = (val == "1");
        } else if (key == "setting.lock_optin") {
            c.settings.lock_propagation_optin = (val == "1");
        } else if (key == "device") {
            auto f = splitFields(val);
            PairedDevice d;
            if (f.size() > 0) d.id = f[0];
            if (f.size() > 1) d.name = f[1];
            if (f.size() > 2) d.last_ip = f[2];
            if (f.size() > 3) d.port = toU16(f[3]);
            if (f.size() > 4) d.os = f[4];
            if (f.size() > 5) d.wol_capable = (f[5] == "1");
            c.devices.push_back(d);
        } else if (key == "priority") {
            auto f = splitFields(val);
            c.priority.assign(f.begin(), f.end());
        } else if (key == "ineligible") {
            auto f = splitFields(val);
            c.ineligible.assign(f.begin(), f.end());
        } else if (key == "monitor") {
            auto f = splitFields(val);
            LayoutMonitor m;
            if (f.size() > 0) m.machine_id = f[0];
            if (f.size() > 1) m.monitor_index = toI32(f[1]);
            if (f.size() > 2) m.x = toI32(f[2]);
            if (f.size() > 3) m.y = toI32(f[3]);
            if (f.size() > 4) m.w = toI32(f[4]);
            if (f.size() > 5) m.h = toI32(f[5]);
            c.monitors.push_back(m);
        }
        // Unknown keys (incl. "version") are ignored on purpose (forward-compat).
    }
    return c;
}

bool Config::saveToFile(const std::string& path) const {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << serialize();
    return static_cast<bool>(f);
}

Config Config::loadFromFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return Config{}; // absent/unreadable -> defaults
    std::ostringstream ss;
    ss << f.rdbuf();
    return parse(ss.str());
}

void Config::addDevice(const PairedDevice& d) {
    bool replaced = false;
    for (auto& e : devices) {
        if (e.id == d.id) {
            e = d;
            replaced = true;
            break;
        }
    }
    if (!replaced) devices.push_back(d);

    // New pairings are eligible and appended at lowest priority by default, unless
    // the user has explicitly removed this machine from election (Section 11.5).
    bool inPriority = false;
    for (const auto& p : priority) {
        if (p == d.id) { inPriority = true; break; }
    }
    bool removed = false;
    for (const auto& r : ineligible) {
        if (r == d.id) { removed = true; break; }
    }
    if (!inPriority && !removed) priority.push_back(d.id);
}

const PairedDevice* Config::findDevice(const PeerId& id) const {
    for (const auto& d : devices) {
        if (d.id == id) return &d;
    }
    return nullptr;
}

} // namespace sm::core
