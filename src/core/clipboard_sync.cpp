#include "core/clipboard_sync.h"

namespace sm::core {

uint64_t ClipboardSync::hash(const std::string& s) {
    // FNV-1a 64-bit.
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

void ClipboardSync::noteAppliedRemote(const std::string& text) {
    pendingRemoteHash_ = hash(text);
    hasPending_ = true;
}

bool ClipboardSync::shouldBroadcastLocalChange(const std::string& text) {
    uint64_t h = hash(text);
    if (hasPending_ && h == pendingRemoteHash_) {
        hasPending_ = false; // consume the one suppressed echo
        return false;
    }
    // A genuine local change: any stale pending echo is no longer relevant.
    hasPending_ = false;
    return true;
}

} // namespace sm::core
