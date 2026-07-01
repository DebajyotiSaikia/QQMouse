#pragma once

// Clipboard loop-prevention decision logic (spec 8). When a machine receives a
// synced clipboard update and writes it locally, that write re-fires the local
// change listener; without a guard it would re-broadcast and ping-pong forever.
// We remember the content we just applied from a peer and suppress exactly that
// one echo. PURE LOGIC -- the OS clipboard listeners live in platform/.

#include <cstdint>
#include <string>

namespace sm::core {

class ClipboardSync {
public:
    // We just wrote `text` locally because a peer sent it. The resulting local
    // change notification for this exact content must not be re-broadcast.
    void noteAppliedRemote(const std::string& text);

    // The local clipboard changed to `text`. Returns true if this should be
    // broadcast to peers, false if it is the echo of a just-applied remote update.
    bool shouldBroadcastLocalChange(const std::string& text);

private:
    static uint64_t hash(const std::string& s);
    uint64_t pendingRemoteHash_ = 0;
    bool hasPending_ = false;
};

} // namespace sm::core
