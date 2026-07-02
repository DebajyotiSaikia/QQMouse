#include "core/heartbeat.h"

namespace sm::core {

void Heartbeat::onHeartbeat(const PeerId& peer, uint64_t now_ms) {
    last_[peer] = now_ms;
}

bool Heartbeat::isAlive(const PeerId& peer, uint64_t now_ms, uint64_t timeout_ms) const {
    auto it = last_.find(peer);
    if (it == last_.end()) return false;
    return now_ms - it->second < timeout_ms;
}

std::vector<PeerId> Heartbeat::timedOut(uint64_t now_ms, uint64_t timeout_ms) const {
    std::vector<PeerId> out;
    for (const auto& kv : last_) {
        if (now_ms - kv.second >= timeout_ms) out.push_back(kv.first);
    }
    return out;
}

void Heartbeat::forget(const PeerId& peer) { last_.erase(peer); }

bool Heartbeat::known(const PeerId& peer) const {
    return last_.find(peer) != last_.end();
}

} // namespace sm::core
