#pragma once

// Heartbeat watchdog for fail-safe local control (spec 15). Records the last time
// a heartbeat was seen from each peer; a peer counts as alive only if seen within
// the timeout. Designed for SILENT death (crash, lid closed, power loss) -- no
// clean goodbye is required, since a dead owner can't send one. PURE LOGIC with an
// injected clock (now_ms), so it is deterministic and unit-testable.

#include <cstdint>
#include <map>
#include <vector>

#include "core/peer_id.h"

namespace sm::core {

class Heartbeat {
public:
    void onHeartbeat(const PeerId& peer, uint64_t now_ms);

    bool isAlive(const PeerId& peer, uint64_t now_ms, uint64_t timeout_ms) const;

    // Known peers whose last heartbeat is older than timeout_ms at now_ms.
    std::vector<PeerId> timedOut(uint64_t now_ms, uint64_t timeout_ms) const;

    void forget(const PeerId& peer);
    bool known(const PeerId& peer) const;

private:
    std::map<PeerId, uint64_t> last_;
};

} // namespace sm::core
