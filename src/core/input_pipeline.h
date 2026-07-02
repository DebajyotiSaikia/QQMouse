#pragma once

// Owner-side input forwarding pipeline (spec 3.1 -> 5.1). Turns captured input into
// wire messages to broadcast to the current sink, while tracking which keys/buttons
// are physically down so a switch-out can synthesize the matching releases first
// (stuck-key prevention, spec 4.4). PURE LOGIC -- the OS hook feeds it, the network
// layer ships what it returns.

#include <cstdint>
#include <vector>

#include "core/input_tracker.h"

namespace sm::core {

class InputPipeline {
public:
    using Bytes = std::vector<uint8_t>;

    // Each returns the encoded 12-byte InputEvent to forward.
    Bytes onMouseMove(int16_t dx, int16_t dy, uint32_t ts);
    Bytes onMouseButton(uint8_t button, bool down, uint32_t ts);
    Bytes onKey(uint8_t code, bool down, uint32_t ts);

    // Release events for everything still held, produced on every switch-out.
    std::vector<Bytes> releaseAll(uint32_t ts);

    const InputTracker& tracker() const { return tracker_; }

private:
    InputTracker tracker_;
};

} // namespace sm::core
