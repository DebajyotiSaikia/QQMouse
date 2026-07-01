#pragma once

// Tracks which keys and mouse buttons are physically down on the capturing (owner)
// machine, so a switch-out can synthesize the matching releases BEFORE handing off
// capture (spec 4.4 -- the single most common bug class: a modifier held through a
// switch stays "stuck" because the real key-up never arrives locally). PURE LOGIC:
// we track our own view rather than trusting OS key state, since capture intercepts
// input before the OS sees it.

#include <cstdint>
#include <set>
#include <vector>

namespace sm::core {

class InputTracker {
public:
    void onKey(uint8_t code, bool down);
    void onButton(uint8_t code, bool down);

    bool isKeyDown(uint8_t code) const;
    bool isButtonDown(uint8_t code) const;
    std::size_t downCount() const { return keysDown_.size() + buttonsDown_.size(); }

    struct Release {
        uint8_t code;
        bool isButton;
    };

    // Everything currently down, as release events, then clears tracked state.
    // Call on every switch-out regardless of trigger.
    std::vector<Release> drainReleases();
    void clear();

private:
    std::set<uint8_t> keysDown_;
    std::set<uint8_t> buttonsDown_;
};

} // namespace sm::core
