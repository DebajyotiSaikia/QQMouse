#include "core/input_tracker.h"

namespace sm::core {

void InputTracker::onKey(uint8_t code, bool down) {
    if (down) keysDown_.insert(code);
    else keysDown_.erase(code);
}

void InputTracker::onButton(uint8_t code, bool down) {
    if (down) buttonsDown_.insert(code);
    else buttonsDown_.erase(code);
}

bool InputTracker::isKeyDown(uint8_t code) const {
    return keysDown_.find(code) != keysDown_.end();
}

bool InputTracker::isButtonDown(uint8_t code) const {
    return buttonsDown_.find(code) != buttonsDown_.end();
}

std::vector<InputTracker::Release> InputTracker::drainReleases() {
    std::vector<Release> out;
    out.reserve(downCount());
    for (uint8_t c : buttonsDown_) out.push_back({c, true});
    for (uint8_t c : keysDown_) out.push_back({c, false});
    clear();
    return out;
}

void InputTracker::clear() {
    keysDown_.clear();
    buttonsDown_.clear();
}

} // namespace sm::core
