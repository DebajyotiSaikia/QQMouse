#pragma once

// Screen lock (spec 14). Opt-in, lock-only, fire-and-forget. Unlock is never
// scripted -- the user switches to the machine and types their own password
// through the normal forwarded-input path. Implemented per-OS.

namespace sm::platform {

// Lock this machine's session. Returns false if the OS call fails.
bool lockScreen();

} // namespace sm::platform
