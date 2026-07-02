// Windows screen lock via LockWorkStation (spec 14). Native Win32.

#include "platform/lock_screen.h"

#include <windows.h>

namespace sm::platform {

bool lockScreen() { return LockWorkStation() != 0; }

} // namespace sm::platform
