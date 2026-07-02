#pragma once

// Factory for the platform WSS/TCP transport (spec 5.1/5.5). Declared separately
// from the pure Transport interface so transport.h stays OS-free. Implemented in
// platform/ws_transport_win.cpp (and later a macOS counterpart).

#include "net/transport.h"

namespace sm::net {

// A client WebSocket transport connecting to a peer's listening port. Caller owns.
// (TLS wrapping via Schannel for full wss:// is the remaining step; message payloads
// are already AES-256-GCM sealed end-to-end per spec 5.4.)
Transport* createWsClientTransport();

} // namespace sm::net
