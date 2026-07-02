#pragma once

// Wire protocol message types and framing (spec Section 5.3).
//
// This header is pure data layout: no OS includes, no logic. Both machines in a
// pair must agree on these definitions byte-for-byte, so every message also
// carries a protocol_version (see Section 15 -- a mismatched pair must reject
// cleanly rather than silently misparse the binary struct).

#include <cstdint>

namespace sm::core {

// Bump on any change to the wire layout below. Checked on every connection.
inline constexpr uint8_t kProtocolVersion = 1;

#pragma pack(push, 1)

enum class MessageType : uint8_t {
    MouseMove       = 1,
    MouseButton     = 2,
    KeyEvent        = 3,
    SwitchOwner     = 4,
    Heartbeat       = 5,
    ClipboardUpdate = 6,   // variable length
    FilePromiseMeta = 7,   // variable length, file channel
    FileChunk       = 8,   // variable length, file channel
    PairingMsg      = 9,   // variable length, pairing only
    PeerHello       = 10,  // variable length; identifies a fresh connection (5.2)
    FilePromiseAnnounce = 11, // variable length; input channel: "I copied these files" (9)
};

// Fixed-size hot-path message, used for MouseMove / MouseButton / KeyEvent /
// SwitchOwner / Heartbeat.
struct InputEvent {
    uint8_t  protocol_version;
    uint8_t  type;          // MessageType
    int16_t  dx;            // mouse delta X, MouseMove only
    int16_t  dy;            // mouse delta Y, MouseMove only
    uint8_t  code;          // key or mouse-button code
    uint8_t  down;          // 1 = press, 0 = release
    uint32_t timestamp_ms;
};

// Header for variable-length messages (ClipboardUpdate, FilePromiseMeta,
// FileChunk, PairingMsg):
//   [protocol_version:1][type:1][payload_length:4][payload: payload_length bytes]
// WebSocket framing already provides message boundaries, so no extra manual
// length-prefixing is needed beyond this header (spec Section 5.3).
struct VarHeader {
    uint8_t  protocol_version;
    uint8_t  type;          // MessageType
    uint32_t payload_length;
};

#pragma pack(pop)

// Wire-size guarantees. NOTE: spec Section 5.3 annotates InputEvent as "10
// bytes", but the field list packs to 12 (two int16 deltas + four 1-byte fields
// + a 4-byte timestamp). The struct layout is authoritative; 12 is the real,
// consistent on-wire size and is what both machines exchange.
static_assert(sizeof(InputEvent) == 12, "InputEvent wire layout changed unexpectedly");
static_assert(sizeof(VarHeader) == 6, "VarHeader wire layout changed unexpectedly");

} // namespace sm::core
