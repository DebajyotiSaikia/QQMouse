#pragma once

// Wire message encode/decode with a protocol-version gate (spec 5.3, 15). Fixed
// hot-path messages (MouseMove/MouseButton/KeyEvent/SwitchOwner/Heartbeat) are the
// 12-byte InputEvent; the rest are VarHeader + payload. Every message starts with
// protocol_version, checked on decode so a mismatched pair rejects cleanly instead
// of misparsing the binary struct. PURE LOGIC. Both target platforms are
// little-endian (x64 / arm64), so the packed struct is used directly on the wire.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "core/event_types.h"

namespace sm::net {

using Bytes = std::vector<uint8_t>;

Bytes encodeInputEvent(const sm::core::InputEvent& e);
Bytes encodeVarMessage(sm::core::MessageType type, const uint8_t* payload, std::size_t len);

enum class DecodeResult {
    Ok,
    NeedMore,         // buffer doesn't yet contain a full message
    VersionMismatch,  // protocol_version byte differs (spec 15)
    Malformed,        // unknown type / impossible length
};

struct DecodedMessage {
    sm::core::MessageType type = sm::core::MessageType::Heartbeat;
    bool isFixed = false;              // true -> use `fixed`; false -> use `payload`
    sm::core::InputEvent fixed{};
    Bytes payload;
};

// Decode one message from data. On Ok, `consumed` is set to its byte length.
DecodeResult decodeMessage(const uint8_t* data, std::size_t len,
                           DecodedMessage& out, std::size_t& consumed);

} // namespace sm::net
