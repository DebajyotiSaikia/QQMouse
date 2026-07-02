#include "net/message_codec.h"

#include <cstring>

namespace sm::net {

using sm::core::InputEvent;
using sm::core::MessageType;
using sm::core::VarHeader;
using sm::core::kProtocolVersion;

namespace {

bool isFixedType(MessageType t) {
    // The genuine 12-byte hot-path messages. SwitchOwner is variable-length: it
    // carries a full ownership claim (target/origin peer ids + sequence), which
    // does not fit the fixed InputEvent struct, so it uses the VarHeader path.
    switch (t) {
        case MessageType::MouseMove:
        case MessageType::MouseButton:
        case MessageType::KeyEvent:
        case MessageType::Heartbeat:
            return true;
        default:
            return false;
    }
}

bool isKnownType(uint8_t t) {
    // Types 1-9 and 11 are decoded here; 10 (PeerHello) is handled by the secure-link
    // layer before the mesh codec ever sees it, so it is intentionally not accepted.
    return (t >= 1 && t <= 9) || t == 11;
}

// Upper bound on a variable-length payload. The real messages are tiny (input,
// clipboard text, 64 KB file chunks, pairing points); anything larger is a malformed
// or malicious header and is rejected before we trust the length or allocate for it.
constexpr uint32_t kMaxVarPayload = 64u * 1024 * 1024;

} // namespace

Bytes encodeInputEvent(const InputEvent& e) {
    Bytes b(sizeof(InputEvent));
    std::memcpy(b.data(), &e, sizeof(InputEvent));
    return b;
}

Bytes encodeVarMessage(MessageType type, const uint8_t* payload, std::size_t len) {
    VarHeader h;
    h.protocol_version = kProtocolVersion;
    h.type = static_cast<uint8_t>(type);
    h.payload_length = static_cast<uint32_t>(len);

    Bytes b(sizeof(VarHeader) + len);
    std::memcpy(b.data(), &h, sizeof(VarHeader));
    if (len) std::memcpy(b.data() + sizeof(VarHeader), payload, len);
    return b;
}

DecodeResult decodeMessage(const uint8_t* data, std::size_t len,
                           DecodedMessage& out, std::size_t& consumed) {
    if (len < 2) return DecodeResult::NeedMore;
    uint8_t version = data[0];
    uint8_t rawType = data[1];
    if (version != kProtocolVersion) return DecodeResult::VersionMismatch;
    if (!isKnownType(rawType)) return DecodeResult::Malformed;

    MessageType type = static_cast<MessageType>(rawType);
    if (isFixedType(type)) {
        if (len < sizeof(InputEvent)) return DecodeResult::NeedMore;
        out.isFixed = true;
        out.type = type;
        std::memcpy(&out.fixed, data, sizeof(InputEvent));
        consumed = sizeof(InputEvent);
        return DecodeResult::Ok;
    }

    // Variable-length message: VarHeader + payload.
    if (len < sizeof(VarHeader)) return DecodeResult::NeedMore;
    VarHeader h;
    std::memcpy(&h, data, sizeof(VarHeader));
    // Reject an implausible/hostile length before it can overflow the size_t add or
    // drive a huge allocation (spec 15: a malformed message rejects cleanly).
    if (h.payload_length > kMaxVarPayload) return DecodeResult::Malformed;
    std::size_t total = sizeof(VarHeader) + static_cast<std::size_t>(h.payload_length);
    if (len < total) return DecodeResult::NeedMore;

    out.isFixed = false;
    out.type = type;
    out.payload.assign(data + sizeof(VarHeader), data + total);
    consumed = total;
    return DecodeResult::Ok;
}

} // namespace sm::net
