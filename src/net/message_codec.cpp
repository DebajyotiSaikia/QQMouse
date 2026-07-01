#include "net/message_codec.h"

#include <cstring>

namespace sm::net {

using sm::core::InputEvent;
using sm::core::MessageType;
using sm::core::VarHeader;
using sm::core::kProtocolVersion;

namespace {

bool isFixedType(MessageType t) {
    switch (t) {
        case MessageType::MouseMove:
        case MessageType::MouseButton:
        case MessageType::KeyEvent:
        case MessageType::SwitchOwner:
        case MessageType::Heartbeat:
            return true;
        default:
            return false;
    }
}

bool isKnownType(uint8_t t) { return t >= 1 && t <= 9; }

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
    std::size_t total = sizeof(VarHeader) + h.payload_length;
    if (len < total) return DecodeResult::NeedMore;

    out.isFixed = false;
    out.type = type;
    out.payload.assign(data + sizeof(VarHeader), data + total);
    consumed = total;
    return DecodeResult::Ok;
}

} // namespace sm::net
