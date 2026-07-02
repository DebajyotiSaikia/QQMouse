#include "core/input_pipeline.h"

#include "net/message_codec.h"

namespace sm::core {

namespace {

InputPipeline::Bytes make(MessageType type, int16_t dx, int16_t dy,
                          uint8_t code, uint8_t down, uint32_t ts) {
    InputEvent e{};
    e.protocol_version = kProtocolVersion;
    e.type = static_cast<uint8_t>(type);
    e.dx = dx;
    e.dy = dy;
    e.code = code;
    e.down = down;
    e.timestamp_ms = ts;
    return sm::net::encodeInputEvent(e);
}

} // namespace

InputPipeline::Bytes InputPipeline::onMouseMove(int16_t dx, int16_t dy, uint32_t ts) {
    return make(MessageType::MouseMove, dx, dy, 0, 0, ts);
}

InputPipeline::Bytes InputPipeline::onMouseButton(uint8_t button, bool down, uint32_t ts) {
    tracker_.onButton(button, down);
    return make(MessageType::MouseButton, 0, 0, button, down ? 1 : 0, ts);
}

InputPipeline::Bytes InputPipeline::onKey(uint8_t code, bool down, uint32_t ts) {
    tracker_.onKey(code, down);
    return make(MessageType::KeyEvent, 0, 0, code, down ? 1 : 0, ts);
}

std::vector<InputPipeline::Bytes> InputPipeline::releaseAll(uint32_t ts) {
    std::vector<Bytes> out;
    for (const auto& r : tracker_.drainReleases()) {
        out.push_back(make(r.isButton ? MessageType::MouseButton : MessageType::KeyEvent,
                           0, 0, r.code, 0, ts));
    }
    return out;
}

} // namespace sm::core
