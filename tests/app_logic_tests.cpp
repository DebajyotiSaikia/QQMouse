#include "test_framework.h"

#include "core/heartbeat.h"
#include "core/input_pipeline.h"
#include "net/message_codec.h"

using namespace sm::core;

namespace {

// Decode a single fixed InputEvent produced by the pipeline.
bool decodeFixed(const std::vector<uint8_t>& bytes, InputEvent& out) {
    sm::net::DecodedMessage m;
    std::size_t consumed = 0;
    auto r = sm::net::decodeMessage(bytes.data(), bytes.size(), m, consumed);
    if (r != sm::net::DecodeResult::Ok || !m.isFixed) return false;
    out = m.fixed;
    return true;
}

} // namespace

void run_app_logic_tests() {
    // --- Heartbeat watchdog / fail-safe (spec 15) ---------------------------
    {
        Heartbeat hb;
        hb.onHeartbeat("owner", 1000);
        SM_CHECK(hb.known("owner"));
        SM_CHECK(hb.isAlive("owner", 1500, 1000));   // 500ms < 1000ms timeout
        SM_CHECK(hb.isAlive("owner", 1999, 1000));
        SM_CHECK(!hb.isAlive("owner", 2000, 1000));  // exactly at timeout -> dead
        SM_CHECK(!hb.isAlive("unknown", 1500, 1000));

        // The owner going silent shows up in timedOut -> caller reverts to local.
        auto dead = hb.timedOut(2001, 1000);
        SM_CHECK_EQ(dead.size(), 1u);
        SM_CHECK_EQ(dead[0], std::string("owner"));

        // A fresh heartbeat clears the timeout.
        hb.onHeartbeat("owner", 2001);
        SM_CHECK(hb.isAlive("owner", 2500, 1000));
        SM_CHECK(hb.timedOut(2500, 1000).empty());

        hb.forget("owner");
        SM_CHECK(!hb.known("owner"));
    }

    // --- InputPipeline: forwarding + stuck-key release (spec 3.1/4.4) -------
    {
        InputPipeline p;

        InputEvent e{};
        SM_CHECK(decodeFixed(p.onKey(0xA2, true, 10), e)); // LCtrl down
        SM_CHECK(e.type == static_cast<uint8_t>(MessageType::KeyEvent));
        SM_CHECK_EQ(e.code, 0xA2);
        SM_CHECK_EQ(e.down, 1);
        SM_CHECK_EQ(e.timestamp_ms, 10u);

        SM_CHECK(decodeFixed(p.onMouseButton(1, true, 11), e)); // left down
        SM_CHECK(e.type == static_cast<uint8_t>(MessageType::MouseButton));
        SM_CHECK_EQ(e.code, 1);
        SM_CHECK_EQ(e.down, 1);

        SM_CHECK(decodeFixed(p.onMouseMove(5, -3, 12), e));
        SM_CHECK(e.type == static_cast<uint8_t>(MessageType::MouseMove));
        SM_CHECK_EQ(e.dx, static_cast<int16_t>(5));
        SM_CHECK_EQ(e.dy, static_cast<int16_t>(-3));

        // Two things are held (LCtrl + left button); a switch-out releases both.
        SM_CHECK_EQ(p.tracker().downCount(), 2u);
        auto rels = p.releaseAll(20);
        SM_CHECK_EQ(rels.size(), 2u);
        for (auto& b : rels) {
            InputEvent re{};
            SM_CHECK(decodeFixed(b, re));
            SM_CHECK_EQ(re.down, 0); // every release is a key/button UP
        }
        SM_CHECK_EQ(p.tracker().downCount(), 0u); // drained

        // Releasing a key normally removes it, so it isn't in a later releaseAll.
        p.onKey(0x41, true, 30);
        p.onKey(0x41, false, 31);
        SM_CHECK_EQ(p.tracker().downCount(), 0u);
        SM_CHECK(p.releaseAll(32).empty());
    }
}
