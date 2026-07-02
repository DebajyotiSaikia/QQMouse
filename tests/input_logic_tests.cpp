#include "test_framework.h"

#include "core/clipboard_sync.h"
#include "core/input_tracker.h"
#include "net/message_codec.h"

#include <string>

using namespace sm::core;

void run_input_logic_tests() {
    // --- InputTracker: stuck-key prevention (spec 4.4) ----------------------
    {
        InputTracker t;
        t.onKey(0xA2, true);  // LCtrl down
        t.onKey(0x41, true);  // 'A' down
        t.onButton(0x01, true); // left button down
        SM_CHECK_EQ(t.downCount(), 3u);
        SM_CHECK(t.isKeyDown(0xA2));
        SM_CHECK(t.isButtonDown(0x01));

        t.onKey(0x41, false); // 'A' up
        SM_CHECK(!t.isKeyDown(0x41));
        SM_CHECK_EQ(t.downCount(), 2u);

        // Double-down is idempotent (set semantics).
        t.onKey(0xA2, true);
        SM_CHECK_EQ(t.downCount(), 2u);

        // Switch-out drains releases for everything still held, then clears.
        auto rel = t.drainReleases();
        SM_CHECK_EQ(rel.size(), 2u);
        SM_CHECK_EQ(t.downCount(), 0u);
        bool sawCtrl = false, sawButton = false;
        for (auto& r : rel) {
            if (!r.isButton && r.code == 0xA2) sawCtrl = true;
            if (r.isButton && r.code == 0x01) sawButton = true;
        }
        SM_CHECK(sawCtrl);
        SM_CHECK(sawButton);

        // Releasing an untracked key is harmless.
        t.onKey(0x99, false);
        SM_CHECK_EQ(t.downCount(), 0u);
    }

    // --- ClipboardSync: loop prevention (spec 8) ----------------------------
    {
        ClipboardSync cs;
        // A genuine local change with no pending remote echo -> broadcast.
        SM_CHECK(cs.shouldBroadcastLocalChange("first"));

        // Applied a remote update; the echoing local change must NOT re-broadcast.
        cs.noteAppliedRemote("from-peer");
        SM_CHECK(!cs.shouldBroadcastLocalChange("from-peer"));
        // ...but only once -- a later identical local copy is a real change.
        SM_CHECK(cs.shouldBroadcastLocalChange("from-peer"));

        // Applied remote, then a different local change -> broadcast (pending cleared).
        cs.noteAppliedRemote("X");
        SM_CHECK(cs.shouldBroadcastLocalChange("Y"));
        SM_CHECK(cs.shouldBroadcastLocalChange("X")); // pending already consumed
    }

    // --- message_codec: fixed InputEvent round-trip -------------------------
    {
        InputEvent e{};
        e.protocol_version = kProtocolVersion;
        e.type = static_cast<uint8_t>(MessageType::MouseMove);
        e.dx = 5;
        e.dy = -3;
        e.code = 0;
        e.down = 0;
        e.timestamp_ms = 123456;

        sm::net::Bytes bytes = sm::net::encodeInputEvent(e);
        SM_CHECK_EQ(bytes.size(), 12u);

        sm::net::DecodedMessage out;
        std::size_t consumed = 0;
        auto r = sm::net::decodeMessage(bytes.data(), bytes.size(), out, consumed);
        SM_CHECK(r == sm::net::DecodeResult::Ok);
        SM_CHECK(out.isFixed);
        SM_CHECK(out.type == MessageType::MouseMove);
        SM_CHECK_EQ(out.fixed.dx, static_cast<int16_t>(5));
        SM_CHECK_EQ(out.fixed.dy, static_cast<int16_t>(-3));
        SM_CHECK_EQ(out.fixed.timestamp_ms, 123456u);
        SM_CHECK_EQ(consumed, 12u);
    }

    // --- message_codec: variable-length message round-trip ------------------
    {
        std::string clip = "clipboard text";
        sm::net::Bytes bytes = sm::net::encodeVarMessage(
            MessageType::ClipboardUpdate,
            reinterpret_cast<const uint8_t*>(clip.data()), clip.size());
        SM_CHECK_EQ(bytes.size(), 6u + clip.size());

        sm::net::DecodedMessage out;
        std::size_t consumed = 0;
        auto r = sm::net::decodeMessage(bytes.data(), bytes.size(), out, consumed);
        SM_CHECK(r == sm::net::DecodeResult::Ok);
        SM_CHECK(!out.isFixed);
        SM_CHECK(out.type == MessageType::ClipboardUpdate);
        SM_CHECK(std::string(out.payload.begin(), out.payload.end()) == clip);
        SM_CHECK_EQ(consumed, 6u + clip.size());
    }

    // --- message_codec: protocol-version mismatch rejected (spec 15) --------
    {
        InputEvent e{};
        e.protocol_version = kProtocolVersion;
        e.type = static_cast<uint8_t>(MessageType::Heartbeat);
        sm::net::Bytes bytes = sm::net::encodeInputEvent(e);
        bytes[0] = 99; // corrupt the version byte

        sm::net::DecodedMessage out;
        std::size_t consumed = 0;
        auto r = sm::net::decodeMessage(bytes.data(), bytes.size(), out, consumed);
        SM_CHECK(r == sm::net::DecodeResult::VersionMismatch);
    }

    // --- message_codec: NeedMore + Malformed --------------------------------
    {
        sm::net::DecodedMessage out;
        std::size_t consumed = 0;
        uint8_t one[1] = {kProtocolVersion};
        SM_CHECK(sm::net::decodeMessage(one, 1, out, consumed) == sm::net::DecodeResult::NeedMore);

        // Fixed type but truncated body.
        uint8_t shortFixed[3] = {kProtocolVersion,
                                 static_cast<uint8_t>(MessageType::KeyEvent), 0};
        SM_CHECK(sm::net::decodeMessage(shortFixed, 3, out, consumed) ==
                 sm::net::DecodeResult::NeedMore);

        // Unknown message type.
        uint8_t badType[2] = {kProtocolVersion, 200};
        SM_CHECK(sm::net::decodeMessage(badType, 2, out, consumed) ==
                 sm::net::DecodeResult::Malformed);

        // Hostile/implausible variable-length header: payload_length = 0xFFFFFFFF must
        // be rejected as Malformed (not trusted into a size_t add or a huge alloc).
        uint8_t hugeLen[6] = {kProtocolVersion,
                              static_cast<uint8_t>(MessageType::ClipboardUpdate),
                              0xFF, 0xFF, 0xFF, 0xFF};
        SM_CHECK(sm::net::decodeMessage(hugeLen, sizeof(hugeLen), out, consumed) ==
                 sm::net::DecodeResult::Malformed);
    }
}
