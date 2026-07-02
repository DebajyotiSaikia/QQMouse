#include "test_framework.h"

#include "loopback_transport.h"

#include "core/clipboard_sync.h"
#include "core/heartbeat.h"
#include "core/input_pipeline.h"
#include "core/ownership_state.h"
#include "net/message_codec.h"
#include "net/session_token.h"
#include "pairing/ecdh_handshake.h"

#include <array>
#include <string>
#include <vector>

using namespace sm;

namespace {

std::vector<uint8_t> recvMsg(net::Transport& t) {
    uint8_t buf[8192];
    int n = t.recv(buf, sizeof(buf));
    if (n <= 0) return {};
    return std::vector<uint8_t>(buf, buf + n);
}

// Minimal ownership-claim wire encoding for the e2e (target|origin|seq).
std::vector<uint8_t> encodeClaim(const core::OwnershipClaim& c) {
    std::vector<uint8_t> b;
    auto ps = [&](const std::string& s) {
        b.push_back(static_cast<uint8_t>(s.size()));
        b.insert(b.end(), s.begin(), s.end());
    };
    ps(c.target);
    ps(c.origin);
    for (int i = 7; i >= 0; --i) b.push_back(static_cast<uint8_t>((c.sequence >> (8 * i)) & 0xff));
    return b;
}

core::OwnershipClaim decodeClaim(const std::vector<uint8_t>& b) {
    core::OwnershipClaim c;
    std::size_t p = 0;
    auto gs = [&](std::string& s) {
        uint8_t n = b[p++];
        s.assign(reinterpret_cast<const char*>(&b[p]), n);
        p += n;
    };
    gs(c.target);
    gs(c.origin);
    c.sequence = 0;
    for (int i = 0; i < 8; ++i) c.sequence = (c.sequence << 8) | b[p++];
    return c;
}

} // namespace

void run_e2e_flow_tests() {
    smtest::LoopbackPair link;
    net::Transport& A = link.a;
    net::Transport& B = link.b;

    // === 1. Pairing over the wire: both sides converge on the same code + PSK ===
    {
        pairing::EcdhHandshake ha, hb;
        SM_CHECK(ha.begin());
        SM_CHECK(hb.begin());
        A.send(ha.publicPoint().data(), ha.publicPoint().size());
        B.send(hb.publicPoint().data(), hb.publicPoint().size());
        auto pubFromA = recvMsg(B);
        auto pubFromB = recvMsg(A);
        SM_CHECK(ha.computeShared(pubFromB));
        SM_CHECK(hb.computeShared(pubFromA));
        SM_CHECK_EQ(ha.verificationCode(), hb.verificationCode()); // the security property

        std::array<uint8_t, 32> pskA{}, pskB{};
        SM_CHECK(ha.derivePsk("A", "B", pskA));
        SM_CHECK(hb.derivePsk("A", "B", pskB));
        SM_CHECK(pskA == pskB);
    }

    // === 2. Session token issued, carried over the wire, validated =============
    {
        net::SessionTokenStore sts;
        auto tok = sts.issue(1000, 5000);
        A.send(tok.value.data(), tok.value.size());
        auto back = recvMsg(B); // file channel would present this token
        SM_CHECK(sts.validate(back, 2000));
        SM_CHECK(!sts.validate(back, 9000)); // expired
    }

    // === 3. Input forwarding owner->sink + stuck-key release on switch-out =====
    {
        core::InputPipeline pipe;
        auto m1 = pipe.onMouseMove(3, 4, 1);
        auto m2 = pipe.onKey(0x41, true, 2);
        auto m3 = pipe.onMouseButton(1, true, 3);
        A.send(m1.data(), m1.size());
        A.send(m2.data(), m2.size());
        A.send(m3.data(), m3.size());

        int count = 0, downs = 0;
        for (;;) {
            auto msg = recvMsg(B);
            if (msg.empty()) break;
            net::DecodedMessage dm;
            std::size_t c = 0;
            SM_CHECK(net::decodeMessage(msg.data(), msg.size(), dm, c) == net::DecodeResult::Ok);
            SM_CHECK(dm.isFixed);
            ++count;
            if (dm.fixed.down) ++downs;
        }
        SM_CHECK_EQ(count, 3);
        SM_CHECK_EQ(downs, 2); // key down + button down

        // Switch-out: releases for the still-held key + button arrive at the sink.
        SM_CHECK_EQ(pipe.tracker().downCount(), 2u);
        for (auto& rb : pipe.releaseAll(9)) A.send(rb.data(), rb.size());
        int releases = 0;
        for (;;) {
            auto msg = recvMsg(B);
            if (msg.empty()) break;
            net::DecodedMessage dm;
            std::size_t c = 0;
            net::decodeMessage(msg.data(), msg.size(), dm, c);
            if (dm.isFixed && dm.fixed.down == 0) ++releases;
        }
        SM_CHECK_EQ(releases, 2);
        SM_CHECK_EQ(pipe.tracker().downCount(), 0u);
    }

    // === 4. Ownership switch broadcast: both machines agree on the new owner ===
    {
        core::OwnershipState osA("A"), osB("B");
        auto claim = osA.requestSwitchTo("B"); // applied locally on A
        auto enc = encodeClaim(claim);
        A.send(enc.data(), enc.size());
        auto got = recvMsg(B);
        osB.applyClaim(decodeClaim(got));
        SM_CHECK(osB.owner() == std::string("B"));
        SM_CHECK(osB.isLocalOwner());
        SM_CHECK(osA.owner() == std::string("B"));
        SM_CHECK(!osA.isLocalOwner());
    }

    // === 5. Clipboard sync across two nodes without a ping-pong loop ===========
    {
        core::ClipboardSync csA, csB;
        SM_CHECK(csA.shouldBroadcastLocalChange("hello")); // genuine local change
        auto cu = net::encodeVarMessage(core::MessageType::ClipboardUpdate,
                                        reinterpret_cast<const uint8_t*>("hello"), 5);
        A.send(cu.data(), cu.size());
        auto rm = recvMsg(B);
        net::DecodedMessage dm;
        std::size_t c = 0;
        SM_CHECK(net::decodeMessage(rm.data(), rm.size(), dm, c) == net::DecodeResult::Ok);
        std::string text(dm.payload.begin(), dm.payload.end());
        SM_CHECK_EQ(text, std::string("hello"));
        csB.noteAppliedRemote(text);                          // B writes it locally...
        SM_CHECK(!csB.shouldBroadcastLocalChange(text));      // ...and does NOT echo it back
    }

    // === 6. Heartbeat fail-safe: silent owner -> sink reverts to local =========
    {
        core::Heartbeat hb;
        hb.onHeartbeat("A", 1000); // B is the sink, A the owner sending heartbeats
        SM_CHECK(hb.isAlive("A", 1500, 1000));

        core::OwnershipState fb("B");
        fb.applyClaim(core::OwnershipClaim{"A", "A", 5}); // owner is A
        SM_CHECK(!fb.isLocalOwner());

        // A goes silent; at 2001ms with a 1000ms timeout it is declared dead.
        if (!hb.isAlive("A", 2001, 1000)) fb.requestSwitchTo("B"); // revert to local
        SM_CHECK(fb.isLocalOwner());
    }

    // === 7. Protocol-version mismatch is rejected cleanly (spec 15) ============
    {
        core::InputEvent bad{};
        bad.protocol_version = 99;
        bad.type = static_cast<uint8_t>(core::MessageType::Heartbeat);
        auto bb = net::encodeInputEvent(bad);
        A.send(bb.data(), bb.size());
        auto bm = recvMsg(B);
        net::DecodedMessage dm;
        std::size_t c = 0;
        SM_CHECK(net::decodeMessage(bm.data(), bm.size(), dm, c) ==
                 net::DecodeResult::VersionMismatch);
    }
}
