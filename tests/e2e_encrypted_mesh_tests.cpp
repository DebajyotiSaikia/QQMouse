#include "test_framework.h"

#include "loopback_transport.h"

#include "app/mesh_node.h"
#include "net/encrypted_transport.h"

#include <array>
#include <memory>
#include <string>
#include <vector>

using namespace sm;
using sm::net::EncryptedTransport;

namespace {

std::array<uint8_t, 32> linkKey(uint8_t seed) {
    std::array<uint8_t, 32> k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed * 31 + i);
    return k;
}

} // namespace

// Runs a full 3-node mesh where EVERY peer link is sealed with the AES-256-GCM
// Transport decorator. Because the decorator is a drop-in Transport, MeshNode is
// unaware of it -- this proves switching, input forwarding and clipboard sync all
// survive the on-the-wire encryption layer end to end.
void run_e2e_encrypted_mesh_tests() {
    smtest::LoopbackPair AB, AC, BC;

    // Distinct key per link (mirrors a per-device-pair PSK); the lexicographically
    // smaller node id is the Initiator, the larger the Responder, so the two ends
    // of each link agree on opposite roles without negotiation.
    std::vector<std::unique_ptr<EncryptedTransport>> keep;
    auto wrap = [&](sm::net::Transport* inner, EncryptedTransport::Role role,
                    uint8_t seed) -> sm::net::Transport* {
        keep.push_back(std::make_unique<EncryptedTransport>(inner, linkKey(seed), role));
        return keep.back().get();
    };

    auto* encAB_a = wrap(&AB.a, EncryptedTransport::Role::Initiator, 1); // A on A-B
    auto* encAB_b = wrap(&AB.b, EncryptedTransport::Role::Responder, 1); // B on A-B
    auto* encAC_a = wrap(&AC.a, EncryptedTransport::Role::Initiator, 2); // A on A-C
    auto* encAC_c = wrap(&AC.b, EncryptedTransport::Role::Responder, 2); // C on A-C
    auto* encBC_b = wrap(&BC.a, EncryptedTransport::Role::Initiator, 3); // B on B-C
    auto* encBC_c = wrap(&BC.b, EncryptedTransport::Role::Responder, 3); // C on B-C

    app::MeshNode A("A"), B("B"), C("C");
    std::vector<core::PeerId> pr = {"A", "B", "C"};
    for (app::MeshNode* n : {&A, &B, &C}) {
        n->setPriority(pr);
        n->heartbeatIntervalMs = 0;
        n->heartbeatTimeoutMs = 1000;
    }
    A.addPeer("B", encAB_a);
    A.addPeer("C", encAC_a);
    B.addPeer("A", encAB_b);
    B.addPeer("C", encBC_b);
    C.addPeer("A", encAC_c);
    C.addPeer("B", encBC_c);

    auto pump = [&](uint64_t now) {
        A.sendHeartbeats(now);
        B.sendHeartbeats(now);
        C.sendHeartbeats(now);
        A.poll(now);
        B.poll(now);
        C.poll(now);
    };

    // Liveness + coordinator election through the encrypted links.
    for (int i = 0; i < 3; ++i) pump(100 + i);
    SM_CHECK(A.isPeerOnline("B"));
    SM_CHECK(A.isPeerOnline("C"));
    SM_CHECK_EQ(A.primary().value_or(""), std::string("A"));
    SM_CHECK_EQ(C.primary().value_or(""), std::string("A"));

    // Switch broadcast reaches every node (sealed on the wire).
    A.requestSwitchTo("B");
    pump(200);
    SM_CHECK(B.isLocalOwner());
    SM_CHECK_EQ(A.owner(), std::string("B"));
    SM_CHECK_EQ(C.owner(), std::string("B"));

    // Owner input forwarded + injected at both sinks, decrypted correctly.
    int aInj = 0, cInj = 0;
    core::InputEvent lastA{};
    A.onInject = [&](const core::InputEvent& e) {
        ++aInj;
        lastA = e;
    };
    C.onInject = [&](const core::InputEvent&) { ++cInj; };
    B.forwardKey(0x42, true, 7);
    pump(210);
    SM_CHECK_EQ(aInj, 1);
    SM_CHECK_EQ(cInj, 1);
    SM_CHECK_EQ(static_cast<int>(lastA.code), 0x42); // payload intact after decrypt
    SM_CHECK_EQ(static_cast<int>(lastA.down), 1);

    // Clipboard sync + loop prevention over the encrypted mesh.
    std::string cClip;
    int cCount = 0;
    C.onRemoteClipboard = [&](const std::string& t) {
        cClip = t;
        ++cCount;
    };
    B.onLocalClipboardChange("encrypted-clip");
    pump(220);
    SM_CHECK_EQ(cClip, std::string("encrypted-clip"));
    SM_CHECK_EQ(cCount, 1);
    C.onLocalClipboardChange("encrypted-clip"); // echo of applied value -> no rebroadcast
    pump(230);
    SM_CHECK_EQ(cCount, 1);
}
