#include "test_framework.h"

#include "loopback_transport.h"

#include "app/connection_manager.h"
#include "app/mesh_node.h"
#include "app/secure_link.h"
#include "net/peer_hello.h"
#include "pairing/key_store.h"

#include <deque>
#include <memory>
#include <string>
#include <vector>

using namespace sm;
using sm::app::InboundHandshake;
using sm::app::secureOutbound;
using sm::app::SecureLink;

namespace {

sm::pairing::Psk makePsk(uint8_t seed) {
    sm::pairing::Psk p{};
    for (std::size_t i = 0; i < p.size(); ++i) p[i] = static_cast<uint8_t>(seed + i * 3);
    return p;
}

std::unique_ptr<smtest::LoopbackEndpoint> endpoint(std::deque<std::vector<uint8_t>>* inbox,
                                                   std::deque<std::vector<uint8_t>>* peerInbox) {
    auto ep = std::make_unique<smtest::LoopbackEndpoint>();
    ep->inbox_ = inbox;
    ep->peerInbox_ = peerInbox;
    ep->connected_ = true;
    return ep;
}

} // namespace

void run_secure_link_tests() {
    // Both machines hold the SAME PSK from pairing, each stored under the other's id.
    const sm::pairing::Psk psk = makePsk(0x40);

    // --- Full path: outbound + inbound seal a link that carries the mesh ---------
    {
        sm::pairing::KeyStore keysA, keysB;
        keysA.setPsk("B", psk); // A paired with B
        keysB.setPsk("A", psk); // B paired with A

        std::deque<std::vector<uint8_t>> aReads, bReads; // aReads: B->A, bReads: A->B
        SecureLink la = secureOutbound(endpoint(&aReads, &bReads), keysA, "A", "B");
        SM_CHECK(la.transport != nullptr);
        SM_CHECK_EQ(la.peerId, std::string("B"));

        InboundHandshake hb(endpoint(&bReads, &aReads), keysB, "B");
        SM_CHECK(hb.poll() == InboundHandshake::Status::Ok); // reads A's clear id-hint
        SecureLink lb = hb.take();
        SM_CHECK_EQ(lb.peerId, std::string("A"));
        SM_CHECK(lb.transport != nullptr);

        // Hand the sealed links to the mesh and drive a real switch through them.
        app::MeshNode meshA("A"), meshB("B");
        std::vector<core::PeerId> pr = {"A", "B"};
        for (app::MeshNode* m : {&meshA, &meshB}) {
            m->setPriority(pr);
            m->heartbeatIntervalMs = 0;
            m->heartbeatTimeoutMs = 1000;
        }
        app::ConnectionManager cmA(meshA), cmB(meshB);
        cmA.addOutgoing("B", std::move(la.transport)); // unique_ptr<EncryptedTransport>
        cmB.addIncoming(std::move(lb.transport));

        cmA.poll(100);
        cmB.poll(100);
        SM_CHECK(cmA.isConnected("B"));
        SM_CHECK(cmB.isConnected("A"));

        for (int i = 1; i < 4; ++i) {
            cmA.poll(100 + i);
            cmB.poll(100 + i);
        }
        SM_CHECK(meshA.isPeerOnline("B"));

        int bInject = 0;
        meshB.onInject = [&](const core::InputEvent&) { ++bInject; };
        meshA.requestSwitchTo("B");
        cmA.poll(200);
        cmB.poll(200);
        SM_CHECK(meshB.isLocalOwner());
        SM_CHECK_EQ(meshA.owner(), std::string("B"));
    }

    // --- Inbound is pending until the id-hint arrives, then seals -------------
    {
        sm::pairing::KeyStore keysB;
        keysB.setPsk("A", psk);
        std::deque<std::vector<uint8_t>> aReads, bReads;
        InboundHandshake hb(endpoint(&bReads, &aReads), keysB, "B");
        SM_CHECK(hb.poll() == InboundHandshake::Status::NeedMore); // nothing yet

        const auto hint = net::encodePeerHello("A");
        bReads.emplace_back(hint.begin(), hint.end());
        SM_CHECK(hb.poll() == InboundHandshake::Status::Ok);
        SM_CHECK_EQ(hb.take().peerId, std::string("A"));
    }

    // --- A connector we never paired with is rejected (NotPaired) ------------
    {
        sm::pairing::KeyStore keysB;
        keysB.setPsk("A", psk); // knows A only
        std::deque<std::vector<uint8_t>> aReads, bReads;
        const auto hint = net::encodePeerHello("STRANGER");
        bReads.emplace_back(hint.begin(), hint.end());
        InboundHandshake hb(endpoint(&bReads, &aReads), keysB, "B");
        SM_CHECK(hb.poll() == InboundHandshake::Status::NotPaired);
    }

    // --- A connector claiming our own id is an error, not a self-link --------
    {
        sm::pairing::KeyStore keysB;
        keysB.setPsk("A", psk);
        std::deque<std::vector<uint8_t>> aReads, bReads;
        const auto hint = net::encodePeerHello("B"); // claims to be us
        bReads.emplace_back(hint.begin(), hint.end());
        InboundHandshake hb(endpoint(&bReads, &aReads), keysB, "B");
        SM_CHECK(hb.poll() == InboundHandshake::Status::Error);
    }

    // --- Outbound to an unpaired peer yields no transport --------------------
    {
        sm::pairing::KeyStore keysA; // empty -- not paired with anyone
        std::deque<std::vector<uint8_t>> aReads, bReads;
        SecureLink la = secureOutbound(endpoint(&aReads, &bReads), keysA, "A", "B");
        SM_CHECK(la.transport == nullptr);
    }

    // --- Wrong PSK on one side -> the sealed hello fails to authenticate ------
    {
        sm::pairing::KeyStore keysA, keysB;
        keysA.setPsk("B", psk);
        keysB.setPsk("A", makePsk(0x99)); // B has a DIFFERENT key for A

        std::deque<std::vector<uint8_t>> aReads, bReads;
        SecureLink la = secureOutbound(endpoint(&aReads, &bReads), keysA, "A", "B");
        InboundHandshake hb(endpoint(&bReads, &aReads), keysB, "B");
        SM_CHECK(hb.poll() == InboundHandshake::Status::Ok); // id-hint still parses
        SecureLink lb = hb.take();

        app::MeshNode meshA("A"), meshB("B");
        std::vector<core::PeerId> pr = {"A", "B"};
        for (app::MeshNode* m : {&meshA, &meshB}) {
            m->setPriority(pr);
            m->heartbeatIntervalMs = 0;
            m->heartbeatTimeoutMs = 1000;
        }
        app::ConnectionManager cmA(meshA), cmB(meshB);
        cmA.addOutgoing("B", std::move(la.transport));
        cmB.addIncoming(std::move(lb.transport));
        for (int i = 0; i < 4; ++i) {
            cmA.poll(100 + i);
            cmB.poll(100 + i);
        }
        // The mismatched PSK means neither encrypted hello authenticates, so no
        // peer is ever registered -- the imposter/garbled link stays unconnected.
        SM_CHECK(!cmA.isConnected("B"));
        SM_CHECK(!cmB.isConnected("A"));
    }
}
