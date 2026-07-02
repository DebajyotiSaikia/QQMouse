#include "test_framework.h"

#include "loopback_transport.h"

#include "app/mesh_node.h"
#include "net/ownership_codec.h"

#include <string>
#include <vector>

using namespace sm;

void run_e2e_meshnode_tests() {
    // --- Ownership claim codec round-trip ------------------------------------
    {
        core::OwnershipClaim c{"target-machine", "origin-machine", 42};
        auto enc = net::encodeOwnershipClaim(c);
        core::OwnershipClaim d;
        SM_CHECK(net::decodeOwnershipClaim(enc.data(), enc.size(), d));
        SM_CHECK_EQ(d.target, c.target);
        SM_CHECK_EQ(d.origin, c.origin);
        SM_CHECK_EQ(d.sequence, c.sequence);
    }

    // Three fully-connected nodes over loopback pairs (A-B, A-C, B-C).
    smtest::LoopbackPair AB, AC, BC;
    app::MeshNode A("A"), B("B"), C("C");
    std::vector<core::PeerId> pr = {"A", "B", "C"};
    for (app::MeshNode* n : {&A, &B, &C}) {
        n->setPriority(pr);
        n->heartbeatIntervalMs = 0;   // force a heartbeat on every pump
        n->heartbeatTimeoutMs = 1000;
    }
    A.addPeer("B", &AB.a);
    A.addPeer("C", &AC.a);
    B.addPeer("A", &AB.b);
    B.addPeer("C", &BC.a);
    C.addPeer("A", &AC.b);
    C.addPeer("B", &BC.b);

    auto pump = [&](uint64_t now, bool aOn, bool bOn, bool cOn) {
        if (aOn) A.sendHeartbeats(now);
        if (bOn) B.sendHeartbeats(now);
        if (cOn) C.sendHeartbeats(now);
        A.poll(now);
        B.poll(now);
        C.poll(now);
    };

    // --- Liveness + coordinator election (spec 11.5) ------------------------
    for (int i = 0; i < 3; ++i) pump(100 + i, true, true, true);
    SM_CHECK(A.isPeerOnline("B"));
    SM_CHECK(A.isPeerOnline("C"));
    SM_CHECK_EQ(A.primary().value_or(""), std::string("A"));
    SM_CHECK_EQ(B.primary().value_or(""), std::string("A"));
    SM_CHECK_EQ(C.primary().value_or(""), std::string("A"));

    // --- Switch broadcasts to ALL peers (spec 11.2) -------------------------
    A.requestSwitchTo("B");
    pump(200, true, true, true);
    SM_CHECK_EQ(A.owner(), std::string("B"));
    SM_CHECK(!A.isLocalOwner());
    SM_CHECK(B.isLocalOwner());
    SM_CHECK_EQ(C.owner(), std::string("B")); // the third machine is NOT left stale

    // --- Owner forwards input; every sink injects (spec 3.2) ----------------
    int aInj = 0, cInj = 0;
    A.onInject = [&](const core::InputEvent&) { ++aInj; };
    C.onInject = [&](const core::InputEvent&) { ++cInj; };
    B.forwardKey(0x41, true, 1); // B is owner
    pump(210, true, true, true);
    SM_CHECK_EQ(aInj, 1);
    SM_CHECK_EQ(cInj, 1);

    // --- Clipboard sync + loop prevention across the mesh (spec 8) ----------
    std::string aClip, cClip;
    int cClipCount = 0;
    A.onRemoteClipboard = [&](const std::string& t) { aClip = t; };
    C.onRemoteClipboard = [&](const std::string& t) { cClip = t; ++cClipCount; };
    B.onLocalClipboardChange("hello");
    pump(220, true, true, true);
    SM_CHECK_EQ(aClip, std::string("hello"));
    SM_CHECK_EQ(cClip, std::string("hello"));
    SM_CHECK_EQ(cClipCount, 1);
    // A's OS re-fires a change for the value it just applied -> must NOT rebroadcast.
    A.onLocalClipboardChange("hello");
    pump(230, true, true, true);
    SM_CHECK_EQ(cClipCount, 1); // no second copy reached C

    // --- Coordinator failover + failback (spec 11.5) ------------------------
    for (int i = 0; i < 4; ++i) pump(2000 + i, false, true, true); // A goes silent
    SM_CHECK(!B.isPeerOnline("A"));
    SM_CHECK_EQ(B.primary().value_or(""), std::string("B"));
    SM_CHECK_EQ(C.primary().value_or(""), std::string("B"));
    for (int i = 0; i < 4; ++i) pump(3000 + i, true, true, true); // A returns
    SM_CHECK_EQ(B.primary().value_or(""), std::string("A")); // preemptive failback

    // --- Fail-safe: silent owner -> every sink reverts to local (spec 15) ---
    A.requestSwitchTo("A"); // owner = A
    pump(4000, true, true, true);
    SM_CHECK_EQ(B.owner(), std::string("A"));
    SM_CHECK(!B.isLocalOwner());
    for (int i = 0; i < 4; ++i) pump(5000 + i, false, true, true); // A dies
    SM_CHECK(B.isLocalOwner()); // B took back its own input
    SM_CHECK(C.isLocalOwner()); // C too

    // --- One-time online/offline transitions + switch-to-unreachable (spec 15) --
    {
        smtest::LoopbackPair XY;
        app::MeshNode X("X"), Y("Y");
        std::vector<core::PeerId> pr2 = {"X", "Y"};
        for (app::MeshNode* n : {&X, &Y}) {
            n->setPriority(pr2);
            n->heartbeatIntervalMs = 0;
            n->heartbeatTimeoutMs = 1000;
        }
        X.addPeer("Y", &XY.a);
        Y.addPeer("X", &XY.b);

        int onlineEvents = 0, offlineEvents = 0;
        core::PeerId lastOnline, lastOffline;
        X.onPeerOnline = [&](const core::PeerId& id) {
            ++onlineEvents;
            lastOnline = id;
        };
        X.onPeerOffline = [&](const core::PeerId& id) {
            ++offlineEvents;
            lastOffline = id;
        };

        auto pump2 = [&](uint64_t now, bool xOn, bool yOn) {
            if (xOn) X.sendHeartbeats(now);
            if (yOn) Y.sendHeartbeats(now);
            X.poll(now);
            Y.poll(now);
        };

        // Y comes online -> exactly one onPeerOnline(Y), no repeats while it stays up.
        for (int i = 0; i < 4; ++i) pump2(100 + i, true, true);
        SM_CHECK_EQ(onlineEvents, 1);
        SM_CHECK_EQ(lastOnline, std::string("Y"));
        SM_CHECK_EQ(offlineEvents, 0);

        // Y drops (stops sending) -> exactly one onPeerOffline(Y), not repeating.
        for (int i = 0; i < 5; ++i) pump2(2000 + i, true, false);
        SM_CHECK_EQ(offlineEvents, 1);
        SM_CHECK_EQ(lastOffline, std::string("Y"));

        // Switching to the now-unreachable Y is a no-op that flashes "unavailable".
        int unavail = 0;
        core::PeerId unavailTarget;
        X.onSwitchUnavailable = [&](const core::PeerId& id) {
            ++unavail;
            unavailTarget = id;
        };
        X.requestSwitchTo("Y");
        SM_CHECK_EQ(unavail, 1);
        SM_CHECK_EQ(unavailTarget, std::string("Y"));
        SM_CHECK(X.isLocalOwner()); // ownership never handed to a dead peer
    }

    // --- Protocol-version mismatch surfaced once per peer (spec 15) -----------
    {
        smtest::LoopbackPair P;
        app::MeshNode N("N");
        N.addPeer("Z", &P.a); // N reads P.a; the "peer" writes via P.b

        int warns = 0;
        core::PeerId who;
        N.onVersionMismatch = [&](const core::PeerId& id) {
            ++warns;
            who = id;
        };

        // A 12-byte fixed message carrying a bad protocol_version byte.
        uint8_t bad[12] = {};
        bad[0] = 99; // wrong version
        bad[1] = 1;  // MouseMove
        P.b.send(bad, sizeof(bad));
        N.poll(100);
        SM_CHECK_EQ(warns, 1);
        SM_CHECK_EQ(who, std::string("Z"));

        // A second mismatched message does NOT re-warn (throttled per peer).
        P.b.send(bad, sizeof(bad));
        N.poll(101);
        SM_CHECK_EQ(warns, 1);
    }
}
