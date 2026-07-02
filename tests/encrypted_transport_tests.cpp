#include "test_framework.h"

#include "net/encrypted_transport.h"

#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace {

using sm::net::EncryptedTransport;
using Role = sm::net::EncryptedTransport::Role;

// A transport whose wire is two externally-owned queues, so a test can inspect and
// tamper with the exact bytes that crossed the "network".
struct WireTap : sm::net::Transport {
    std::deque<std::vector<uint8_t>>* out = nullptr; // send() appends here
    std::deque<std::vector<uint8_t>>* in = nullptr;  // recv() pops from here
    bool connected = true;

    bool connect(const std::string&, uint16_t) override {
        connected = true;
        return true;
    }
    bool isConnected() const override { return connected; }
    bool send(const uint8_t* d, std::size_t n) override {
        if (!out) return false;
        out->emplace_back(d, d + n);
        return true;
    }
    int recv(uint8_t* b, std::size_t cap) override {
        if (!in || in->empty()) return 0;
        std::vector<uint8_t>& m = in->front();
        std::size_t k = m.size() <= cap ? m.size() : cap;
        std::memcpy(b, m.data(), k);
        in->pop_front();
        return static_cast<int>(k);
    }
    void close() override { connected = false; }
};

std::array<uint8_t, 32> testKey(uint8_t seed) {
    std::array<uint8_t, 32> k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed + i);
    return k;
}

std::vector<uint8_t> bytesOf(const char* s) {
    return std::vector<uint8_t>(s, s + std::strlen(s));
}

} // namespace

void run_encrypted_transport_tests() {
    const auto key = testKey(0x11);

    // --- Round-trip both directions ------------------------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba; // a->b and b->a
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;

        EncryptedTransport a(&ta, key, Role::Initiator);
        EncryptedTransport b(&tb, key, Role::Responder);

        auto msg = bytesOf("hello mesh");
        SM_CHECK(a.send(msg.data(), msg.size()));

        uint8_t buf[256];
        int n = b.recv(buf, sizeof(buf));
        SM_CHECK_EQ(static_cast<int>(msg.size()), n);
        SM_CHECK(std::memcmp(buf, msg.data(), msg.size()) == 0);

        // The bytes on the wire are NOT the plaintext (encryption happened) and
        // include the 28-byte nonce+tag overhead.
        SM_CHECK(ab.empty());
        auto reply = bytesOf("ack from responder");
        SM_CHECK(b.send(reply.data(), reply.size()));
        SM_CHECK_EQ(static_cast<int>(reply.size() + EncryptedTransport::kOverhead),
                    static_cast<int>(ba.front().size()));
        SM_CHECK(std::memcmp(ba.front().data() + EncryptedTransport::kOverhead,
                             reply.data(), reply.size()) != 0);

        n = a.recv(buf, sizeof(buf));
        SM_CHECK_EQ(static_cast<int>(reply.size()), n);
        SM_CHECK(std::memcmp(buf, reply.data(), reply.size()) == 0);
    }

    // --- recv() reports "nothing available" as 0 -----------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap tb;
        tb.in = &ab;
        tb.out = &ba;
        EncryptedTransport b(&tb, key, Role::Responder);
        uint8_t buf[64];
        SM_CHECK_EQ(0, b.recv(buf, sizeof(buf)));
    }

    // --- Nonce increments: identical plaintext -> different ciphertext --------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        EncryptedTransport a(&ta, key, Role::Initiator);

        auto msg = bytesOf("same");
        SM_CHECK(a.send(msg.data(), msg.size()));
        SM_CHECK(a.send(msg.data(), msg.size()));
        SM_CHECK_EQ(2u, static_cast<unsigned>(ab.size()));
        // Same length, but different bytes because the nonce (and thus keystream
        // and tag) changed between the two sends.
        SM_CHECK_EQ(static_cast<int>(ab[0].size()), static_cast<int>(ab[1].size()));
        SM_CHECK(ab[0] != ab[1]);
        // Nonce counter byte advanced 0 -> 1 (last byte of the 12-byte nonce).
        SM_CHECK_EQ(0, static_cast<int>(ab[0][EncryptedTransport::kNonceLen - 1]));
        SM_CHECK_EQ(1, static_cast<int>(ab[1][EncryptedTransport::kNonceLen - 1]));
        // Role byte is the Initiator's (0) on both.
        SM_CHECK_EQ(0, static_cast<int>(ab[0][0]));
    }

    // --- Tampered ciphertext is rejected -------------------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;
        EncryptedTransport a(&ta, key, Role::Initiator);
        EncryptedTransport b(&tb, key, Role::Responder);

        auto msg = bytesOf("secret payload");
        SM_CHECK(a.send(msg.data(), msg.size()));
        // Flip a ciphertext byte (just past nonce+tag).
        ab.front()[EncryptedTransport::kOverhead] ^= 0x01;
        uint8_t buf[256];
        SM_CHECK_EQ(-1, b.recv(buf, sizeof(buf)));
    }

    // --- Tampered tag is rejected --------------------------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;
        EncryptedTransport a(&ta, key, Role::Initiator);
        EncryptedTransport b(&tb, key, Role::Responder);

        auto msg = bytesOf("tag check");
        SM_CHECK(a.send(msg.data(), msg.size()));
        ab.front()[EncryptedTransport::kNonceLen] ^= 0x80; // first tag byte
        uint8_t buf[256];
        SM_CHECK_EQ(-1, b.recv(buf, sizeof(buf)));
    }

    // --- Wrong key is rejected (auth failure) --------------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;
        EncryptedTransport a(&ta, key, Role::Initiator);
        EncryptedTransport b(&tb, testKey(0x99), Role::Responder); // different key

        auto msg = bytesOf("mismatch");
        SM_CHECK(a.send(msg.data(), msg.size()));
        uint8_t buf[256];
        SM_CHECK_EQ(-1, b.recv(buf, sizeof(buf)));
    }

    // --- Replay is rejected (same frame delivered twice) ---------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;
        EncryptedTransport a(&ta, key, Role::Initiator);
        EncryptedTransport b(&tb, key, Role::Responder);

        auto msg = bytesOf("once only");
        SM_CHECK(a.send(msg.data(), msg.size()));
        std::vector<uint8_t> captured = ab.front();
        uint8_t buf[256];
        SM_CHECK(b.recv(buf, sizeof(buf)) > 0); // first delivery accepted
        ab.push_back(captured);                 // replay the exact same frame
        SM_CHECK_EQ(-1, b.recv(buf, sizeof(buf)));
    }

    // --- Out-of-order / older counter is rejected ----------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;
        EncryptedTransport a(&ta, key, Role::Initiator);
        EncryptedTransport b(&tb, key, Role::Responder);

        auto m0 = bytesOf("frame0");
        auto m1 = bytesOf("frame1");
        SM_CHECK(a.send(m0.data(), m0.size())); // counter 0
        SM_CHECK(a.send(m1.data(), m1.size())); // counter 1
        std::vector<uint8_t> f0 = ab[0];
        std::vector<uint8_t> f1 = ab[1];
        ab.clear();
        // Deliver the newer frame first, then the older one.
        ab.push_back(f1);
        ab.push_back(f0);
        uint8_t buf[256];
        SM_CHECK(b.recv(buf, sizeof(buf)) > 0);  // f1 (counter 1) accepted
        SM_CHECK_EQ(-1, b.recv(buf, sizeof(buf))); // f0 (counter 0) rejected
    }

    // --- Wrong-direction role byte is rejected -------------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;
        EncryptedTransport a(&ta, key, Role::Initiator);
        // Second receiver is ALSO an Initiator, so it expects the peer role to be
        // Responder(1); the frame carries Initiator(0) and must be rejected before
        // decryption even considers it.
        EncryptedTransport bWrong(&tb, key, Role::Initiator);

        auto msg = bytesOf("dir");
        SM_CHECK(a.send(msg.data(), msg.size()));
        uint8_t buf[256];
        SM_CHECK_EQ(-1, bWrong.recv(buf, sizeof(buf)));
    }

    // --- Short frame (< overhead) is rejected, not misparsed ------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap tb;
        tb.in = &ab;
        tb.out = &ba;
        EncryptedTransport b(&tb, key, Role::Responder);
        ab.push_back(std::vector<uint8_t>(10, 0)); // 10 < 28
        uint8_t buf[64];
        SM_CHECK_EQ(-1, b.recv(buf, sizeof(buf)));
    }

    // --- connect / isConnected / close delegate to the inner transport --------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        ta.connected = false;
        EncryptedTransport a(&ta, key, Role::Initiator);
        SM_CHECK(!a.isConnected());
        SM_CHECK(a.connect("host", 1234));
        SM_CHECK(a.isConnected());
        a.close();
        SM_CHECK(!a.isConnected());
    }

    // --- Empty payload refused (see header note) ------------------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        EncryptedTransport a(&ta, key, Role::Initiator);
        SM_CHECK(!a.send(nullptr, 0));
        SM_CHECK(ab.empty());
    }

    // --- Long payload survives round-trip (multi-block GCM) -------------------
    {
        std::deque<std::vector<uint8_t>> ab, ba;
        WireTap ta;
        ta.out = &ab;
        ta.in = &ba;
        WireTap tb;
        tb.out = &ba;
        tb.in = &ab;
        EncryptedTransport a(&ta, key, Role::Initiator);
        EncryptedTransport b(&tb, key, Role::Responder);

        std::vector<uint8_t> big(4096);
        for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i * 7 + 3);
        SM_CHECK(a.send(big.data(), big.size()));
        std::vector<uint8_t> buf(8192);
        int n = b.recv(buf.data(), buf.size());
        SM_CHECK_EQ(static_cast<int>(big.size()), n);
        SM_CHECK(std::memcmp(buf.data(), big.data(), big.size()) == 0);
    }

    // --- Owning constructor: the decorator keeps its inner transport alive -----
    {
        auto qab = std::make_shared<std::deque<std::vector<uint8_t>>>();
        auto qba = std::make_shared<std::deque<std::vector<uint8_t>>>();
        auto ownedA = std::make_unique<WireTap>();
        ownedA->out = qab.get();
        ownedA->in = qba.get();
        auto ownedB = std::make_unique<WireTap>();
        ownedB->out = qba.get();
        ownedB->in = qab.get();

        // Move the inner transports in; `a`/`b` now own them.
        EncryptedTransport a(std::move(ownedA), key, Role::Initiator);
        EncryptedTransport b(std::move(ownedB), key, Role::Responder);

        auto msg = bytesOf("owned round trip");
        SM_CHECK(a.send(msg.data(), msg.size()));
        uint8_t buf[128];
        int n = b.recv(buf, sizeof(buf));
        SM_CHECK_EQ(static_cast<int>(msg.size()), n);
        SM_CHECK(std::memcmp(buf, msg.data(), msg.size()) == 0);
    }
}
