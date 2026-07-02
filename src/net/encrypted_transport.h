#pragma once

// AES-256-GCM per-message Transport decorator (spec Section 5.4). Seals every
// message the mesh sends with a strictly-incrementing per-direction nonce counter
// -- never reused -- and rejects tampered or replayed frames on receive. It wraps
// any Transport, so the app layers this over the WSS transport and MeshNode traffic
// is encrypted on the wire without MeshNode knowing anything about it.
//
// Frame written to the inner transport: [nonce:12][tag:16][ciphertext:N].
//
// Nonce = [role:1][0:3][counter:8 big-endian]. The role byte differs between the
// two endpoints (Initiator vs Responder) so, under the shared session key, the two
// directions can never generate the same nonce; the 64-bit counter then guarantees
// per-message uniqueness within a direction. On receive we require the peer's role
// byte and a strictly-increasing counter, which also gives replay/reorder rejection
// (the underlying WSS transport is TCP-reliable and in-order, so a lower-or-equal
// counter can only be a duplicate or an attack).
//
// PURE LOGIC over the Transport + crypto interfaces -- no OS includes here.

#include "crypto/crypto.h"
#include "net/transport.h"

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace sm::net {

class EncryptedTransport : public Transport {
public:
    enum class Role : uint8_t { Initiator = 0, Responder = 1 };

    static constexpr std::size_t kNonceLen = crypto::kGcmNonceLen; // 12
    static constexpr std::size_t kTagLen = crypto::kGcmTagLen;     // 16
    static constexpr std::size_t kOverhead = kNonceLen + kTagLen;  // 28

    // Non-owning: the caller keeps `inner` alive for this decorator's lifetime.
    EncryptedTransport(Transport* inner,
                       const std::array<uint8_t, crypto::kAesKeyLen>& key,
                       Role role)
        : inner_(inner),
          key_(key),
          sendRole_(static_cast<uint8_t>(role)),
          recvRole_(role == Role::Initiator ? uint8_t{1} : uint8_t{0}) {}

    // Owning: takes ownership of `inner`, so a sealed link can carry its own socket
    // (the mesh then holds a single object). Delegates to the non-owning ctor.
    EncryptedTransport(std::unique_ptr<Transport> inner,
                       const std::array<uint8_t, crypto::kAesKeyLen>& key,
                       Role role)
        : EncryptedTransport(inner.get(), key, role) {
        owned_ = std::move(inner);
    }

    bool connect(const std::string& host, uint16_t port) override {
        return inner_ && inner_->connect(host, port);
    }
    bool isConnected() const override { return inner_ && inner_->isConnected(); }
    void close() override {
        if (inner_) inner_->close();
    }

    // Empty messages are not supported: a zero-length payload frames to exactly
    // kOverhead bytes and would decrypt to ptLen 0, which recv() reports as "no
    // message". The mesh never sends empty payloads (every message carries at
    // least a version+type header), so this is a non-issue in practice.
    bool send(const uint8_t* data, std::size_t len) override {
        if (!inner_ || len == 0) return false;

        uint8_t nonce[kNonceLen];
        makeNonce(nonce, sendRole_, sendCtr_);

        frame_.resize(kOverhead + len);
        std::memcpy(frame_.data(), nonce, kNonceLen);
        uint8_t* tag = frame_.data() + kNonceLen;
        uint8_t* ct = frame_.data() + kOverhead;

        if (!crypto::aesGcmEncrypt(key_.data(), nonce, kNonceLen,
                                   nullptr, 0, data, len, ct, tag)) {
            return false;
        }
        // Refuse to wrap the counter -- reusing a nonce under GCM is catastrophic,
        // so fail closed rather than roll over (unreachable in practice).
        if (sendCtr_ == UINT64_MAX) return false;
        ++sendCtr_;
        return inner_->send(frame_.data(), frame_.size());
    }

    int recv(uint8_t* buf, std::size_t cap) override {
        if (!inner_) return -1;
        if (scratch_.size() < cap + kOverhead) scratch_.resize(cap + kOverhead);

        int n = inner_->recv(scratch_.data(), scratch_.size());
        if (n <= 0) return n; // 0 = nothing available, <0 = error/disconnect
        if (static_cast<std::size_t>(n) < kOverhead) return -1;

        const uint8_t* nonce = scratch_.data();
        if (nonce[0] != recvRole_) return -1; // wrong direction / spoofed role
        const uint64_t ctr = readCounter(nonce);
        if (haveRecv_ && ctr <= lastRecvCtr_) return -1; // replay or reorder

        const uint8_t* tag = scratch_.data() + kNonceLen;
        const uint8_t* ct = scratch_.data() + kOverhead;
        const std::size_t ptLen = static_cast<std::size_t>(n) - kOverhead;
        if (ptLen > cap) return -1; // caller's buffer is too small

        if (!crypto::aesGcmDecrypt(key_.data(), nonce, kNonceLen,
                                   nullptr, 0, ct, ptLen, tag, buf)) {
            return -1; // authentication failure -- tampered or wrong key
        }
        haveRecv_ = true;
        lastRecvCtr_ = ctr;
        return static_cast<int>(ptLen);
    }

private:
    static void makeNonce(uint8_t* nonce, uint8_t role, uint64_t ctr) {
        std::memset(nonce, 0, kNonceLen);
        nonce[0] = role;
        for (int i = 0; i < 8; ++i) {
            nonce[kNonceLen - 1 - i] = static_cast<uint8_t>((ctr >> (8 * i)) & 0xFF);
        }
    }
    static uint64_t readCounter(const uint8_t* nonce) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | nonce[kNonceLen - 8 + i];
        }
        return v;
    }

    Transport* inner_;
    std::unique_ptr<Transport> owned_; // non-null only when this decorator owns inner_
    std::array<uint8_t, crypto::kAesKeyLen> key_;
    uint8_t sendRole_;
    uint8_t recvRole_;
    uint64_t sendCtr_ = 0;
    uint64_t lastRecvCtr_ = 0;
    bool haveRecv_ = false;
    std::vector<uint8_t> frame_;
    std::vector<uint8_t> scratch_;
};

// Deterministic per-link role so the two ends agree without negotiation: the peer
// with the lexicographically smaller id is the Initiator (nonce role 0), the other
// the Responder. Guarantees the two directions never share a nonce under one PSK.
inline EncryptedTransport::Role linkRoleFor(const std::string& self,
                                            const std::string& peer) {
    return self < peer ? EncryptedTransport::Role::Initiator
                       : EncryptedTransport::Role::Responder;
}

} // namespace sm::net
