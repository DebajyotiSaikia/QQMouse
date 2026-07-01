#pragma once

// ECDH-derived pairing handshake (spec 7.1). Wraps the crypto interface to drive
// the numeric-comparison flow: generate an ephemeral P-256 keypair, exchange
// public points, compute the shared secret, show a 6-digit code, and on mutual
// confirm derive the long-term 256-bit PSK via HKDF. PURE LOGIC (crypto behind
// the interface). The ephemeral keys are discarded once the PSK exists.

#include <array>
#include <string>

#include "crypto/crypto.h"

namespace sm::pairing {

class EcdhHandshake {
public:
    // Generate the ephemeral keypair. publicPoint() is sent to the peer.
    bool begin();
    const sm::crypto::Bytes& publicPoint() const { return kp_.publicPoint; }

    // Combine our private key with the peer's 64-byte public point.
    bool computeShared(const sm::crypto::Bytes& peerPublicPoint);
    bool hasShared() const { return shared_.size() == sm::crypto::kSharedLen; }

    // 6-digit code both humans compare (requires hasShared()).
    std::string verificationCode() const;

    // Long-term PSK = HKDF(shared, salt = sorted(idA,idB), info) -> 32 bytes.
    // Sorting the ids makes both machines derive the same key regardless of who
    // initiated. Returns false unless a shared secret exists.
    bool derivePsk(const std::string& idA, const std::string& idB,
                   std::array<uint8_t, 32>& pskOut) const;

private:
    sm::crypto::EcdhKeyPair kp_;
    sm::crypto::Bytes shared_;
};

} // namespace sm::pairing
