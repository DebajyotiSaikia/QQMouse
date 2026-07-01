#include "pairing/ecdh_handshake.h"

#include "pairing/verification_code.h"

#include <algorithm>

namespace sm::pairing {

bool EcdhHandshake::begin() {
    return sm::crypto::ecdhGenerateKeyPair(kp_);
}

bool EcdhHandshake::computeShared(const sm::crypto::Bytes& peerPublicPoint) {
    return sm::crypto::ecdhComputeShared(kp_, peerPublicPoint, shared_);
}

std::string EcdhHandshake::verificationCode() const {
    if (!hasShared()) return std::string();
    return sm::pairing::verificationCode(shared_.data(), shared_.size());
}

bool EcdhHandshake::derivePsk(const std::string& idA, const std::string& idB,
                              std::array<uint8_t, 32>& pskOut) const {
    if (!hasShared()) return false;

    // Order-independent salt: "<lo>|<hi>" so both peers agree.
    const std::string& lo = (idA < idB) ? idA : idB;
    const std::string& hi = (idA < idB) ? idB : idA;
    std::string salt = lo + "|" + hi;
    static const char kInfo[] = "skittermouse-psk-v1";

    sm::crypto::Bytes okm = sm::crypto::hkdfSha256(
        shared_.data(), shared_.size(),
        reinterpret_cast<const uint8_t*>(salt.data()), salt.size(),
        reinterpret_cast<const uint8_t*>(kInfo), sizeof(kInfo) - 1,
        pskOut.size());
    if (okm.size() != pskOut.size()) return false;
    std::copy(okm.begin(), okm.end(), pskOut.begin());
    return true;
}

} // namespace sm::pairing
