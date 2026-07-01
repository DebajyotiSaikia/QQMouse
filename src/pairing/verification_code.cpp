#include "pairing/verification_code.h"

#include "crypto/crypto.h"

#include <cstdio>

namespace sm::pairing {

std::string verificationCode(const uint8_t* shared, std::size_t len) {
    static const char kContext[] = "pairing";
    sm::crypto::Hash256 mac = sm::crypto::hmacSha256(
        shared, len, reinterpret_cast<const uint8_t*>(kContext), sizeof(kContext) - 1);

    uint32_t v = (static_cast<uint32_t>(mac[0]) << 24) |
                 (static_cast<uint32_t>(mac[1]) << 16) |
                 (static_cast<uint32_t>(mac[2]) << 8) |
                 static_cast<uint32_t>(mac[3]);
    v &= 0x7fffffffu; // clear high bit so the value is layout/sign-stable
    uint32_t code = v % 1000000u;

    char buf[7];
    std::snprintf(buf, sizeof(buf), "%06u", code);
    return std::string(buf);
}

} // namespace sm::pairing
