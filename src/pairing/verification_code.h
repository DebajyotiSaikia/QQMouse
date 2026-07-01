#pragma once

// 6-digit numeric verification code for numeric-comparison pairing (spec 7.1).
//
// code = ( big-endian uint32 of the first 4 bytes of
//          HMAC-SHA256(shared_secret, "pairing"), high bit cleared ) % 1000000,
// zero-padded to 6 digits. Both machines derive it from their ECDH shared secret
// and the human compares them; a MITM lands on different secrets, so the codes
// differ and the user rejects. PURE LOGIC on top of the crypto interface.

#include <cstddef>
#include <cstdint>
#include <string>

namespace sm::pairing {

std::string verificationCode(const uint8_t* shared, std::size_t len);

} // namespace sm::pairing
