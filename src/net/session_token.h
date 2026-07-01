#pragma once

// Short-lived session token correlating the on-demand file channel to the already
// authenticated input channel (spec 5.2). After the input channel completes the
// PSK handshake it issues a token; when the file channel opens it presents the
// token instead of repeating the full pairing handshake. PURE LOGIC -- the clock
// is injected (now_ms) so this is deterministic and unit-testable.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "crypto/crypto.h"

namespace sm::net {

struct SessionToken {
    sm::crypto::Bytes value;
    uint64_t expires_ms = 0;
};

class SessionTokenStore {
public:
    // Mint a random token valid for ttl_ms from now.
    SessionToken issue(uint64_t now_ms, uint64_t ttl_ms, std::size_t nbytes = 32);

    // True iff the token is known and not yet expired at now_ms.
    bool validate(const sm::crypto::Bytes& token, uint64_t now_ms) const;

    // Drop tokens whose expiry is at or before now_ms.
    void purgeExpired(uint64_t now_ms);

    std::size_t size() const { return tokens_.size(); }

private:
    std::vector<SessionToken> tokens_;
};

} // namespace sm::net
