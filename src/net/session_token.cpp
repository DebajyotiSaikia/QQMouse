#include "net/session_token.h"

#include <algorithm>

namespace sm::net {

SessionToken SessionTokenStore::issue(uint64_t now_ms, uint64_t ttl_ms, std::size_t nbytes) {
    SessionToken t;
    t.value = sm::crypto::randomBytes(nbytes);
    t.expires_ms = now_ms + ttl_ms;
    tokens_.push_back(t);
    return t;
}

bool SessionTokenStore::validate(const sm::crypto::Bytes& token, uint64_t now_ms) const {
    for (const auto& t : tokens_) {
        if (t.expires_ms > now_ms && t.value.size() == token.size() &&
            std::equal(t.value.begin(), t.value.end(), token.begin())) {
            return true;
        }
    }
    return false;
}

void SessionTokenStore::purgeExpired(uint64_t now_ms) {
    tokens_.erase(std::remove_if(tokens_.begin(), tokens_.end(),
                                 [&](const SessionToken& t) { return t.expires_ms <= now_ms; }),
                  tokens_.end());
}

} // namespace sm::net
