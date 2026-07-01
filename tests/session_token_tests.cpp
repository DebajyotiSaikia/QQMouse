#include "test_framework.h"

#include "net/session_token.h"

using namespace sm::net;

void run_session_token_tests() {
    SessionTokenStore store;

    // Issue a token valid for 5s from t=1000ms.
    SessionToken t = store.issue(/*now*/ 1000, /*ttl*/ 5000);
    SM_CHECK_EQ(t.value.size(), 32u);
    SM_CHECK_EQ(t.expires_ms, static_cast<uint64_t>(6000));

    // Valid before expiry, invalid at/after expiry.
    SM_CHECK(store.validate(t.value, 2000));
    SM_CHECK(store.validate(t.value, 5999));
    SM_CHECK(!store.validate(t.value, 6000));
    SM_CHECK(!store.validate(t.value, 9999));

    // Unknown token never validates.
    sm::crypto::Bytes bogus(32, 0);
    SM_CHECK(!store.validate(bogus, 2000));

    // Two issued tokens differ.
    SessionToken t2 = store.issue(1000, 5000);
    SM_CHECK(t2.value != t.value);
    SM_CHECK_EQ(store.size(), 2u);

    // purgeExpired drops only expired tokens.
    store.purgeExpired(6000); // both expire at 6000 -> removed
    SM_CHECK_EQ(store.size(), 0u);

    SessionToken t3 = store.issue(10000, 1000); // expires 11000
    store.purgeExpired(10500);                   // still valid
    SM_CHECK_EQ(store.size(), 1u);
    SM_CHECK(store.validate(t3.value, 10500));
}
