#include "test_framework.h"

#include "pairing/ecdh_handshake.h"
#include "pairing/key_store.h"
#include "pairing/verification_code.h"

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>

using namespace sm::pairing;

void run_pairing_tests() {
    // --- verification code: KAT + determinism + format ----------------------
    {
        std::array<uint8_t, 32> shared{};
        for (int i = 0; i < 32; ++i) shared[i] = static_cast<uint8_t>(i);
        std::string code = verificationCode(shared.data(), shared.size());
        SM_CHECK_EQ(code, std::string("384102")); // cross-checked with Node HMAC
        SM_CHECK_EQ(code.size(), 6u);
        for (char ch : code) SM_CHECK(ch >= '0' && ch <= '9');
        // Deterministic.
        SM_CHECK_EQ(verificationCode(shared.data(), shared.size()), code);
        // A different secret almost certainly yields a different code.
        shared[0] = 0xff;
        SM_CHECK(verificationCode(shared.data(), shared.size()) != std::string("384102"));
    }

    // --- ECDH handshake: both parties converge on the same code + PSK -------
    {
        EcdhHandshake a, b;
        SM_CHECK(a.begin());
        SM_CHECK(b.begin());
        SM_CHECK(a.computeShared(b.publicPoint()));
        SM_CHECK(b.computeShared(a.publicPoint()));
        SM_CHECK(a.hasShared());
        SM_CHECK(b.hasShared());

        // The whole security property: identical codes on both machines.
        SM_CHECK_EQ(a.verificationCode(), b.verificationCode());
        SM_CHECK_EQ(a.verificationCode().size(), 6u);

        // PSK derivation is order-independent and identical on both sides.
        std::array<uint8_t, 32> pskA{}, pskB{};
        SM_CHECK(a.derivePsk("mac-1", "win-2", pskA));
        SM_CHECK(b.derivePsk("win-2", "mac-1", pskB)); // ids passed in the other order
        SM_CHECK(pskA == pskB);

        // A third party derives a different secret -> different code.
        EcdhHandshake c;
        SM_CHECK(c.begin());
        SM_CHECK(c.computeShared(a.publicPoint()));
        // a<->c share is different from a<->b share, so codes differ (overwhelmingly).
        SM_CHECK(c.verificationCode() != a.verificationCode() ||
                 c.verificationCode().empty());
    }

    // --- KeyStore: set/get/remove + encrypted round-trip + auth failure -----
    {
        KeyStore ks;
        Psk p1{}, p2{};
        for (int i = 0; i < 32; ++i) { p1[i] = static_cast<uint8_t>(i); p2[i] = static_cast<uint8_t>(200 - i); }
        ks.setPsk("dev-A", p1);
        ks.setPsk("dev-B", p2);
        SM_CHECK_EQ(ks.size(), 2u);
        SM_CHECK(ks.getPsk("dev-A") != nullptr);
        SM_CHECK(*ks.getPsk("dev-A") == p1);
        SM_CHECK(ks.getPsk("absent") == nullptr);

        std::array<uint8_t, 32> protKey{};
        for (int i = 0; i < 32; ++i) protKey[i] = static_cast<uint8_t>(0xA0 + i);
        sm::crypto::Bytes blob = ks.serializeEncrypted(protKey.data());
        SM_CHECK(!blob.empty());

        KeyStore loaded;
        SM_CHECK(loaded.loadEncrypted(blob, protKey.data()));
        SM_CHECK_EQ(loaded.size(), 2u);
        SM_CHECK(loaded.getPsk("dev-A") && *loaded.getPsk("dev-A") == p1);
        SM_CHECK(loaded.getPsk("dev-B") && *loaded.getPsk("dev-B") == p2);

        // Wrong protection key must fail authentication and leave store unchanged.
        std::array<uint8_t, 32> wrong = protKey;
        wrong[0] ^= 0x01;
        KeyStore bad;
        bad.setPsk("keep", p1);
        SM_CHECK(!bad.loadEncrypted(blob, wrong.data()));
        SM_CHECK_EQ(bad.size(), 1u); // unchanged

        // Tampered blob is rejected.
        sm::crypto::Bytes tampered = blob;
        tampered[tampered.size() - 1] ^= 0x01;
        KeyStore bad2;
        SM_CHECK(!bad2.loadEncrypted(tampered, protKey.data()));

        // remove.
        ks.removePsk("dev-A");
        SM_CHECK(ks.getPsk("dev-A") == nullptr);
        SM_CHECK_EQ(ks.size(), 1u);

        // File round-trip.
        std::filesystem::path tmp =
            std::filesystem::temp_directory_path() / "skittermouse_keystore_test.bin";
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        KeyStore diskA;
        diskA.setPsk("disk-dev", p2);
        SM_CHECK(diskA.saveToFile(tmp.string(), protKey.data()));
        KeyStore diskB;
        SM_CHECK(diskB.loadFromFile(tmp.string(), protKey.data()));
        SM_CHECK(diskB.getPsk("disk-dev") && *diskB.getPsk("disk-dev") == p2);
        std::filesystem::remove(tmp, ec);
    }
}
