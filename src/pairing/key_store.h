#pragma once

// Per-device pre-shared-key storage, encrypted at rest (spec 7.2). The PSK map is
// serialized and sealed with AES-256-GCM under a machine-local protection key
// (which the app derives from an OS secret and passes in). PURE LOGIC on top of
// the crypto interface -- how the protection key is obtained is a platform detail
// kept out of here so this stays unit-testable.

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "core/peer_id.h"
#include "crypto/crypto.h"

namespace sm::pairing {

using Psk = std::array<uint8_t, 32>;

class KeyStore {
public:
    void setPsk(const sm::core::PeerId& id, const Psk& psk);
    const Psk* getPsk(const sm::core::PeerId& id) const;
    void removePsk(const sm::core::PeerId& id);
    std::vector<sm::core::PeerId> devices() const;
    std::size_t size() const { return psks_.size(); }

    // Sealed blob layout: [nonce:12][tag:16][ciphertext]. protectionKey32 is the
    // 32-byte machine-local key. loadEncrypted returns false on auth failure
    // (wrong key or tampering) and leaves the store unchanged.
    sm::crypto::Bytes serializeEncrypted(const uint8_t* protectionKey32) const;
    bool loadEncrypted(const sm::crypto::Bytes& blob, const uint8_t* protectionKey32);

    bool saveToFile(const std::string& path, const uint8_t* protectionKey32) const;
    bool loadFromFile(const std::string& path, const uint8_t* protectionKey32);

private:
    std::map<sm::core::PeerId, Psk> psks_;
};

} // namespace sm::pairing
