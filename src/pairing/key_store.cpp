#include "pairing/key_store.h"

#include <fstream>
#include <sstream>

namespace sm::pairing {

namespace {

void putU16(sm::crypto::Bytes& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xff));
}
void putU32(sm::crypto::Bytes& b, uint32_t v) {
    b.push_back(static_cast<uint8_t>(v >> 24));
    b.push_back(static_cast<uint8_t>(v >> 16));
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xff));
}
uint16_t getU16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
uint32_t getU32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

} // namespace

void KeyStore::setPsk(const sm::core::PeerId& id, const Psk& psk) { psks_[id] = psk; }

const Psk* KeyStore::getPsk(const sm::core::PeerId& id) const {
    auto it = psks_.find(id);
    return it == psks_.end() ? nullptr : &it->second;
}

void KeyStore::removePsk(const sm::core::PeerId& id) { psks_.erase(id); }

std::vector<sm::core::PeerId> KeyStore::devices() const {
    std::vector<sm::core::PeerId> out;
    out.reserve(psks_.size());
    for (const auto& kv : psks_) out.push_back(kv.first);
    return out;
}

sm::crypto::Bytes KeyStore::serializeEncrypted(const uint8_t* protectionKey32) const {
    // Plaintext: [count:4] then per entry [idlen:2][id][psk:32].
    sm::crypto::Bytes plain;
    putU32(plain, static_cast<uint32_t>(psks_.size()));
    for (const auto& kv : psks_) {
        putU16(plain, static_cast<uint16_t>(kv.first.size()));
        plain.insert(plain.end(), kv.first.begin(), kv.first.end());
        plain.insert(plain.end(), kv.second.begin(), kv.second.end());
    }

    sm::crypto::Bytes nonce = sm::crypto::randomBytes(sm::crypto::kGcmNonceLen);
    sm::crypto::Bytes ct(plain.size());
    uint8_t tag[sm::crypto::kGcmTagLen];
    if (!sm::crypto::aesGcmEncrypt(protectionKey32, nonce.data(), nonce.size(),
                                   nullptr, 0, plain.data(), plain.size(),
                                   ct.data(), tag)) {
        return {};
    }

    sm::crypto::Bytes out;
    out.reserve(nonce.size() + sm::crypto::kGcmTagLen + ct.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), tag, tag + sm::crypto::kGcmTagLen);
    out.insert(out.end(), ct.begin(), ct.end());
    return out;
}

bool KeyStore::loadEncrypted(const sm::crypto::Bytes& blob, const uint8_t* protectionKey32) {
    const std::size_t hdr = sm::crypto::kGcmNonceLen + sm::crypto::kGcmTagLen;
    if (blob.size() < hdr) return false;

    const uint8_t* nonce = blob.data();
    const uint8_t* tag = blob.data() + sm::crypto::kGcmNonceLen;
    const uint8_t* ct = blob.data() + hdr;
    std::size_t ctLen = blob.size() - hdr;

    sm::crypto::Bytes plain(ctLen);
    if (!sm::crypto::aesGcmDecrypt(protectionKey32, nonce, sm::crypto::kGcmNonceLen,
                                   nullptr, 0, ct, ctLen, tag, plain.data())) {
        return false; // wrong key or tampered -- store unchanged
    }

    std::map<sm::core::PeerId, Psk> parsed;
    std::size_t pos = 0;
    if (plain.size() < 4) return false;
    uint32_t count = getU32(plain.data());
    pos = 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (pos + 2 > plain.size()) return false;
        uint16_t idlen = getU16(plain.data() + pos);
        pos += 2;
        if (pos + idlen + 32 > plain.size()) return false;
        sm::core::PeerId id(reinterpret_cast<const char*>(plain.data() + pos), idlen);
        pos += idlen;
        Psk psk{};
        std::copy(plain.data() + pos, plain.data() + pos + 32, psk.begin());
        pos += 32;
        parsed.emplace(std::move(id), psk);
    }
    psks_ = std::move(parsed);
    return true;
}

bool KeyStore::saveToFile(const std::string& path, const uint8_t* protectionKey32) const {
    sm::crypto::Bytes blob = serializeEncrypted(protectionKey32);
    if (blob.empty() && !psks_.empty()) return false;
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(reinterpret_cast<const char*>(blob.data()),
            static_cast<std::streamsize>(blob.size()));
    return static_cast<bool>(f);
}

bool KeyStore::loadFromFile(const std::string& path, const uint8_t* protectionKey32) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    std::string s = ss.str();
    sm::crypto::Bytes blob(s.begin(), s.end());
    return loadEncrypted(blob, protectionKey32);
}

} // namespace sm::pairing
