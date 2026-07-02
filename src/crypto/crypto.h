#pragma once

// Native crypto interface (spec Sections 5.4, 7). PURE DECLARATIONS -- the
// implementation is per-OS (platform/crypto_win.cpp via CNG/BCrypt;
// platform/crypto_mac.mm via CommonCrypto + Security.framework). No third-party
// crypto library (Section 16).
//
// Wire formats are chosen to be identical across both backends so a Windows
// machine and a Mac can pair (Section 7.1):
//   - ECDH is NIST P-256; public keys travel as the raw 64-byte X||Y point
//     (big-endian), the shared secret is the 32-byte big-endian X coordinate.
//   - AES-256-GCM uses a 32-byte key, 12-byte nonce, 16-byte tag.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sm::crypto {

using Bytes = std::vector<uint8_t>;
using Hash256 = std::array<uint8_t, 32>;
using Hash160 = std::array<uint8_t, 20>;

inline constexpr size_t kAesKeyLen = 32;   // AES-256
inline constexpr size_t kGcmNonceLen = 12; // 96-bit GCM nonce
inline constexpr size_t kGcmTagLen = 16;   // 128-bit GCM tag
inline constexpr size_t kEcPointLen = 64;  // P-256 X||Y, big-endian
inline constexpr size_t kSharedLen = 32;   // P-256 shared X, big-endian

// Wipe sensitive bytes so decrypted keys/PSKs don't linger in freed memory. The
// volatile writes are not elided by the optimizer (unlike a plain memset that the
// compiler may drop when the buffer is about to die). Portable, header-only.
inline void secureZero(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}

// --- Randomness --------------------------------------------------------------
bool randomBytes(uint8_t* buf, size_t len);
Bytes randomBytes(size_t len);

// --- Hashing / MAC / KDF -----------------------------------------------------
Hash256 sha256(const uint8_t* data, size_t len);
Hash160 sha1(const uint8_t* data, size_t len); // for the WebSocket accept key
Hash256 hmacSha256(const uint8_t* key, size_t keyLen,
                   const uint8_t* data, size_t dataLen);

// Standard base64 (RFC 4648) encode. Portable (crypto/base64.cpp).
std::string base64Encode(const uint8_t* data, size_t len);

// HKDF-SHA256 (RFC 5869). Portable: implemented in crypto/hkdf.cpp on top of
// hmacSha256(). okmLen must be <= 255*32.
Bytes hkdfSha256(const uint8_t* ikm, size_t ikmLen,
                 const uint8_t* salt, size_t saltLen,
                 const uint8_t* info, size_t infoLen,
                 size_t okmLen);

// --- AES-256-GCM -------------------------------------------------------------
// Encrypt writes ctLen==ptLen ciphertext bytes and a 16-byte tag. Nonce must be
// a strictly-incrementing per-session counter, never reused (Section 5.4).
bool aesGcmEncrypt(const uint8_t* key32, const uint8_t* nonce, size_t nonceLen,
                   const uint8_t* aad, size_t aadLen,
                   const uint8_t* plaintext, size_t ptLen,
                   uint8_t* ciphertext, uint8_t* tag16);

// Decrypt returns false (and writes nothing meaningful) on authentication
// failure -- a tampered ciphertext/tag/aad/nonce must be rejected.
bool aesGcmDecrypt(const uint8_t* key32, const uint8_t* nonce, size_t nonceLen,
                   const uint8_t* aad, size_t aadLen,
                   const uint8_t* ciphertext, size_t ctLen,
                   const uint8_t* tag16, uint8_t* plaintext);

// --- ECDH P-256 --------------------------------------------------------------
struct EcdhKeyPair {
    Bytes publicPoint; // 64 bytes: X||Y, big-endian (goes on the wire)
    Bytes privateBlob; // opaque, backend-specific; kept local, never transmitted
};

bool ecdhGenerateKeyPair(EcdhKeyPair& out);

// Shared secret = X coordinate (32 bytes, big-endian) of mine.priv * peerPublic.
// peerPublic is the peer's 64-byte X||Y point. Returns false on invalid input.
bool ecdhComputeShared(const EcdhKeyPair& mine, const Bytes& peerPublicPoint,
                       Bytes& sharedOut);

} // namespace sm::crypto
