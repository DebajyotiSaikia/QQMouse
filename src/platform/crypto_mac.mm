// macOS native crypto (spec 5.4, 7). SHA/HMAC + AES-256-GCM via CommonCrypto,
// ECDH P-256 via Security.framework, randomness via SecRandomCopyBytes. Wire
// formats match the Windows CNG backend byte-for-byte (P-256 public = 64-byte
// X||Y big-endian; shared secret = 32-byte X). HKDF + base64 are portable.

#include "crypto/crypto.h"

#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>

#include <algorithm>

namespace sm::crypto {

bool randomBytes(uint8_t* buf, size_t len) {
    return SecRandomCopyBytes(kSecRandomDefault, len, buf) == errSecSuccess;
}

Bytes randomBytes(size_t len) {
    Bytes b(len);
    if (!randomBytes(b.data(), len)) b.clear();
    return b;
}

Hash256 sha256(const uint8_t* data, size_t len) {
    Hash256 o{};
    CC_SHA256(data, static_cast<CC_LONG>(len), o.data());
    return o;
}

Hash160 sha1(const uint8_t* data, size_t len) {
    Hash160 o{};
    CC_SHA1(data, static_cast<CC_LONG>(len), o.data());
    return o;
}

Hash256 hmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen) {
    Hash256 o{};
    CCHmac(kCCHmacAlgSHA256, key, keyLen, data, dataLen, o.data());
    return o;
}

namespace {

// Piecewise CommonCrypto GCM (create -> AddIV -> addAAD -> Encrypt/Decrypt -> Final).
bool gcm(bool encrypt, const uint8_t* key, const uint8_t* nonce, size_t nlen,
         const uint8_t* aad, size_t alen, const uint8_t* in, size_t ilen,
         uint8_t* out, uint8_t* tag16) {
    CCCryptorRef c = nullptr;
    if (CCCryptorCreateWithMode(encrypt ? kCCEncrypt : kCCDecrypt, kCCModeGCM, kCCAlgorithmAES,
                                ccNoPadding, nullptr, key, kCCKeySizeAES256, nullptr, 0, 0, 0,
                                &c) != kCCSuccess) {
        return false;
    }
    bool ok = false;
    do {
        if (CCCryptorGCMAddIV(c, nonce, nlen) != kCCSuccess) break;
        if (alen && CCCryptorGCMaddAAD(c, aad, alen) != kCCSuccess) break;
        if (encrypt) {
            if (ilen && CCCryptorGCMEncrypt(c, in, ilen, out) != kCCSuccess) break;
        } else {
            if (ilen && CCCryptorGCMDecrypt(c, in, ilen, out) != kCCSuccess) break;
        }
        uint8_t computed[kGcmTagLen];
        size_t tl = kGcmTagLen;
        if (CCCryptorGCMFinal(c, computed, &tl) != kCCSuccess || tl != kGcmTagLen) break;
        if (encrypt) {
            std::copy(computed, computed + kGcmTagLen, tag16);
            ok = true;
        } else {
            uint8_t diff = 0;
            for (size_t i = 0; i < kGcmTagLen; ++i)
                diff = static_cast<uint8_t>(diff | (computed[i] ^ tag16[i]));
            ok = (diff == 0); // constant-time tag compare
        }
    } while (false);
    CCCryptorRelease(c);
    return ok;
}

} // namespace

bool aesGcmEncrypt(const uint8_t* key32, const uint8_t* nonce, size_t nonceLen,
                   const uint8_t* aad, size_t aadLen, const uint8_t* plaintext, size_t ptLen,
                   uint8_t* ciphertext, uint8_t* tag16) {
    return gcm(true, key32, nonce, nonceLen, aad, aadLen, plaintext, ptLen, ciphertext, tag16);
}

bool aesGcmDecrypt(const uint8_t* key32, const uint8_t* nonce, size_t nonceLen,
                   const uint8_t* aad, size_t aadLen, const uint8_t* ciphertext, size_t ctLen,
                   const uint8_t* tag16, uint8_t* plaintext) {
    uint8_t tagCopy[kGcmTagLen];
    std::copy(tag16, tag16 + kGcmTagLen, tagCopy);
    return gcm(false, key32, nonce, nonceLen, aad, aadLen, ciphertext, ctLen, plaintext, tagCopy);
}

bool ecdhGenerateKeyPair(EcdhKeyPair& out) {
    @autoreleasepool {
        NSDictionary* attrs = @{
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeySizeInBits : @256
        };
        CFErrorRef err = nullptr;
        SecKeyRef priv = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &err);
        if (!priv) {
            if (err) CFRelease(err);
            return false;
        }
        bool ok = false;
        SecKeyRef pub = SecKeyCopyPublicKey(priv);
        if (pub) {
            CFDataRef pubData = SecKeyCopyExternalRepresentation(pub, nullptr); // 0x04||X||Y
            CFDataRef privData = SecKeyCopyExternalRepresentation(priv, nullptr);
            if (pubData && privData) {
                const uint8_t* pb = CFDataGetBytePtr(pubData);
                size_t pl = static_cast<size_t>(CFDataGetLength(pubData));
                const uint8_t* kb = CFDataGetBytePtr(privData);
                size_t kl = static_cast<size_t>(CFDataGetLength(privData));
                if (pl >= 1 + kEcPointLen) {
                    out.publicPoint.assign(pb + 1, pb + 1 + kEcPointLen); // strip 0x04 prefix
                    out.privateBlob.assign(kb, kb + kl);
                    ok = out.publicPoint.size() == kEcPointLen && !out.privateBlob.empty();
                }
            }
            if (pubData) CFRelease(pubData);
            if (privData) CFRelease(privData);
            CFRelease(pub);
        }
        CFRelease(priv);
        return ok;
    }
}

bool ecdhComputeShared(const EcdhKeyPair& mine, const Bytes& peerPublicPoint, Bytes& sharedOut) {
    if (peerPublicPoint.size() != kEcPointLen || mine.privateBlob.empty()) return false;
    @autoreleasepool {
        NSData* privExt = [NSData dataWithBytes:mine.privateBlob.data()
                                         length:mine.privateBlob.size()];
        NSDictionary* privAttrs = @{
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeyClass : (id)kSecAttrKeyClassPrivate
        };
        SecKeyRef priv =
            SecKeyCreateWithData((__bridge CFDataRef)privExt, (__bridge CFDictionaryRef)privAttrs,
                                 nullptr);
        if (!priv) return false;

        Bytes pubExt;
        pubExt.reserve(1 + kEcPointLen);
        pubExt.push_back(0x04); // uncompressed point marker
        pubExt.insert(pubExt.end(), peerPublicPoint.begin(), peerPublicPoint.end());
        NSData* pubExtData = [NSData dataWithBytes:pubExt.data() length:pubExt.size()];
        NSDictionary* pubAttrs = @{
            (id)kSecAttrKeyType : (id)kSecAttrKeyTypeECSECPrimeRandom,
            (id)kSecAttrKeyClass : (id)kSecAttrKeyClassPublic
        };
        SecKeyRef pub = SecKeyCreateWithData((__bridge CFDataRef)pubExtData,
                                             (__bridge CFDictionaryRef)pubAttrs, nullptr);
        bool ok = false;
        if (pub) {
            CFDataRef sec = SecKeyCopyKeyExchangeResult(
                priv, kSecKeyAlgorithmECDHKeyExchangeStandard, pub,
                (__bridge CFDictionaryRef) @ {}, nullptr);
            if (sec) {
                size_t sl = static_cast<size_t>(CFDataGetLength(sec));
                if (sl == kSharedLen) {
                    const uint8_t* sb = CFDataGetBytePtr(sec);
                    sharedOut.assign(sb, sb + sl); // big-endian X, matches CNG backend
                    ok = true;
                }
                CFRelease(sec);
            }
            CFRelease(pub);
        }
        CFRelease(priv);
        return ok;
    }
}

} // namespace sm::crypto
