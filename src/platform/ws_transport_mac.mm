// macOS client/server WebSocket transport over TCP + TLS (spec 5.1/5.5: wss://).
// Native BSD sockets + Security.framework SecureTransport, zero third-party. Mirrors
// ws_transport_posix.cpp (OpenSSL) and ws_transport_win.cpp (Schannel) exactly -- same
// WS handshake, same frame codec, same non-blocking recv contract -- so a mac node
// interoperates on the wire with a Windows node.
//
// TLS is encryption-only: the server presents an EPHEMERAL self-signed identity and the
// client does NOT verify it (kSSLSessionOptionBreakOnServerAuth) -- the app-layer PSK
// secure link remains the trust gate, identical to the other two backends. The self-
// signed certificate DER comes from the unit-tested crypto/x509_selfsigned builder
// (CryptoAPI-verified byte-for-byte on Windows), signed here by a runtime P-256 key.
//
// SecureTransport (SSLContext) is deprecated but is the native synchronous TLS API that
// fits the poll-based Transport interface; the deprecation warnings are silenced below.
// This file compiles on CI but, like the Schannel backend, needs a real Mac to validate.

#include "net/ws_transport.h"

#include "core/log.h"
#include "crypto/x509_selfsigned.h"
#include "net/frame_assembler.h"
#include "net/ws_frame.h"
#include "net/ws_handshake.h"

#import <Security/Security.h>
#import <Security/SecureTransport.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <string>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

namespace sm::net {

namespace {

inline void mlog(const std::string& m) { sm::log::write("[tls-mac] " + m); }

void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
void setBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

// --- Ephemeral server identity ---------------------------------------------------
// Build a fresh self-signed P-256 identity in a throwaway keychain (SecureTransport's
// SSLSetCertificate requires a SecIdentityRef, which requires the private key to live
// in a keychain). The keychain is created with a known password (no user prompt) and
// deleted on process exit. Cached: one identity per process. Null on failure -- in
// which case this node can still be a TLS CLIENT (no cert needed), just not a server.
SecIdentityRef ephemeralServerIdentity() {
    static SecIdentityRef cached = nullptr;
    static bool tried = false;
    if (tried) return cached;
    tried = true;

    // Unique temp keychain path; remove any stale file first.
    std::string path = "/tmp/skittermouse-" + std::to_string(getpid()) + "-" +
                       std::to_string(static_cast<long>(time(nullptr))) + ".keychain";
    unlink(path.c_str());
    const char* pw = "skittermouse-ephemeral";
    SecKeychainRef keychain = nullptr;
    if (SecKeychainCreate(path.c_str(), static_cast<UInt32>(strlen(pw)), pw, false, nullptr,
                          &keychain) != errSecSuccess ||
        !keychain) {
        mlog("SecKeychainCreate failed");
        return nullptr;
    }

    // Generate a permanent P-256 key pair inside the temp keychain.
    const void* keys[] = {kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrIsPermanent,
                          kSecUseKeychain};
    int bits = 256;
    CFNumberRef bitsRef = CFNumberCreate(nullptr, kCFNumberIntType, &bits);
    const void* vals[] = {kSecAttrKeyTypeECSECPrimeRandom, bitsRef, kCFBooleanTrue, keychain};
    CFDictionaryRef attrs = CFDictionaryCreate(nullptr, keys, vals, 4,
                                               &kCFTypeDictionaryKeyCallBacks,
                                               &kCFTypeDictionaryValueCallBacks);
    CFErrorRef err = nullptr;
    SecKeyRef priv = SecKeyCreateRandomKey(attrs, &err);
    CFRelease(attrs);
    CFRelease(bitsRef);
    if (!priv) {
        mlog("SecKeyCreateRandomKey failed");
        if (err) CFRelease(err);
        SecKeychainDelete(keychain);
        CFRelease(keychain);
        return nullptr;
    }
    SecKeyRef pub = SecKeyCopyPublicKey(priv);
    CFDataRef pointRef = pub ? SecKeyCopyExternalRepresentation(pub, nullptr) : nullptr;
    if (!pointRef) {
        mlog("public key export failed");
        if (pub) CFRelease(pub);
        CFRelease(priv);
        SecKeychainDelete(keychain);
        CFRelease(keychain);
        return nullptr;
    }
    sm::crypto::Bytes point(CFDataGetBytePtr(pointRef),
                            CFDataGetBytePtr(pointRef) + CFDataGetLength(pointRef));
    CFRelease(pointRef);
    CFRelease(pub);

    // Sign the TBSCertificate with the private key (ECDSA-SHA256 -> DER signature).
    auto sign = [priv](const sm::crypto::Bytes& tbs) -> sm::crypto::Bytes {
        CFDataRef tbsRef = CFDataCreate(nullptr, tbs.data(), static_cast<CFIndex>(tbs.size()));
        CFErrorRef e = nullptr;
        CFDataRef sig = SecKeyCreateSignature(
            priv, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, tbsRef, &e);
        CFRelease(tbsRef);
        if (!sig) {
            if (e) CFRelease(e);
            return {};
        }
        sm::crypto::Bytes out(CFDataGetBytePtr(sig), CFDataGetBytePtr(sig) + CFDataGetLength(sig));
        CFRelease(sig);
        return out;
    };

    const int64_t now = static_cast<int64_t>(time(nullptr));
    sm::crypto::Bytes der =
        sm::crypto::buildSelfSignedP256Cert(point, sign, now - 3600, now + 3600LL * 24 * 3650);
    if (der.empty()) {
        mlog("cert DER build failed");
        CFRelease(priv);
        SecKeychainDelete(keychain);
        CFRelease(keychain);
        return nullptr;
    }

    CFDataRef derRef = CFDataCreate(nullptr, der.data(), static_cast<CFIndex>(der.size()));
    SecCertificateRef cert = SecCertificateCreateWithData(nullptr, derRef);
    CFRelease(derRef);
    if (!cert) {
        mlog("SecCertificateCreateWithData failed");
        CFRelease(priv);
        SecKeychainDelete(keychain);
        CFRelease(keychain);
        return nullptr;
    }

    // Store the cert in the same keychain, then pair it with its private key.
    const void* addKeys[] = {kSecClass, kSecValueRef, kSecUseKeychain};
    const void* addVals[] = {kSecClassCertificate, cert, keychain};
    CFDictionaryRef addDict = CFDictionaryCreate(nullptr, addKeys, addVals, 3,
                                                 &kCFTypeDictionaryKeyCallBacks,
                                                 &kCFTypeDictionaryValueCallBacks);
    SecItemAdd(addDict, nullptr);
    CFRelease(addDict);

    SecIdentityRef identity = nullptr;
    SecIdentityCreateWithCertificate(keychain, cert, &identity);
    CFRelease(cert);
    CFRelease(priv);
    if (!identity) {
        mlog("SecIdentityCreateWithCertificate failed");
        SecKeychainDelete(keychain);
        CFRelease(keychain);
        return nullptr;
    }
    // Success: the identity references this keychain, so it is retained for the
    // process lifetime (freed by the OS at exit) alongside the cached identity.
    mlog("ephemeral server identity ready");
    cached = identity;
    return cached;
}

// SecureTransport raw socket I/O callbacks (operate on the int fd via the connection).
OSStatus sockRead(SSLConnectionRef conn, void* data, size_t* dataLength) {
    int fd = *static_cast<const int*>(conn);
    size_t want = *dataLength, got = 0;
    auto* p = static_cast<uint8_t*>(data);
    while (got < want) {
        ssize_t n = ::read(fd, p + got, want - got);
        if (n > 0) { got += static_cast<size_t>(n); continue; }
        if (n == 0) { *dataLength = got; return errSSLClosedGraceful; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { *dataLength = got; return errSSLWouldBlock; }
        *dataLength = got;
        return errSSLClosedAbort;
    }
    *dataLength = got;
    return noErr;
}
OSStatus sockWrite(SSLConnectionRef conn, const void* data, size_t* dataLength) {
    int fd = *static_cast<const int*>(conn);
    size_t want = *dataLength, put = 0;
    auto* p = static_cast<const uint8_t*>(data);
    while (put < want) {
        ssize_t n = ::write(fd, p + put, want - put);
        if (n > 0) { put += static_cast<size_t>(n); continue; }
        if (n == 0) { *dataLength = put; return errSSLClosedGraceful; }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) { *dataLength = put; return errSSLWouldBlock; }
        *dataLength = put;
        return errSSLClosedAbort;
    }
    *dataLength = put;
    return noErr;
}

// Run the TLS handshake to completion on the blocking socket. Accepts the peer without
// verification (encryption-only). Returns false on failure.
bool tlsHandshake(SSLContextRef ctx) {
    for (;;) {
        OSStatus st = SSLHandshake(ctx);
        if (st == noErr) return true;
        if (st == errSSLPeerAuthCompleted) continue;   // client: accept the unverified cert
        if (st == errSSLWouldBlock) continue;          // blocking fd: just retry
        mlog("SSLHandshake failed " + std::to_string(st));
        return false;
    }
}

class MacWsTransport : public Transport {
public:
    MacWsTransport(int sock = -1, bool client = true, SSLContextRef ssl = nullptr)
        : sock_(sock), client_(client), connected_(sock >= 0), ssl_(ssl) {}

    ~MacWsTransport() override { close(); }

    bool connect(const std::string& host, uint16_t port) override {
        if (connected_) return true;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* res = nullptr;
        std::string portStr = std::to_string(port);
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) return false;
        sock_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock_ < 0) { freeaddrinfo(res); return false; }
        setNonBlocking(sock_);
        int cr = ::connect(sock_, res->ai_addr, res->ai_addrlen);
        bool ok = (cr == 0);
        if (!ok && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
            fd_set wr;
            FD_ZERO(&wr);
            FD_SET(sock_, &wr);
            timeval tv{3, 0};
            if (select(sock_ + 1, nullptr, &wr, nullptr, &tv) > 0 && FD_ISSET(sock_, &wr)) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(sock_, SOL_SOCKET, SO_ERROR, &err, &len);
                ok = (err == 0);
            }
        }
        setBlocking(sock_);
        freeaddrinfo(res);
        if (!ok) { ::close(sock_); sock_ = -1; return false; }

        ssl_ = SSLCreateContext(nullptr, kSSLClientSide, kSSLStreamType);
        if (!ssl_) { ::close(sock_); sock_ = -1; return false; }
        SSLSetIOFuncs(ssl_, sockRead, sockWrite);
        SSLSetConnection(ssl_, &sock_);
        SSLSetSessionOption(ssl_, kSSLSessionOptionBreakOnServerAuth, true); // don't verify
        if (!tlsHandshake(ssl_)) { close(); return false; }

        std::string key = wsGenerateClientKey();
        std::string req = wsBuildClientHandshake(host + ":" + portStr, "/input", key);
        // Past this point ssl_ + sock_ are live; close() (idempotent) frees both on any
        // WS-handshake failure so a rejected upgrade never leaks the TLS context.
        if (!rawSendAll(reinterpret_cast<const uint8_t*>(req.data()), req.size())) {
            close();
            return false;
        }
        std::string resp;
        char c;
        while (resp.find("\r\n\r\n") == std::string::npos) {
            long n = rawRecv(&c, 1);
            if (n <= 0) {
                close();
                return false;
            }
            resp += c;
            if (resp.size() > 8192) {
                close();
                return false;
            }
        }
        if (resp.find(wsAcceptKey(key)) == std::string::npos) {
            close();
            return false;
        }
        setNonBlocking(sock_);
        connected_ = true;
        return true;
    }

    bool isConnected() const override { return connected_; }

    bool send(const uint8_t* data, std::size_t len) override {
        if (!connected_) return false;
        Bytes frame = wsEncodeFrame(WsOpcode::Binary, data, len, /*masked*/ client_);
        return rawSendAll(frame.data(), frame.size());
    }

    int recv(uint8_t* buf, std::size_t cap) override {
        if (!connected_) return -1;
        WsFrame out;
        if (assembler_.next(out)) return copyFrame(out, buf, cap);
        char tmp[4096];
        long n = rawRecv(tmp, sizeof(tmp));
        if (n == 0) { connected_ = false; return -1; }
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) return 0;
            connected_ = false;
            return -1;
        }
        assembler_.feed(reinterpret_cast<const uint8_t*>(tmp), static_cast<std::size_t>(n));
        if (assembler_.next(out)) return copyFrame(out, buf, cap);
        return 0;
    }

    void close() override {
        if (ssl_) { SSLClose(ssl_); CFRelease(ssl_); ssl_ = nullptr; }
        if (sock_ >= 0) { ::close(sock_); sock_ = -1; }
        connected_ = false;
    }

    // Server post-accept: TLS handshake with our identity, then the WS handshake.
    bool acceptServerSide() {
        SecIdentityRef identity = ephemeralServerIdentity();
        if (!identity) return false;
        ssl_ = SSLCreateContext(nullptr, kSSLServerSide, kSSLStreamType);
        if (!ssl_) return false;
        SSLSetIOFuncs(ssl_, sockRead, sockWrite);
        SSLSetConnection(ssl_, &sock_);
        const void* certs[] = {identity};
        CFArrayRef certArray = CFArrayCreate(nullptr, certs, 1, &kCFTypeArrayCallBacks);
        OSStatus cs = SSLSetCertificate(ssl_, certArray);
        CFRelease(certArray);
        if (cs != noErr) { mlog("SSLSetCertificate failed"); return false; }
        if (!tlsHandshake(ssl_)) return false;

        std::string req;
        char c;
        while (req.find("\r\n\r\n") == std::string::npos) {
            long n = rawRecv(&c, 1);
            if (n <= 0) return false;
            req += c;
            if (req.size() > 8192) return false;
        }
        const std::string tag = "Sec-WebSocket-Key:";
        std::size_t p = req.find(tag);
        if (p == std::string::npos) return false;
        p += tag.size();
        while (p < req.size() && (req[p] == ' ' || req[p] == '\t')) ++p;
        std::size_t e = req.find("\r\n", p);
        if (e == std::string::npos) return false;
        std::string key = req.substr(p, e - p);
        if (key.empty()) return false;
        std::string resp = wsBuildServerResponse(key);
        if (!rawSendAll(reinterpret_cast<const uint8_t*>(resp.data()), resp.size())) return false;
        setNonBlocking(sock_);
        connected_ = true;
        return true;
    }

private:
    int copyFrame(const WsFrame& f, uint8_t* buf, std::size_t cap) {
        std::size_t n = f.payload.size() <= cap ? f.payload.size() : cap;
        std::memcpy(buf, f.payload.data(), n);
        return static_cast<int>(n);
    }
    long rawRecv(void* buf, std::size_t n) {
        size_t got = 0;
        OSStatus st = SSLRead(ssl_, buf, n, &got);
        if (got > 0) return static_cast<long>(got);
        if (st == errSSLWouldBlock) { errno = EWOULDBLOCK; return -1; }
        return 0; // closed / error -> EOF
    }
    bool rawSendAll(const uint8_t* d, std::size_t len) {
        std::size_t sent = 0;
        while (sent < len) {
            size_t put = 0;
            OSStatus st = SSLWrite(ssl_, d + sent, len - sent, &put);
            sent += put;
            if (st == noErr) continue;
            if (st == errSSLWouldBlock) {
                fd_set wr;
                FD_ZERO(&wr);
                FD_SET(sock_, &wr);
                timeval tv{0, 100000};
                if (select(sock_ + 1, nullptr, &wr, nullptr, &tv) <= 0) return false;
                continue;
            }
            return false;
        }
        return true;
    }

    int sock_ = -1;
    bool client_ = true;
    bool connected_ = false;
    SSLContextRef ssl_ = nullptr;
    WsFrameAssembler assembler_;
};

} // namespace

Transport* createWsClientTransport() { return new MacWsTransport(-1, true); }

Transport* wsAcceptOne(uint16_t port, int timeoutMs, std::string* outPeerIp) {
    int listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock < 0) return nullptr;
    int yes = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        listen(listenSock, 1) != 0) {
        ::close(listenSock);
        return nullptr;
    }

    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(listenSock, &rd);
    timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    if (select(listenSock + 1, &rd, nullptr, nullptr, &tv) <= 0) {
        ::close(listenSock);
        return nullptr;
    }

    int client = accept(listenSock, nullptr, nullptr);
    ::close(listenSock);
    if (client < 0) return nullptr;

    if (outPeerIp) {
        sockaddr_in pa{};
        socklen_t palen = sizeof(pa);
        char ip[INET_ADDRSTRLEN] = "";
        if (getpeername(client, reinterpret_cast<sockaddr*>(&pa), &palen) == 0 &&
            inet_ntop(AF_INET, &pa.sin_addr, ip, sizeof(ip)))
            *outPeerIp = ip;
    }

    auto* t = new MacWsTransport(client, /*client role*/ false);
    if (!t->acceptServerSide()) {
        delete t;
        return nullptr;
    }
    return t;
}

} // namespace sm::net

#pragma clang diagnostic pop
