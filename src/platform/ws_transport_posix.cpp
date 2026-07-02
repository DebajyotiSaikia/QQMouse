// POSIX client/server WebSocket transport over TCP (spec 5.1/5.5). BSD sockets, so
// it serves both the macOS product build and the Linux container test rig. Mirrors
// platform/ws_transport_win.cpp exactly (same handshake, frame codec, non-blocking
// recv contract) so a node on either OS interoperates on the wire.

#include "net/ws_transport.h"

#include "net/frame_assembler.h"
#include "net/ws_frame.h"
#include "net/ws_handshake.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

namespace sm::net {

namespace {

void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// One WebSocket transport over a connected TCP socket. Per RFC 6455, client-role
// frames are masked and server-role (accepted) frames are not.
class PosixWsTransport : public Transport {
public:
    explicit PosixWsTransport(int sock = -1, bool client = true)
        : sock_(sock), client_(client), connected_(sock >= 0) {}

    ~PosixWsTransport() override { close(); }

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
        // Non-blocking connect with a bounded timeout, so dialing an offline peer
        // can't stall the dial loop (or app shutdown) for the full OS SYN timeout.
        setNonBlocking(sock_);
        int cr = ::connect(sock_, res->ai_addr, res->ai_addrlen);
        bool connectedOk = (cr == 0);
        if (!connectedOk && (errno == EINPROGRESS || errno == EWOULDBLOCK)) {
            fd_set wr;
            FD_ZERO(&wr);
            FD_SET(sock_, &wr);
            timeval tv{3, 0}; // 3s connect timeout
            if (select(sock_ + 1, nullptr, &wr, nullptr, &tv) > 0 && FD_ISSET(sock_, &wr)) {
                int err = 0;
                socklen_t len = sizeof(err);
                getsockopt(sock_, SOL_SOCKET, SO_ERROR, &err, &len);
                connectedOk = (err == 0);
            }
        }
        // Back to blocking for the handshake reads (recv switches to non-blocking
        // again once the WebSocket upgrade completes).
        {
            int flags = fcntl(sock_, F_GETFL, 0);
            if (flags >= 0) fcntl(sock_, F_SETFL, flags & ~O_NONBLOCK);
        }
        if (!connectedOk) {
            freeaddrinfo(res);
            ::close(sock_);
            sock_ = -1;
            return false;
        }
        freeaddrinfo(res);

        std::string key = wsGenerateClientKey();
        std::string req = wsBuildClientHandshake(host + ":" + portStr, "/input", key);
        if (!sendAll(reinterpret_cast<const uint8_t*>(req.data()), req.size())) return false;
        std::string resp;
        char c;
        while (resp.find("\r\n\r\n") == std::string::npos) {
            long n = ::recv(sock_, &c, 1, 0);
            if (n <= 0) return false;
            resp += c;
            if (resp.size() > 8192) return false;
        }
        if (resp.find(wsAcceptKey(key)) == std::string::npos) return false;
        setNonBlocking(sock_); // recv() below is non-blocking (returns 0 when idle)
        connected_ = true;
        return true;
    }

    bool isConnected() const override { return connected_; }

    bool send(const uint8_t* data, std::size_t len) override {
        if (!connected_) return false;
        Bytes frame = wsEncodeFrame(WsOpcode::Binary, data, len, /*masked*/ client_);
        return sendAll(frame.data(), frame.size());
    }

    int recv(uint8_t* buf, std::size_t cap) override {
        if (!connected_) return -1;
        WsFrame out;
        if (assembler_.next(out)) return copyFrame(out, buf, cap);
        char tmp[4096];
        long n = ::recv(sock_, tmp, sizeof(tmp), 0);
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
        if (sock_ >= 0) {
            ::close(sock_);
            sock_ = -1;
        }
        connected_ = false;
    }

private:
    int copyFrame(const WsFrame& f, uint8_t* buf, std::size_t cap) {
        std::size_t n = f.payload.size() <= cap ? f.payload.size() : cap;
        std::memcpy(buf, f.payload.data(), n);
        return static_cast<int>(n);
    }
    bool sendAll(const uint8_t* d, std::size_t len) {
        std::size_t sent = 0;
        while (sent < len) {
            long n = ::send(sock_, d + sent, len - sent, 0);
            if (n < 0) {
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    fd_set wr;
                    FD_ZERO(&wr);
                    FD_SET(sock_, &wr);
                    timeval tv{0, 100000}; // 100 ms
                    if (select(sock_ + 1, nullptr, &wr, nullptr, &tv) <= 0) return false;
                    continue;
                }
                return false;
            }
            if (n == 0) return false;
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    int sock_ = -1;
    bool client_ = true;
    bool connected_ = false;
    WsFrameAssembler assembler_;
};

std::string parseKey(const std::string& req) {
    const std::string tag = "Sec-WebSocket-Key:";
    std::size_t p = req.find(tag);
    if (p == std::string::npos) return {};
    p += tag.size();
    while (p < req.size() && (req[p] == ' ' || req[p] == '\t')) ++p;
    std::size_t e = req.find("\r\n", p);
    if (e == std::string::npos) return {};
    return req.substr(p, e - p);
}

} // namespace

Transport* createWsClientTransport() { return new PosixWsTransport(-1, true); }

Transport* wsAcceptOne(uint16_t port, int timeoutMs) {
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

    std::string req;
    char c;
    while (req.find("\r\n\r\n") == std::string::npos) {
        long n = ::recv(client, &c, 1, 0);
        if (n <= 0) { ::close(client); return nullptr; }
        req += c;
        if (req.size() > 8192) { ::close(client); return nullptr; }
    }
    std::string key = parseKey(req);
    if (key.empty()) { ::close(client); return nullptr; }
    std::string resp = wsBuildServerResponse(key);
    std::size_t sent = 0;
    while (sent < resp.size()) {
        long n = ::send(client, resp.data() + sent, resp.size() - sent, 0);
        if (n <= 0) { ::close(client); return nullptr; }
        sent += static_cast<std::size_t>(n);
    }
    setNonBlocking(client);
    return new PosixWsTransport(client, /*client role*/ false);
}

} // namespace sm::net
