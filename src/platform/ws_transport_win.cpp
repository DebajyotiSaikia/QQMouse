// Windows client WebSocket transport over TCP (spec 5.1/5.5). Native WinSock2, zero
// third-party. Built on the unit-tested WS handshake (net/ws_handshake) and frame
// codec/assembler (net/ws_frame, net/frame_assembler). TLS (Schannel) wrapping for
// full wss:// is the remaining layer; message payloads are AES-256-GCM sealed
// end-to-end regardless (spec 5.4).

#include "net/ws_transport.h"

#include "net/frame_assembler.h"
#include "net/ws_frame.h"
#include "net/ws_handshake.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <string>

namespace sm::net {

namespace {

class WinWsClientTransport : public Transport {
public:
    ~WinWsClientTransport() override {
        close();
        if (wsaUp_) WSACleanup();
    }

    bool connect(const std::string& host, uint16_t port) override {
        if (!wsaUp_) {
            WSADATA w;
            if (WSAStartup(MAKEWORD(2, 2), &w) != 0) return false;
            wsaUp_ = true;
        }

        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* res = nullptr;
        std::string portStr = std::to_string(port);
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) return false;

        sock_ = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sock_ == INVALID_SOCKET) { freeaddrinfo(res); return false; }
        if (::connect(sock_, res->ai_addr, static_cast<int>(res->ai_addrlen)) == SOCKET_ERROR) {
            freeaddrinfo(res);
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
            return false;
        }
        freeaddrinfo(res);

        // WebSocket opening handshake.
        std::string key = wsGenerateClientKey();
        std::string req = wsBuildClientHandshake(host + ":" + portStr, "/input", key);
        if (!sendAll(reinterpret_cast<const uint8_t*>(req.data()), req.size())) return false;

        std::string resp;
        char c;
        while (resp.find("\r\n\r\n") == std::string::npos) {
            int n = ::recv(sock_, &c, 1, 0);
            if (n <= 0) return false;
            resp += c;
            if (resp.size() > 8192) return false; // runaway header
        }
        if (resp.find(wsAcceptKey(key)) == std::string::npos) return false;

        connected_ = true;
        return true;
    }

    bool isConnected() const override { return connected_; }

    bool send(const uint8_t* data, std::size_t len) override {
        if (!connected_) return false;
        Bytes frame = wsEncodeFrame(WsOpcode::Binary, data, len, /*masked*/ true);
        return sendAll(frame.data(), frame.size());
    }

    int recv(uint8_t* buf, std::size_t cap) override {
        if (!connected_) return -1;
        WsFrame out;
        if (assembler_.next(out)) return copyFrame(out, buf, cap);

        char tmp[4096];
        int n = ::recv(sock_, tmp, sizeof(tmp), 0);
        if (n == 0) { connected_ = false; return -1; }
        if (n < 0) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) return 0;
            connected_ = false;
            return -1;
        }
        assembler_.feed(reinterpret_cast<const uint8_t*>(tmp), static_cast<std::size_t>(n));
        if (assembler_.next(out)) return copyFrame(out, buf, cap);
        return 0;
    }

    void close() override {
        if (sock_ != INVALID_SOCKET) {
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
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
            int n = ::send(sock_, reinterpret_cast<const char*>(d) + sent,
                           static_cast<int>(len - sent), 0);
            if (n <= 0) return false;
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    SOCKET sock_ = INVALID_SOCKET;
    bool connected_ = false;
    bool wsaUp_ = false;
    WsFrameAssembler assembler_;
};

} // namespace

Transport* createWsClientTransport() { return new WinWsClientTransport(); }

} // namespace sm::net
