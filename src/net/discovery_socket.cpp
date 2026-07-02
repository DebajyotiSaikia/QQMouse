#include "net/discovery_socket.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h> // GetAdaptersAddresses (must follow winsock2.h)
using socklen_t = int;
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <cstdint>
#include <vector>

namespace sm::net {

namespace {

#ifdef _WIN32
struct WsaScope {
    bool ok;
    WsaScope() {
        WSADATA w;
        ok = (WSAStartup(MAKEWORD(2, 2), &w) == 0);
    }
    ~WsaScope() {
        if (ok) WSACleanup();
    }
};
void closeSock(SOCKET s) { closesocket(s); }
#else
using SOCKET = int;
constexpr int INVALID_SOCKET = -1;
struct WsaScope {
    bool ok = true;
};
void closeSock(int s) { ::close(s); }
#endif

// Per-interface directed broadcast addresses (network byte order). A limited broadcast
// to 255.255.255.255 only egresses the interface the default route points at -- which,
// with a VPN up, is the VPN tunnel, so LAN peers never see it. Sending to each active
// interface's OWN subnet broadcast (ip | ~mask) makes the routing table egress the
// matching NIC, so the LAN adapter is always covered regardless of VPN/default route.
std::vector<uint32_t> directedBroadcasts() {
    std::vector<uint32_t> out;
#ifdef _WIN32
    ULONG size = 15000;
    std::vector<uint8_t> buf(size);
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (rc != NO_ERROR) return out;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            uint32_t ip = ntohl(reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr)->sin_addr.s_addr);
            unsigned prefix = ua->OnLinkPrefixLength;
            if (prefix == 0 || prefix > 32) continue;
            uint32_t mask = (prefix == 32) ? 0xFFFFFFFFu : ~((1u << (32 - prefix)) - 1);
            out.push_back(htonl((ip & mask) | ~mask));
        }
    }
#else
    ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return out;
    for (ifaddrs* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) || !(ifa->ifa_flags & IFF_UP)) continue;
        if (!(ifa->ifa_flags & IFF_BROADCAST) || !ifa->ifa_broadaddr) continue;
        out.push_back(reinterpret_cast<sockaddr_in*>(ifa->ifa_broadaddr)->sin_addr.s_addr);
    }
    freeifaddrs(ifap);
#endif
    return out;
}

} // namespace

bool broadcastBeacon(const Beacon& b, uint16_t port) {
    WsaScope wsa;
    if (!wsa.ok) return false;

    Bytes pkt = encodeBeacon(b);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&yes), sizeof(yes));

    // Send to every interface's directed broadcast (covers the LAN even with a VPN up),
    // plus the limited broadcast as a belt-and-braces fallback.
    std::vector<uint32_t> targets = directedBroadcasts();
    targets.push_back(htonl(INADDR_BROADCAST));

    bool anySent = false;
    for (uint32_t dst : targets) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = dst;
        int sent = sendto(s, reinterpret_cast<const char*>(pkt.data()),
                          static_cast<int>(pkt.size()), 0, reinterpret_cast<sockaddr*>(&addr),
                          sizeof(addr));
        if (sent == static_cast<int>(pkt.size())) anySent = true;
    }
    closeSock(s);
    return anySent;
}

bool receiveBeacon(uint16_t port, int timeout_ms, Beacon& out) {
    WsaScope wsa;
    if (!wsa.ok) return false;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closeSock(s);
        return false;
    }

#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    uint8_t buf[2048];
    sockaddr_in from{};
    socklen_t fromLen = sizeof(from);
    int n = recvfrom(s, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                     reinterpret_cast<sockaddr*>(&from), &fromLen);
    closeSock(s);
    if (n <= 0) return false;
    if (!decodeBeacon(buf, static_cast<std::size_t>(n), out)) return false;
    // The UDP source address is the address we can actually reach the peer at --
    // more reliable than the sender's self-reported ip (multi-NIC, DHCP, etc.), so
    // it wins. Presence only; pairing (spec 7) remains the security gate.
    char ipstr[INET_ADDRSTRLEN] = "";
    if (inet_ntop(AF_INET, &from.sin_addr, ipstr, sizeof(ipstr))) out.ip = ipstr;
    return true;
}

} // namespace sm::net
