#pragma once

// UDP presence broadcast + receive (spec 6). Native sockets (WinSock / BSD), no
// mDNS/Bonjour dependency. Broadcasts stay link-local (255.255.255.255 is not
// forwarded by routers). The beacon reveals only presence -- pairing (spec 7) is
// the real security gate. Decoded beacons feed net/discovery_table.

#include <cstdint>

#include "net/discovery_beacon.h"

namespace sm::net {

// Broadcast one beacon to 255.255.255.255:port. Returns false on socket error.
bool broadcastBeacon(const Beacon& b, uint16_t port);

// Send one beacon by UNICAST to ip:port. Used to reply to a received broadcast so the
// sender discovers us too, even when OUR broadcast can't reach it (VPN split routing,
// a corp firewall dropping broadcast, WiFi client isolation). Returns false on error.
bool sendBeaconTo(const Beacon& b, const std::string& ip, uint16_t port);

// Bind to port and wait up to timeout_ms for a beacon; decode into out. Returns
// false on timeout, socket error, or an undecodable packet.
bool receiveBeacon(uint16_t port, int timeout_ms, Beacon& out);

} // namespace sm::net
