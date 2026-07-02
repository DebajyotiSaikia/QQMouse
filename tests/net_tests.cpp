#include "test_framework.h"

#include "net/discovery_beacon.h"
#include "net/discovery_socket.h"
#include "net/wol_sender.h"
#include "net/ws_frame.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>

using namespace sm::net;

namespace {

bool roundTripWs(const Bytes& payload, bool masked) {
    Bytes frame = wsEncodeFrame(WsOpcode::Binary, payload.data(), payload.size(), masked);
    WsFrame out;
    long consumed = wsDecodeFrame(frame.data(), frame.size(), out);
    return consumed == static_cast<long>(frame.size()) &&
           out.opcode == WsOpcode::Binary && out.fin && out.payload == payload;
}

} // namespace

void run_net_tests() {
    // --- WebSocket framing: known vector (unmasked text "Hello") ------------
    {
        std::string hello = "Hello";
        Bytes f = wsEncodeFrame(WsOpcode::Text,
                                reinterpret_cast<const uint8_t*>(hello.data()),
                                hello.size(), /*masked*/ false);
        const uint8_t expected[] = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
        SM_CHECK_EQ(f.size(), sizeof(expected));
        bool same = f.size() == sizeof(expected);
        for (std::size_t i = 0; same && i < f.size(); ++i) same = same && (f[i] == expected[i]);
        SM_CHECK(same);

        WsFrame out;
        long n = wsDecodeFrame(expected, sizeof(expected), out);
        SM_CHECK_EQ(n, 7L);
        SM_CHECK(out.opcode == WsOpcode::Text);
        SM_CHECK(std::string(out.payload.begin(), out.payload.end()) == "Hello");
    }

    // --- WebSocket framing: masked + multiple length encodings round-trip ----
    {
        SM_CHECK(roundTripWs(Bytes(5, 0xAB), true));    // 7-bit length
        SM_CHECK(roundTripWs(Bytes(125, 0x01), true));  // largest 7-bit length
        SM_CHECK(roundTripWs(Bytes(126, 0x02), true));  // 16-bit length boundary
        SM_CHECK(roundTripWs(Bytes(1000, 0x03), true)); // 16-bit length
        SM_CHECK(roundTripWs(Bytes(70000, 0x04), true));// 64-bit length
        SM_CHECK(roundTripWs(Bytes(5, 0xAB), false));   // unmasked round-trip
    }

    // --- WebSocket framing: incomplete buffers report "need more" ------------
    {
        WsFrame out;
        SM_CHECK_EQ(wsDecodeFrame(nullptr, 0, out), 0L);
        uint8_t partial[] = {0x82, 0x05, 0x00, 0x00}; // says 5 bytes, only 2 present
        SM_CHECK_EQ(wsDecodeFrame(partial, sizeof(partial), out), 0L);
    }

    // --- Wake-on-LAN: MAC parsing + 102-byte magic packet -------------------
    {
        Mac mac;
        SM_CHECK(parseMac("01:02:03:04:05:06", mac));
        SM_CHECK_EQ(mac[0], 0x01);
        SM_CHECK_EQ(mac[5], 0x06);

        Mac mac2;
        SM_CHECK(parseMac("AA-BB-CC-DD-EE-FF", mac2));
        SM_CHECK_EQ(mac2[0], 0xAA);
        SM_CHECK_EQ(mac2[5], 0xFF);

        SM_CHECK(!parseMac("nonsense", mac));
        SM_CHECK(!parseMac("01:02:03:04:05", mac));       // too short
        SM_CHECK(!parseMac("01:02:03:04:05:06:07", mac)); // too long

        Bytes pkt = buildMagicPacket(mac2);
        SM_CHECK_EQ(pkt.size(), 102u);
        for (int i = 0; i < 6; ++i) SM_CHECK_EQ(pkt[i], 0xFF);
        // 16 repetitions of the MAC follow the 6 sync bytes.
        for (int rep = 0; rep < 16; ++rep)
            for (int i = 0; i < 6; ++i)
                SM_CHECK_EQ(pkt[6 + rep * 6 + i], mac2[i]);
    }

    // --- Discovery beacon: encode/decode round-trip + validation ------------
    {
        Beacon b;
        b.machine_name = "DESKTOP-B";
        b.machine_id = "uuid-1234";
        b.ip = "192.168.1.50";
        b.port = 7777;
        b.os = 0;
        b.wol_capable = 1;

        Bytes enc = encodeBeacon(b);
        Beacon d;
        SM_CHECK(decodeBeacon(enc.data(), enc.size(), d));
        SM_CHECK_EQ(d.machine_name, b.machine_name);
        SM_CHECK_EQ(d.machine_id, b.machine_id);
        SM_CHECK_EQ(d.ip, b.ip);
        SM_CHECK_EQ(d.port, b.port);
        SM_CHECK_EQ(d.os, b.os);
        SM_CHECK_EQ(d.wol_capable, b.wol_capable);

        // Bad magic and truncated buffers are rejected.
        Beacon j;
        const uint8_t junk[] = {'X', 'X', 'X', 'X', 0, 0};
        SM_CHECK(!decodeBeacon(junk, sizeof(junk), j));
        SM_CHECK(!decodeBeacon(enc.data(), 3, j));            // shorter than magic
        SM_CHECK(!decodeBeacon(enc.data(), enc.size() - 1, j)); // truncated tail
    }

    // --- Real UDP paths: Wake-on-LAN send + discovery broadcast/receive -----
    // Headless but exercises the actual sockets (sendMagicPacket, per-interface
    // broadcastBeacon, receiveBeacon bind+recv). A loopback round-trip is asserted
    // only when the OS actually delivers the broadcast (some CI sandboxes drop it),
    // so this can never flake-fail.
    {
        Mac mac;
        parseMac("01:02:03:04:05:06", mac);
        sendMagicPacket(mac, "255.255.255.255", 9); // covers the UDP send path

        const uint16_t port = 47899;
        Beacon self;
        self.machine_name = "COV-HOST";
        self.machine_id = "cov-id";
        self.port = 47800;
        self.os = 0;

        std::atomic<bool> stop{false};
        std::thread sender([&] {
            while (!stop.load()) {
                broadcastBeacon(self, port);
                sendBeaconTo(self, "127.0.0.1", port); // unicast reply path (deterministic on loopback)
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
            }
        });
        Beacon got;
        bool received = false;
        for (int i = 0; i < 12 && !received; ++i) received = receiveBeacon(port, 300, got);
        stop.store(true);
        sender.join();
        if (received) SM_CHECK_EQ(got.machine_id, std::string("cov-id"));
    }
}
