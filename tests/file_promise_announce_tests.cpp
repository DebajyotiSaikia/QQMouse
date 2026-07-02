#include "test_framework.h"

#include "loopback_transport.h"

#include "app/mesh_node.h"
#include "net/file_promise_announce.h"

#include <string>
#include <vector>

using namespace sm;

// Codec round-trips (including empty name / zero size / multi-file) and rejects a
// truncated buffer; then the announce rides the mesh input channel end to end.
void run_file_promise_announce_tests() {
    // --- Codec round-trip -----------------------------------------------------
    std::vector<net::FilePromiseItem> in = {
        {"report.pdf", 123456}, {"", 0}, {"a-very-long-name-\xE2\x9C\x93.bin", 1ull << 40}};
    std::vector<uint8_t> enc = net::encodeFilePromiseAnnounce(in);
    std::vector<net::FilePromiseItem> out;
    SM_CHECK(net::decodeFilePromiseAnnounce(enc.data(), enc.size(), out));
    SM_CHECK_EQ(out.size(), in.size());
    for (std::size_t i = 0; i < out.size(); ++i) {
        SM_CHECK_EQ(out[i].name, in[i].name);
        SM_CHECK(out[i].size == in[i].size);
    }

    // Truncated payload -> clean rejection (never a misparse).
    SM_CHECK(!net::decodeFilePromiseAnnounce(enc.data(), enc.size() - 3, out));

    // Empty list encodes to just the count and decodes to nothing.
    std::vector<uint8_t> empty = net::encodeFilePromiseAnnounce({});
    SM_CHECK(net::decodeFilePromiseAnnounce(empty.data(), empty.size(), out));
    SM_CHECK_EQ(out.size(), static_cast<std::size_t>(0));

    // --- Mesh round-trip (spec 9): A announces, B is notified with source + list.
    smtest::LoopbackPair pp;
    app::MeshNode a("A"), b("B");
    a.addPeer("B", &pp.a);
    b.addPeer("A", &pp.b);

    core::PeerId gotFrom;
    std::vector<net::FilePromiseItem> gotFiles;
    b.onRemoteFilePromise = [&](const core::PeerId& from,
                                const std::vector<net::FilePromiseItem>& files) {
        gotFrom = from;
        gotFiles = files;
    };

    a.announceFilePromise({{"photo.jpg", 2048}, {"notes.txt", 12}});
    b.poll(100);

    SM_CHECK_EQ(gotFrom, std::string("A"));
    SM_CHECK_EQ(gotFiles.size(), static_cast<std::size_t>(2));
    if (gotFiles.size() == 2) {
        SM_CHECK_EQ(gotFiles[0].name, std::string("photo.jpg"));
        SM_CHECK(gotFiles[0].size == 2048);
        SM_CHECK_EQ(gotFiles[1].name, std::string("notes.txt"));
        SM_CHECK(gotFiles[1].size == 12);
    }
}
