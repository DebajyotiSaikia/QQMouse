#include "net/file_promise_announce.h"

#include <cstring>

namespace sm::net {

namespace {
void put16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v & 0xFF));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}
void put32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
void put64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}
} // namespace

std::vector<uint8_t> encodeFilePromiseAnnounce(const std::vector<FilePromiseItem>& files) {
    std::vector<uint8_t> b;
    put32(b, static_cast<uint32_t>(files.size()));
    for (const auto& f : files) {
        const uint16_t nlen = static_cast<uint16_t>(f.name.size() > 0xFFFF ? 0xFFFF : f.name.size());
        put16(b, nlen);
        b.insert(b.end(), f.name.begin(), f.name.begin() + nlen);
        put64(b, f.size);
    }
    return b;
}

bool decodeFilePromiseAnnounce(const uint8_t* data, std::size_t len,
                               std::vector<FilePromiseItem>& out) {
    out.clear();
    std::size_t p = 0;
    auto need = [&](std::size_t n) { return p + n <= len; };
    if (!need(4)) return false;
    uint32_t count = 0;
    for (int i = 0; i < 4; ++i) count |= static_cast<uint32_t>(data[p++]) << (8 * i);
    for (uint32_t i = 0; i < count; ++i) {
        if (!need(2)) return false;
        uint16_t nlen = static_cast<uint16_t>(data[p] | (data[p + 1] << 8));
        p += 2;
        if (!need(nlen)) return false;
        FilePromiseItem it;
        it.name.assign(reinterpret_cast<const char*>(data + p), nlen);
        p += nlen;
        if (!need(8)) return false;
        uint64_t size = 0;
        for (int k = 0; k < 8; ++k) size |= static_cast<uint64_t>(data[p++]) << (8 * k);
        it.size = size;
        out.push_back(std::move(it));
    }
    return true;
}

} // namespace sm::net
