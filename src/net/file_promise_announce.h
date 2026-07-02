#pragma once

// File-promise announcement codec (spec 9). When a machine copies files, it tells the
// mesh "I now hold these files" over the input channel so the destination can put a
// matching delay-render promise on ITS clipboard (the destination pulls the bytes on
// paste over the on-demand /files channel). This is only the small names+sizes notice;
// the bytes themselves ride net/FileChannel. PURE LOGIC, unit-tested.
//
// Payload layout (little-endian, after the VarHeader added by encodeVarMessage):
//   [count:4]  then per file:  [name_len:2][name bytes][size:8]

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace sm::net {

struct FilePromiseItem {
    std::string name;  // display name, no path
    uint64_t size = 0; // total bytes
};

// Encode the item list into a FilePromiseAnnounce payload (without the VarHeader --
// pass the result to encodeVarMessage(FilePromiseAnnounce, ...)).
std::vector<uint8_t> encodeFilePromiseAnnounce(const std::vector<FilePromiseItem>& files);

// Decode a FilePromiseAnnounce payload. Returns false on truncation/overflow.
bool decodeFilePromiseAnnounce(const uint8_t* data, std::size_t len,
                               std::vector<FilePromiseItem>& out);

} // namespace sm::net
