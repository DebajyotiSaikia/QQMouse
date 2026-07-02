#include "app/secure_link.h"

#include "net/peer_hello.h"

#include <cstdint>
#include <utility>

namespace sm::app {

using sm::core::PeerId;
using sm::net::EncryptedTransport;
using sm::pairing::Psk;

// Psk is std::array<uint8_t, 32>, which is exactly the key type EncryptedTransport
// takes (crypto::kAesKeyLen == 32), so a paired PSK is used directly as the link key.

SecureLink secureOutbound(std::unique_ptr<sm::net::Transport> raw,
                          const sm::pairing::KeyStore& keys, const PeerId& self,
                          const PeerId& peer) {
    SecureLink link;
    if (!raw) return link;
    const Psk* psk = keys.getPsk(peer);
    if (!psk) return link; // not paired with `peer` -> transport stays null

    // Clear id-hint so the far end can select our PSK (id is not secret).
    const auto hint = sm::net::encodePeerHello(self);
    raw->send(hint.data(), hint.size());

    link.peerId = peer;
    link.transport = std::make_unique<EncryptedTransport>(
        std::move(raw), *psk, sm::net::linkRoleFor(self, peer));
    return link;
}

InboundHandshake::InboundHandshake(std::unique_ptr<sm::net::Transport> raw,
                                   const sm::pairing::KeyStore& keys, PeerId self)
    : raw_(std::move(raw)), keys_(keys), self_(std::move(self)) {}

InboundHandshake::Status InboundHandshake::poll() {
    if (status_ != Status::NeedMore) return status_;
    if (!raw_ || !raw_->isConnected()) {
        status_ = Status::Error;
        return status_;
    }

    uint8_t buf[512];
    const int n = raw_->recv(buf, sizeof(buf));
    if (n == 0) return Status::NeedMore; // id-hint hasn't arrived yet -> retry
    if (n < 0) {
        status_ = Status::Error;
        return status_;
    }

    PeerId claimed;
    if (!sm::net::decodePeerHello(buf, static_cast<std::size_t>(n), claimed) ||
        claimed.empty() || claimed == self_) {
        status_ = Status::Error; // junk / self-connection
        return status_;
    }
    const Psk* psk = keys_.getPsk(claimed);
    if (!psk) {
        status_ = Status::NotPaired; // caller isn't a paired device -> reject
        return status_;
    }

    result_.peerId = claimed;
    result_.transport = std::make_unique<EncryptedTransport>(
        std::move(raw_), *psk, sm::net::linkRoleFor(self_, claimed));
    status_ = Status::Ok;
    return status_;
}

SecureLink InboundHandshake::take() { return std::move(result_); }

} // namespace sm::app
