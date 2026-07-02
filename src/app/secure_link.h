#pragma once

// Secure link establishment (spec 5.2, 7.2). Resolves the one routine question a
// peer-mesh has when a socket connects: which paired PSK secures this link, and who
// is on the other end? Pairing (spec 7) already derived a long-term PSK per device
// pair, stored in the KeyStore. Here:
//
//   - the connector announces its own id in the CLEAR (the id is not secret -- the
//     discovery beacon already broadcasts it) so the acceptor can select the PSK;
//   - both ends then seal the link with that PSK via EncryptedTransport, and every
//     subsequent AES-256-GCM frame cryptographically PROVES the peer holds the PSK.
//     An imposter that lacks the PSK cannot produce an authentic frame and is
//     rejected at the mesh's first encrypted hello -- so the clear id-hint is only a
//     routing hint, never a trust decision.
//
// PURE LOGIC over Transport + KeyStore + EncryptedTransport: the OS layer supplies
// the connected/accepted raw socket; unit-testable with a loopback transport.

#include <memory>

#include "core/peer_id.h"
#include "net/encrypted_transport.h"
#include "net/transport.h"
#include "pairing/key_store.h"

namespace sm::app {

struct SecureLink {
    sm::core::PeerId peerId;                              // the confirmed peer
    std::unique_ptr<sm::net::EncryptedTransport> transport; // sealed; owns the socket
};

// Outbound: we dialed a KNOWN peer. Announce our id in the clear, then seal the link
// with the paired PSK. `transport` is null (not paired) if we hold no PSK for `peer`.
SecureLink secureOutbound(std::unique_ptr<sm::net::Transport> raw,
                          const sm::pairing::KeyStore& keys,
                          const sm::core::PeerId& self, const sm::core::PeerId& peer);

// Inbound: identity is unknown until the connector's clear id-hint arrives. Poll
// until the status is no longer NeedMore, then take() the sealed link on Ok.
class InboundHandshake {
public:
    enum class Status { NeedMore, Ok, NotPaired, Error };

    InboundHandshake(std::unique_ptr<sm::net::Transport> raw,
                     const sm::pairing::KeyStore& keys, sm::core::PeerId self);

    Status poll();     // read the id-hint if present; seal the link once known
    Status status() const { return status_; }
    SecureLink take(); // valid once poll() has returned Ok

private:
    std::unique_ptr<sm::net::Transport> raw_;
    const sm::pairing::KeyStore& keys_;
    sm::core::PeerId self_;
    SecureLink result_;
    Status status_ = Status::NeedMore;
};

} // namespace sm::app
