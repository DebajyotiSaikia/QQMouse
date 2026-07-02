#include "app/mesh_node.h"

#include "net/message_codec.h"
#include "net/ownership_codec.h"

namespace sm::app {

using sm::core::InputEvent;
using sm::core::MessageType;
using sm::core::OwnershipClaim;
using sm::core::PeerId;
using sm::core::kProtocolVersion;

MeshNode::MeshNode(PeerId self) : self_(std::move(self)), ownership_(self_) {
    election_.addToPriority(self_); // self is eligible to be coordinator by default
}

void MeshNode::setPriority(const std::vector<PeerId>& priority) {
    election_.setPriority(priority);
}

std::optional<PeerId> MeshNode::primary() const { return election_.currentServer(); }

void MeshNode::addPeer(const PeerId& id, sm::net::Transport* transport) {
    peers_[id] = transport;
    election_.addToPriority(id); // new pairings append at lowest priority (11.5)
}

void MeshNode::removePeer(const PeerId& id) {
    peers_.erase(id);
    heartbeat_.forget(id);
    auto it = peerOnline_.find(id);
    if (it != peerOnline_.end()) {
        const bool wasOnline = it->second;
        peerOnline_.erase(it);
        if (wasOnline && onPeerOffline) onPeerOffline(id);
    }
    versionWarned_.erase(id); // a fresh connection may warn again if still mismatched
    refreshOnlineAndFailSafe(now_);
}

bool MeshNode::isPeerOnline(const PeerId& id) const {
    if (id == self_) return true;
    return heartbeat_.isAlive(id, now_, heartbeatTimeoutMs);
}

void MeshNode::requestSwitchTo(const PeerId& target) {
    // Switching to an unreachable machine is a no-op, never a hang (spec 15). Self
    // is always reachable; the fail-safe revert calls ownership_ directly and so is
    // unaffected by this guard.
    if (target != self_ && !isPeerOnline(target)) {
        if (onSwitchUnavailable) onSwitchUnavailable(target);
        return;
    }
    PeerId before = ownership_.owner();
    OwnershipClaim claim = ownership_.requestSwitchTo(target);
    auto payload = sm::net::encodeOwnershipClaim(claim);
    broadcast(sm::net::encodeVarMessage(MessageType::SwitchOwner, payload.data(), payload.size()));
    if (ownership_.owner() != before && onOwnerChanged) onOwnerChanged(ownership_.owner());
}

void MeshNode::forwardMouseMove(int16_t dx, int16_t dy, uint32_t ts) {
    if (!ownership_.isLocalOwner()) return;
    broadcast(pipeline_.onMouseMove(dx, dy, ts));
}

void MeshNode::forwardMouseButton(uint8_t button, bool down, uint32_t ts) {
    if (!ownership_.isLocalOwner()) return;
    broadcast(pipeline_.onMouseButton(button, down, ts));
}

void MeshNode::forwardKey(uint8_t code, bool down, uint32_t ts) {
    if (!ownership_.isLocalOwner()) return;
    broadcast(pipeline_.onKey(code, down, ts));
}

void MeshNode::releaseHeldKeys(uint32_t ts) {
    for (const auto& m : pipeline_.releaseAll(ts)) broadcast(m);
}

void MeshNode::onLocalClipboardChange(const std::string& text) {
    if (!clipboard_.shouldBroadcastLocalChange(text)) return;
    broadcast(sm::net::encodeVarMessage(MessageType::ClipboardUpdate,
                                        reinterpret_cast<const uint8_t*>(text.data()),
                                        text.size()));
}

void MeshNode::sendHeartbeats(uint64_t now_ms) {
    now_ = now_ms;
    if (lastHeartbeatSent_ != 0 && now_ms - lastHeartbeatSent_ < heartbeatIntervalMs) return;
    InputEvent hb{};
    hb.protocol_version = kProtocolVersion;
    hb.type = static_cast<uint8_t>(MessageType::Heartbeat);
    hb.timestamp_ms = static_cast<uint32_t>(now_ms);
    broadcast(sm::net::encodeInputEvent(hb));
    lastHeartbeatSent_ = now_ms;
}

void MeshNode::poll(uint64_t now_ms) {
    now_ = now_ms;
    uint8_t buf[8192];
    for (auto& kv : peers_) {
        sm::net::Transport* t = kv.second;
        if (!t) continue;
        for (;;) {
            int n = t->recv(buf, sizeof(buf));
            if (n <= 0) break;
            handle(kv.first, buf, static_cast<std::size_t>(n), now_ms);
        }
    }
    refreshOnlineAndFailSafe(now_ms);
}

void MeshNode::broadcast(const std::vector<uint8_t>& msg) {
    for (auto& kv : peers_) {
        if (kv.second) kv.second->send(msg.data(), msg.size());
    }
}

void MeshNode::handle(const PeerId& from, const uint8_t* data, std::size_t len, uint64_t now) {
    // Any message proves the sender is alive.
    heartbeat_.onHeartbeat(from, now);

    sm::net::DecodedMessage m;
    std::size_t consumed = 0;
    auto r = sm::net::decodeMessage(data, len, m, consumed);
    if (r == sm::net::DecodeResult::VersionMismatch) {
        // Surface once per peer so the user updates the other machine (spec 15).
        if (versionWarned_.insert(from).second && onVersionMismatch) onVersionMismatch(from);
        return;
    }
    if (r != sm::net::DecodeResult::Ok) return; // malformed / incomplete -> drop

    if (m.isFixed) {
        switch (m.type) {
            case MessageType::Heartbeat:
                break; // liveness already recorded
            case MessageType::MouseMove:
            case MessageType::MouseButton:
            case MessageType::KeyEvent:
                // Sinks inject forwarded input from the current owner.
                if (!ownership_.isLocalOwner() && onInject) onInject(m.fixed);
                break;
            default:
                break;
        }
        return;
    }

    switch (m.type) {
        case MessageType::SwitchOwner: {
            OwnershipClaim claim;
            if (sm::net::decodeOwnershipClaim(m.payload.data(), m.payload.size(), claim)) {
                PeerId before = ownership_.owner();
                ownership_.applyClaim(claim);
                if (ownership_.owner() != before && onOwnerChanged)
                    onOwnerChanged(ownership_.owner());
            }
            break;
        }
        case MessageType::ClipboardUpdate: {
            std::string text(m.payload.begin(), m.payload.end());
            clipboard_.noteAppliedRemote(text);
            if (onRemoteClipboard) onRemoteClipboard(text);
            break;
        }
        default:
            break; // FilePromiseMeta / FileChunk / PairingMsg handled elsewhere
    }
}

void MeshNode::refreshOnlineAndFailSafe(uint64_t now) {
    std::vector<PeerId> online;
    online.push_back(self_);
    for (auto& kv : peers_) {
        const bool alive = heartbeat_.isAlive(kv.first, now, heartbeatTimeoutMs);
        if (alive) online.push_back(kv.first);
        // Emit a one-time transition callback whenever a peer's liveness flips.
        auto it = peerOnline_.find(kv.first);
        const bool prev = (it != peerOnline_.end()) && it->second;
        if (alive != prev) {
            peerOnline_[kv.first] = alive;
            if (alive) {
                if (onPeerOnline) onPeerOnline(kv.first);
            } else {
                if (onPeerOffline) onPeerOffline(kv.first);
            }
        }
    }
    election_.setOnline(online);

    // Fail-safe: if the current (remote) owner has gone silent, revert to local
    // control immediately. This is a LOCAL revert with no broadcast -- every sink
    // independently takes back its own input during the outage (spec 15: "every
    // listening machine immediately reverts to normal local input"). A later
    // explicit switch re-establishes a single mesh-wide owner.
    if (!ownership_.isLocalOwner() &&
        !heartbeat_.isAlive(ownership_.owner(), now, heartbeatTimeoutMs)) {
        ownership_.requestSwitchTo(self_);
        if (onOwnerChanged) onOwnerChanged(self_);
    }
}

} // namespace sm::app
