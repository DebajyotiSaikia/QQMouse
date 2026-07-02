#pragma once

// Peer-mesh application logic for one machine (spec 2.1, 11, 12, 15). PURE LOGIC:
// ties together ownership (11), coordinator election (11.5), the heartbeat
// watchdog / fail-safe (15), clipboard sync (8), and owner-side input forwarding
// (3.1/5.1) over the abstract Transport (5.5). The OS layer supplies a Transport
// per peer and callbacks for injection / clipboard writes; everything here is
// deterministic and unit-testable with a loopback transport and an injected clock.

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "core/clipboard_sync.h"
#include "core/event_types.h"
#include "core/heartbeat.h"
#include "core/input_pipeline.h"
#include "core/ownership_state.h"
#include "core/peer_id.h"
#include "core/server_election.h"
#include "net/file_promise_announce.h"
#include "net/transport.h"

namespace sm::app {

class MeshNode {
public:
    explicit MeshNode(sm::core::PeerId self);

    const sm::core::PeerId& self() const { return self_; }

    // Coordinator priority list (spec 11.5). index 0 = highest.
    void setPriority(const std::vector<sm::core::PeerId>& priority);
    std::optional<sm::core::PeerId> primary() const;

    // The OS layer registers one Transport per peer (not owned by the node).
    void addPeer(const sm::core::PeerId& id, sm::net::Transport* transport);
    void removePeer(const sm::core::PeerId& id);
    bool isPeerOnline(const sm::core::PeerId& id) const;

    // Ownership (spec 11). A switch broadcasts a claim to EVERY peer (11.2).
    bool isLocalOwner() const { return ownership_.isLocalOwner(); }
    sm::core::PeerId owner() const { return ownership_.owner(); }
    void requestSwitchTo(const sm::core::PeerId& target);

    // Owner-side input forwarding (no-op unless this machine currently owns input).
    void forwardMouseMove(int16_t dx, int16_t dy, uint32_t ts);
    void forwardMouseButton(uint8_t button, bool down, uint32_t ts);
    void forwardKey(uint8_t code, bool down, uint32_t ts);
    void releaseHeldKeys(uint32_t ts); // stuck-key release on switch-out (spec 4.4)

    // Clipboard (spec 8): broadcast a local change unless it echoes a remote write.
    void onLocalClipboardChange(const std::string& text);

    // File promise (spec 9): tell every peer "I copied these files" so the machine the
    // user pastes on can offer them. Bytes are pulled later over the /files channel.
    void announceFilePromise(const std::vector<sm::net::FilePromiseItem>& files);

    // Pump network input, update liveness, and enforce fail-safe (spec 15).
    void poll(uint64_t now_ms);
    // Broadcast a heartbeat if the interval has elapsed.
    void sendHeartbeats(uint64_t now_ms);

    // OS-layer hooks.
    std::function<void(const sm::core::InputEvent&)> onInject;   // sink injects this
    std::function<void(const std::string&)> onRemoteClipboard;   // write to OS clipboard
    std::function<void(const sm::core::PeerId&)> onOwnerChanged;

    // A peer announced copied files (spec 9): (source peer, file list). The OS layer
    // puts a matching delay-render promise on the local clipboard.
    std::function<void(const sm::core::PeerId&, const std::vector<sm::net::FilePromiseItem>&)>
        onRemoteFilePromise;

    // Connection-state transitions, each fired EXACTLY ONCE per change (spec 15:
    // a one-time notification on drop, not a repeating one). A peer that is removed
    // while online also fires onPeerOffline.
    std::function<void(const sm::core::PeerId&)> onPeerOnline;
    std::function<void(const sm::core::PeerId&)> onPeerOffline;
    // Fired when a switch is requested to a peer that is currently unreachable; the
    // switch is a no-op (spec 15: never a hang), and the UI can flash "unavailable".
    std::function<void(const sm::core::PeerId&)> onSwitchUnavailable;
    // Fired once per peer when it sends a message with a mismatched protocol version
    // (spec 15: "update Skittermouse on <machine>", never a silent misparse).
    std::function<void(const sm::core::PeerId&)> onVersionMismatch;

    uint64_t heartbeatTimeoutMs = 2000;
    uint64_t heartbeatIntervalMs = 500;

private:
    void broadcast(const std::vector<uint8_t>& msg);
    void handle(const sm::core::PeerId& from, const uint8_t* data, std::size_t len, uint64_t now);
    void refreshOnlineAndFailSafe(uint64_t now);

    sm::core::PeerId self_;
    std::map<sm::core::PeerId, sm::net::Transport*> peers_;
    std::map<sm::core::PeerId, bool> peerOnline_; // last-known liveness, for transitions
    std::set<sm::core::PeerId> versionWarned_;    // peers already flagged as mismatched
    sm::core::OwnershipState ownership_;
    sm::core::ServerElection election_;
    sm::core::Heartbeat heartbeat_;
    sm::core::ClipboardSync clipboard_;
    sm::core::InputPipeline pipeline_;
    uint64_t now_ = 0;
    uint64_t lastHeartbeatSent_ = 0;
};

} // namespace sm::app
