#pragma once

// In-memory message-oriented Transport pair for headless e2e tests. Each endpoint's
// send() enqueues a whole message into the peer's inbox; recv() pops one. This lets
// the app logic be driven end-to-end through the real sm::net::Transport interface
// without any sockets (spec 5.5: everything above the transport is backend-agnostic).

#include "net/transport.h"

#include <cstring>
#include <deque>
#include <vector>

namespace smtest {

class LoopbackEndpoint : public sm::net::Transport {
public:
    bool connect(const std::string&, uint16_t) override {
        connected_ = true;
        return true;
    }
    bool isConnected() const override { return connected_; }

    bool send(const uint8_t* data, std::size_t len) override {
        if (!connected_ || !peerInbox_) return false;
        peerInbox_->emplace_back(data, data + len);
        return true;
    }

    int recv(uint8_t* buf, std::size_t cap) override {
        if (!inbox_ || inbox_->empty()) return 0;
        std::vector<uint8_t>& msg = inbox_->front();
        std::size_t n = msg.size() <= cap ? msg.size() : cap;
        std::memcpy(buf, msg.data(), n);
        inbox_->pop_front();
        return static_cast<int>(n);
    }

    void close() override { connected_ = false; }

    std::deque<std::vector<uint8_t>>* inbox_ = nullptr;
    std::deque<std::vector<uint8_t>>* peerInbox_ = nullptr;
    bool connected_ = false;
};

class LoopbackPair {
public:
    LoopbackPair() {
        a.inbox_ = &qA;
        a.peerInbox_ = &qB;
        a.connected_ = true;
        b.inbox_ = &qB;
        b.peerInbox_ = &qA;
        b.connected_ = true;
    }

    LoopbackEndpoint a, b;

private:
    std::deque<std::vector<uint8_t>> qA, qB;
};

} // namespace smtest
