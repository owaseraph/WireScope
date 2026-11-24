#pragma once
#include "wirescope/common.hpp"
#include "wirescope/decoder.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace wirescope {
enum class TcpState { Unknown, SynSent, SynReceived, Established, FinWait, CloseWait, TimeWait, Closed, Reset, Midstream };
[[nodiscard]] const char* tcp_state_name(TcpState state) noexcept;
struct TcpConnection {
    std::uint64_t id{};
    Endpoint a, b;
    Endpoint initiator;
    bool has_initiator{};
    std::uint32_t initial_syn_sequence{};
    bool has_syn_sequence{};
    TcpState state_a{TcpState::Unknown}, state_b{TcpState::Unknown};
    std::uint64_t first_seen_us{}, last_seen_us{}, packets{}, bytes{};
    std::uint64_t packets_a_to_b{}, packets_b_to_a{}, bytes_a_to_b{}, bytes_b_to_a{};
    std::uint64_t syn{}, syn_ack{}, ack{}, fin{}, rst{};
    bool expired{};
};
class TcpConnectionTracker {
public:
    void observe(const PacketSummary& packet, std::uint64_t timestamp_us);
    [[nodiscard]] std::size_t expire_idle(std::uint64_t now_us, std::uint64_t timeout_us);
    [[nodiscard]] const std::vector<TcpConnection>& connections() const noexcept { return connections_; }
    [[nodiscard]] std::size_t size() const noexcept { return connections_.size(); }
    [[nodiscard]] std::size_t active_size() const noexcept { return active_.size(); }
private:
    struct Key { Endpoint a,b; friend bool operator<(const Key& x,const Key& y) { return x.a<y.a || (!(y.a<x.a)&&x.b<y.b); } };
    std::vector<TcpConnection> connections_;
    std::map<Key,std::size_t> active_;
    std::uint64_t next_id_{1};
};
}
