
#pragma once

#include "wirescope/decoder.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace wirescope {

// 
// TCP endpoint
// 

struct TcpEndpoint {
    std::string address;
    std::uint16_t port{};

    friend bool operator==(
        const TcpEndpoint& lhs,
        const TcpEndpoint& rhs
    ) = default;

    friend bool operator<(
        const TcpEndpoint& lhs,
        const TcpEndpoint& rhs
    ) {
        return std::tie(lhs.address, lhs.port) <
               std::tie(rhs.address, rhs.port);
    }
};


// 
// Bidirectional connection identifier
// 

struct TcpConnectionKey {
    TcpEndpoint first;
    TcpEndpoint second;

    friend bool operator==(
        const TcpConnectionKey& lhs,
        const TcpConnectionKey& rhs
    ) = default;

    friend bool operator<(
        const TcpConnectionKey& lhs,
        const TcpConnectionKey& rhs
    ) {
        return std::tie(lhs.first, lhs.second) <
               std::tie(rhs.first, rhs.second);
    }
};


// 
// Individual TCP endpoint state
// 

enum class TcpEndpointState {
    Unknown,
    Midstream,

    SynSent,
    SynReceived,
    Established,

    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,

    Reset
};


// 
// Tracked TCP connection
// 

struct TcpConnection {

    // Unique connection generation identifier.
    std::uint64_t id{};

    // Canonically ordered endpoints.
    TcpConnectionKey key;

    // Original SYN sender, when observed or inferred.
    std::optional<TcpEndpoint> initiator;

    // Each endpoint maintains its own TCP state.
    TcpEndpointState state_a{TcpEndpointState::Unknown};
    TcpEndpointState state_b{TcpEndpointState::Unknown};

    // Capture timestamps in microseconds.
    std::uint64_t first_seen_us{};
    std::uint64_t last_seen_us{};

    // Total traffic.
    std::uint64_t packet_count{};
    std::uint64_t captured_bytes{};

    // Directional traffic.
    std::uint64_t packets_a_to_b{};
    std::uint64_t packets_b_to_a{};

    std::uint64_t bytes_a_to_b{};
    std::uint64_t bytes_b_to_a{};

    // TCP control flag counters.
    std::uint64_t syn_packets{};
    std::uint64_t syn_ack_packets{};
    std::uint64_t ack_packets{};
    std::uint64_t fin_packets{};
    std::uint64_t rst_packets{};

    // FIN tracking.
    bool fin_from_a{};
    bool fin_from_b{};

    // Sequence number immediately following each observed FIN.
    // FIN consumes one sequence number.
    std::uint32_t fin_end_sequence_a{};
    std::uint32_t fin_end_sequence_b{};

    // Whether the opposite endpoint acknowledged each FIN.
    bool fin_acked_by_a{};
    bool fin_acked_by_b{};

    // True when this generation has been removed from active tracking.
    bool expired{};
};


// 
// TCP connection tracker
// 

class TcpConnectionTracker {
public:

    // Observe a decoded TCP packet.
    void observe(
        const PacketSummary& packet,
        std::uint64_t timestamp_microseconds
    );

    // Expire connections that have been idle for at least
    // idle_timeout_microseconds.
    //
    // Expired records remain available through connections(),
    // but are removed from the active connection index.
    //
    // Returns the number of connections expired.
    [[nodiscard]] std::size_t expire_idle(
        std::uint64_t current_time_us,
        std::uint64_t idle_timeout_microseconds
    );

    // Access all connection generations, including expired ones.
    [[nodiscard]] const std::vector<TcpConnection>&
    connections() const noexcept;

    // Total historical connection generations.
    [[nodiscard]] std::size_t size() const noexcept;

    // Number of currently indexed connections.
    [[nodiscard]] std::size_t active_size() const noexcept;

    // Clear all connection records and reset identifiers.
    void clear() noexcept;

private:

    // All observed connection generations.
    std::vector<TcpConnection> connections_;

    // Active connection lookup.
    // Value is an index into connections_.
    std::map<TcpConnectionKey, std::size_t> active_connections_;

    // Monotonically increasing identifier.
    std::uint64_t next_connection_id_{1U};
};


// 
// State formatting
// 

[[nodiscard]] const char* tcp_endpoint_state_name(
    TcpEndpointState state
) noexcept;

} // namespace wirescope
