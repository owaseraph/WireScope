
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

// TCP endpoint

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


// Bidirectional connection identifier

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


// Connection lifecycle

enum class TcpConnectionState {
    SynSent,
    SynReceived,
    Established,
    Midstream,
    FinWait,
    Closing,
    Reset
};


// Tracked TCP connection

struct TcpConnection {
    // Unique identifier for this observed connection generation.
    std::uint64_t id{};

    // Canonically ordered endpoints.
    TcpConnectionKey key;

    // Known only when we observe the initial SYN.
    std::optional<TcpEndpoint> initiator;

    TcpConnectionState state{TcpConnectionState::Midstream};

    // Capture timestamps, measured in microseconds.
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

    // Tracks which direction has sent FIN.
    bool fin_from_a{};
    bool fin_from_b{};
};


// TCP connection tracker

class TcpConnectionTracker {
public:

    // Observe a decoded packet and update its TCP connection.
    // timestamp_microseconds comes from the PCAP timestamp.
    void observe(
        const PacketSummary& packet,
        std::uint64_t timestamp_microseconds
    );

    // Access all tracked connection generations.
    [[nodiscard]] const std::vector<TcpConnection>& connections() const noexcept;

    // Number of tracked connection generations.
    [[nodiscard]] std::size_t size() const noexcept;

    // Remove all tracked connections and reset the ID counter.
    void clear() noexcept;

private:

    // All observed connections, including completed/reset ones.
    std::vector<TcpConnection> connections_;

    // Maps a canonical endpoint pair to its current connection.
    // The value is an index into connections_.
    std::map<TcpConnectionKey, std::size_t> active_connections_;

    // Monotonically increasing connection identifier.
    std::uint64_t next_connection_id_{1U};
};



// Utility

[[nodiscard]] const char* tcp_connection_state_name(
    TcpConnectionState state
) noexcept;

} // namespace wirescope
