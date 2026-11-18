
#include "wirescope/tcp_tracker.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <utility>
#include <variant>

namespace wirescope {
namespace {

constexpr std::uint8_t tcp_flag_fin = 0x01U;
constexpr std::uint8_t tcp_flag_syn = 0x02U;
constexpr std::uint8_t tcp_flag_rst = 0x04U;
constexpr std::uint8_t tcp_flag_ack = 0x10U;

struct TcpPacketView {
    TcpEndpoint source;
    TcpEndpoint destination;
    const TcpInfo* tcp{};
};

// Extract TCP information from either IPv4 or IPv6.
[[nodiscard]] std::optional<TcpPacketView> extract_tcp_packet(
    const PacketSummary& packet
) {
    if (packet.ipv4.has_value()) {
        const auto& ip = *packet.ipv4;

        if (ip.transport.has_value()) {
            if (const auto* tcp =
                std::get_if<TcpInfo>(&*ip.transport)) {

                return TcpPacketView{
                    TcpEndpoint{ip.source_address, tcp->source_port},
                    TcpEndpoint{ip.destination_address, tcp->destination_port},
                    tcp
                };
            }
        }
    }

    if (packet.ipv6.has_value()) {
        const auto& ip = *packet.ipv6;

        if (ip.transport.has_value()) {
            if (const auto* tcp =
                std::get_if<TcpInfo>(&*ip.transport)) {

                return TcpPacketView{
                    TcpEndpoint{ip.source_address, tcp->source_port},
                    TcpEndpoint{ip.destination_address, tcp->destination_port},
                    tcp
                };
            }
        }
    }

    return std::nullopt;
}

// Convert a directional endpoint pair into a canonical key.
// Both A -> B and B -> A produce the same key.
[[nodiscard]] TcpConnectionKey make_connection_key(
    TcpEndpoint source,
    TcpEndpoint destination
) {
    if (destination < source) {
        std::swap(source, destination);
    }

    return TcpConnectionKey{
        std::move(source),
        std::move(destination)
    };
}

[[nodiscard]] bool has_flag(
    std::uint8_t flags,
    std::uint8_t mask
) noexcept {
    return (flags & mask) != 0U;
}

// Saturating addition prevents long-running captures from wrapping
// connection counters back to zero.
void add_counter(
    std::uint64_t& counter,
    std::uint64_t amount
) noexcept {
    if (amount > std::numeric_limits<std::uint64_t>::max() - counter) {
        counter = std::numeric_limits<std::uint64_t>::max();
        return;
    }

    counter += amount;
}

// Update the observed connection lifecycle.
void update_connection_state(
    TcpConnection& connection,
    const TcpEndpoint& source,
    std::uint8_t flags
) {
    const bool syn = has_flag(flags, tcp_flag_syn);
    const bool ack = has_flag(flags, tcp_flag_ack);
    const bool fin = has_flag(flags, tcp_flag_fin);
    const bool rst = has_flag(flags, tcp_flag_rst);

    // A reset terminates the observed connection.
    if (rst) {
        connection.state = TcpConnectionState::Reset;
        return;
    }

    // Once reset, ordinary packets don't revive this generation.
    if (connection.state == TcpConnectionState::Reset) {
        return;
    }

    // Observe an initial SYN.
    if (syn && !ack) {
        if (connection.state == TcpConnectionState::Midstream &&
            !connection.initiator.has_value()) {

            connection.initiator = source;
            connection.state = TcpConnectionState::SynSent;
        }
    }

    // Observe SYN-ACK.
    if (syn && ack) {
        if (connection.state == TcpConnectionState::Midstream &&
            !connection.initiator.has_value()) {

            // The destination is the presumed original initiator.
            // Its initial SYN wasn't present in our capture.
            connection.initiator =
                connection.key.first == source
                    ? connection.key.second
                    : connection.key.first;

            connection.state = TcpConnectionState::SynReceived;

        } else if (
            connection.state == TcpConnectionState::SynSent &&
            connection.initiator.has_value() &&
            source != *connection.initiator
        ) {
            connection.state = TcpConnectionState::SynReceived;
        }
    }

    // Observe the final ACK of a three-way handshake.
    if (
        ack &&
        !syn &&
        connection.state == TcpConnectionState::SynReceived &&
        connection.initiator.has_value() &&
        source == *connection.initiator
    ) {
        connection.state = TcpConnectionState::Established;
    }

    // Record FIN independently for each direction.
    if (fin) {
        if (source == connection.key.first) {
            connection.fin_from_a = true;
        } else {
            connection.fin_from_b = true;
        }

        connection.state =
            connection.fin_from_a && connection.fin_from_b
                ? TcpConnectionState::Closing
                : TcpConnectionState::FinWait;
    }
}

// Update traffic counters and timestamps.
void account_packet(
    TcpConnection& connection,
    const TcpEndpoint& source,
    std::uint8_t flags,
    std::size_t captured_length,
    std::uint64_t timestamp_microseconds
) {
    const std::uint64_t captured_bytes =
        static_cast<std::uint64_t>(captured_length);

    add_counter(connection.packet_count, 1U);
    add_counter(connection.captured_bytes, captured_bytes);

    // Preserve the earliest and latest observed timestamps even
    // if packets are supplied out of timestamp order.
    connection.first_seen_us =
        std::min(connection.first_seen_us, timestamp_microseconds);

    connection.last_seen_us =
        std::max(connection.last_seen_us, timestamp_microseconds);

    // Determine packet direction using the canonical endpoint order.
    if (source == connection.key.first) {
        add_counter(connection.packets_a_to_b, 1U);
        add_counter(connection.bytes_a_to_b, captured_bytes);
    } else {
        add_counter(connection.packets_b_to_a, 1U);
        add_counter(connection.bytes_b_to_a, captured_bytes);
    }

    const bool syn = has_flag(flags, tcp_flag_syn);
    const bool ack = has_flag(flags, tcp_flag_ack);
    const bool fin = has_flag(flags, tcp_flag_fin);
    const bool rst = has_flag(flags, tcp_flag_rst);

    if (syn) {
        add_counter(connection.syn_packets, 1U);
    }

    if (syn && ack) {
        add_counter(connection.syn_ack_packets, 1U);
    }

    if (ack) {
        add_counter(connection.ack_packets, 1U);
    }

    if (fin) {
        add_counter(connection.fin_packets, 1U);
    }

    if (rst) {
        add_counter(connection.rst_packets, 1U);
    }
}

} // namespace


// ============================================================
// Public tracker implementation
// ============================================================

void TcpConnectionTracker::observe(
    const PacketSummary& packet,
    std::uint64_t timestamp_microseconds
) {
    const auto observation = extract_tcp_packet(packet);

    // Ignore packets that don't contain a successfully decoded TCP header.
    if (!observation.has_value()) {
        return;
    }

    const TcpEndpoint& source = observation->source;
    const TcpEndpoint& destination = observation->destination;
    const TcpInfo& tcp = *observation->tcp;

    const std::uint8_t flags = tcp.flags;

    const bool syn = has_flag(flags, tcp_flag_syn);
    const bool ack = has_flag(flags, tcp_flag_ack);
    const bool rst = has_flag(flags, tcp_flag_rst);

    const TcpConnectionKey key =
        make_connection_key(source, destination);

    auto active = active_connections_.find(key);

    bool create_new_generation = active == active_connections_.end();

    // A new initial SYN after a reset or completed two-sided FIN
    // sequence represents a new observed connection generation.
    if (!create_new_generation && syn && !ack && !rst) {
        const TcpConnection& previous =
            connections_[active->second];

        if (
            previous.state == TcpConnectionState::Reset ||
            previous.state == TcpConnectionState::Closing
        ) {
            create_new_generation = true;
        }
    }

    std::size_t connection_index{};

    if (create_new_generation) {
        TcpConnection connection;

        connection.id = next_connection_id_++;
        connection.key = key;
        connection.state = TcpConnectionState::Midstream;
        connection.first_seen_us = timestamp_microseconds;
        connection.last_seen_us = timestamp_microseconds;

        connection_index = connections_.size();

        connections_.push_back(std::move(connection));

        active_connections_[key] = connection_index;
    } else {
        connection_index = active->second;
    }

    TcpConnection& connection = connections_[connection_index];

    account_packet(
        connection,
        source,
        flags,
        packet.captured_length,
        timestamp_microseconds
    );

    update_connection_state(
        connection,
        source,
        flags
    );
}

const std::vector<TcpConnection>&
TcpConnectionTracker::connections() const noexcept {
    return connections_;
}

std::size_t TcpConnectionTracker::size() const noexcept {
    return connections_.size();
}

void TcpConnectionTracker::clear() noexcept {
    connections_.clear();
    active_connections_.clear();
    next_connection_id_ = 1U;
}


// ============================================================
// State formatting
// ============================================================

const char* tcp_connection_state_name(
    TcpConnectionState state
) noexcept {
    switch (state) {
        case TcpConnectionState::SynSent:
            return "SYN_SENT";

        case TcpConnectionState::SynReceived:
            return "SYN_RECEIVED";

        case TcpConnectionState::Established:
            return "ESTABLISHED";

        case TcpConnectionState::Midstream:
            return "MIDSTREAM";

        case TcpConnectionState::FinWait:
            return "FIN_WAIT";

        case TcpConnectionState::Closing:
            return "CLOSING";

        case TcpConnectionState::Reset:
            return "RESET";
    }

    return "UNKNOWN";
}

} // namespace wirescope
