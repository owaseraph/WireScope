
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

constexpr std::size_t ipv6_base_header_length = 40U;

// 
// Extract TCP packet information
// 

struct TcpPacketView {
    TcpEndpoint source;
    TcpEndpoint destination;
    const TcpInfo* tcp{};
};

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


// 
// Connection identification
// 

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


// 
// Counter handling
// 

void add_counter(
    std::uint64_t& counter,
    std::uint64_t amount
) noexcept {
    if (amount >
        std::numeric_limits<std::uint64_t>::max() - counter) {

        counter = std::numeric_limits<std::uint64_t>::max();
        return;
    }

    counter += amount;
}


// 
// Endpoint helpers
// 

[[nodiscard]] TcpEndpointState& state_for(
    TcpConnection& connection,
    const TcpEndpoint& endpoint
) noexcept {
    return endpoint == connection.key.first
        ? connection.state_a
        : connection.state_b;
}

[[nodiscard]] const TcpEndpoint& peer_of(
    const TcpConnection& connection,
    const TcpEndpoint& endpoint
) noexcept {
    return endpoint == connection.key.first
        ? connection.key.second
        : connection.key.first;
}


// 
// TCP sequence number handling
// 

[[nodiscard]] bool sequence_at_or_after(
    std::uint32_t acknowledgement,
    std::uint32_t sequence
) noexcept {
    // TCP sequence numbers use modulo 2^32 arithmetic.
    // This comparison is valid within half of the sequence space.

    return static_cast<std::uint32_t>(
        acknowledgement - sequence
    ) < 0x80000000U;
}


// 
// TCP payload length
// 

[[nodiscard]] std::uint32_t tcp_payload_length(
    const PacketSummary& packet,
    const TcpInfo& tcp
) noexcept {
    std::size_t transport_length = 0U;

    if (packet.ipv4.has_value()) {
        const auto& ip = *packet.ipv4;

        const std::size_t ip_header_length = ip.header_length;
        const std::size_t total_length = ip.total_length;

        if (total_length < ip_header_length) {
            return 0U;
        }

        transport_length = total_length - ip_header_length;

    } else if (packet.ipv6.has_value()) {
        const auto& ip = *packet.ipv6;

        if (ip.header_length < ipv6_base_header_length) {
            return 0U;
        }

        const std::size_t extension_length =
            ip.header_length - ipv6_base_header_length;

        const std::size_t payload_length = ip.payload_length;

        if (payload_length < extension_length) {
            return 0U;
        }

        transport_length = payload_length - extension_length;

    } else {
        return 0U;
    }

    if (transport_length < tcp.header_length) {
        return 0U;
    }

    const std::size_t payload_length =
        transport_length - tcp.header_length;

    return static_cast<std::uint32_t>(payload_length);
}


// 
// Connection generation helpers
// 

[[nodiscard]] bool is_terminal_state(
    TcpEndpointState state
) noexcept {
    return state == TcpEndpointState::TimeWait ||
           state == TcpEndpointState::Closed ||
           state == TcpEndpointState::Reset;
}

[[nodiscard]] bool is_finished_generation(
    const TcpConnection& connection
) noexcept {
    if (connection.state_a == TcpEndpointState::Reset ||
        connection.state_b == TcpEndpointState::Reset) {

        return true;
    }

    return is_terminal_state(connection.state_a) &&
           is_terminal_state(connection.state_b);
}

void set_midstream_if_unknown(
    TcpConnection& connection
) noexcept {
    if (connection.state_a == TcpEndpointState::Unknown &&
        connection.state_b == TcpEndpointState::Unknown) {

        connection.state_a = TcpEndpointState::Midstream;
        connection.state_b = TcpEndpointState::Midstream;
    }
}


// 
// TCP handshake tracking
// 

void update_handshake(
    TcpConnection& connection,
    const TcpEndpoint& source,
    const TcpEndpoint& destination,
    std::uint8_t flags
) {
    const bool syn = has_flag(flags, tcp_flag_syn);
    const bool ack = has_flag(flags, tcp_flag_ack);

    TcpEndpointState& source_state =
        state_for(connection, source);

    TcpEndpointState& destination_state =
        state_for(connection, destination);

    // Initial SYN.
    if (syn && !ack) {
        if (!connection.initiator.has_value()) {
            connection.initiator = source;

            source_state = TcpEndpointState::SynSent;

            if (destination_state == TcpEndpointState::Midstream) {
                destination_state = TcpEndpointState::Unknown;
            }
        }

        return;
    }

    // SYN-ACK.
    if (syn && ack) {
        if (!connection.initiator.has_value()) {
            // The initial SYN wasn't captured.
            connection.initiator = destination;
            destination_state = TcpEndpointState::SynSent;
        }

        if (connection.initiator.has_value() &&
            destination == *connection.initiator) {

            source_state = TcpEndpointState::SynReceived;
        }

        return;
    }

    // Final ACK of the handshake.
    if (
        ack &&
        !syn &&
        connection.initiator.has_value() &&
        source == *connection.initiator &&
        source_state == TcpEndpointState::SynSent &&
        destination_state == TcpEndpointState::SynReceived
    ) {
        source_state = TcpEndpointState::Established;
        destination_state = TcpEndpointState::Established;
    }
}


// 
// FIN acknowledgement tracking
// 

void acknowledge_peer_fin(
    TcpConnection& connection,
    const TcpEndpoint& source,
    std::uint32_t acknowledgement_number
) noexcept {
    const bool source_is_a =
        source == connection.key.first;

    const bool peer_fin_seen = source_is_a
        ? connection.fin_from_b
        : connection.fin_from_a;

    const bool peer_fin_already_acked = source_is_a
        ? connection.fin_acked_by_a
        : connection.fin_acked_by_b;

    const std::uint32_t peer_fin_end = source_is_a
        ? connection.fin_end_sequence_b
        : connection.fin_end_sequence_a;

    if (
        !peer_fin_seen ||
        peer_fin_already_acked ||
        !sequence_at_or_after(
            acknowledgement_number,
            peer_fin_end
        )
    ) {
        return;
    }

    // Record that this endpoint acknowledged the peer's FIN.
    if (source_is_a) {
        connection.fin_acked_by_a = true;
    } else {
        connection.fin_acked_by_b = true;
    }

    TcpEndpointState& fin_sender_state =
        state_for(connection, peer_of(connection, source));

    // Advance the state of the endpoint whose FIN was acknowledged.
    switch (fin_sender_state) {
        case TcpEndpointState::FinWait1:
            fin_sender_state = TcpEndpointState::FinWait2;
            break;

        case TcpEndpointState::Closing:
            fin_sender_state = TcpEndpointState::TimeWait;
            break;

        case TcpEndpointState::LastAck:
            fin_sender_state = TcpEndpointState::Closed;
            break;

        default:
            break;
    }

    // If this endpoint's own FIN was also acknowledged, and it
    // has acknowledged the peer's FIN, it can enter TIME-WAIT.
    const bool own_fin_acked = source_is_a
        ? connection.fin_acked_by_b
        : connection.fin_acked_by_a;

    if (own_fin_acked) {
        TcpEndpointState& source_state =
            state_for(connection, source);

        if (
            source_state == TcpEndpointState::FinWait2 ||
            source_state == TcpEndpointState::Closing
        ) {
            source_state = TcpEndpointState::TimeWait;
        }
    }
}


// 
// FIN transmission tracking
// 

void record_fin(
    TcpConnection& connection,
    const PacketSummary& packet,
    const TcpEndpoint& source,
    const TcpInfo& tcp
) noexcept {
    const bool source_is_a =
        source == connection.key.first;

    bool& fin_seen = source_is_a
        ? connection.fin_from_a
        : connection.fin_from_b;

    // A retransmitted FIN increments packet counters but must not
    // overwrite the original sequence boundary or replay transitions.
    if (fin_seen) {
        return;
    }

    const std::uint32_t payload_length =
        tcp_payload_length(packet, tcp);

    const std::uint32_t fin_end_sequence =
        tcp.sequence_number + payload_length + 1U;

    fin_seen = true;

    if (source_is_a) {
        connection.fin_end_sequence_a = fin_end_sequence;
    } else {
        connection.fin_end_sequence_b = fin_end_sequence;
    }

    TcpEndpointState& sender_state =
        state_for(connection, source);

    TcpEndpointState& receiver_state =
        state_for(connection, peer_of(connection, source));

    // The sender's transition.
    if (sender_state == TcpEndpointState::CloseWait) {
        sender_state = TcpEndpointState::LastAck;

    } else if (
        sender_state == TcpEndpointState::Established ||
        sender_state == TcpEndpointState::Midstream ||
        sender_state == TcpEndpointState::Unknown ||
        sender_state == TcpEndpointState::SynSent ||
        sender_state == TcpEndpointState::SynReceived
    ) {
        sender_state = TcpEndpointState::FinWait1;
    }

    // The receiver's transition.
    if (
        receiver_state == TcpEndpointState::Established ||
        receiver_state == TcpEndpointState::Midstream ||
        receiver_state == TcpEndpointState::Unknown ||
        receiver_state == TcpEndpointState::SynSent ||
        receiver_state == TcpEndpointState::SynReceived
    ) {
        receiver_state = TcpEndpointState::CloseWait;

    } else if (receiver_state == TcpEndpointState::FinWait1) {
        receiver_state = TcpEndpointState::Closing;
    }

    // If the receiver is in FIN_WAIT_2, it will enter TIME_WAIT
    // when its ACK of this FIN is observed.
}


// 
// Combined connection state update
// 

void update_connection_state(
    TcpConnection& connection,
    const PacketSummary& packet,
    const TcpEndpoint& source,
    const TcpEndpoint& destination,
    const TcpInfo& tcp
) {
    const std::uint8_t flags = tcp.flags;

    const bool rst = has_flag(flags, tcp_flag_rst);
    const bool ack = has_flag(flags, tcp_flag_ack);
    const bool fin = has_flag(flags, tcp_flag_fin);

    // RST terminates the observed connection immediately.
    if (rst) {
        connection.state_a = TcpEndpointState::Reset;
        connection.state_b = TcpEndpointState::Reset;
        return;
    }

    // A reset generation cannot be revived by ordinary packets.
    if (
        connection.state_a == TcpEndpointState::Reset ||
        connection.state_b == TcpEndpointState::Reset
    ) {
        return;
    }

    // Process ACK before FIN because a FIN+ACK packet may
    // acknowledge the peer's earlier FIN.
    if (ack) {
        acknowledge_peer_fin(
            connection,
            source,
            tcp.acknowledgement_number
        );
    }

    update_handshake(
        connection,
        source,
        destination,
        flags
    );

    // A first observed ACK, data packet, or FIN can belong to
    // a capture that began after the handshake.
    if (!has_flag(flags, tcp_flag_syn)) {
        set_midstream_if_unknown(connection);
    }

    if (fin) {
        record_fin(
            connection,
            packet,
            source,
            tcp
        );
    }
}


// 
// Packet accounting
// 

void account_packet(
    TcpConnection& connection,
    const TcpEndpoint& source,
    std::uint8_t flags,
    std::size_t captured_length,
    std::uint64_t timestamp_microseconds
) noexcept {
    const std::uint64_t byte_count =
        static_cast<std::uint64_t>(captured_length);

    add_counter(connection.packet_count, 1U);
    add_counter(connection.captured_bytes, byte_count);

    // Keep the earliest and latest observed timestamps.
    connection.first_seen_us =
        std::min(
            connection.first_seen_us,
            timestamp_microseconds
        );

    connection.last_seen_us =
        std::max(
            connection.last_seen_us,
            timestamp_microseconds
        );

    // Directional traffic accounting.
    if (source == connection.key.first) {
        add_counter(connection.packets_a_to_b, 1U);
        add_counter(connection.bytes_a_to_b, byte_count);
    } else {
        add_counter(connection.packets_b_to_a, 1U);
        add_counter(connection.bytes_b_to_a, byte_count);
    }

    // TCP flag accounting.
    if (has_flag(flags, tcp_flag_syn)) {
        add_counter(connection.syn_packets, 1U);
    }

    if (
        has_flag(flags, tcp_flag_syn) &&
        has_flag(flags, tcp_flag_ack)
    ) {
        add_counter(connection.syn_ack_packets, 1U);
    }

    if (has_flag(flags, tcp_flag_ack)) {
        add_counter(connection.ack_packets, 1U);
    }

    if (has_flag(flags, tcp_flag_fin)) {
        add_counter(connection.fin_packets, 1U);
    }

    if (has_flag(flags, tcp_flag_rst)) {
        add_counter(connection.rst_packets, 1U);
    }
}

} // namespace


// 
// Public tracker implementation
// 

void TcpConnectionTracker::observe(
    const PacketSummary& packet,
    std::uint64_t timestamp_microseconds
) {
    const auto observation =
        extract_tcp_packet(packet);

    // Ignore anything that isn't a successfully decoded TCP packet.
    if (!observation.has_value()) {
        return;
    }

    const TcpEndpoint& source =
        observation->source;

    const TcpEndpoint& destination =
        observation->destination;

    const TcpInfo& tcp =
        *observation->tcp;

    const bool new_initial_syn =
        has_flag(tcp.flags, tcp_flag_syn) &&
        !has_flag(tcp.flags, tcp_flag_ack) &&
        !has_flag(tcp.flags, tcp_flag_rst);

    const TcpConnectionKey key =
        make_connection_key(source, destination);

    auto active = active_connections_.find(key);

    bool create_generation =
        active == active_connections_.end();

    // Reusing an endpoint pair after a completed or reset
    // generation creates a separate historical connection.
    if (!create_generation && new_initial_syn) {
        const TcpConnection& previous =
            connections_[active->second];

        create_generation =
            is_finished_generation(previous);
    }

    std::size_t connection_index = 0U;

    if (create_generation) {
        TcpConnection connection;

        connection.id = next_connection_id_++;
        connection.key = key;

        connection.first_seen_us = timestamp_microseconds;
        connection.last_seen_us = timestamp_microseconds;

        connection_index = connections_.size();

        connections_.push_back(std::move(connection));

        active_connections_[key] = connection_index;

    } else {
        connection_index = active->second;
    }

    TcpConnection& connection =
        connections_[connection_index];

    account_packet(
        connection,
        source,
        tcp.flags,
        packet.captured_length,
        timestamp_microseconds
    );

    update_connection_state(
        connection,
        packet,
        source,
        destination,
        tcp
    );
}


// 
// Idle expiration
// 

std::size_t TcpConnectionTracker::expire_idle(
    std::uint64_t current_time_us,
    std::uint64_t idle_timeout_microseconds
) {
    std::size_t expired_count = 0U;

    for (
        auto iterator = active_connections_.begin();
        iterator != active_connections_.end();
    ) {
        TcpConnection& connection =
            connections_[iterator->second];

        const bool clock_is_after_last_packet =
            current_time_us >= connection.last_seen_us;

        const bool idle_long_enough =
            clock_is_after_last_packet &&
            current_time_us - connection.last_seen_us >=
                idle_timeout_microseconds;

        if (idle_long_enough) {
            connection.expired = true;

            iterator = active_connections_.erase(iterator);

            ++expired_count;

        } else {
            ++iterator;
        }
    }

    return expired_count;
}


// 
// Public accessors
// 

const std::vector<TcpConnection>&
TcpConnectionTracker::connections() const noexcept {
    return connections_;
}

std::size_t TcpConnectionTracker::size() const noexcept {
    return connections_.size();
}

std::size_t TcpConnectionTracker::active_size() const noexcept {
    return active_connections_.size();
}

void TcpConnectionTracker::clear() noexcept {
    connections_.clear();
    active_connections_.clear();

    next_connection_id_ = 1U;
}


// 
// State formatting
// 

const char* tcp_endpoint_state_name(
    TcpEndpointState state
) noexcept {
    switch (state) {
        case TcpEndpointState::Unknown:
            return "UNKNOWN";

        case TcpEndpointState::Midstream:
            return "MIDSTREAM";

        case TcpEndpointState::SynSent:
            return "SYN_SENT";

        case TcpEndpointState::SynReceived:
            return "SYN_RECEIVED";

        case TcpEndpointState::Established:
            return "ESTABLISHED";

        case TcpEndpointState::FinWait1:
            return "FIN_WAIT_1";

        case TcpEndpointState::FinWait2:
            return "FIN_WAIT_2";

        case TcpEndpointState::CloseWait:
            return "CLOSE_WAIT";

        case TcpEndpointState::Closing:
            return "CLOSING";

        case TcpEndpointState::LastAck:
            return "LAST_ACK";

        case TcpEndpointState::TimeWait:
            return "TIME_WAIT";

        case TcpEndpointState::Closed:
            return "CLOSED";

        case TcpEndpointState::Reset:
            return "RESET";
    }

    return "UNKNOWN";
}

} // namespace wirescope
