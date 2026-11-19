
#include "wirescope/tcp_tracker.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>

namespace {

using wirescope::PacketSummary;
using wirescope::TcpEndpointState;
using wirescope::TcpConnectionTracker;

constexpr std::uint8_t flag_fin = 0x01U;
constexpr std::uint8_t flag_syn = 0x02U;
constexpr std::uint8_t flag_rst = 0x04U;
constexpr std::uint8_t flag_ack = 0x10U;

constexpr std::uint16_t client_port = 50000U;
constexpr std::uint16_t server_port = 443U;

constexpr std::uint32_t client_isn = 1000U;
constexpr std::uint32_t server_isn = 5000U;

const wirescope::TcpEndpoint client{
    "192.0.2.1", client_port
};

const wirescope::TcpEndpoint server{
    "198.51.100.2", server_port
};


// 
// Test packet builders
// 

[[nodiscard]] PacketSummary make_ipv4_tcp_packet(
    const std::string& source,
    const std::string& destination,
    std::uint16_t source_port,
    std::uint16_t destination_port,
    std::uint8_t flags,
    std::uint32_t sequence_number = 0U,
    std::uint32_t acknowledgement_number = 0U,
    std::size_t payload_length = 0U
) {
    PacketSummary packet;

    packet.captured_length = 54U + payload_length;
    packet.wire_length = packet.captured_length;

    wirescope::TcpInfo tcp;
    tcp.source_port = source_port;
    tcp.destination_port = destination_port;
    tcp.sequence_number = sequence_number;
    tcp.acknowledgement_number = acknowledgement_number;
    tcp.flags = flags;
    tcp.header_length = 20U;

    wirescope::Ipv4Info ip;
    ip.source_address = source;
    ip.destination_address = destination;
    ip.protocol = 6U;
    ip.header_length = 20U;
    ip.total_length = static_cast<std::uint16_t>(
        40U + payload_length
    );
    ip.transport = wirescope::TransportInfo{tcp};

    packet.ipv4 = std::move(ip);

    return packet;
}


[[nodiscard]] PacketSummary make_ipv6_tcp_packet(
    const std::string& source,
    const std::string& destination,
    std::uint16_t source_port,
    std::uint16_t destination_port,
    std::uint8_t flags,
    std::uint32_t sequence_number = 0U,
    std::uint32_t acknowledgement_number = 0U,
    std::size_t payload_length = 0U
) {
    PacketSummary packet;

    packet.captured_length = 74U + payload_length;
    packet.wire_length = packet.captured_length;

    wirescope::TcpInfo tcp;
    tcp.source_port = source_port;
    tcp.destination_port = destination_port;
    tcp.sequence_number = sequence_number;
    tcp.acknowledgement_number = acknowledgement_number;
    tcp.flags = flags;
    tcp.header_length = 20U;

    wirescope::Ipv6Info ip;
    ip.source_address = source;
    ip.destination_address = destination;
    ip.next_header = 6U;
    ip.upper_layer_protocol = 6U;
    ip.header_length = 40U;
    ip.payload_length = static_cast<std::uint16_t>(
        20U + payload_length
    );
    ip.transport = wirescope::TransportInfo{tcp};

    packet.ipv6 = std::move(ip);

    return packet;
}


[[nodiscard]] PacketSummary make_udp_packet() {
    PacketSummary packet;
    packet.captured_length = 60U;
    packet.wire_length = 60U;

    wirescope::UdpInfo udp;
    udp.source_port = client_port;
    udp.destination_port = 53U;
    udp.length = 20U;

    wirescope::Ipv4Info ip;
    ip.source_address = client.address;
    ip.destination_address = server.address;
    ip.protocol = 17U;
    ip.transport = wirescope::TransportInfo{udp};

    packet.ipv4 = std::move(ip);

    return packet;
}


// 
// Handshake helper
// 

void establish_connection(
    TcpConnectionTracker& tracker,
    std::uint64_t timestamp = 1000000U,
    std::uint32_t client_sequence = client_isn,
    std::uint32_t server_sequence = server_isn
) {
    // Step 1: Client sends SYN.
    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_syn,
            client_sequence
        ),
        timestamp
    );

    // Step 2: Server responds with SYN-ACK.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_syn | flag_ack,
            server_sequence,
            client_sequence + 1U
        ),
        timestamp + 100U
    );

    // Step 3: Client sends final ACK.
    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack,
            client_sequence + 1U,
            server_sequence + 1U
        ),
        timestamp + 200U
    );
}


// 
// Normal connection termination helper
// 

void complete_normal_close(
    TcpConnectionTracker& tracker,
    std::uint64_t timestamp = 1000000U
) {
    establish_connection(tracker, timestamp);

    // Client sends FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            client_isn + 1U,
            server_isn + 1U
        ),
        timestamp + 300U
    );

    // Server acknowledges the client's FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack,
            server_isn + 1U,
            client_isn + 2U
        ),
        timestamp + 400U
    );

    // Server sends its FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_fin | flag_ack,
            server_isn + 1U,
            client_isn + 2U
        ),
        timestamp + 500U
    );

    // Client acknowledges the server's FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack,
            client_isn + 2U,
            server_isn + 2U
        ),
        timestamp + 600U
    );
}


// 
// Initial connection and handshake tests
// 

void test_initial_syn_creates_connection() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_syn,
            client_isn
        ),
        1000000U
    );

    assert(tracker.size() == 1U);
    assert(tracker.active_size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.id == 1U);
    assert(connection.initiator.has_value());
    assert(*connection.initiator == client);

    assert(connection.state_a == TcpEndpointState::SynSent);
    assert(connection.state_b == TcpEndpointState::Unknown);

    assert(connection.syn_packets == 1U);
    assert(connection.packet_count == 1U);
}


void test_syn_ack_advances_endpoint_state() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_syn,
            client_isn
        ),
        1000000U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_syn | flag_ack,
            server_isn,
            client_isn + 1U
        ),
        1000100U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::SynSent);
    assert(connection.state_b == TcpEndpointState::SynReceived);

    assert(connection.syn_packets == 2U);
    assert(connection.syn_ack_packets == 1U);
}


void test_final_ack_establishes_both_endpoints() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::Established);
    assert(connection.state_b == TcpEndpointState::Established);

    assert(connection.packet_count == 3U);
    assert(connection.syn_packets == 2U);
    assert(connection.syn_ack_packets == 1U);
    assert(connection.ack_packets == 2U);
}


void test_syn_retransmission_does_not_create_generation() {
    TcpConnectionTracker tracker;

    const auto syn = make_ipv4_tcp_packet(
        client.address,
        server.address,
        client_port,
        server_port,
        flag_syn,
        client_isn
    );

    tracker.observe(syn, 1000000U);
    tracker.observe(syn, 1000100U);

    assert(tracker.size() == 1U);
    assert(tracker.active_size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.id == 1U);
    assert(connection.state_a == TcpEndpointState::SynSent);
    assert(connection.syn_packets == 2U);
}


// 
// Bidirectional connection tests
// 

void test_reverse_direction_uses_same_connection() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        1000000U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack
        ),
        1000100U
    );

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::Midstream);
    assert(connection.state_b == TcpEndpointState::Midstream);

    assert(connection.packet_count == 2U);
    assert(connection.packets_a_to_b == 1U);
    assert(connection.packets_b_to_a == 1U);
}


void test_directional_byte_counters() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        1000000U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack
        ),
        1000100U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.captured_bytes == 108U);
    assert(connection.bytes_a_to_b == 54U);
    assert(connection.bytes_b_to_a == 54U);
}


void test_different_ports_create_different_connections() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            50000U,
            443U,
            flag_syn
        ),
        1000000U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            50001U,
            443U,
            flag_syn
        ),
        1000100U
    );

    assert(tracker.size() == 2U);
    assert(tracker.active_size() == 2U);

    assert(tracker.connections()[0].id == 1U);
    assert(tracker.connections()[1].id == 2U);
}


// 
// Midstream capture tests
// 

void test_midstream_connection_is_identified() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        1000000U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::Midstream);
    assert(connection.state_b == TcpEndpointState::Midstream);
    assert(!connection.initiator.has_value());
}


void test_first_observed_syn_ack_infers_initiator() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_syn | flag_ack,
            server_isn,
            client_isn + 1U
        ),
        1000000U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.initiator.has_value());
    assert(*connection.initiator == client);

    assert(connection.state_a == TcpEndpointState::SynSent);
    assert(connection.state_b == TcpEndpointState::SynReceived);
}


// 
// IPv6 tracking tests
// 

void test_ipv6_tcp_handshake() {
    TcpConnectionTracker tracker;

    const std::string ipv6_client = "2001:db8::1";
    const std::string ipv6_server = "2001:db8::2";

    tracker.observe(
        make_ipv6_tcp_packet(
            ipv6_client,
            ipv6_server,
            client_port,
            server_port,
            flag_syn,
            client_isn
        ),
        2000000U
    );

    tracker.observe(
        make_ipv6_tcp_packet(
            ipv6_server,
            ipv6_client,
            server_port,
            client_port,
            flag_syn | flag_ack,
            server_isn,
            client_isn + 1U
        ),
        2000100U
    );

    tracker.observe(
        make_ipv6_tcp_packet(
            ipv6_client,
            ipv6_server,
            client_port,
            server_port,
            flag_ack,
            client_isn + 1U,
            server_isn + 1U
        ),
        2000200U
    );

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::Established);
    assert(connection.state_b == TcpEndpointState::Established);

    assert(connection.initiator.has_value());
    assert(connection.initiator->address == ipv6_client);
}


// 
// FIN lifecycle tests
// 

void test_first_fin_enters_fin_wait_1_and_close_wait() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            client_isn + 1U,
            server_isn + 1U
        ),
        1000300U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::FinWait1);
    assert(connection.state_b == TcpEndpointState::CloseWait);

    assert(connection.fin_from_a);
    assert(!connection.fin_from_b);

    assert(connection.fin_end_sequence_a == client_isn + 2U);
    assert(connection.fin_packets == 1U);
}


void test_acknowledging_fin_enters_fin_wait_2() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            client_isn + 1U,
            server_isn + 1U
        ),
        1000300U
    );

    // Server acknowledges the client's FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack,
            server_isn + 1U,
            client_isn + 2U
        ),
        1000400U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::FinWait2);
    assert(connection.state_b == TcpEndpointState::CloseWait);

    assert(connection.fin_acked_by_b);
}


void test_server_fin_enters_last_ack() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    // Client sends FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            client_isn + 1U,
            server_isn + 1U
        ),
        1000300U
    );

    // Server acknowledges it.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack,
            server_isn + 1U,
            client_isn + 2U
        ),
        1000400U
    );

    // Server sends its FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_fin | flag_ack,
            server_isn + 1U,
            client_isn + 2U
        ),
        1000500U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::FinWait2);
    assert(connection.state_b == TcpEndpointState::LastAck);
}


void test_final_ack_enters_time_wait_and_closed() {
    TcpConnectionTracker tracker;

    complete_normal_close(tracker);

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::TimeWait);
    assert(connection.state_b == TcpEndpointState::Closed);

    assert(connection.fin_from_a);
    assert(connection.fin_from_b);

    assert(connection.fin_acked_by_a);
    assert(connection.fin_acked_by_b);

    assert(connection.fin_packets == 2U);
}


void test_ack_below_fin_boundary_does_not_advance_state() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            client_isn + 1U,
            server_isn + 1U
        ),
        1000300U
    );

    // The FIN ends at client_isn + 2.
    // This ACK only acknowledges up to client_isn + 1.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack,
            server_isn + 1U,
            client_isn + 1U
        ),
        1000400U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::FinWait1);
    assert(connection.state_b == TcpEndpointState::CloseWait);

    assert(!connection.fin_acked_by_b);
}


void test_fin_payload_is_included_in_sequence_boundary() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    constexpr std::size_t payload_size = 10U;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            client_isn + 1U,
            server_isn + 1U,
            payload_size
        ),
        1000300U
    );

    const auto& after_fin = tracker.connections().front();

    constexpr std::uint32_t expected_fin_end =
        client_isn + 1U +
        static_cast<std::uint32_t>(payload_size) + 1U;

    assert(after_fin.fin_end_sequence_a == expected_fin_end);

    // ACKs only the data, not the FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack,
            server_isn + 1U,
            expected_fin_end - 1U
        ),
        1000400U
    );

    assert(
        tracker.connections().front().state_a ==
        TcpEndpointState::FinWait1
    );

    // Now acknowledges the FIN itself.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack,
            server_isn + 1U,
            expected_fin_end
        ),
        1000500U
    );

    assert(
        tracker.connections().front().state_a ==
        TcpEndpointState::FinWait2
    );
}


void test_fin_sequence_number_wraparound() {
    TcpConnectionTracker tracker;

    constexpr std::uint32_t wrapping_client_isn = 0xFFFFFFFEU;

    establish_connection(
        tracker,
        1000000U,
        wrapping_client_isn,
        server_isn
    );

    // SYN consumed sequence FFFFFFFE.
    // FIN is sent at FFFFFFFF and ends at zero.
    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            0xFFFFFFFFU,
            server_isn + 1U
        ),
        1000300U
    );

    // ACK zero is a valid acknowledgement of the wrapped FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack,
            server_isn + 1U,
            0U
        ),
        1000400U
    );

    assert(
        tracker.connections().front().state_a ==
        TcpEndpointState::FinWait2
    );

    assert(tracker.connections().front().fin_acked_by_b);
}


void test_simultaneous_close_tracks_closing_state() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    // Client sends FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack,
            client_isn + 1U,
            server_isn + 1U
        ),
        1000300U
    );

    // Server sends its FIN before acknowledging the client's FIN.
    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_fin | flag_ack,
            server_isn + 1U,
            client_isn + 1U
        ),
        1000400U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::Closing);
    assert(connection.state_b == TcpEndpointState::LastAck);
}


// 
// RST tests
// 

void test_rst_resets_both_endpoints() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_rst | flag_ack
        ),
        1000300U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::Reset);
    assert(connection.state_b == TcpEndpointState::Reset);

    assert(connection.rst_packets == 1U);
}


void test_reset_connection_does_not_revive() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_rst
        ),
        1000300U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        1000400U
    );

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state_a == TcpEndpointState::Reset);
    assert(connection.state_b == TcpEndpointState::Reset);
}


// 
// Connection generation tests
// 

void test_rst_followed_by_syn_creates_new_generation() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_rst | flag_ack
        ),
        1000300U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_syn,
            2000U
        ),
        2000000U
    );

    assert(tracker.size() == 2U);
    assert(tracker.active_size() == 1U);

    assert(tracker.connections()[0].id == 1U);
    assert(tracker.connections()[0].state_a == TcpEndpointState::Reset);

    assert(tracker.connections()[1].id == 2U);
    assert(tracker.connections()[1].state_a == TcpEndpointState::SynSent);
}


void test_completed_close_allows_new_generation() {
    TcpConnectionTracker tracker;

    complete_normal_close(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_syn,
            3000U
        ),
        2000000U
    );

    assert(tracker.size() == 2U);
    assert(tracker.active_size() == 1U);

    assert(tracker.connections()[0].state_a == TcpEndpointState::TimeWait);
    assert(tracker.connections()[0].state_b == TcpEndpointState::Closed);

    assert(tracker.connections()[1].state_a == TcpEndpointState::SynSent);
}


// 
// Idle expiration tests
// 

void test_idle_connection_expires_at_timeout_boundary() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        1000000U
    );

    constexpr std::uint64_t timeout = 30000000U;

    // One microsecond before the timeout.
    const std::size_t early_expired =
        tracker.expire_idle(
            1000000U + timeout - 1U,
            timeout
        );

    assert(early_expired == 0U);
    assert(tracker.active_size() == 1U);

    // Exactly at the timeout boundary.
    const std::size_t expired =
        tracker.expire_idle(
            1000000U + timeout,
            timeout
        );

    assert(expired == 1U);

    // Historical record remains.
    assert(tracker.size() == 1U);
    assert(tracker.active_size() == 0U);
    assert(tracker.connections().front().expired);
}


void test_expiration_preserves_historical_statistics() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        1000000U
    );

    const auto original_packet_count =
        tracker.connections().front().packet_count;

    tracker.expire_idle(2000000U, 1000000U);

    const auto& historical = tracker.connections().front();

    assert(historical.expired);
    assert(historical.packet_count == original_packet_count);
    assert(historical.id == 1U);
}


void test_packet_after_expiration_creates_new_generation() {
    TcpConnectionTracker tracker;

    const auto packet = make_ipv4_tcp_packet(
        client.address,
        server.address,
        client_port,
        server_port,
        flag_ack
    );

    tracker.observe(packet, 1000000U);

    tracker.expire_idle(2000000U, 1000000U);

    tracker.observe(packet, 3000000U);

    assert(tracker.size() == 2U);
    assert(tracker.active_size() == 1U);

    assert(tracker.connections()[0].id == 1U);
    assert(tracker.connections()[0].expired);

    assert(tracker.connections()[1].id == 2U);
    assert(!tracker.connections()[1].expired);

    assert(
        tracker.connections()[1].state_a ==
        TcpEndpointState::Midstream
    );
}


void test_expiration_does_not_use_a_time_before_last_packet() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        5000000U
    );

    const std::size_t expired =
        tracker.expire_idle(4000000U, 0U);

    assert(expired == 0U);
    assert(tracker.active_size() == 1U);
}


// 
// Timestamp tests
// 

void test_timestamps_track_earliest_and_latest_packet() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        2000000U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_ack
        ),
        1000000U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.first_seen_us == 1000000U);
    assert(connection.last_seen_us == 2000000U);
}


// 
// Ignored packet tests
// 

void test_udp_packet_is_ignored() {
    TcpConnectionTracker tracker;

    tracker.observe(make_udp_packet(), 1000000U);

    assert(tracker.size() == 0U);
    assert(tracker.active_size() == 0U);
}


void test_packet_without_transport_is_ignored() {
    TcpConnectionTracker tracker;

    PacketSummary packet;

    wirescope::Ipv4Info ip;
    ip.source_address = client.address;
    ip.destination_address = server.address;
    ip.protocol = 6U;

    packet.ipv4 = ip;

    tracker.observe(packet, 1000000U);

    assert(tracker.size() == 0U);
}


void test_packet_without_ip_layer_is_ignored() {
    TcpConnectionTracker tracker;

    const PacketSummary packet;

    tracker.observe(packet, 1000000U);

    assert(tracker.size() == 0U);
}


// 
// Reset and utility tests
// 

void test_clear_removes_all_connections() {
    TcpConnectionTracker tracker;

    establish_connection(tracker);

    assert(tracker.size() == 1U);
    assert(tracker.active_size() == 1U);

    tracker.clear();

    assert(tracker.size() == 0U);
    assert(tracker.active_size() == 0U);
    assert(tracker.connections().empty());
}


void test_clear_resets_connection_identifier() {
    TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_syn
        ),
        1000000U
    );

    tracker.clear();

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_syn
        ),
        2000000U
    );

    assert(tracker.size() == 1U);
    assert(tracker.connections().front().id == 1U);
}


void test_state_name_formatting() {
    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::Unknown
            )
        ) == "UNKNOWN"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::Midstream
            )
        ) == "MIDSTREAM"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::SynSent
            )
        ) == "SYN_SENT"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::SynReceived
            )
        ) == "SYN_RECEIVED"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::Established
            )
        ) == "ESTABLISHED"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::FinWait1
            )
        ) == "FIN_WAIT_1"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::FinWait2
            )
        ) == "FIN_WAIT_2"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::CloseWait
            )
        ) == "CLOSE_WAIT"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::Closing
            )
        ) == "CLOSING"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::LastAck
            )
        ) == "LAST_ACK"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::TimeWait
            )
        ) == "TIME_WAIT"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::Closed
            )
        ) == "CLOSED"
    );

    assert(
        std::string(
            wirescope::tcp_endpoint_state_name(
                TcpEndpointState::Reset
            )
        ) == "RESET"
    );
}

} // namespace


// 
// Test runner
// 

int main() {

    // Initial connection and handshake.
    test_initial_syn_creates_connection();
    test_syn_ack_advances_endpoint_state();
    test_final_ack_establishes_both_endpoints();
    test_syn_retransmission_does_not_create_generation();

    // Bidirectional connections.
    test_reverse_direction_uses_same_connection();
    test_directional_byte_counters();
    test_different_ports_create_different_connections();

    // Midstream captures.
    test_midstream_connection_is_identified();
    test_first_observed_syn_ack_infers_initiator();

    // IPv6.
    test_ipv6_tcp_handshake();

    // FIN lifecycle.
    test_first_fin_enters_fin_wait_1_and_close_wait();
    test_acknowledging_fin_enters_fin_wait_2();
    test_server_fin_enters_last_ack();
    test_final_ack_enters_time_wait_and_closed();
    test_ack_below_fin_boundary_does_not_advance_state();
    test_fin_payload_is_included_in_sequence_boundary();
    test_fin_sequence_number_wraparound();
    test_simultaneous_close_tracks_closing_state();

    // RST.
    test_rst_resets_both_endpoints();
    test_reset_connection_does_not_revive();

    // Connection generations.
    test_rst_followed_by_syn_creates_new_generation();
    test_completed_close_allows_new_generation();

    // Idle expiration.
    test_idle_connection_expires_at_timeout_boundary();
    test_expiration_preserves_historical_statistics();
    test_packet_after_expiration_creates_new_generation();
    test_expiration_does_not_use_a_time_before_last_packet();

    // Timestamps.
    test_timestamps_track_earliest_and_latest_packet();

    // Ignored traffic.
    test_udp_packet_is_ignored();
    test_packet_without_transport_is_ignored();
    test_packet_without_ip_layer_is_ignored();

    // Reset and utilities.
    test_clear_removes_all_connections();
    test_clear_resets_connection_identifier();
    test_state_name_formatting();

    std::cout << "All TCP tracker tests passed.\n";
}
