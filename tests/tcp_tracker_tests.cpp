
#include "wirescope/tcp_tracker.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <utility>

namespace {

constexpr std::uint8_t flag_fin = 0x01U;
constexpr std::uint8_t flag_syn = 0x02U;
constexpr std::uint8_t flag_rst = 0x04U;
constexpr std::uint8_t flag_ack = 0x10U;

constexpr std::uint16_t client_port = 50000U;
constexpr std::uint16_t server_port = 443U;

const wirescope::TcpEndpoint client{
    "192.0.2.1", client_port
};

const wirescope::TcpEndpoint server{
    "198.51.100.2", server_port
};

// Test packet builders

[[nodiscard]] wirescope::PacketSummary make_ipv4_tcp_packet(
    const std::string& source,
    const std::string& destination,
    std::uint16_t source_port,
    std::uint16_t destination_port,
    std::uint8_t flags,
    std::size_t captured_length = 60U
) {
    wirescope::PacketSummary packet;

    packet.captured_length = captured_length;
    packet.wire_length = captured_length;

    wirescope::TcpInfo tcp;
    tcp.source_port = source_port;
    tcp.destination_port = destination_port;
    tcp.flags = flags;

    wirescope::Ipv4Info ip;
    ip.source_address = source;
    ip.destination_address = destination;
    ip.protocol = 6U;
    ip.transport = wirescope::TransportInfo{tcp};

    packet.ipv4 = std::move(ip);

    return packet;
}

[[nodiscard]] wirescope::PacketSummary make_ipv6_tcp_packet(
    const std::string& source,
    const std::string& destination,
    std::uint16_t source_port,
    std::uint16_t destination_port,
    std::uint8_t flags,
    std::size_t captured_length = 80U
) {
    wirescope::PacketSummary packet;

    packet.captured_length = captured_length;
    packet.wire_length = captured_length;

    wirescope::TcpInfo tcp;
    tcp.source_port = source_port;
    tcp.destination_port = destination_port;
    tcp.flags = flags;

    wirescope::Ipv6Info ip;
    ip.source_address = source;
    ip.destination_address = destination;
    ip.upper_layer_protocol = 6U;
    ip.transport = wirescope::TransportInfo{tcp};

    packet.ipv6 = std::move(ip);

    return packet;
}

[[nodiscard]] wirescope::PacketSummary make_udp_packet() {
    wirescope::PacketSummary packet;
    packet.captured_length = 60U;

    wirescope::UdpInfo udp;
    udp.source_port = 50000U;
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


// Handshake helper

void establish_connection(
    wirescope::TcpConnectionTracker& tracker
) {
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

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_syn | flag_ack
        ),
        1000100U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        1000200U
    );
}


// IPv4 connection tracking


void test_initial_syn_creates_connection() {
    wirescope::TcpConnectionTracker tracker;

    const auto packet = make_ipv4_tcp_packet(
        client.address,
        server.address,
        client_port,
        server_port,
        flag_syn
    );

    tracker.observe(packet, 1000000U);

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.id == 1U);
    assert(connection.state ==
           wirescope::TcpConnectionState::SynSent);

    assert(connection.initiator.has_value());
    assert(*connection.initiator == client);

    assert(connection.syn_packets == 1U);
    assert(connection.packet_count == 1U);
}

void test_syn_ack_advances_connection_state() {
    wirescope::TcpConnectionTracker tracker;

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

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_syn | flag_ack
        ),
        1000100U
    );

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::SynReceived);

    assert(connection.syn_packets == 2U);
    assert(connection.syn_ack_packets == 1U);
}

void test_final_ack_establishes_connection() {
    wirescope::TcpConnectionTracker tracker;

    establish_connection(tracker);

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::Established);

    assert(connection.packet_count == 3U);
    assert(connection.ack_packets == 2U);
}

void test_reverse_direction_uses_same_connection() {
    wirescope::TcpConnectionTracker tracker;

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

    assert(connection.packet_count == 2U);
    assert(connection.state ==
           wirescope::TcpConnectionState::Midstream);

    assert(connection.packets_a_to_b == 1U);
    assert(connection.packets_b_to_a == 1U);
}

void test_directional_byte_counters() {
    wirescope::TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address, server.address,
            client_port, server_port, flag_ack, 60U
        ),
        1000000U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address, client.address,
            server_port, client_port, flag_ack, 80U
        ),
        1000100U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.captured_bytes == 140U);
    assert(connection.bytes_a_to_b == 60U);
    assert(connection.bytes_b_to_a == 80U);
}

// IPv6 connection tracking

void test_ipv6_tcp_handshake() {
    wirescope::TcpConnectionTracker tracker;

    const std::string ipv6_client = "2001:db8::1";
    const std::string ipv6_server = "2001:db8::2";

    tracker.observe(
        make_ipv6_tcp_packet(
            ipv6_client,
            ipv6_server,
            client_port,
            server_port,
            flag_syn
        ),
        2000000U
    );

    tracker.observe(
        make_ipv6_tcp_packet(
            ipv6_server,
            ipv6_client,
            server_port,
            client_port,
            flag_syn | flag_ack
        ),
        2000100U
    );

    tracker.observe(
        make_ipv6_tcp_packet(
            ipv6_client,
            ipv6_server,
            client_port,
            server_port,
            flag_ack
        ),
        2000200U
    );

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::Established);

    assert(connection.packet_count == 3U);
    assert(connection.initiator.has_value());
    assert(connection.initiator->address == ipv6_client);
}

// Midstream capture 

void test_midstream_connection_is_identified() {
    wirescope::TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_ack
        ),
        3000000U
    );

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::Midstream);

    assert(!connection.initiator.has_value());
}

void test_first_observed_syn_ack_infers_initiator() {
    wirescope::TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_syn | flag_ack
        ),
        3000000U
    );

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::SynReceived);

    assert(connection.initiator.has_value());
    assert(*connection.initiator == client);
}

// Connection termination

void test_first_fin_enters_fin_wait() {
    wirescope::TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack
        ),
        1000300U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::FinWait);

    assert(connection.fin_from_a);
    assert(!connection.fin_from_b);
    assert(connection.fin_packets == 1U);
}

void test_both_fin_directions_enter_closing() {
    wirescope::TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address,
            server.address,
            client_port,
            server_port,
            flag_fin | flag_ack
        ),
        1000300U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address,
            client.address,
            server_port,
            client_port,
            flag_fin | flag_ack
        ),
        1000400U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::Closing);

    assert(connection.fin_from_a);
    assert(connection.fin_from_b);
    assert(connection.fin_packets == 2U);
}

void test_rst_resets_connection() {
    wirescope::TcpConnectionTracker tracker;

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

    assert(connection.state ==
           wirescope::TcpConnectionState::Reset);

    assert(connection.rst_packets == 1U);
}

// Connection generations

void test_syn_retransmission_does_not_create_new_generation() {
    wirescope::TcpConnectionTracker tracker;

    const auto syn = make_ipv4_tcp_packet(
        client.address,
        server.address,
        client_port,
        server_port,
        flag_syn
    );

    tracker.observe(syn, 1000000U);
    tracker.observe(syn, 1000100U);

    assert(tracker.size() == 1U);

    const auto& connection = tracker.connections().front();

    assert(connection.state ==
           wirescope::TcpConnectionState::SynSent);

    assert(connection.syn_packets == 2U);
    assert(connection.packet_count == 2U);
}

void test_rst_followed_by_syn_creates_new_generation() {
    wirescope::TcpConnectionTracker tracker;

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
            flag_syn
        ),
        2000000U
    );

    assert(tracker.size() == 2U);

    const auto& old_connection = tracker.connections()[0];
    const auto& new_connection = tracker.connections()[1];

    assert(old_connection.id == 1U);
    assert(old_connection.state ==
           wirescope::TcpConnectionState::Reset);

    assert(new_connection.id == 2U);
    assert(new_connection.state ==
           wirescope::TcpConnectionState::SynSent);

    assert(new_connection.packet_count == 1U);
}

void test_completed_fin_sequence_allows_new_generation() {
    wirescope::TcpConnectionTracker tracker;

    establish_connection(tracker);

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address, server.address,
            client_port, server_port,
            flag_fin | flag_ack
        ),
        1000300U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address, client.address,
            server_port, client_port,
            flag_fin | flag_ack
        ),
        1000400U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address, server.address,
            client_port, server_port,
            flag_syn
        ),
        2000000U
    );

    assert(tracker.size() == 2U);

    assert(tracker.connections()[0].state ==
           wirescope::TcpConnectionState::Closing);

    assert(tracker.connections()[1].state ==
           wirescope::TcpConnectionState::SynSent);
}

// Timestamp handling

void test_connection_timestamps_track_minimum_and_maximum() {
    wirescope::TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address, server.address,
            client_port, server_port, flag_ack
        ),
        2000000U
    );

    tracker.observe(
        make_ipv4_tcp_packet(
            server.address, client.address,
            server_port, client_port, flag_ack
        ),
        1000000U
    );

    const auto& connection = tracker.connections().front();

    assert(connection.first_seen_us == 1000000U);
    assert(connection.last_seen_us == 2000000U);
}

// Ignored packets

void test_udp_packet_is_ignored() {
    wirescope::TcpConnectionTracker tracker;

    const auto packet = make_udp_packet();

    tracker.observe(packet, 1000000U);

    assert(tracker.size() == 0U);
}

void test_packet_without_transport_is_ignored() {
    wirescope::TcpConnectionTracker tracker;

    wirescope::PacketSummary packet;

    wirescope::Ipv4Info ip;
    ip.source_address = client.address;
    ip.destination_address = server.address;
    ip.protocol = 6U;

    packet.ipv4 = ip;

    tracker.observe(packet, 1000000U);

    assert(tracker.size() == 0U);
}

void test_packet_without_ip_layer_is_ignored() {
    wirescope::TcpConnectionTracker tracker;

    const wirescope::PacketSummary packet;

    tracker.observe(packet, 1000000U);

    assert(tracker.size() == 0U);
}

// Reset and utility functions 

void test_clear_removes_all_connections() {
    wirescope::TcpConnectionTracker tracker;

    establish_connection(tracker);

    assert(tracker.size() == 1U);

    tracker.clear();

    assert(tracker.size() == 0U);
    assert(tracker.connections().empty());
}

void test_clear_resets_connection_identifier() {
    wirescope::TcpConnectionTracker tracker;

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address, server.address,
            client_port, server_port, flag_syn
        ),
        1000000U
    );

    tracker.clear();

    tracker.observe(
        make_ipv4_tcp_packet(
            client.address, server.address,
            client_port, server_port, flag_syn
        ),
        2000000U
    );

    assert(tracker.size() == 1U);
    assert(tracker.connections().front().id == 1U);
}

void test_state_names() {
    using wirescope::TcpConnectionState;

    assert(std::string(
        wirescope::tcp_connection_state_name(
            TcpConnectionState::SynSent
        )) == "SYN_SENT");

    assert(std::string(
        wirescope::tcp_connection_state_name(
            TcpConnectionState::SynReceived
        )) == "SYN_RECEIVED");

    assert(std::string(
        wirescope::tcp_connection_state_name(
            TcpConnectionState::Established
        )) == "ESTABLISHED");

    assert(std::string(
        wirescope::tcp_connection_state_name(
            TcpConnectionState::Midstream
        )) == "MIDSTREAM");

    assert(std::string(
        wirescope::tcp_connection_state_name(
            TcpConnectionState::FinWait
        )) == "FIN_WAIT");

    assert(std::string(
        wirescope::tcp_connection_state_name(
            TcpConnectionState::Closing
        )) == "CLOSING");

    assert(std::string(
        wirescope::tcp_connection_state_name(
            TcpConnectionState::Reset
        )) == "RESET");
}

} // namespace

int main() {
    // IPv4 connection tracking.
    test_initial_syn_creates_connection();
    test_syn_ack_advances_connection_state();
    test_final_ack_establishes_connection();
    test_reverse_direction_uses_same_connection();
    test_directional_byte_counters();

    // IPv6 connection tracking.
    test_ipv6_tcp_handshake();

    // Midstream capture.
    test_midstream_connection_is_identified();
    test_first_observed_syn_ack_infers_initiator();

    // Connection termination.
    test_first_fin_enters_fin_wait();
    test_both_fin_directions_enter_closing();
    test_rst_resets_connection();

    // Connection generations.
    test_syn_retransmission_does_not_create_new_generation();
    test_rst_followed_by_syn_creates_new_generation();
    test_completed_fin_sequence_allows_new_generation();

    // Timestamp handling.
    test_connection_timestamps_track_minimum_and_maximum();

    // Ignored packets.
    test_udp_packet_is_ignored();
    test_packet_without_transport_is_ignored();
    test_packet_without_ip_layer_is_ignored();

    // Reset and utility functions.
    test_clear_removes_all_connections();
    test_clear_resets_connection_identifier();
    test_state_names();

    std::cout << "All TCP tracker tests passed.\n";
}
