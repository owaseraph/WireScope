
#include "wirescope/decoder.hpp"
#include "wirescope/tcp_tracker.hpp"

#include <pcap/pcap.h>

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <string>
#include <type_traits>
#include <variant>

namespace {

// 
// Protocol name helpers
// 

[[nodiscard]] const char* ether_type_name(std::uint16_t ether_type) {
    switch (ether_type) {
        case 0x0800U: return "IPv4";
        case 0x0806U: return "ARP";
        case 0x86DDU: return "IPv6";
        case 0x8100U: return "802.1Q VLAN";
        case 0x88A8U: return "802.1ad VLAN";
        default: return "unknown";
    }
}

[[nodiscard]] const char* ip_protocol_name(std::uint8_t protocol) {
    switch (protocol) {
        case 1U: return "ICMP";
        case 6U: return "TCP";
        case 17U: return "UDP";
        case 58U: return "ICMPv6";
        default: return "other";
    }
}

[[nodiscard]] const char* ipv6_header_name(std::uint8_t header) {
    switch (header) {
        case 0U: return "Hop-by-Hop Options";
        case 6U: return "TCP";
        case 17U: return "UDP";
        case 43U: return "Routing";
        case 44U: return "Fragment";
        case 50U: return "ESP";
        case 51U: return "AH";
        case 58U: return "ICMPv6";
        case 59U: return "No Next Header";
        case 60U: return "Destination Options";
        default: return "unknown";
    }
}


// 
// TCP timestamp conversion
// 

// libpcap's offline-open API returns timestamps in microsecond
// precision by default.
[[nodiscard]] std::uint64_t timestamp_to_microseconds(
    const pcap_pkthdr& header
) noexcept {
    const auto seconds =
        static_cast<std::uint64_t>(header.ts.tv_sec);

    const auto microseconds =
        static_cast<std::uint64_t>(header.ts.tv_usec);

    constexpr std::uint64_t micros_per_second = 1'000'000U;

    return seconds * micros_per_second + microseconds;
}


// 
// Packet printing
// 

void print_transport(const wirescope::TransportInfo& transport) {
    std::visit(
        [](const auto& info) {
            using T = std::decay_t<decltype(info)>;

            if constexpr (std::is_same_v<T, wirescope::TcpInfo>) {
                std::cout << "    TCP       "
                          << info.source_port << " -> "
                          << info.destination_port
                          << "  seq=" << info.sequence_number
                          << "  ack=" << info.acknowledgement_number
                          << "  flags="
                          << wirescope::format_tcp_flags(info.flags)
                          << "  window=" << info.window_size
                          << "  header=" << info.header_length << " B\n";

            } else if constexpr (std::is_same_v<T, wirescope::UdpInfo>) {
                std::cout << "    UDP       "
                          << info.source_port << " -> "
                          << info.destination_port
                          << "  length=" << info.length << " B\n";
            }
        },
        transport
    );
}

void print_ipv4(const wirescope::Ipv4Info& ip) {
    std::cout << "    IPv4      "
              << ip.source_address << " -> " << ip.destination_address
              << "  ttl=" << static_cast<unsigned int>(ip.ttl)
              << "  protocol=" << static_cast<unsigned int>(ip.protocol)
              << " (" << ip_protocol_name(ip.protocol) << ')'
              << "  total_length=" << ip.total_length
              << "  id=" << ip.identification
              << "  fragment_offset=" << ip.fragment_offset
              << (ip.more_fragments ? " MF" : "")
              << '\n';

    if (ip.transport.has_value()) {
        print_transport(*ip.transport);
    }
}

void print_ipv6(const wirescope::Ipv6Info& ip) {
    std::cout << "    IPv6      "
              << ip.source_address << " -> " << ip.destination_address
              << "  hop_limit=" << static_cast<unsigned int>(ip.hop_limit)
              << "  traffic_class=0x" << std::hex
              << static_cast<unsigned int>(ip.traffic_class)
              << "  flow_label=0x" << ip.flow_label
              << std::dec
              << "  payload_length=" << ip.payload_length
              << " B\n";

    std::cout << "    IPv6 next  "
              << static_cast<unsigned int>(ip.next_header)
              << " (" << ipv6_header_name(ip.next_header) << ')'
              << "  upper_layer="
              << static_cast<unsigned int>(ip.upper_layer_protocol)
              << " (" << ipv6_header_name(ip.upper_layer_protocol) << ')'
              << "  parsed_header_length=" << ip.header_length
              << " B\n";

    for (std::size_t index = 0; index < ip.extension_headers.size(); ++index) {
        const auto& extension = ip.extension_headers[index];

        std::cout << "    IPv6 ext   #" << (index + 1U)
                  << " " << ipv6_header_name(extension.type)
                  << " (type=" << static_cast<unsigned int>(extension.type)
                  << ", length=" << extension.header_length
                  << " B, next="
                  << ipv6_header_name(extension.next_header)
                  << ")\n";
    }

    if (ip.fragment.has_value()) {
        const auto& fragment = *ip.fragment;

        std::cout << "    IPv6 frag  offset=" << fragment.offset
                  << " (8-byte units)"
                  << "  more_fragments="
                  << (fragment.more_fragments ? "yes" : "no")
                  << "  id=0x" << std::hex << fragment.identification
                  << std::dec << '\n';
    }

    if (ip.transport.has_value()) {
        print_transport(*ip.transport);
    }
}

void print_packet(
    std::size_t index,
    const pcap_pkthdr& header,
    const wirescope::PacketSummary& packet
) {
    std::cout << '#' << index
              << "  " << header.ts.tv_sec << '.'
              << std::setw(6) << std::setfill('0')
              << header.ts.tv_usec << std::setfill(' ')
              << "  caplen=" << packet.captured_length
              << " wirelen=" << packet.wire_length
              << '\n';

    if (!packet.source_mac.empty() || !packet.destination_mac.empty()) {
        std::cout << "    Ethernet  "
                  << packet.source_mac << " -> "
                  << packet.destination_mac
                  << "  type=" << ether_type_name(packet.ether_type)
                  << " (0x" << std::hex << std::setw(4)
                  << std::setfill('0') << packet.ether_type
                  << std::dec << std::setfill(' ') << ")\n";
    }

    for (std::size_t index = 0; index < packet.vlan_tags.size(); ++index) {
        const auto& tag = packet.vlan_tags[index];

        std::cout << "    VLAN      #" << (index + 1U)
                  << " TPID=" << ether_type_name(tag.tag_protocol_id)
                  << " VID=" << tag.vlan_id
                  << " PCP=" << static_cast<unsigned int>(tag.priority)
                  << " DEI=" << (tag.drop_eligible ? 1 : 0)
                  << " next=" << ether_type_name(tag.encapsulated_ether_type)
                  << " (0x" << std::hex << std::setw(4)
                  << std::setfill('0') << tag.encapsulated_ether_type
                  << std::dec << std::setfill(' ') << ")\n";
    }

    if (packet.ipv4.has_value()) {
        print_ipv4(*packet.ipv4);
    }

    if (packet.ipv6.has_value()) {
        print_ipv6(*packet.ipv6);
    }

    if (!packet.parse_error.empty()) {
        std::cout << "    [!]       " << packet.parse_error << '\n';
    }
}


// 
// TCP connection table
// 

void print_connections(
    const wirescope::TcpConnectionTracker& tracker
) {
    std::cout << "\n========================================\n";
    std::cout << "          TCP CONNECTIONS\n";
    std::cout << "========================================\n";

    if (tracker.size() == 0U) {
        std::cout << "No TCP connections observed.\n";
        return;
    }

    for (const auto& connection : tracker.connections()) {
        const std::uint64_t duration_us =
            connection.last_seen_us - connection.first_seen_us;

        std::cout << "\n#" << connection.id << '\n';

        std::cout << "    A           "
                  << connection.key.first.address << ':'
                  << connection.key.first.port << '\n';

        std::cout << "    B           "
                  << connection.key.second.address << ':'
                  << connection.key.second.port << '\n';

        std::cout << "    State       "
                  << wirescope::tcp_connection_state_name(
                      connection.state
                  ) << '\n';

        if (connection.initiator.has_value()) {
            std::cout << "    Initiator   "
                      << connection.initiator->address << ':'
                      << connection.initiator->port << '\n';
        } else {
            std::cout << "    Initiator   unknown (midstream capture)\n";
        }

        std::cout << "    Packets     "
                  << connection.packet_count << '\n';

        std::cout << "    Bytes       "
                  << connection.captured_bytes << '\n';

        std::cout << "    A -> B      "
                  << connection.packets_a_to_b
                  << " packets / "
                  << connection.bytes_a_to_b
                  << " bytes\n";

        std::cout << "    B -> A      "
                  << connection.packets_b_to_a
                  << " packets / "
                  << connection.bytes_b_to_a
                  << " bytes\n";

        std::cout << "    SYN         "
                  << connection.syn_packets
                  << "  SYN-ACK="
                  << connection.syn_ack_packets << '\n';

        std::cout << "    ACK         "
                  << connection.ack_packets
                  << "  FIN="
                  << connection.fin_packets
                  << "  RST="
                  << connection.rst_packets << '\n';

        std::cout << "    Duration    "
                  << duration_us / 1000U << '.'
                  << std::setw(3) << std::setfill('0')
                  << duration_us % 1000U
                  << std::setfill(' ')
                  << " ms\n";
    }

    std::cout << "\n========================================\n";
    std::cout << "Total TCP connection generations: "
              << tracker.size() << '\n';
    std::cout << "========================================\n";
}

} // namespace


// 
// Application entry point
// 

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: wirescope <capture.pcap>\n";
        return 2;
    }

    char error_buffer[PCAP_ERRBUF_SIZE]{};

    pcap_t* capture = pcap_open_offline(
        argv[1],
        error_buffer
    );

    if (capture == nullptr) {
        std::cerr << "Could not open capture: "
                  << error_buffer << '\n';

        return 1;
    }

    if (pcap_datalink(capture) != DLT_EN10MB) {
        std::cerr
            << "Unsupported capture link type. "
            << "This version expects Ethernet (DLT_EN10MB).\n";

        pcap_close(capture);
        return 1;
    }

    // Create our TCP connection tracker.
    wirescope::TcpConnectionTracker tcp_tracker;

    std::size_t packet_count = 0U;

    pcap_pkthdr* header = nullptr;
    const u_char* packet_data = nullptr;

    int status = 0;

    // Read packets from the capture.
    while (
        (status = pcap_next_ex(
            capture,
            &header,
            &packet_data
        )) == 1
    ) {
        ++packet_count;

        const auto* bytes =
            reinterpret_cast<const std::uint8_t*>(packet_data);

        const std::span<const std::uint8_t> frame(
            bytes,
            static_cast<std::size_t>(header->caplen)
        );

        // Decode the packet.
        const wirescope::PacketSummary summary =
            wirescope::decode_ethernet(
                frame,
                static_cast<std::size_t>(header->len)
            );

        // Feed the decoded packet into the TCP tracker.
        tcp_tracker.observe(
            summary,
            timestamp_to_microseconds(*header)
        );

        // Display individual packet information.
        print_packet(
            packet_count,
            *header,
            summary
        );
    }

    if (status == -1) {
        std::cerr << "Error reading capture: "
                  << pcap_geterr(capture)
                  << '\n';

        pcap_close(capture);
        return 1;
    }

    pcap_close(capture);

    // Display aggregated TCP connection information.
    print_connections(tcp_tracker);

    std::cout << "\nRead "
              << packet_count
              << " packet(s).\n";

    return 0;
}
