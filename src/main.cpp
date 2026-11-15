#include "wirescope/decoder.hpp"

#include <pcap/pcap.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <type_traits>
#include <span>
#include <string>
#include <variant>

namespace {

[[nodiscard]] std::string ether_type_name(std::uint16_t ether_type) {
    switch (ether_type) {
        case 0x0800U: return "IPv4";
        case 0x0806U: return "ARP";
        case 0x86DDU: return "IPv6";
        case 0x8100U: return "802.1Q VLAN";
        case 0x88A8U: return "802.1ad VLAN";
        default: {
            std::ostringstream output;
            output << "0x" << std::hex << std::setw(4) << std::setfill('0') << ether_type;
            return output.str();
        }
    }
}

void print_packet(std::size_t index,
                  const pcap_pkthdr& header,
                  const wirescope::PacketSummary& packet) {
    std::cout << '#' << index
              << "  " << header.ts.tv_sec << '.' << std::setw(6) << std::setfill('0')
              << header.ts.tv_usec << std::setfill(' ')
              << "  caplen=" << packet.captured_length
              << " wirelen=" << packet.wire_length << '\n';

    if (packet.ether_type != 0U) {
        std::cout << "    Ethernet  " << packet.source_mac << " -> "
                  << packet.destination_mac << "  type="
                  << ether_type_name(packet.ether_type) << '\n';
    }

    if (packet.ipv4.has_value()) {
        const auto& ip = *packet.ipv4;
        std::cout << "    IPv4      " << ip.source_address << " -> "
                  << ip.destination_address
                  << "  ttl=" << static_cast<unsigned int>(ip.ttl)
                  << "  protocol=" << static_cast<unsigned int>(ip.protocol)
                  << " (" << (ip.protocol == 6U ? "TCP" :
                                ip.protocol == 17U ? "UDP" : "other") << ')'
                  << "  id=" << ip.identification
                  << "  frag_offset=" << ip.fragment_offset
                  << (ip.more_fragments ? " MF" : "") << '\n';

        if (ip.transport.has_value()) {
            std::visit([](const auto& transport) {
                using T = std::decay_t<decltype(transport)>;
                if constexpr (std::is_same_v<T, wirescope::TcpInfo>) {
                    std::cout << "    TCP       " << transport.source_port << " -> "
                              << transport.destination_port
                              << "  seq=" << transport.sequence_number
                              << "  ack=" << transport.acknowledgement_number
                              << "  flags=" << wirescope::format_tcp_flags(transport.flags)
                              << "  window=" << transport.window_size << '\n';
                } else {
                    std::cout << "    UDP       " << transport.source_port << " -> "
                              << transport.destination_port
                              << "  length=" << transport.length << '\n';
                }
            }, *ip.transport);
        }
    }

    if (!packet.parse_error.empty()) {
        std::cout << "    [!]       " << packet.parse_error << '\n';
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: wirescope <capture.pcap>\n";
        return 2;
    }

    char error_buffer[PCAP_ERRBUF_SIZE]{};
    pcap_t* capture = pcap_open_offline(argv[1], error_buffer);
    if (capture == nullptr) {
        std::cerr << "Could not open capture: " << error_buffer << '\n';
        return 1;
    }

    if (pcap_datalink(capture) != DLT_EN10MB) {
        std::cerr << "Unsupported capture link type. This version expects Ethernet (DLT_EN10MB).\n";
        pcap_close(capture);
        return 1;
    }

    std::size_t packet_count = 0U;
    pcap_pkthdr* header = nullptr;
    const u_char* packet_data = nullptr;
    int status = 0;

    while ((status = pcap_next_ex(capture, &header, &packet_data)) == 1) {
        ++packet_count;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(packet_data);
        const auto frame = std::span<const std::uint8_t>(bytes, header->caplen);
        const auto summary = wirescope::decode_ethernet(frame, header->len);
        print_packet(packet_count, *header, summary);
    }

    if (status == -1) {
        std::cerr << "Error reading capture: " << pcap_geterr(capture) << '\n';
        pcap_close(capture);
        return 1;
    }

    pcap_close(capture);
    std::cout << "\nRead " << packet_count << " packet(s).\n";
    return 0;
}
