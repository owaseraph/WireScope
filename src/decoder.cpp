#include "wirescope/decoder.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <utility>

namespace wirescope {
namespace {

constexpr std::uint16_t ether_type_ipv4 = 0x0800U;
constexpr std::uint16_t ether_type_ipv6 = 0x86DDU;
constexpr std::uint16_t ether_type_vlan = 0x8100U;
constexpr std::uint16_t ether_type_service_vlan = 0x88A8U;

constexpr std::uint8_t protocol_tcp = 6U;
constexpr std::uint8_t protocol_udp = 17U;

constexpr std::uint8_t ipv6_hop_by_hop = 0U;
constexpr std::uint8_t ipv6_routing = 43U;
constexpr std::uint8_t ipv6_fragment = 44U;
constexpr std::uint8_t ipv6_destination_options = 60U;

[[nodiscard]] std::uint16_t read_u16(
    std::span<const std::uint8_t> bytes,
    std::size_t offset
) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U])
    );
}

[[nodiscard]] std::uint32_t read_u32(
    std::span<const std::uint8_t> bytes,
    std::size_t offset
) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

[[nodiscard]] bool has_bytes(
    std::span<const std::uint8_t> bytes,
    std::size_t offset,
    std::size_t count
) {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

void set_parse_error(std::string& current_error, std::string_view new_error) {
    if (current_error.empty()) {
        current_error = new_error;
    }
}

[[nodiscard]] bool is_vlan_ether_type(std::uint16_t ether_type) {
    return ether_type == ether_type_vlan ||
           ether_type == ether_type_service_vlan;
}

[[nodiscard]] bool is_ipv6_extension_header(std::uint8_t next_header) {
    return next_header == ipv6_hop_by_hop ||
           next_header == ipv6_routing ||
           next_header == ipv6_fragment ||
           next_header == ipv6_destination_options;
}

void decode_transport(
    std::span<const std::uint8_t> payload,
    std::uint8_t protocol,
    bool allow_partial_udp_datagram,
    std::optional<TransportInfo>& transport,
    std::string& parse_error
) {
    if (protocol == protocol_tcp) {
        constexpr std::size_t minimum_tcp_header = 20U;

        if (payload.size() < minimum_tcp_header) {
            set_parse_error(parse_error, "truncated TCP header");
            return;
        }

        const std::size_t tcp_header_length =
            static_cast<std::size_t>(payload[12U] >> 4U) * 4U;

        if (tcp_header_length < minimum_tcp_header ||
            tcp_header_length > payload.size()) {
            set_parse_error(parse_error, "invalid or truncated TCP data offset");
            return;
        }

        TcpInfo info;
        info.source_port = read_u16(payload, 0U);
        info.destination_port = read_u16(payload, 2U);
        info.sequence_number = read_u32(payload, 4U);
        info.acknowledgement_number = read_u32(payload, 8U);
        info.flags = payload[13U];
        info.window_size = read_u16(payload, 14U);
        info.header_length = tcp_header_length;

        transport = TransportInfo{info};
        return;
    }

    if (protocol == protocol_udp) {
        constexpr std::size_t minimum_udp_header = 8U;

        if (payload.size() < minimum_udp_header) {
            set_parse_error(parse_error, "truncated UDP header");
            return;
        }

        const std::uint16_t udp_length = read_u16(payload, 4U);

        if (udp_length < minimum_udp_header ||
            (!allow_partial_udp_datagram &&
             static_cast<std::size_t>(udp_length) > payload.size())) {
            set_parse_error(parse_error, "invalid UDP length");
            return;
        }

        UdpInfo info;
        info.source_port = read_u16(payload, 0U);
        info.destination_port = read_u16(payload, 2U);
        info.length = udp_length;

        transport = TransportInfo{info};
    }
}

void decode_ipv4(
    std::span<const std::uint8_t> frame,
    std::size_t ip_offset,
    PacketSummary& result
) {
    constexpr std::size_t minimum_ipv4_header = 20U;

    if (!has_bytes(frame, ip_offset, minimum_ipv4_header)) {
        set_parse_error(result.parse_error, "truncated IPv4 header");
        return;
    }

    const auto ip = frame.subspan(ip_offset);
    const std::uint8_t version_and_ihl = ip[0U];
    const std::uint8_t version = static_cast<std::uint8_t>(version_and_ihl >> 4U);
    const std::size_t header_length =
        static_cast<std::size_t>(version_and_ihl & 0x0FU) * 4U;

    if (version != 4U) {
        set_parse_error(
            result.parse_error,
            "EtherType says IPv4, but IP version is not 4"
        );
        return;
    }

    if (header_length < minimum_ipv4_header) {
        set_parse_error(
            result.parse_error,
            "invalid IPv4 header length (less than 20 bytes)"
        );
        return;
    }

    if (!has_bytes(frame, ip_offset, header_length)) {
        set_parse_error(result.parse_error, "truncated IPv4 header options");
        return;
    }

    const std::uint16_t total_length = read_u16(ip, 2U);
    if (static_cast<std::size_t>(total_length) < header_length) {
        set_parse_error(
            result.parse_error,
            "invalid IPv4 total length (smaller than header)"
        );
        return;
    }

    const bool datagram_complete =
        static_cast<std::size_t>(total_length) <= ip.size();

    if (!datagram_complete) {
        set_parse_error(
            result.parse_error,
            "truncated IPv4 packet (captured bytes do not cover total length)"
        );
    }

    const std::uint16_t flags_and_offset = read_u16(ip, 6U);
    const std::uint16_t fragment_offset =
        static_cast<std::uint16_t>(flags_and_offset & 0x1FFFU);
    const bool more_fragments = (flags_and_offset & 0x2000U) != 0U;

    Ipv4Info info;
    info.source_address = format_ipv4(
        std::span<const std::uint8_t, 4>(ip.data() + 12U, 4U)
    );
    info.destination_address = format_ipv4(
        std::span<const std::uint8_t, 4>(ip.data() + 16U, 4U)
    );
    info.ttl = ip[8U];
    info.protocol = ip[9U];
    info.total_length = total_length;
    info.identification = read_u16(ip, 4U);
    info.fragment_offset = fragment_offset;
    info.more_fragments = more_fragments;
    info.header_length = header_length;

    const bool first_fragment = fragment_offset == 0U;
    if (datagram_complete && first_fragment) {
        const std::size_t transport_length =
            static_cast<std::size_t>(total_length) - header_length;
        const auto transport_payload = ip.subspan(header_length, transport_length);

        decode_transport(
            transport_payload,
            info.protocol,
            more_fragments,
            info.transport,
            result.parse_error
        );
    }

    result.ipv4 = std::move(info);
}

void decode_ipv6(
    std::span<const std::uint8_t> frame,
    std::size_t ip_offset,
    PacketSummary& result
) {
    constexpr std::size_t ipv6_header_length = 40U;

    if (!has_bytes(frame, ip_offset, ipv6_header_length)) {
        set_parse_error(result.parse_error, "truncated IPv6 header");
        return;
    }

    const auto ip = frame.subspan(ip_offset);
    const std::uint32_t first_word = read_u32(ip, 0U);
    const std::uint8_t version = static_cast<std::uint8_t>(first_word >> 28U);

    if (version != 6U) {
        set_parse_error(
            result.parse_error,
            "EtherType says IPv6, but IP version is not 6"
        );
        return;
    }

    Ipv6Info info;
    info.traffic_class = static_cast<std::uint8_t>((first_word >> 20U) & 0xFFU);
    info.flow_label = first_word & 0x000FFFFFU;
    info.payload_length = read_u16(ip, 4U);
    info.next_header = ip[6U];
    info.upper_layer_protocol = info.next_header;
    info.hop_limit = ip[7U];
    info.source_address = format_ipv6(
        std::span<const std::uint8_t, 16>(ip.data() + 8U, 16U)
    );
    info.destination_address = format_ipv6(
        std::span<const std::uint8_t, 16>(ip.data() + 24U, 16U)
    );

    const std::size_t declared_payload_length =
        static_cast<std::size_t>(info.payload_length);
    const std::size_t captured_payload_length =
        std::min(declared_payload_length, ip.size() - ipv6_header_length);
    const bool datagram_complete =
        captured_payload_length == declared_payload_length;

    if (!datagram_complete) {
        set_parse_error(
            result.parse_error,
            "truncated IPv6 packet (captured bytes do not cover payload length)"
        );
    }

    const auto payload = ip.subspan(
        ipv6_header_length,
        captured_payload_length
    );

    std::size_t payload_offset = 0U;
    std::uint8_t current_header = info.next_header;
    bool extension_chain_valid = true;
    bool non_initial_fragment = false;
    bool allow_partial_udp_datagram = false;

    while (is_ipv6_extension_header(current_header)) {
        const std::uint8_t extension_type = current_header;
        const std::size_t declared_remaining =
            declared_payload_length - payload_offset;

        std::size_t extension_length = 0U;
        std::uint8_t next_header = 0U;

        if (extension_type == ipv6_fragment) {
            constexpr std::size_t fragment_header_length = 8U;

            if (declared_remaining < fragment_header_length) {
                set_parse_error(
                    result.parse_error,
                    "IPv6 Fragment header exceeds declared payload length"
                );
                extension_chain_valid = false;
                break;
            }

            if (!has_bytes(payload, payload_offset, fragment_header_length)) {
                set_parse_error(result.parse_error, "truncated IPv6 Fragment header");
                extension_chain_valid = false;
                break;
            }

            if (info.fragment.has_value()) {
                set_parse_error(result.parse_error, "multiple IPv6 Fragment headers");
                extension_chain_valid = false;
                break;
            }

            next_header = payload[payload_offset];
            const std::uint16_t fragment_field =
                read_u16(payload, payload_offset + 2U);

            Ipv6FragmentInfo fragment_info;
            fragment_info.offset = static_cast<std::uint16_t>(fragment_field >> 3U);
            fragment_info.more_fragments = (fragment_field & 0x0001U) != 0U;
            fragment_info.identification =
                read_u32(payload, payload_offset + 4U);

            info.fragment = fragment_info;
            non_initial_fragment = fragment_info.offset != 0U;
            allow_partial_udp_datagram = fragment_info.more_fragments;
            extension_length = fragment_header_length;
        } else {
            constexpr std::size_t minimum_options_header_length = 2U;

            if (declared_remaining < minimum_options_header_length) {
                set_parse_error(
                    result.parse_error,
                    "IPv6 extension header exceeds declared payload length"
                );
                extension_chain_valid = false;
                break;
            }

            if (!has_bytes(payload, payload_offset, minimum_options_header_length)) {
                set_parse_error(
                    result.parse_error,
                    "truncated IPv6 extension header"
                );
                extension_chain_valid = false;
                break;
            }

            next_header = payload[payload_offset];
            extension_length =
                (static_cast<std::size_t>(payload[payload_offset + 1U]) + 1U) * 8U;

            if (extension_length > declared_remaining) {
                set_parse_error(
                    result.parse_error,
                    "IPv6 extension header exceeds declared payload length"
                );
                extension_chain_valid = false;
                break;
            }

            if (!has_bytes(payload, payload_offset, extension_length)) {
                set_parse_error(
                    result.parse_error,
                    "truncated IPv6 extension header"
                );
                extension_chain_valid = false;
                break;
            }
        }

        info.extension_headers.push_back(
            Ipv6ExtensionInfo{
                extension_type,
                next_header,
                extension_length
            }
        );

        payload_offset += extension_length;
        current_header = next_header;

        // A non-initial fragment does not begin at the start of the
        // fragmentable part, so its following bytes cannot be parsed as
        // another extension header or as a transport header.
        if (non_initial_fragment) {
            break;
        }
    }

    info.upper_layer_protocol = current_header;
    info.header_length = ipv6_header_length + payload_offset;

    if (extension_chain_valid && datagram_complete && !non_initial_fragment) {
        const auto transport_payload = payload.subspan(payload_offset);

        decode_transport(
            transport_payload,
            info.upper_layer_protocol,
            allow_partial_udp_datagram,
            info.transport,
            result.parse_error
        );
    }

    result.ipv6 = std::move(info);
}

} // namespace

std::string format_mac(std::span<const std::uint8_t, 6> address) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (std::size_t i = 0U; i < address.size(); ++i) {
        if (i != 0U) {
            output << ':';
        }

        output << std::setw(2)
               << static_cast<unsigned int>(address[i]);
    }

    return output.str();
}

std::string format_ipv4(std::span<const std::uint8_t, 4> address) {
    std::ostringstream output;
    output << static_cast<unsigned int>(address[0]) << '.'
           << static_cast<unsigned int>(address[1]) << '.'
           << static_cast<unsigned int>(address[2]) << '.'
           << static_cast<unsigned int>(address[3]);
    return output.str();
}

std::string format_ipv6(std::span<const std::uint8_t, 16> address) {
    std::array<std::uint16_t, 8> groups{};

    for (std::size_t i = 0U; i < groups.size(); ++i) {
        groups[i] = read_u16(address, i * 2U);
    }

    // RFC 5952-style zero compression: compress the longest run of at least
    // two zero groups. In a tie, the first run is selected.
    std::size_t best_start = groups.size();
    std::size_t best_length = 0U;

    for (std::size_t i = 0U; i < groups.size();) {
        if (groups[i] != 0U) {
            ++i;
            continue;
        }

        const std::size_t run_start = i;
        while (i < groups.size() && groups[i] == 0U) {
            ++i;
        }

        const std::size_t run_length = i - run_start;
        if (run_length >= 2U && run_length > best_length) {
            best_start = run_start;
            best_length = run_length;
        }
    }

    std::ostringstream output;
    output << std::hex;

    std::size_t i = 0U;
    while (i < groups.size()) {
        if (i == best_start) {
            output << "::";
            i += best_length;

            if (i == groups.size()) {
                break;
            }

            continue;
        }

        if (i != 0U && i != best_start + best_length) {
            output << ':';
        }

        output << groups[i];
        ++i;
    }

    return output.str();
}

std::string format_tcp_flags(std::uint8_t flags) {
    constexpr std::array<std::pair<std::uint8_t, std::string_view>, 8> names{{
        {0x01U, "FIN"},
        {0x02U, "SYN"},
        {0x04U, "RST"},
        {0x08U, "PSH"},
        {0x10U, "ACK"},
        {0x20U, "URG"},
        {0x40U, "ECE"},
        {0x80U, "CWR"}
    }};

    std::string result;

    for (const auto& [mask, name] : names) {
        if ((flags & mask) != 0U) {
            if (!result.empty()) {
                result += ',';
            }

            result += name;
        }
    }

    return result.empty() ? "none" : result;
}

PacketSummary decode_ethernet(
    std::span<const std::uint8_t> frame,
    std::size_t wire_length
) {
    PacketSummary result;
    result.captured_length = frame.size();
    result.wire_length = wire_length;

    constexpr std::size_t ethernet_header_length = 14U;

    if (frame.size() < ethernet_header_length) {
        result.parse_error = "truncated Ethernet II header";
        return result;
    }

    result.destination_mac = format_mac(
        std::span<const std::uint8_t, 6>(frame.data(), 6U)
    );
    result.source_mac = format_mac(
        std::span<const std::uint8_t, 6>(frame.data() + 6U, 6U)
    );

    result.ether_type = read_u16(frame, 12U);
    std::size_t network_offset = ethernet_header_length;

    // Each 802.1Q/802.1ad tag adds a 4-byte TCI + inner EtherType pair.
    // Repeating this loop also supports stacked VLAN tags (Q-in-Q).
    while (is_vlan_ether_type(result.ether_type)) {
        constexpr std::size_t vlan_tag_body_length = 4U;

        if (!has_bytes(frame, network_offset, vlan_tag_body_length)) {
            set_parse_error(result.parse_error, "truncated VLAN tag");
            return result;
        }

        const std::uint16_t tag_protocol_id = result.ether_type;
        const std::uint16_t tag_control_information =
            read_u16(frame, network_offset);
        const std::uint16_t encapsulated_ether_type =
            read_u16(frame, network_offset + 2U);

        VlanTag tag;
        tag.tag_protocol_id = tag_protocol_id;
        tag.priority = static_cast<std::uint8_t>(
            (tag_control_information >> 13U) & 0x0007U
        );
        tag.drop_eligible = (tag_control_information & 0x1000U) != 0U;
        tag.vlan_id = static_cast<std::uint16_t>(
            tag_control_information & 0x0FFFU
        );
        tag.encapsulated_ether_type = encapsulated_ether_type;

        result.vlan_tags.push_back(tag);
        result.ether_type = encapsulated_ether_type;
        network_offset += vlan_tag_body_length;
    }

    if (result.ether_type == ether_type_ipv4) {
        decode_ipv4(frame, network_offset, result);
    } else if (result.ether_type == ether_type_ipv6) {
        decode_ipv6(frame, network_offset, result);
    }

    return result;
}

PacketSummary decode_packet(LinkType link_type, std::span<const std::uint8_t> bytes,
                            std::size_t wire_length) {
    if (is_ethernet(link_type)) return decode_ethernet(bytes, wire_length);
    PacketSummary summary;
    summary.captured_length = bytes.size();
    summary.wire_length = wire_length;
    if (const auto* pcap = std::get_if<PcapLinkType>(&link_type.framing)) {
        summary.parse_error = "unsupported PCAP link type " + std::to_string(pcap->value);
    } else {
        const auto hardware = std::get<LinuxHardwareType>(link_type.framing);
        summary.parse_error = "unsupported Linux hardware type " + std::to_string(hardware.value);
    }
    return summary;
}

} // namespace wirescope
