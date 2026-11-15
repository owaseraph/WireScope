#include "wirescope/decoder.hpp"

#include <array>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <utility>

namespace wirescope {
namespace {

[[nodiscard]] std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1U])
    );
}

[[nodiscard]] std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
           (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(bytes[offset + 3U]);
}

[[nodiscard]] bool has_bytes(std::span<const std::uint8_t> bytes,
                              std::size_t offset,
                              std::size_t count) {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}


void decode_ipv4(std::span<const std::uint8_t> packet, PacketSummary& result) {
    constexpr std::size_t minimum_ipv4_header = 20U;
    constexpr std::size_t ipv4_offset = 14U;

    if (!has_bytes(packet, ipv4_offset, minimum_ipv4_header)) {
        result.parse_error = "truncated IPv4 header";
        return;
    }

    const auto ip = packet.subspan(ipv4_offset);
    const std::uint8_t version_and_ihl = ip[0];
    const std::uint8_t version = static_cast<std::uint8_t>(version_and_ihl >> 4U);
    const std::size_t header_length =
        static_cast<std::size_t>(version_and_ihl & 0x0FU) * 4U;

    if (version != 4U) {
        result.parse_error = "EtherType says IPv4, but IP version is not 4";
        return;
    }
    if (header_length < minimum_ipv4_header) {
        result.parse_error = "invalid IPv4 header length (less than 20 bytes)";
        return;
    }
    if (!has_bytes(packet, ipv4_offset, header_length)) {
        result.parse_error = "truncated IPv4 header options";
        return;
    }

    const std::uint16_t total_length = read_u16(ip, 2U);
    if (total_length < header_length) {
        result.parse_error = "invalid IPv4 total length (smaller than header)";
        return;
    }
    if (static_cast<std::size_t>(total_length) > ip.size()) {
        result.parse_error = "truncated IPv4 packet (captured bytes do not cover total length)";
        // We still expose the valid IPv4 header below, but do not parse a
        // transport header from an incomplete IP datagram.
    }

    const std::uint16_t flags_and_offset = read_u16(ip, 6U);
    const std::uint16_t fragment_offset =
        static_cast<std::uint16_t>(flags_and_offset & 0x1FFFU);
    const bool more_fragments = (flags_and_offset & 0x2000U) != 0U;

    Ipv4Info info;
    info.source_address = format_ipv4(std::span<const std::uint8_t, 4>(ip.data() + 12U, 4U));
    info.destination_address = format_ipv4(std::span<const std::uint8_t, 4>(ip.data() + 16U, 4U));
    info.ttl = ip[8U];
    info.protocol = ip[9U];
    info.total_length = total_length;
    info.identification = read_u16(ip, 4U);
    info.fragment_offset = fragment_offset;
    info.more_fragments = more_fragments;
    info.header_length = header_length;

    const bool datagram_complete = static_cast<std::size_t>(total_length) <= ip.size();
    const bool first_fragment = fragment_offset == 0U;
    if (!datagram_complete || !first_fragment) {
        result.ipv4 = std::move(info);
        return;
    }

    const std::size_t transport_offset = ipv4_offset + header_length;
    const std::size_t transport_length =
        static_cast<std::size_t>(total_length) - header_length;

    if (info.protocol == 6U) { // TCP
        constexpr std::size_t minimum_tcp_header = 20U;
        if (transport_length < minimum_tcp_header ||
            !has_bytes(packet, transport_offset, minimum_tcp_header)) {
            result.parse_error = "truncated TCP header";
            result.ipv4 = std::move(info);
            return;
        }

        const auto tcp = packet.subspan(transport_offset, transport_length);
        const std::size_t tcp_header_length =
            static_cast<std::size_t>(tcp[12U] >> 4U) * 4U;
        if (tcp_header_length < minimum_tcp_header || tcp_header_length > transport_length) {
            result.parse_error = "invalid or truncated TCP data offset";
            result.ipv4 = std::move(info);
            return;
        }

        TcpInfo tcp_info;
        tcp_info.source_port = read_u16(tcp, 0U);
        tcp_info.destination_port = read_u16(tcp, 2U);
        tcp_info.sequence_number = read_u32(tcp, 4U);
        tcp_info.acknowledgement_number = read_u32(tcp, 8U);
        tcp_info.flags = tcp[13U];
        tcp_info.window_size = read_u16(tcp, 14U);
        tcp_info.header_length = tcp_header_length;
        info.transport = tcp_info;
    } else if (info.protocol == 17U) { // UDP
        constexpr std::size_t minimum_udp_header = 8U;
        if (transport_length < minimum_udp_header ||
            !has_bytes(packet, transport_offset, minimum_udp_header)) {
            result.parse_error = "truncated UDP header";
            result.ipv4 = std::move(info);
            return;
        }

        const auto udp = packet.subspan(transport_offset, minimum_udp_header);
        const std::uint16_t udp_length = read_u16(udp, 4U);
        if (udp_length < minimum_udp_header ||
            (!more_fragments && udp_length > transport_length)) {
            result.parse_error = "invalid UDP length";
            result.ipv4 = std::move(info);
            return;
        }

        UdpInfo udp_info;
        udp_info.source_port = read_u16(udp, 0U);
        udp_info.destination_port = read_u16(udp, 2U);
        udp_info.length = udp_length;
        info.transport = udp_info;
    }

    result.ipv4 = std::move(info);
}

} // namespace

std::string format_mac(std::span<const std::uint8_t, 6> address) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < address.size(); ++i) {
        if (i != 0U) {
            output << ':';
        }
        output << std::setw(2) << static_cast<unsigned int>(address[i]);
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

std::string format_tcp_flags(std::uint8_t flags) {
    constexpr std::array<std::pair<std::uint8_t, std::string_view>, 8> names{{
        {0x01U, "FIN"}, {0x02U, "SYN"}, {0x04U, "RST"}, {0x08U, "PSH"},
        {0x10U, "ACK"}, {0x20U, "URG"}, {0x40U, "ECE"}, {0x80U, "CWR"}
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

PacketSummary decode_ethernet(std::span<const std::uint8_t> frame,
                              std::size_t wire_length) {
    PacketSummary result;
    result.captured_length = frame.size();
    result.wire_length = wire_length;

    constexpr std::size_t ethernet_header_length = 14U;
    if (frame.size() < ethernet_header_length) {
        result.parse_error = "truncated Ethernet II header";
        return result;
    }

    result.destination_mac = format_mac(
        std::span<const std::uint8_t, 6>(frame.data(), 6U));
    result.source_mac = format_mac(
        std::span<const std::uint8_t, 6>(frame.data() + 6U, 6U));
    result.ether_type = read_u16(frame, 12U);

    if (result.ether_type == 0x0800U) {
        decode_ipv4(frame, result);
    }

    return result;
}

} // namespace wirescope
