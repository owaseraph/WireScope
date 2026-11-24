#include "wirescope/decoder.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

// ------------------------------------------------------------
// Small packet-building helpers
// ------------------------------------------------------------

void append_u16(Bytes& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value & 0x00FFU));
}

void append_u32(Bytes& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

void append_ethernet(Bytes& bytes, std::uint16_t ether_type) {
    // Destination MAC: 02:00:00:00:00:02
    // Source MAC:      02:00:00:00:00:01
    bytes.insert(bytes.end(), {
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U
    });
    append_u16(bytes, ether_type);
}

void append_ipv6_base(
    Bytes& bytes,
    std::uint16_t payload_length,
    std::uint8_t next_header
) {
    // Version 6, traffic class 0, flow label 0.
    append_u32(bytes, 0x60000000U);
    append_u16(bytes, payload_length);
    bytes.push_back(next_header);
    bytes.push_back(64U); // Hop Limit

    // Source:      2001:db8::1
    bytes.insert(bytes.end(), {
        0x20U, 0x01U, 0x0DU, 0xB8U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x01U
    });

    // Destination: 2001:db8::2
    bytes.insert(bytes.end(), {
        0x20U, 0x01U, 0x0DU, 0xB8U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x02U
    });
}

void append_udp(
    Bytes& bytes,
    std::uint16_t length,
    std::uint16_t source_port = 12345U,
    std::uint16_t destination_port = 53U
) {
    append_u16(bytes, source_port);
    append_u16(bytes, destination_port);
    append_u16(bytes, length);
    append_u16(bytes, 0U); // Checksum (not validated by this decoder)
}

void append_tcp_syn(Bytes& bytes) {
    append_u16(bytes, 50000U); // Source port
    append_u16(bytes, 443U);   // Destination port
    append_u32(bytes, 1U);     // Sequence number
    append_u32(bytes, 0U);     // Acknowledgement number
    bytes.push_back(0x50U);    // Data offset: 5 words (20 bytes)
    bytes.push_back(0x02U);    // SYN
    append_u16(bytes, 64240U); // Window size
    append_u16(bytes, 0U);     // Checksum (not validated)
    append_u16(bytes, 0U);     // Urgent pointer
}

[[nodiscard]] Bytes make_ipv6_udp_frame() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 8U, 17U);
    append_udp(bytes, 8U);
    return bytes;
}

// ------------------------------------------------------------
// Original regression tests: Ethernet and IPv4 behavior
// ------------------------------------------------------------

void test_truncated_ethernet() {
    const std::array<std::uint8_t, 5> bytes{0U, 1U, 2U, 3U, 4U};
    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error == "truncated Ethernet II header");
}

void test_arp_frame() {
    const std::array<std::uint8_t, 14> bytes{
        0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
        0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U,
        0x08U, 0x06U
    };

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.ether_type == 0x0806U);
    assert(result.source_mac == "00:11:22:33:44:55");
    assert(result.destination_mac == "ff:ff:ff:ff:ff:ff");
    assert(!result.ipv4.has_value());
    assert(!result.ipv6.has_value());
    assert(result.parse_error.empty());
}

void test_ipv4_udp_frame() {
    const std::array<std::uint8_t, 42> bytes{
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x08U, 0x00U,
        0x45U, 0x00U, 0x00U, 0x1CU, 0x12U, 0x34U, 0x00U, 0x00U,
        0x40U, 0x11U, 0x00U, 0x00U, 0xC0U, 0x00U, 0x02U, 0x01U,
        0xC6U, 0x33U, 0x64U, 0x02U,
        0x30U, 0x39U, 0x00U, 0x35U, 0x00U, 0x08U, 0x00U, 0x00U
    };

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv4.has_value());

    const auto& ip = *result.ipv4;
    assert(ip.source_address == "192.0.2.1");
    assert(ip.destination_address == "198.51.100.2");
    assert(ip.ttl == 64U);
    assert(ip.protocol == 17U);
    assert(ip.transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*ip.transport));

    const auto& udp = std::get<wirescope::UdpInfo>(*ip.transport);
    assert(udp.source_port == 12345U);
    assert(udp.destination_port == 53U);
    assert(udp.length == 8U);
}

void test_ipv4_tcp_syn_frame() {
    const std::array<std::uint8_t, 54> bytes{
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x08U, 0x00U,
        0x45U, 0x00U, 0x00U, 0x28U, 0x00U, 0x01U, 0x00U, 0x00U,
        0x40U, 0x06U, 0x00U, 0x00U, 0xC0U, 0x00U, 0x02U, 0x01U,
        0xC6U, 0x33U, 0x64U, 0x02U,
        0xC3U, 0x50U, 0x00U, 0x50U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x50U, 0x02U, 0xFAU, 0xF0U,
        0x00U, 0x00U, 0x00U, 0x00U
    };

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv4.has_value());
    assert(result.ipv4->transport.has_value());
    assert(std::holds_alternative<wirescope::TcpInfo>(*result.ipv4->transport));

    const auto& tcp = std::get<wirescope::TcpInfo>(*result.ipv4->transport);
    assert(tcp.source_port == 50000U);
    assert(tcp.destination_port == 80U);
    assert(tcp.sequence_number == 1U);
    assert(tcp.flags == 0x02U);
    assert(wirescope::format_tcp_flags(tcp.flags) == "SYN");
}

void test_non_initial_ipv4_fragment_skips_transport() {
    Bytes bytes{
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x08U, 0x00U,
        0x45U, 0x00U, 0x00U, 0x1CU, 0x12U, 0x34U, 0x00U, 0x01U,
        0x40U, 0x11U, 0x00U, 0x00U, 0xC0U, 0x00U, 0x02U, 0x01U,
        0xC6U, 0x33U, 0x64U, 0x02U
    };
    bytes.resize(14U + 28U, 0xAAU);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.ipv4.has_value());
    assert(result.ipv4->fragment_offset == 1U);
    assert(!result.ipv4->transport.has_value());
}

void test_truncated_ipv4_is_reported_without_transport_decode() {
    const std::array<std::uint8_t, 34> bytes{
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x08U, 0x00U,
        0x45U, 0x00U, 0x00U, 0x28U, 0x00U, 0x01U, 0x00U, 0x00U,
        0x40U, 0x11U, 0x00U, 0x00U, 0xC0U, 0x00U, 0x02U, 0x01U,
        0xC6U, 0x33U, 0x64U, 0x02U
    };

    const auto result = wirescope::decode_ethernet(bytes, 60U);
    assert(result.ipv4.has_value());
    assert(result.parse_error ==
        "truncated IPv4 packet (captured bytes do not cover total length)");
    assert(!result.ipv4->transport.has_value());
}

void test_first_ipv4_fragment_can_contain_partial_udp_datagram() {
    const std::array<std::uint8_t, 42> bytes{
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x02U,
        0x02U, 0x00U, 0x00U, 0x00U, 0x00U, 0x01U,
        0x08U, 0x00U,
        0x45U, 0x00U, 0x00U, 0x1CU, 0x12U, 0x34U, 0x20U, 0x00U,
        0x40U, 0x11U, 0x00U, 0x00U, 0xC0U, 0x00U, 0x02U, 0x01U,
        0xC6U, 0x33U, 0x64U, 0x02U,
        0x30U, 0x39U, 0x00U, 0x35U, 0x00U, 0x20U, 0x00U, 0x00U
    };

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv4.has_value());
    assert(result.ipv4->more_fragments);
    assert(result.ipv4->transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*result.ipv4->transport));
    assert(std::get<wirescope::UdpInfo>(*result.ipv4->transport).length == 32U);
}

// ------------------------------------------------------------
// IPv6 address formatting
// ------------------------------------------------------------

void test_ipv6_formatting_compresses_middle_zero_run() {
    const std::array<std::uint8_t, 16> address{
        0x20U, 0x01U, 0x0DU, 0xB8U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x01U
    };
    assert(wirescope::format_ipv6(address) == "2001:db8::1");
}

void test_ipv6_formatting_handles_all_zero_address() {
    const std::array<std::uint8_t, 16> address{};
    assert(wirescope::format_ipv6(address) == "::");
}

void test_ipv6_formatting_handles_leading_and_trailing_zero_runs() {
    const std::array<std::uint8_t, 16> leading{
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x01U
    };
    const std::array<std::uint8_t, 16> trailing{
        0x20U, 0x01U, 0x0DU, 0xB8U,
        0x00U, 0x01U, 0x00U, 0x02U,
        0x00U, 0x03U, 0x00U, 0x04U,
        0x00U, 0x00U, 0x00U, 0x00U
    };

    assert(wirescope::format_ipv6(leading) == "::1");
    assert(wirescope::format_ipv6(trailing) == "2001:db8:1:2:3:4::");
}

void test_ipv6_formatting_does_not_compress_single_zero_group() {
    const std::array<std::uint8_t, 16> address{
        0x20U, 0x01U, 0x0DU, 0xB8U,
        0x00U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x02U, 0x00U, 0x03U,
        0x00U, 0x04U, 0x00U, 0x05U
    };
    assert(wirescope::format_ipv6(address) == "2001:db8:0:1:2:3:4:5");
}

void test_ipv6_formatting_uses_first_longest_run_on_tie() {
    const std::array<std::uint8_t, 16> address{
        0x00U, 0x01U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x02U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x03U, 0x00U, 0x04U
    };
    assert(wirescope::format_ipv6(address) == "1::2:0:0:3:4");
}

// ------------------------------------------------------------
// VLAN parsing
// ------------------------------------------------------------

void test_single_vlan_tag_decodes_ipv4_at_correct_offset() {
    Bytes bytes;
    append_ethernet(bytes, 0x8100U);
    append_u16(bytes, 0xB064U); // PCP=5, DEI=1, VID=100
    append_u16(bytes, 0x0800U); // Encapsulated IPv4

    // IPv4 header: 192.0.2.1 -> 198.51.100.2, UDP.
    bytes.insert(bytes.end(), {
        0x45U, 0x00U, 0x00U, 0x1CU, 0x12U, 0x34U, 0x00U, 0x00U,
        0x40U, 0x11U, 0x00U, 0x00U,
        0xC0U, 0x00U, 0x02U, 0x01U,
        0xC6U, 0x33U, 0x64U, 0x02U
    });
    append_udp(bytes, 8U);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.vlan_tags.size() == 1U);
    assert(result.vlan_tags[0].tag_protocol_id == 0x8100U);
    assert(result.vlan_tags[0].priority == 5U);
    assert(result.vlan_tags[0].drop_eligible);
    assert(result.vlan_tags[0].vlan_id == 100U);
    assert(result.vlan_tags[0].encapsulated_ether_type == 0x0800U);
    assert(result.ether_type == 0x0800U);
    assert(result.ipv4.has_value());
    assert(result.ipv4->source_address == "192.0.2.1");
    assert(result.ipv4->transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*result.ipv4->transport));
}

void test_vlan_tagged_ipv6_frame() {
    Bytes bytes;
    append_ethernet(bytes, 0x8100U);
    append_u16(bytes, 0x0064U); // VID=100, PCP=0, DEI=0
    append_u16(bytes, 0x86DDU);
    append_ipv6_base(bytes, 8U, 17U);
    append_udp(bytes, 8U);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.vlan_tags.size() == 1U);
    assert(result.vlan_tags[0].vlan_id == 100U);
    assert(result.ether_type == 0x86DDU);
    assert(!result.ipv4.has_value());
    assert(result.ipv6.has_value());
    assert(result.ipv6->source_address == "2001:db8::1");
    assert(result.ipv6->transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*result.ipv6->transport));
}

void test_stacked_vlan_tags_preserve_outer_and_inner_tags() {
    Bytes bytes;
    append_ethernet(bytes, 0x88A8U); // Outer service VLAN
    append_u16(bytes, 10U);          // Outer VID=10
    append_u16(bytes, 0x8100U);      // Inner 802.1Q tag follows
    append_u16(bytes, 20U);          // Inner VID=20
    append_u16(bytes, 0x0806U);      // Final EtherType: ARP

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.vlan_tags.size() == 2U);
    assert(result.vlan_tags[0].tag_protocol_id == 0x88A8U);
    assert(result.vlan_tags[0].vlan_id == 10U);
    assert(result.vlan_tags[0].encapsulated_ether_type == 0x8100U);
    assert(result.vlan_tags[1].tag_protocol_id == 0x8100U);
    assert(result.vlan_tags[1].vlan_id == 20U);
    assert(result.vlan_tags[1].encapsulated_ether_type == 0x0806U);
    assert(result.ether_type == 0x0806U);
}

void test_truncated_vlan_tag_is_reported() {
    Bytes bytes;
    append_ethernet(bytes, 0x8100U);
    bytes.push_back(0x00U); // Only one of the four VLAN tag bytes.

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error == "truncated VLAN tag");
    assert(result.vlan_tags.empty());
}

// ------------------------------------------------------------
// IPv6 base header and transport parsing
// ------------------------------------------------------------

void test_ipv6_udp_frame() {
    const auto bytes = make_ipv6_udp_frame();
    const auto result = wirescope::decode_ethernet(bytes, bytes.size());

    assert(result.parse_error.empty());
    assert(result.ether_type == 0x86DDU);
    assert(result.ipv6.has_value());
    assert(!result.ipv4.has_value());

    const auto& ip = *result.ipv6;
    assert(ip.source_address == "2001:db8::1");
    assert(ip.destination_address == "2001:db8::2");
    assert(ip.traffic_class == 0U);
    assert(ip.flow_label == 0U);
    assert(ip.payload_length == 8U);
    assert(ip.next_header == 17U);
    assert(ip.upper_layer_protocol == 17U);
    assert(ip.hop_limit == 64U);
    assert(ip.header_length == 40U);
    assert(ip.extension_headers.empty());
    assert(!ip.fragment.has_value());
    assert(ip.transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*ip.transport));

    const auto& udp = std::get<wirescope::UdpInfo>(*ip.transport);
    assert(udp.source_port == 12345U);
    assert(udp.destination_port == 53U);
    assert(udp.length == 8U);
}

void test_ipv6_tcp_syn_frame() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 20U, 6U);
    append_tcp_syn(bytes);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv6.has_value());
    assert(result.ipv6->transport.has_value());
    assert(std::holds_alternative<wirescope::TcpInfo>(*result.ipv6->transport));

    const auto& tcp = std::get<wirescope::TcpInfo>(*result.ipv6->transport);
    assert(tcp.source_port == 50000U);
    assert(tcp.destination_port == 443U);
    assert(tcp.sequence_number == 1U);
    assert(tcp.flags == 0x02U);
    assert(tcp.header_length == 20U);
}

void test_truncated_ipv6_base_header_is_reported() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    bytes.resize(14U + 20U, 0U);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error == "truncated IPv6 header");
    assert(!result.ipv6.has_value());
}

void test_truncated_ipv6_payload_is_reported_without_transport_decode() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 16U, 17U); // Declares 16 payload bytes.
    append_udp(bytes, 16U);            // Capture only has 8 payload bytes.

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.ipv6.has_value());
    assert(result.parse_error ==
        "truncated IPv6 packet (captured bytes do not cover payload length)");
    assert(!result.ipv6->transport.has_value());
}

void test_wrong_version_in_ipv6_frame_is_reported() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_u32(bytes, 0x40000000U); // Version field says 4, not 6.
    bytes.resize(14U + 40U, 0U);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error ==
        "EtherType says IPv6, but IP version is not 6");
    assert(!result.ipv6.has_value());
}

// ------------------------------------------------------------
// IPv6 extension headers and fragmentation
// ------------------------------------------------------------

void test_ipv6_hop_by_hop_header_then_udp() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 16U, 0U); // Hop-by-Hop header follows.

    bytes.push_back(17U); // Extension's Next Header: UDP.
    bytes.push_back(0U);  // Hdr Ext Len: (0 + 1) * 8 = 8 bytes.
    bytes.insert(bytes.end(), {0U, 0U, 0U, 0U, 0U, 0U});
    append_udp(bytes, 8U);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv6.has_value());
    assert(result.ipv6->extension_headers.size() == 1U);
    assert(result.ipv6->extension_headers[0].type == 0U);
    assert(result.ipv6->extension_headers[0].next_header == 17U);
    assert(result.ipv6->extension_headers[0].header_length == 8U);
    assert(result.ipv6->upper_layer_protocol == 17U);
    assert(result.ipv6->header_length == 48U);
    assert(result.ipv6->transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*result.ipv6->transport));
}

void test_ipv6_extension_header_chain() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 32U, 0U); // Hop-by-Hop -> Routing -> Destination -> UDP.

    // Hop-by-Hop Options: 8 bytes, next is Routing (43).
    bytes.insert(bytes.end(), {43U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    // Routing: 8 bytes, next is Destination Options (60).
    bytes.insert(bytes.end(), {60U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    // Destination Options: 8 bytes, next is UDP (17).
    bytes.insert(bytes.end(), {17U, 0U, 0U, 0U, 0U, 0U, 0U, 0U});
    append_udp(bytes, 8U);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv6.has_value());
    assert(result.ipv6->extension_headers.size() == 3U);
    assert(result.ipv6->extension_headers[0].type == 0U);
    assert(result.ipv6->extension_headers[1].type == 43U);
    assert(result.ipv6->extension_headers[2].type == 60U);
    assert(result.ipv6->upper_layer_protocol == 17U);
    assert(result.ipv6->header_length == 64U);
    assert(result.ipv6->transport.has_value());
}

void test_first_ipv6_fragment_can_contain_partial_udp_datagram() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 16U, 44U); // Fragment header + UDP header.

    bytes.push_back(17U);       // Fragment header's Next Header: UDP.
    bytes.push_back(0U);        // Reserved.
    append_u16(bytes, 0x0001U); // Offset=0, M=1.
    append_u32(bytes, 0x12345678U);
    append_udp(bytes, 32U);     // Full datagram length exceeds this fragment.

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv6.has_value());
    assert(result.ipv6->fragment.has_value());
    assert(result.ipv6->fragment->offset == 0U);
    assert(result.ipv6->fragment->more_fragments);
    assert(result.ipv6->fragment->identification == 0x12345678U);
    assert(result.ipv6->upper_layer_protocol == 17U);
    assert(result.ipv6->transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*result.ipv6->transport));
    assert(std::get<wirescope::UdpInfo>(*result.ipv6->transport).length == 32U);
}

void test_non_initial_ipv6_fragment_skips_transport() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 16U, 44U);

    bytes.push_back(17U);
    bytes.push_back(0U);
    append_u16(bytes, 0x0009U); // Offset=1 (8 bytes), M=1.
    append_u32(bytes, 0x12345678U);
    bytes.insert(bytes.end(), {0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x11U, 0x22U});

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv6.has_value());
    assert(result.ipv6->fragment.has_value());
    assert(result.ipv6->fragment->offset == 1U);
    assert(result.ipv6->fragment->more_fragments);
    assert(!result.ipv6->transport.has_value());
}

void test_ipv6_extension_header_exceeding_declared_payload_is_reported() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 8U, 0U);
    // Hdr Ext Len=1 means 16 bytes, but IPv6 declares only 8 payload bytes.
    bytes.insert(bytes.end(), {17U, 1U, 0U, 0U, 0U, 0U, 0U, 0U});

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.ipv6.has_value());
    assert(result.parse_error ==
        "IPv6 extension header exceeds declared payload length");
    assert(result.ipv6->extension_headers.empty());
    assert(!result.ipv6->transport.has_value());
}

void test_duplicate_ipv6_fragment_headers_are_reported() {
    Bytes bytes;
    append_ethernet(bytes, 0x86DDU);
    append_ipv6_base(bytes, 16U, 44U);

    // First Fragment header points to another Fragment header.
    bytes.insert(bytes.end(), {44U, 0U, 0U, 0U, 0U, 0U, 0U, 1U});
    bytes.insert(bytes.end(), {17U, 0U, 0U, 0U, 0U, 0U, 0U, 2U});

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.ipv6.has_value());
    assert(result.parse_error == "multiple IPv6 Fragment headers");
    assert(result.ipv6->extension_headers.size() == 1U);
    assert(!result.ipv6->transport.has_value());
}

} // namespace

int main() {
    // Existing Ethernet and IPv4 regression coverage.
    test_truncated_ethernet();
    test_arp_frame();
    test_ipv4_udp_frame();
    test_ipv4_tcp_syn_frame();
    test_non_initial_ipv4_fragment_skips_transport();
    test_truncated_ipv4_is_reported_without_transport_decode();
    test_first_ipv4_fragment_can_contain_partial_udp_datagram();

    // IPv6 address formatting.
    test_ipv6_formatting_compresses_middle_zero_run();
    test_ipv6_formatting_handles_all_zero_address();
    test_ipv6_formatting_handles_leading_and_trailing_zero_runs();
    test_ipv6_formatting_does_not_compress_single_zero_group();
    test_ipv6_formatting_uses_first_longest_run_on_tie();

    // VLAN parsing.
    test_single_vlan_tag_decodes_ipv4_at_correct_offset();
    test_vlan_tagged_ipv6_frame();
    test_stacked_vlan_tags_preserve_outer_and_inner_tags();
    test_truncated_vlan_tag_is_reported();

    // IPv6 base header and transport parsing.
    test_ipv6_udp_frame();
    test_ipv6_tcp_syn_frame();
    test_truncated_ipv6_base_header_is_reported();
    test_truncated_ipv6_payload_is_reported_without_transport_decode();
    test_wrong_version_in_ipv6_frame_is_reported();

    // IPv6 extension headers and fragmentation.
    test_ipv6_hop_by_hop_header_then_udp();
    test_ipv6_extension_header_chain();
    test_first_ipv6_fragment_can_contain_partial_udp_datagram();
    test_non_initial_ipv6_fragment_skips_transport();
    test_ipv6_extension_header_exceeding_declared_payload_is_reported();
    test_duplicate_ipv6_fragment_headers_are_reported();

    std::cout << "All decoder tests passed.\n";
}
