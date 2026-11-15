#include "wirescope/decoder.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void test_truncated_ethernet() {
    const std::array<std::uint8_t, 5> bytes{0, 1, 2, 3, 4};
    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error == "truncated Ethernet II header");
}

void test_arp_frame() {
    const std::array<std::uint8_t, 14> bytes{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x06
    };
    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.ether_type == 0x0806U);
    assert(result.source_mac == "00:11:22:33:44:55");
    assert(result.destination_mac == "ff:ff:ff:ff:ff:ff");
    assert(!result.ipv4.has_value());
    assert(result.parse_error.empty());
}

void test_ipv4_udp_frame() {
    // Ethernet (14) + IPv4 (20) + UDP (8), no payload.
    const std::array<std::uint8_t, 42> bytes{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x01,
        0xC6, 0x33, 0x64, 0x02,
        0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00
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
    // Ethernet (14) + IPv4 (20) + TCP (20).
    const std::array<std::uint8_t, 54> bytes{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x01,
        0xC6, 0x33, 0x64, 0x02,
        0xC3, 0x50, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xFA, 0xF0,
        0x00, 0x00, 0x00, 0x00
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

void test_non_initial_fragment_skips_transport() {
    std::vector<std::uint8_t> bytes{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x00, 0x01,
        0x40, 0x11, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x01,
        0xC6, 0x33, 0x64, 0x02
    };
    bytes.resize(14U + 28U, 0xAA);

    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.ipv4.has_value());
    assert(result.ipv4->fragment_offset == 1U);
    assert(!result.ipv4->transport.has_value());
}

void test_truncated_ipv4_is_reported_without_transport_decode() {
    const std::array<std::uint8_t, 34> bytes{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x01,
        0xC6, 0x33, 0x64, 0x02
    };
    const auto result = wirescope::decode_ethernet(bytes, 60U);
    assert(result.ipv4.has_value());
    assert(result.parse_error == "truncated IPv4 packet (captured bytes do not cover total length)");
    assert(!result.ipv4->transport.has_value());
}

void test_first_fragment_can_contain_partial_udp_datagram() {
    // A first fragment may carry the UDP header while the UDP length describes
    // the complete datagram, which is larger than this fragment's payload.
    const std::array<std::uint8_t, 42> bytes{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x1C, 0x12, 0x34, 0x20, 0x00,
        0x40, 0x11, 0x00, 0x00, 0xC0, 0x00, 0x02, 0x01,
        0xC6, 0x33, 0x64, 0x02,
        0x30, 0x39, 0x00, 0x35, 0x00, 0x20, 0x00, 0x00
    };
    const auto result = wirescope::decode_ethernet(bytes, bytes.size());
    assert(result.parse_error.empty());
    assert(result.ipv4.has_value());
    assert(result.ipv4->more_fragments);
    assert(result.ipv4->transport.has_value());
    assert(std::holds_alternative<wirescope::UdpInfo>(*result.ipv4->transport));
    assert(std::get<wirescope::UdpInfo>(*result.ipv4->transport).length == 32U);
}

} // namespace

int main() {
    test_truncated_ethernet();
    test_arp_frame();
    test_ipv4_udp_frame();
    test_ipv4_tcp_syn_frame();
    test_non_initial_fragment_skips_transport();
    test_truncated_ipv4_is_reported_without_transport_decode();
    test_first_fragment_can_contain_partial_udp_datagram();
    std::cout << "All decoder tests passed.\n";
}
