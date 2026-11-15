#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>

namespace wirescope {

struct TcpInfo {
    std::uint16_t source_port{};
    std::uint16_t destination_port{};
    std::uint32_t sequence_number{};
    std::uint32_t acknowledgement_number{};
    std::uint8_t flags{};
    std::uint16_t window_size{};
    std::size_t header_length{};
};

struct UdpInfo {
    std::uint16_t source_port{};
    std::uint16_t destination_port{};
    std::uint16_t length{};
};

using TransportInfo = std::variant<TcpInfo, UdpInfo>;

struct Ipv4Info {
    std::string source_address;
    std::string destination_address;
    std::uint8_t ttl{};
    std::uint8_t protocol{};
    std::uint16_t total_length{};
    std::uint16_t identification{};
    std::uint16_t fragment_offset{}; // In 8-byte units, as encoded on the wire.
    bool more_fragments{};
    std::size_t header_length{};
    std::optional<TransportInfo> transport;
};

struct PacketSummary {
    std::size_t captured_length{};
    std::size_t wire_length{};
    std::string source_mac;
    std::string destination_mac;
    std::uint16_t ether_type{};
    std::optional<Ipv4Info> ipv4;
    std::string parse_error;
};

// Decodes an Ethernet II frame. The input span must contain only bytes captured
// from the frame; wire_length may be larger when the capture was truncated.
[[nodiscard]] PacketSummary decode_ethernet(
    std::span<const std::uint8_t> frame,
    std::size_t wire_length
);

[[nodiscard]] std::string format_mac(std::span<const std::uint8_t, 6> address);
[[nodiscard]] std::string format_ipv4(std::span<const std::uint8_t, 4> address);
[[nodiscard]] std::string format_tcp_flags(std::uint8_t flags);

} // namespace wirescope
