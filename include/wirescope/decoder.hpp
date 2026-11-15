#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include <variant>

namespace wirescope {

    //Transport Layer
    /// @brief Defines TCP protocol
    struct TcpInfo {
        std::uint16_t source_port{};
        std::uint16_t destination_port{};
        std::uint32_t sequence_number{};
        std::uint32_t acknowledgement_number{};
        std::uint8_t flags{};
        std::uint16_t window_size{};
        std::size_t header_length{};
    };

    /// @brief Define UDP protocol
    struct UdpInfo {
        std::uint16_t source_port{};
        std::uint16_t destination_port{};
        std::uint16_t length{};
    };

    using TransportInfo = std::variant<TcpInfo, UdpInfo>;


    //VLAN
    /// @brief defines VLAN into our data structure
    struct VlanTag{
        std::uint16_t tag_protocol_id{};
        std::uint8_t priority{};
        bool drop_eligible{};
        std::uint16_t vlan_id{};
        std::uint16_t encapsulated_ether_type{};
    };

    //IPv4 Layer
    /// @brief Defines IPv4 into our data structure 
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

    //IPv6 extensions

    /// @brief IPv6 extension headers
    struct Ipv6ExtensionInfo{
        std::uint8_t type{};
        std::uint8_t next_header{};
        std::size_t header_length{};
    };

    struct Ipv6FragmentInfo{
        std::uint16_t offset{};
        bool more_fragments{};
        std::uint32_t identification{};
    };

    
    struct Ipv6Info {
        std::string source_address;
        std::string destination_address;

        std::uint8_t traffic_class{};
        std::uint32_t flow_label{};

        std::uint16_t payload_length{};

        std::uint8_t next_header{};
        std::uint8_t upper_layer_protocol{};

        std::uint8_t hop_limit{};

        std::size_t header_length{};

        std::vector<Ipv6ExtensionInfo> extension_headers;

        std::optional<Ipv6FragmentInfo> fragment;

        std::optional<TransportInfo> transport;
    };


    /// @brief Complete packet summary
    struct PacketSummary {
        std::size_t captured_length{};
        std::size_t wire_length{};
        std::string source_mac;
        std::string destination_mac;
        std::uint16_t ether_type{};
        std::vector<VlanTag> vlan_tags;
        std::optional<Ipv4Info> ipv4;
        std::optional<Ipv6Info> ipv6;
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
    [[nodiscard]] std::string format_ipv6(std::span<const std::uint8_t, 16> address);
    [[nodiscard]] std::string format_tcp_flags(std::uint8_t flags);

} // namespace wirescope
