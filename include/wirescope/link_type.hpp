#pragma once

#include <cstdint>
#include <variant>

namespace wirescope {

struct PcapLinkType {
    std::uint32_t value{};
    friend constexpr bool operator==(PcapLinkType, PcapLinkType) noexcept = default;
};

struct LinuxHardwareType {
    std::uint16_t value{};
    friend constexpr bool operator==(LinuxHardwareType, LinuxHardwareType) noexcept = default;
};

// Host byte order, copied from sockaddr_ll::sll_protocol with ntohs().
struct LinuxPacketProtocol {
    std::uint16_t value{};
    friend constexpr bool operator==(LinuxPacketProtocol, LinuxPacketProtocol) noexcept = default;
};

struct LinkType {
    std::variant<PcapLinkType, LinuxHardwareType> framing{PcapLinkType{1U}};
    LinuxPacketProtocol linux_protocol{};
    friend constexpr bool operator==(const LinkType&, const LinkType&) noexcept = default;
};

inline constexpr PcapLinkType ethernet_pcap_link_type{1U};
// Linux UAPI ARPHRD_ETHER. It is a distinct namespace from PCAP LINKTYPE_ETHERNET.
inline constexpr LinuxHardwareType linux_ethernet_hardware_type{1U};

[[nodiscard]] constexpr LinkType pcap_link_type(std::uint32_t value) noexcept {
    return LinkType{PcapLinkType{value}, {}};
}

[[nodiscard]] constexpr LinkType linux_link_type(std::uint16_t hardware_type,
                                                  std::uint16_t protocol) noexcept {
    return LinkType{LinuxHardwareType{hardware_type}, LinuxPacketProtocol{protocol}};
}

[[nodiscard]] constexpr bool is_ethernet(const LinkType& link_type) noexcept {
    if (const auto* pcap = std::get_if<PcapLinkType>(&link_type.framing))
        return *pcap == ethernet_pcap_link_type;
    return std::get<LinuxHardwareType>(link_type.framing) == linux_ethernet_hardware_type;
}

} // namespace wirescope
