#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "wirescope/link_type.hpp"
namespace wirescope {
struct CapturedPacket {std::uint64_t timestamp_us{};std::uint32_t wire_length{};std::vector<std::uint8_t> bytes;LinkType link_type{PcapLinkType{ethernet_pcap_link_type}};};
using PacketHandler=std::function<bool(const CapturedPacket&)>;
using StopPredicate=std::function<bool()>;
[[nodiscard]] bool read_pcap_file(const std::string&,const PacketHandler&,std::string& error);
[[nodiscard]] bool capture_live(const std::string& interface_name,bool promiscuous,const PacketHandler&,const StopPredicate& should_stop,std::string& error);
[[nodiscard]] std::vector<std::string> list_interfaces();
}
