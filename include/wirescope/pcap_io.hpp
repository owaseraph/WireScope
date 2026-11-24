#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <csignal>
#include <string>
#include <vector>
namespace wirescope {
struct CapturedPacket {std::uint64_t timestamp_us{};std::uint32_t wire_length{};std::vector<std::uint8_t> bytes;};
using PacketHandler=std::function<bool(const CapturedPacket&)>;
[[nodiscard]] bool read_pcap_file(const std::string&,const PacketHandler&,std::string& error);
[[nodiscard]] bool capture_live(const std::string& interface_name,bool promiscuous,const PacketHandler&,volatile std::sig_atomic_t& stop,std::string& error);
[[nodiscard]] std::vector<std::string> list_interfaces();
}
