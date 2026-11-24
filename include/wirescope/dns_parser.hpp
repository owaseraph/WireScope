#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace wirescope {
struct DnsQuestion {std::string name;std::uint16_t type{},class_code{};};
struct DnsRecord {std::string name,value;std::uint16_t type{},class_code{};std::uint32_t ttl{};};
struct DnsMessage {std::uint16_t id{};bool response{},authoritative{},truncated{},recursion_desired{},recursion_available{};std::uint8_t opcode{},rcode{};std::vector<DnsQuestion> questions;std::vector<DnsRecord> answers,authorities,additional;};
struct DnsResult {std::optional<DnsMessage> message;std::string error;explicit operator bool()const noexcept{return message.has_value();}};
[[nodiscard]] DnsResult parse_dns(std::span<const std::uint8_t>);
[[nodiscard]] std::string dns_type_name(std::uint16_t);
[[nodiscard]] std::string dns_rcode_name(std::uint8_t);
}
