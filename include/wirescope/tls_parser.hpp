#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>
namespace wirescope {
struct TlsClientHello {
    std::string legacy_version;
    std::vector<std::string> supported_versions;
    std::vector<std::string> alpn_protocols;
    std::string server_name;
    std::vector<std::uint16_t> cipher_suites;
    bool complete{};
};
[[nodiscard]] std::optional<TlsClientHello> parse_tls_client_hello(std::span<const std::uint8_t> stream);
[[nodiscard]] std::string tls_version_name(std::uint16_t version);
[[nodiscard]] std::string tls_cipher_name(std::uint16_t cipher);
}
