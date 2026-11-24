#pragma once
#include <cstdint>
#include <string>

namespace wirescope {
struct Endpoint {
    std::string address;
    std::uint16_t port{};
    friend bool operator==(const Endpoint&, const Endpoint&) = default;
    friend bool operator<(const Endpoint& a, const Endpoint& b) {
        return a.address < b.address || (a.address == b.address && a.port < b.port);
    }
};
[[nodiscard]] inline std::string endpoint_string(const Endpoint& e) {
    return e.address.find(':') != std::string::npos
        ? "[" + e.address + "]:" + std::to_string(e.port)
        : e.address + ":" + std::to_string(e.port);
}
}
