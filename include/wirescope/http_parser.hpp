#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>
namespace wirescope {
struct HttpMessage {
    bool request{};
    std::string method,target,version,reason;
    unsigned status{};
    std::vector<std::pair<std::string,std::string>> headers;
    std::size_t body_bytes{};
    bool complete{},chunked{},close_delimited{},malformed{};
};
[[nodiscard]] std::vector<HttpMessage> parse_http_stream(std::span<const std::uint8_t> bytes);
}
