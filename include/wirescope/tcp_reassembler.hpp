#pragma once
#include "wirescope/common.hpp"
#include "wirescope/decoder.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>
namespace wirescope {
struct TcpStream {
    Endpoint source,destination;
    std::vector<std::uint8_t> payload;
    std::uint64_t segments{},out_of_order_segments{},retransmitted_bytes{},dropped_bytes{};
    std::uint64_t first_seen_us{}, last_seen_us{};
    bool has_timestamps{};
    std::size_t pending_bytes{};
};
class TcpStreamReassembler {
public:
    void observe(const Endpoint&, const Endpoint&, const TcpInfo&,
                 std::span<const std::uint8_t>, std::uint64_t timestamp_us = 0U);
    [[nodiscard]] const std::vector<TcpStream>& streams() const noexcept{return streams_;}
private:
    struct State {std::optional<std::uint32_t> initial_syn; std::optional<std::uint32_t> next; std::map<std::uint32_t,std::uint8_t> pending;};
    std::vector<TcpStream> streams_;
    std::vector<State> states_;
    std::map<std::pair<Endpoint,Endpoint>,std::size_t> indices_;
};
}
