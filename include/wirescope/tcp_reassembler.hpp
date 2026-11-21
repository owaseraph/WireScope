#pragma once

#include "wirescope/decoder.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace wirescope {

struct TcpStreamEndpoint {
    std::string address;
    std::uint16_t port{};

    friend bool operator==(
        const TcpStreamEndpoint&,
        const TcpStreamEndpoint&
    ) = default;

    friend bool operator<(
        const TcpStreamEndpoint& lhs,
        const TcpStreamEndpoint& rhs
    ) {
        if (lhs.address != rhs.address) {
            return lhs.address < rhs.address;
        }

        return lhs.port < rhs.port;
    }
};

struct TcpStream {
    TcpStreamEndpoint source;
    TcpStreamEndpoint destination;

    std::vector<std::uint8_t> payload;

    std::uint64_t segments_observed{};
    std::uint64_t out_of_order_segments{};
    std::uint64_t retransmitted_bytes{};
    std::uint64_t dropped_bytes{};

    std::size_t pending_bytes{};
};

class TcpStreamReassembler {
public:
    void observe(
        const TcpStreamEndpoint& source,
        const TcpStreamEndpoint& destination,
        const TcpInfo& tcp,
        std::span<const std::uint8_t> payload
    );

    [[nodiscard]] const std::vector<TcpStream>&
    streams() const noexcept;

    void clear() noexcept;

private:
    struct StreamKey {
        TcpStreamEndpoint source;
        TcpStreamEndpoint destination;

        friend bool operator<(
            const StreamKey& lhs,
            const StreamKey& rhs
        ) {
            if (lhs.source < rhs.source) {
                return true;
            }

            if (rhs.source < lhs.source) {
                return false;
            }

            return lhs.destination < rhs.destination;
        }
    };

    struct SequenceState {
        std::optional<std::uint32_t> initial_syn_sequence;
        std::optional<std::uint32_t> next_sequence;

        std::map<std::uint32_t, std::uint8_t> pending;
    };

    static constexpr std::size_t max_pending_bytes_per_stream =
        1U * 1024U * 1024U;

    std::vector<TcpStream> streams_;
    std::vector<SequenceState> sequence_states_;

    std::map<StreamKey, std::size_t> stream_indices_;
};

} // namespace wirescope
