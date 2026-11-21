#include "wirescope/tcp_reassembler.hpp"

#include <limits>
#include <utility>

namespace wirescope {
namespace {

constexpr std::uint8_t tcp_flag_syn = 0x02U;

constexpr std::size_t max_reassembled_bytes_per_stream =
    16U * 1024U * 1024U;

void add_saturated(
    std::uint64_t& value,
    std::uint64_t amount
) noexcept {
    const auto maximum =
        std::numeric_limits<std::uint64_t>::max();

    if (amount > maximum - value) {
        value = maximum;
    } else {
        value += amount;
    }
}

void append_contiguous_byte(
    TcpStream& stream,
    std::uint8_t byte
) {
    if (stream.payload.size() < max_reassembled_bytes_per_stream) {
        stream.payload.push_back(byte);
    } else {
        add_saturated(stream.dropped_bytes, 1U);
    }
}

[[nodiscard]] bool sequence_is_ahead(
    std::uint32_t sequence,
    std::uint32_t expected
) noexcept {
    const std::uint32_t distance = sequence - expected;

    return distance != 0U &&
           distance < 0x80000000U;
}

} // namespace

void TcpStreamReassembler::observe(
    const TcpStreamEndpoint& source,
    const TcpStreamEndpoint& destination,
    const TcpInfo& tcp,
    std::span<const std::uint8_t> payload
) {
    const bool syn =
        (tcp.flags & tcp_flag_syn) != 0U;

    const StreamKey key{
        source,
        destination
    };

    auto found = stream_indices_.find(key);

    // A different initial SYN sequence starts a new stream generation.
    if (found != stream_indices_.end() && syn) {
        const SequenceState& previous_state =
            sequence_states_[found->second];

        if (
            !previous_state.initial_syn_sequence.has_value() ||
            *previous_state.initial_syn_sequence != tcp.sequence_number
        ) {
            const std::size_t new_index = streams_.size();

            TcpStream new_stream;
            new_stream.source = source;
            new_stream.destination = destination;

            streams_.push_back(std::move(new_stream));
            sequence_states_.push_back(SequenceState{});

            // Keep the old stream in history but index the new generation.
            found->second = new_index;
        }
    }

    if (found == stream_indices_.end()) {
        if (!syn && payload.empty()) {
            return;
        }

        const std::size_t index = streams_.size();

        TcpStream new_stream;
        new_stream.source = source;
        new_stream.destination = destination;

        streams_.push_back(std::move(new_stream));
        sequence_states_.push_back(SequenceState{});

        found = stream_indices_.emplace(
            key,
            index
        ).first;
    }

    const std::size_t index = found->second;

    TcpStream& stream = streams_[index];
    SequenceState& state = sequence_states_[index];

    add_saturated(stream.segments_observed, 1U);

    // SYN consumes one TCP sequence number.
    const std::uint32_t payload_sequence =
        tcp.sequence_number + (syn ? 1U : 0U);

    if (syn && !state.initial_syn_sequence.has_value()) {
        state.initial_syn_sequence = tcp.sequence_number;
        state.next_sequence = payload_sequence;
    }

    // For a midstream capture, use the first observed payload.
    if (
        !state.next_sequence.has_value() &&
        !payload.empty()
    ) {
        state.next_sequence = payload_sequence;
    }

    if (payload.empty()) {
        stream.pending_bytes = state.pending.size();
        return;
    }

    if (sequence_is_ahead(
        payload_sequence,
        *state.next_sequence
    )) {
        add_saturated(stream.out_of_order_segments, 1U);
    }

    for (
        std::size_t index_in_payload = 0U;
        index_in_payload < payload.size();
        ++index_in_payload
    ) {
        const auto offset =
            static_cast<std::uint32_t>(index_in_payload);

        const std::uint32_t byte_sequence =
            payload_sequence + offset;

        const std::uint32_t distance =
            byte_sequence - *state.next_sequence;

        const std::uint8_t byte =
            payload[index_in_payload];

        if (distance == 0U) {
            append_contiguous_byte(stream, byte);

            ++(*state.next_sequence);

            // Flush buffered bytes whenever a missing range is filled.
            while (true) {
                const auto pending =
                    state.pending.find(*state.next_sequence);

                if (pending == state.pending.end()) {
                    break;
                }

                append_contiguous_byte(
                    stream,
                    pending->second
                );

                state.pending.erase(pending);

                ++(*state.next_sequence);
            }

        } else if (distance < 0x80000000U) {
            const auto existing =
                state.pending.find(byte_sequence);

            if (existing != state.pending.end()) {
                add_saturated(stream.retransmitted_bytes, 1U);
                continue;
            }

            if (
                state.pending.size() >=
                max_pending_bytes_per_stream
            ) {
                add_saturated(stream.dropped_bytes, 1U);
                continue;
            }

            state.pending.emplace(byte_sequence, byte);

        } else {
            add_saturated(stream.retransmitted_bytes, 1U);
        }
    }

    stream.pending_bytes = state.pending.size();
}

const std::vector<TcpStream>&
TcpStreamReassembler::streams() const noexcept {
    return streams_;
}

void TcpStreamReassembler::clear() noexcept {
    streams_.clear();
    sequence_states_.clear();
    stream_indices_.clear();
}

} // namespace wirescope
