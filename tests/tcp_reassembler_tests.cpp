#include "wirescope/tcp_reassembler.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace wirescope;

constexpr std::uint8_t flag_syn = 0x02U;
constexpr std::uint8_t flag_ack = 0x10U;

const TcpStreamEndpoint client{
    "192.0.2.10",
    50000U
};

const TcpStreamEndpoint server{
    "192.0.2.20",
    8080U
};

TcpInfo segment(
    std::uint32_t sequence,
    std::uint8_t flags = flag_ack
) {
    TcpInfo tcp;
    tcp.sequence_number = sequence;
    tcp.flags = flags;
    return tcp;
}

std::vector<std::uint8_t> bytes(std::string_view value) {
    return {
        value.begin(),
        value.end()
    };
}

std::string as_string(
    const std::vector<std::uint8_t>& value
) {
    return {
        value.begin(),
        value.end()
    };
}

void test_in_order_payload() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U, flag_syn),
        {}
    );

    const auto data = bytes("hello");

    reassembler.observe(
        client,
        server,
        segment(101U),
        data
    );

    assert(reassembler.streams().size() == 1U);

    const auto& stream = reassembler.streams().front();

    assert(as_string(stream.payload) == "hello");
    assert(stream.pending_bytes == 0U);
    assert(stream.out_of_order_segments == 0U);
}

void test_out_of_order_segments_are_flushed() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U, flag_syn),
        {}
    );

    const auto tail = bytes("world");

    reassembler.observe(
        client,
        server,
        segment(106U),
        tail
    );

    assert(reassembler.streams().front().payload.empty());
    assert(reassembler.streams().front().pending_bytes == 5U);

    const auto head = bytes("hello");

    reassembler.observe(
        client,
        server,
        segment(101U),
        head
    );

    const auto& stream = reassembler.streams().front();

    assert(as_string(stream.payload) == "helloworld");
    assert(stream.pending_bytes == 0U);
    assert(stream.out_of_order_segments == 1U);
}

void test_retransmitted_bytes_are_not_duplicated() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U, flag_syn),
        {}
    );

    const auto original = bytes("hello");

    reassembler.observe(
        client,
        server,
        segment(101U),
        original
    );

    reassembler.observe(
        client,
        server,
        segment(101U),
        original
    );

    const auto& stream = reassembler.streams().front();

    assert(as_string(stream.payload) == "hello");
    assert(stream.retransmitted_bytes == 5U);
}

void test_overlapping_segment_only_appends_new_bytes() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U, flag_syn),
        {}
    );

    const auto first = bytes("hello");
    const auto second = bytes("loworld");

    reassembler.observe(
        client,
        server,
        segment(101U),
        first
    );

    reassembler.observe(
        client,
        server,
        segment(104U),
        second
    );

    const auto& stream = reassembler.streams().front();

    assert(as_string(stream.payload) == "helloworld");
    assert(stream.retransmitted_bytes == 2U);
}

void test_directions_are_independent() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U, flag_syn),
        {}
    );

    reassembler.observe(
        server,
        client,
        segment(500U, flag_syn),
        {}
    );

    const auto request = bytes("request");
    const auto response = bytes("response");

    reassembler.observe(
        client,
        server,
        segment(101U),
        request
    );

    reassembler.observe(
        server,
        client,
        segment(501U),
        response
    );

    assert(reassembler.streams().size() == 2U);

    assert(
        as_string(reassembler.streams()[0].payload) ==
        "request"
    );

    assert(
        as_string(reassembler.streams()[1].payload) ==
        "response"
    );
}

void test_sequence_number_wraparound() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(0xFFFFFFFDU, flag_syn),
        {}
    );

    const auto data = bytes("abcd");

    reassembler.observe(
        client,
        server,
        segment(0xFFFFFFFEU),
        data
    );

    assert(
        as_string(reassembler.streams().front().payload) ==
        "abcd"
    );

    assert(
        reassembler.streams().front().pending_bytes == 0U
    );
}

void test_clear_resets_all_streams() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U, flag_syn),
        {}
    );

    const auto data = bytes("data");

    reassembler.observe(
        client,
        server,
        segment(101U),
        data
    );

    reassembler.clear();

    assert(reassembler.streams().empty());

    reassembler.observe(
        client,
        server,
        segment(200U, flag_syn),
        {}
    );

    assert(reassembler.streams().size() == 1U);
    assert(reassembler.streams().front().payload.empty());
}

void test_empty_non_syn_segment_does_not_create_stream() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U),
        {}
    );

    assert(reassembler.streams().empty());
}

void test_new_syn_creates_new_stream_generation() {
    TcpStreamReassembler reassembler;

    reassembler.observe(
        client,
        server,
        segment(100U, flag_syn),
        {}
    );

    const auto first_payload = bytes("first");

    reassembler.observe(
        client,
        server,
        segment(101U),
        first_payload
    );

    // The endpoint tuple is reused with a new initial sequence number.
    reassembler.observe(
        client,
        server,
        segment(900U, flag_syn),
        {}
    );

    const auto second_payload = bytes("second");

    reassembler.observe(
        client,
        server,
        segment(901U),
        second_payload
    );

    assert(reassembler.streams().size() == 2U);

    assert(
        as_string(reassembler.streams()[0].payload) ==
        "first"
    );

    assert(
        as_string(reassembler.streams()[1].payload) ==
        "second"
    );
}

} // namespace

int main() {
    test_in_order_payload();
    test_out_of_order_segments_are_flushed();
    test_retransmitted_bytes_are_not_duplicated();
    test_overlapping_segment_only_appends_new_bytes();
    test_directions_are_independent();
    test_sequence_number_wraparound();
    test_clear_resets_all_streams();
    test_empty_non_syn_segment_does_not_create_stream();
    test_new_syn_creates_new_stream_generation();

    std::cout << "All TCP stream reassembler tests passed.\n";
}
