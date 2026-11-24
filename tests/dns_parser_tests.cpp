#include "wirescope/dns_parser.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

namespace {

void test_query() {
    const std::vector<std::uint8_t> query{
        0x12U, 0x34U, 0x01U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x07U, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03U, 'c', 'o', 'm', 0x00U,
        0x00U, 0x01U, 0x00U, 0x01U
    };

    const auto result = wirescope::parse_dns_message(query);
    assert(result);

    const auto& message = *result.message;

    assert(message.id == 0x1234U);
    assert(!message.is_response);
    assert(message.recursion_desired);
    assert(message.questions.size() == 1U);
    assert(message.questions.front().name == "example.com");
    assert(message.questions.front().type == 1U);
    assert(message.questions.front().class_code == 1U);
}

void test_compressed_a_response() {
    const std::vector<std::uint8_t> response{
        0x12U, 0x34U, 0x81U, 0x80U, 0x00U, 0x01U,
        0x00U, 0x01U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x07U, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03U, 'c', 'o', 'm', 0x00U,
        0x00U, 0x01U, 0x00U, 0x01U,
        0xC0U, 0x0CU, 0x00U, 0x01U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x3CU, 0x00U, 0x04U,
        0x5DU, 0xB8U, 0xD8U, 0x22U
    };

    const auto result = wirescope::parse_dns_message(response);
    assert(result);

    const auto& message = *result.message;

    assert(message.is_response);
    assert(message.response_code == 0U);
    assert(message.answers.size() == 1U);
    assert(message.answers.front().name == "example.com");
    assert(message.answers.front().type == 1U);
    assert(message.answers.front().ttl == 60U);
    assert(message.answers.front().value == "93.184.216.34");
}

void test_compression_loop_is_rejected() {
    const std::vector<std::uint8_t> payload{
        0x00U, 0x01U, 0x01U, 0x00U, 0x00U, 0x01U,
        0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
        0xC0U, 0x0CU, 0x00U, 0x01U, 0x00U, 0x01U
    };

    const auto result = wirescope::parse_dns_message(payload);

    assert(!result);
    assert(!result.error.empty());
}

void test_truncated_header_is_rejected() {
    const std::vector<std::uint8_t> payload{
        0x00U, 0x01U, 0x01U, 0x00U
    };

    const auto result = wirescope::parse_dns_message(payload);
    assert(!result);
}

} // namespace

int main() {
    test_query();
    test_compressed_a_response();
    test_compression_loop_is_rejected();
    test_truncated_header_is_rejected();

    std::cout << "DNS parser smoke tests passed.\n";
}