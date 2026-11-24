#include "wirescope/http_parser.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {

[[nodiscard]] std::vector<std::uint8_t> bytes(std::string_view text) {
    return {
        text.begin(),
        text.end()
    };
}

[[nodiscard]] std::span<const std::uint8_t> view(
    const std::vector<std::uint8_t>& payload
) {
    return {payload.data(), payload.size()};
}

void test_get_request_and_case_insensitive_headers() {
    const auto payload = bytes(
        "GET /status HTTP/1.1\r\n"
        "hOsT: localhost:8080\r\n"
        "User-Agent: WireScopeTest/1.0\r\n"
        "Accept: */*\r\n"
        "\r\n"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(!result.incomplete);
    assert(!result.malformed);
    assert(result.messages.size() == 1U);

    const auto& message = result.messages.front();
    assert(message.kind == wirescope::HttpMessageKind::request);
    assert(message.method == "GET");
    assert(message.target == "/status");
    assert(message.version == "HTTP/1.1");
    assert(message.header("HOST").value() == "localhost:8080");
    assert(message.header("user-agent").value() == "WireScopeTest/1.0");
    assert(!message.content_length.has_value());
    assert(message.body_bytes == 0U);
}

void test_response_with_content_length() {
    const auto payload = bytes(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "Connection: close\r\n"
        "\r\n"
        "hello"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(!result.incomplete);
    assert(!result.malformed);
    assert(result.messages.size() == 1U);

    const auto& message = result.messages.front();
    assert(message.kind == wirescope::HttpMessageKind::response);
    assert(message.status_code == 200U);
    assert(message.reason_phrase == "OK");
    assert(message.content_length.value() == 5U);
    assert(message.body_bytes == 5U);
    assert(message.header("content-type").value() == "text/plain");
}

void test_chunked_response_and_trailers() {
    const auto payload = bytes(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\nWiki\r\n"
        "5\r\npedia\r\n"
        "0\r\n"
        "X-Checksum: yes\r\n"
        "\r\n"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(!result.incomplete);
    assert(!result.malformed);
    assert(result.messages.size() == 1U);
    assert(result.messages.front().chunked);
    assert(result.messages.front().body_bytes == 9U);
}

void test_incomplete_chunked_body() {
    const auto payload = bytes(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\nWi"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(result.incomplete);
    assert(result.messages.size() == 1U);
    assert(result.messages.front().chunked);
    assert(result.messages.front().body_bytes == 0U);
}

void test_malformed_chunk_terminator_is_rejected() {
    const auto payload = bytes(
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "4\r\nWikiXX"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(result.malformed);
    assert(result.messages.size() == 1U);
}

void test_equal_duplicate_content_lengths_are_accepted() {
    const auto payload = bytes(
        "POST / HTTP/1.1\r\n"
        "Content-Length: 4\r\n"
        "Content-Length: 4\r\n"
        "\r\n"
        "data"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(!result.malformed);
    assert(!result.incomplete);
    assert(result.messages.size() == 1U);
    assert(result.messages.front().content_length.value() == 4U);
    assert(result.messages.front().body_bytes == 4U);
}

void test_multiple_pipelined_requests() {
    const auto payload = bytes(
        "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n"
        "HEAD /two HTTP/1.0\r\nHost: example.test\r\n\r\n"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(!result.incomplete);
    assert(!result.malformed);
    assert(result.messages.size() == 2U);
    assert(result.messages[0].target == "/one");
    assert(result.messages[1].method == "HEAD");
    assert(result.messages[1].version == "HTTP/1.0");
}

void test_multiple_response_messages_with_no_body_status() {
    const auto payload = bytes(
        "HTTP/1.1 100 Continue\r\n\r\n"
        "HTTP/1.1 204 No Content\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(!result.incomplete);
    assert(!result.malformed);
    assert(result.messages.size() == 3U);
    assert(result.messages[0].status_code == 100U);
    assert(result.messages[1].status_code == 204U);
    assert(result.messages[2].body_bytes == 2U);
}

void test_incomplete_headers() {
    const auto payload = bytes(
        "GET /partial HTTP/1.1\r\n"
        "Host: example.test\r\n"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(result.incomplete);
    assert(result.messages.empty());
}

void test_incomplete_content_length_body() {
    const auto payload = bytes(
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "short"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(result.incomplete);
    assert(result.messages.size() == 1U);
    assert(result.messages.front().body_bytes == 5U);
}

void test_conflicting_content_lengths_are_rejected() {
    const auto payload = bytes(
        "POST / HTTP/1.1\r\n"
        "Content-Length: 4\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(result.malformed);
    assert(result.messages.empty());
}

void test_content_length_and_chunked_conflict_is_rejected() {
    const auto payload = bytes(
        "POST / HTTP/1.1\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n\r\n"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(result.malformed);
    assert(result.messages.empty());
}

void test_non_http_payload_is_ignored() {
    const auto payload = bytes("not an HTTP message\0binary");
    const auto result = wirescope::parse_http_stream(view(payload));

    assert(!result.recognized);
    assert(result.messages.empty());
}

void test_header_without_colon_is_rejected() {
    const auto payload = bytes(
        "GET / HTTP/1.1\r\n"
        "Invalid-Header\r\n"
        "\r\n"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(result.malformed);
    assert(result.messages.empty());
}

void test_close_delimited_response_consumes_remaining_payload() {
    const auto payload = bytes(
        "HTTP/1.0 200 OK\r\n"
        "Connection: close\r\n"
        "\r\n"
        "body without a declared length"
    );

    const auto result = wirescope::parse_http_stream(view(payload));

    assert(result.recognized);
    assert(!result.incomplete);
    assert(result.messages.size() == 1U);
    assert(result.messages.front().body_bytes == 30U);
}

} // namespace

int main() {
    test_get_request_and_case_insensitive_headers();
    test_response_with_content_length();
    test_chunked_response_and_trailers();
    test_incomplete_chunked_body();
    test_malformed_chunk_terminator_is_rejected();
    test_equal_duplicate_content_lengths_are_accepted();
    test_multiple_pipelined_requests();
    test_multiple_response_messages_with_no_body_status();
    test_incomplete_headers();
    test_incomplete_content_length_body();
    test_conflicting_content_lengths_are_rejected();
    test_content_length_and_chunked_conflict_is_rejected();
    test_non_http_payload_is_ignored();
    test_header_without_colon_is_rejected();
    test_close_delimited_response_consumes_remaining_payload();

    std::cout << "All HTTP parser tests passed.\n";
}