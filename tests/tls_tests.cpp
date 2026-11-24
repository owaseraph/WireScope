#include "wirescope/tls_parser.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>
using namespace wirescope;
static void put16(std::vector<std::uint8_t>& b, std::uint16_t n) {
    b.push_back(static_cast<std::uint8_t>(n >> 8U));
    b.push_back(static_cast<std::uint8_t>(n & 0xffU));
}
int main() {
    // ClientHello with SNI, ALPN and supported_versions extensions.
    std::vector<std::uint8_t> body{0x03, 0x03};
    body.insert(body.end(), 32, 0x00); // random
    body.push_back(0x00);             // session ID
    put16(body, 2); body.push_back(0x13); body.push_back(0x01); // cipher suites
    body.push_back(1); body.push_back(0); // compression methods

    std::vector<std::uint8_t> extensions;
    const std::string host = "example.com";
    std::vector<std::uint8_t> sni;
    put16(sni, static_cast<std::uint16_t>(host.size() + 3));
    sni.push_back(0); put16(sni, static_cast<std::uint16_t>(host.size()));
    sni.insert(sni.end(), host.begin(), host.end());
    put16(extensions, 0); put16(extensions, static_cast<std::uint16_t>(sni.size()));
    extensions.insert(extensions.end(), sni.begin(), sni.end());

    const std::vector<std::uint8_t> alpn{0, 3, 2, 'h', '2'};
    put16(extensions, 16); put16(extensions, static_cast<std::uint16_t>(alpn.size()));
    extensions.insert(extensions.end(), alpn.begin(), alpn.end());

    const std::vector<std::uint8_t> versions{2, 0x03, 0x04};
    put16(extensions, 43); put16(extensions, static_cast<std::uint16_t>(versions.size()));
    extensions.insert(extensions.end(), versions.begin(), versions.end());

    put16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());
    std::vector<std::uint8_t> handshake{1,
        static_cast<std::uint8_t>((body.size() >> 16U) & 0xffU),
        static_cast<std::uint8_t>((body.size() >> 8U) & 0xffU),
        static_cast<std::uint8_t>(body.size() & 0xffU)};
    handshake.insert(handshake.end(), body.begin(), body.end());
    std::vector<std::uint8_t> record{0x16, 0x03, 0x01};
    put16(record, static_cast<std::uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());

    const auto hello = parse_tls_client_hello(record);
    assert(hello.has_value());
    assert(hello->complete);
    assert(hello->legacy_version == "TLS 1.2");
    assert(hello->server_name == "example.com");
    assert(hello->alpn_protocols.size() == 1 && hello->alpn_protocols[0] == "h2");
    assert(hello->supported_versions.size() == 1 && hello->supported_versions[0] == "TLS 1.3");
    assert(hello->cipher_suites.size() == 1 && hello->cipher_suites[0] == 0x1301);
    std::cout << "TLS tests passed\n";
}
