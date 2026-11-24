#include "wirescope/tls_parser.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace wirescope {
namespace {
bool read_u16(std::span<const std::uint8_t> bytes, std::size_t offset,
              std::uint16_t& value) {
    if (offset > bytes.size() || bytes.size() - offset < 2U) return false;
    value = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) | bytes[offset + 1U]);
    return true;
}
bool skip(std::span<const std::uint8_t> bytes, std::size_t& offset,
          std::size_t count) {
    if (offset > bytes.size() || count > bytes.size() - offset) return false;
    offset += count;
    return true;
}
std::string hex16(std::uint16_t value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out = "0x0000";
    for (int i = 0; i < 4; ++i) {
        const auto shift = static_cast<unsigned int>((3 - i) * 4);
        out[static_cast<std::size_t>(i + 2)] = digits[(value >> shift) & 0x0fU];
    }
    return out;
}
}

std::string tls_version_name(std::uint16_t value) {
    switch (value) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: return hex16(value);
    }
}

std::string tls_cipher_name(std::uint16_t cipher) {
    switch (cipher) {
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
        default: return hex16(cipher);
    }
}

std::optional<TlsClientHello> parse_tls_client_hello(
    std::span<const std::uint8_t> stream) {
    if (stream.size() < 9U || stream[0] != 0x16U) return std::nullopt;

    // Reassemble a handshake message carried across consecutive handshake records.
    std::vector<std::uint8_t> handshake;
    std::size_t record_offset = 0;
    while (record_offset + 5U <= stream.size() && stream[record_offset] == 0x16U) {
        std::uint16_t record_length{};
        if (!read_u16(stream, record_offset + 3U, record_length) ||
            record_length > stream.size() - record_offset - 5U) return std::nullopt;
        const auto first = stream.begin() + static_cast<std::ptrdiff_t>(record_offset + 5U);
        const auto last = first + static_cast<std::ptrdiff_t>(record_length);
        handshake.insert(handshake.end(), first, last);
        record_offset += 5U + record_length;
        if (handshake.size() >= 4U) {
            const std::size_t expected =
                (static_cast<std::size_t>(handshake[1]) << 16U) |
                (static_cast<std::size_t>(handshake[2]) << 8U) | handshake[3];
            if (handshake.size() >= expected + 4U) break;
        }
    }

    if (handshake.size() < 4U || handshake[0] != 1U) return std::nullopt;
    const std::size_t hello_length =
        (static_cast<std::size_t>(handshake[1]) << 16U) |
        (static_cast<std::size_t>(handshake[2]) << 8U) | handshake[3];
    if (hello_length > handshake.size() - 4U) return std::nullopt;
    const auto body = std::span<const std::uint8_t>(handshake).subspan(4U, hello_length);

    std::size_t offset = 0;
    std::uint16_t version{};
    if (!read_u16(body, offset, version)) return std::nullopt;
    TlsClientHello hello;
    hello.legacy_version = tls_version_name(version);
    offset += 2U;
    if (!skip(body, offset, 32U) || offset >= body.size()) return std::nullopt;

    const std::size_t session_id_length = body[offset++];
    if (!skip(body, offset, session_id_length)) return std::nullopt;
    std::uint16_t cipher_bytes{};
    if (!read_u16(body, offset, cipher_bytes)) return std::nullopt;
    offset += 2U;
    if (cipher_bytes % 2U != 0U || cipher_bytes > body.size() - offset) return std::nullopt;
    for (std::size_t i = 0; i < cipher_bytes; i += 2U) {
        std::uint16_t cipher{};
        if (!read_u16(body, offset + i, cipher)) return std::nullopt;
        hello.cipher_suites.push_back(cipher);
    }
    offset += cipher_bytes;

    if (offset >= body.size()) return std::nullopt;
    const std::size_t compression_length = body[offset++];
    if (!skip(body, offset, compression_length)) return std::nullopt;
    if (offset == body.size()) {
        hello.complete = true;
        return hello;
    }

    std::uint16_t extensions_length{};
    if (!read_u16(body, offset, extensions_length)) return std::nullopt;
    offset += 2U;
    if (extensions_length > body.size() - offset) return std::nullopt;
    const std::size_t extensions_end = offset + extensions_length;

    while (offset + 4U <= extensions_end) {
        std::uint16_t type{}, length{};
        if (!read_u16(body, offset, type) || !read_u16(body, offset + 2U, length))
            return std::nullopt;
        offset += 4U;
        if (length > extensions_end - offset) return std::nullopt;
        const auto extension = body.subspan(offset, length);
        offset += length;

        if (type == 0U && extension.size() >= 5U) { // server_name
            std::uint16_t list_length{};
            if (!read_u16(extension, 0U, list_length) ||
                list_length > extension.size() - 2U) return std::nullopt;
            const std::size_t list_end = 2U + static_cast<std::size_t>(list_length);
            std::size_t cursor = 2U;
            while (cursor + 3U <= list_end) {
                const auto name_type = extension[cursor++];
                std::uint16_t name_length{};
                if (!read_u16(extension, cursor, name_length)) break;
                cursor += 2U;
                const auto n = static_cast<std::size_t>(name_length);
                if (n > list_end - cursor) break;
                if (name_type == 0U && n > 0U)
                    hello.server_name.assign(reinterpret_cast<const char*>(extension.data() + cursor), n);
                cursor += n;
            }
        } else if (type == 16U && extension.size() >= 2U) { // ALPN
            std::uint16_t list_length{};
            if (!read_u16(extension, 0U, list_length) ||
                list_length > extension.size() - 2U) return std::nullopt;
            const std::size_t list_end = 2U + static_cast<std::size_t>(list_length);
            std::size_t cursor = 2U;
            while (cursor < list_end) {
                const std::size_t n = extension[cursor++];
                if (n > list_end - cursor) break;
                hello.alpn_protocols.emplace_back(
                    reinterpret_cast<const char*>(extension.data() + cursor), n);
                cursor += n;
            }
        } else if (type == 43U && !extension.empty()) { // supported_versions
            const std::size_t list_length = extension[0];
            if (list_length % 2U == 0U && list_length <= extension.size() - 1U) {
                std::size_t cursor = 1U;
                const std::size_t list_end = 1U + list_length;
                while (cursor < list_end) {
                    std::uint16_t supported{};
                    if (!read_u16(extension, cursor, supported)) return std::nullopt;
                    hello.supported_versions.push_back(tls_version_name(supported));
                    cursor += 2U;
                }
            }
        }
    }
    hello.complete = true;
    return hello;
}
}
