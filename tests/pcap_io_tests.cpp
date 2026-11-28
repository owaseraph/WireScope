#include "wirescope/pcap_io.hpp"

#include <array>
#include <cassert>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace {

void append_le(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    for (unsigned shift = 0U; shift < 32U; shift += 8U)
        bytes.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
}

void test_classic_pcap_preserves_link_type() {
    std::vector<std::uint8_t> bytes{
        0xd4U, 0xc3U, 0xb2U, 0xa1U, 2U, 0U, 4U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
    };
    append_le(bytes, 127U); // snapshot length
    append_le(bytes, 276U); // unsupported but valid PCAP link type
    append_le(bytes, 1U);
    append_le(bytes, 2U);
    append_le(bytes, 3U);
    append_le(bytes, 3U);
    bytes.insert(bytes.end(), {0xaaU, 0xbbU, 0xccU});

    const auto path = std::filesystem::temp_directory_path() / "wirescope-linktype-test.pcap";
    {
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        assert(file.good());
    }

    std::size_t packet_count = 0U;
    std::string error;
    const bool ok = wirescope::read_pcap_file(path.string(), [&](const wirescope::CapturedPacket& packet) {
        ++packet_count;
        const auto* link_type = std::get_if<wirescope::PcapLinkType>(&packet.link_type.framing);
        assert(link_type != nullptr);
        assert(link_type->value == 276U);
        assert(packet.timestamp_us == 1'000'002U);
        assert(packet.bytes == std::vector<std::uint8_t>({0xaaU, 0xbbU, 0xccU}));
        return true;
    }, error);
    std::filesystem::remove(path);
    assert(ok);
    assert(packet_count == 1U);
}

} // namespace

int main() {
    test_classic_pcap_preserves_link_type();
    std::cout << "PCAP I/O tests passed.\n";
}
