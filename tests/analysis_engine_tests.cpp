#include "wirescope/analysis_engine.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>

namespace {

void load_capture(const std::string& path, wirescope::AnalysisEngine& engine) {
    std::string error;
    const bool ok = wirescope::read_pcap_file(
        path,
        [&engine](const wirescope::CapturedPacket& packet) {
            assert(engine.ingest(packet));
            return true;
        },
        error
    );
    if (!ok) {
        std::cerr << "Could not read fixture: " << path << ": " << error << '\n';
    }
    assert(ok);
}

void test_dns_capture() {
    wirescope::AnalysisEngine engine;
    load_capture(std::string(WIRESCOPE_FIXTURE_DIR) + "/dns-demo.pcap", engine);
    assert(engine.packets().size() == 2U);
    assert(engine.dns_messages().size() == 2U);
    assert(engine.dns_messages()[0].packet_number == 1U);
    assert(engine.dns_messages()[1].packet_number == 2U);
    assert(engine.dns_messages()[0].message.response == false);
    assert(engine.dns_messages()[1].message.response == true);
    assert(engine.dns_messages()[0].message.questions.front().name == "example.com");
}

void test_http_capture() {
    wirescope::AnalysisEngine engine;
    load_capture(std::string(WIRESCOPE_FIXTURE_DIR) + "/http-demo.pcap", engine);
    assert(engine.packets().size() >= 2U);
    assert(!engine.tcp_streams().streams().empty());
    for (const auto& stream : engine.tcp_streams().streams()) {
        assert(stream.has_timestamps);
        assert(stream.first_seen_us <= stream.last_seen_us);
    }
    const auto analysis = engine.application_streams();
    bool found_http = false;
    for (const auto& stream : analysis) {
        if (!stream.http_messages.empty()) found_http = true;
    }
    assert(found_http);
}

void test_tls_capture() {
    wirescope::AnalysisEngine engine;
    load_capture(std::string(WIRESCOPE_FIXTURE_DIR) + "/tls-clienthello-demo.pcap", engine);
    const auto analysis = engine.application_streams();
    bool found_sni = false;
    for (const auto& stream : analysis) {
        if (stream.tls_client_hello && stream.tls_client_hello->server_name == "example.test")
            found_sni = true;
    }
    assert(found_sni);
}

void test_display_filter() {
    wirescope::PacketRecord record;
    record.protocol = "TCP";
    record.source.address = "192.0.2.10";
    record.source.port = 50500U;
    record.destination.address = "192.0.2.20";
    record.destination.port = 443U;
    wirescope::TcpInfo tcp;
    record.decoded.ipv4 = wirescope::Ipv4Info{};
    record.decoded.ipv4->protocol = 6U;
    record.decoded.ipv4->transport = wirescope::TransportInfo{tcp};

    std::string error;
    assert(wirescope::packet_matches_filter(record, "tcp and port 443", error));
    assert(wirescope::packet_matches_filter(record, "host 192.0.2.10", error));
    assert(!wirescope::packet_matches_filter(record, "udp", error));
    static_cast<void>(wirescope::packet_matches_filter(record, "port", error));
    assert(!error.empty());
}

void test_link_type_routing() {
    wirescope::AnalysisEngine ethernet_engine;
    wirescope::CapturedPacket ethernet;
    ethernet.link_type = wirescope::pcap_link_type(wirescope::ethernet_pcap_link_type.value);
    ethernet.bytes.resize(14U);
    ethernet.wire_length = 14U;
    assert(ethernet_engine.ingest(ethernet));
    assert(ethernet_engine.packets().front().captured.link_type == ethernet.link_type);
    assert(!ethernet_engine.packets().front().decoded.source_mac.empty());

    wirescope::AnalysisEngine unsupported_engine;
    wirescope::CapturedPacket unsupported;
    unsupported.link_type = wirescope::pcap_link_type(127U);
    unsupported.bytes = {0xffU, 0xffU, 0xffU, 0xffU};
    unsupported.wire_length = 4U;
    assert(unsupported_engine.ingest(unsupported));
    const auto& record = unsupported_engine.packets().front();
    const auto* pcap_type = std::get_if<wirescope::PcapLinkType>(&record.captured.link_type.framing);
    assert(pcap_type != nullptr && pcap_type->value == 127U);
    assert(record.decoded.parse_error == "unsupported PCAP link type 127");
    assert(record.decoded.source_mac.empty());
    assert(!record.decoded.ipv4 && !record.decoded.ipv6);

    wirescope::AnalysisEngine linux_engine;
    wirescope::CapturedPacket linux_ethernet;
    linux_ethernet.link_type = wirescope::linux_link_type(wirescope::linux_ethernet_hardware_type.value,
                                                           0x0800U);
    linux_ethernet.bytes.resize(14U);
    linux_ethernet.wire_length = 14U;
    assert(linux_engine.ingest(linux_ethernet));
    assert(linux_engine.packets().front().captured.link_type.linux_protocol.value == 0x0800U);
    assert(linux_engine.packets().front().decoded.source_mac != "");

    wirescope::AnalysisEngine unknown_linux_engine;
    wirescope::CapturedPacket unknown_linux;
    unknown_linux.link_type = wirescope::linux_link_type(801U, 0x0800U);
    unknown_linux.bytes.resize(14U);
    unknown_linux.wire_length = 14U;
    assert(unknown_linux_engine.ingest(unknown_linux));
    assert(unknown_linux_engine.packets().front().decoded.parse_error ==
           "unsupported Linux hardware type 801");
}

} // namespace

int main() {
    test_dns_capture();
    test_http_capture();
    test_tls_capture();
    test_display_filter();
    test_link_type_routing();
    std::cout << "Analysis engine tests passed.\n";
}
