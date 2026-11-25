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

} // namespace

int main() {
    test_dns_capture();
    test_http_capture();
    test_tls_capture();
    test_display_filter();
    std::cout << "Analysis engine tests passed.\n";
}
