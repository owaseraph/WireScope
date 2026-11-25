#pragma once

#include "wirescope/common.hpp"
#include "wirescope/decoder.hpp"
#include "wirescope/dns_parser.hpp"
#include "wirescope/http_parser.hpp"
#include "wirescope/pcap_io.hpp"
#include "wirescope/tcp_reassembler.hpp"
#include "wirescope/tcp_tracker.hpp"
#include "wirescope/tls_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace wirescope {

struct PacketRecord {
    std::uint64_t number{};
    CapturedPacket captured;
    PacketSummary decoded;
    Endpoint source;
    Endpoint destination;
    std::string protocol{"OTHER"};
    std::string info;
};

struct DnsObservation {
    std::uint64_t packet_number{};
    Endpoint source;
    Endpoint destination;
    DnsMessage message;
};

struct ApplicationStreamAnalysis {
    std::size_t index{};
    Endpoint source;
    Endpoint destination;
    std::vector<HttpMessage> http_messages;
    std::optional<TlsClientHello> tls_client_hello;
};

class AnalysisEngine {
public:
    explicit AnalysisEngine(std::uint64_t tcp_idle_timeout_us = 300'000'000U);

    // Consumes one captured Ethernet frame and updates all analysis state.
    // Returns false only when the frame could not be retained due to an
    // allocation failure; malformed network packets are retained with their
    // decoder error instead of failing ingestion.
    [[nodiscard]] bool ingest(CapturedPacket packet);

    void expire_idle_connections(std::uint64_t now_us);
    void clear();
    void set_tcp_idle_timeout(std::uint64_t timeout_us) noexcept;

    [[nodiscard]] const std::vector<PacketRecord>& packets() const noexcept;
    [[nodiscard]] const TcpConnectionTracker& tcp_connections() const noexcept;
    [[nodiscard]] const TcpStreamReassembler& tcp_streams() const noexcept;
    [[nodiscard]] const std::vector<DnsObservation>& dns_messages() const noexcept;
    [[nodiscard]] std::vector<ApplicationStreamAnalysis> application_streams() const;

    [[nodiscard]] std::uint64_t total_wire_bytes() const noexcept;
    [[nodiscard]] std::uint64_t protocol_packet_count(const std::string& protocol) const noexcept;

private:
    std::uint64_t tcp_idle_timeout_us_;
    std::uint64_t next_packet_number_{1U};
    std::uint64_t total_wire_bytes_{};
    std::vector<PacketRecord> packets_;
    std::vector<DnsObservation> dns_messages_;
    TcpConnectionTracker tcp_tracker_;
    TcpStreamReassembler tcp_reassembler_;
};

// Display-filter subset also used by the GUI. Terms are ANDed, as in the
// built-in CLI filter grammar: tcp, udp, ip, ip6, icmp6, port N,
// src port N, dst port N, host ADDRESS.
[[nodiscard]] bool packet_matches_filter(
    const PacketRecord& packet,
    const std::string& expression,
    std::string& error
);

[[nodiscard]] std::string packet_protocol_name(const PacketSummary& packet);
[[nodiscard]] std::string packet_info_string(const PacketSummary& packet);

} // namespace wirescope
