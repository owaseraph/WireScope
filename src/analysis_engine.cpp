#include "wirescope/analysis_engine.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <sstream>
#include <string_view>
#include <variant>
#include <utility>

namespace wirescope {
namespace {

struct PayloadView {
    Endpoint source;
    Endpoint destination;
    std::span<const std::uint8_t> bytes;
};

[[nodiscard]] const TransportInfo* transport_of(const PacketSummary& packet) noexcept {
    if (packet.ipv4 && packet.ipv4->transport) return &*packet.ipv4->transport;
    if (packet.ipv6 && packet.ipv6->transport) return &*packet.ipv6->transport;
    return nullptr;
}

[[nodiscard]] std::optional<PayloadView> extract_payload(
    const PacketSummary& packet,
    std::span<const std::uint8_t> frame,
    bool tcp_payload
) {
    const std::size_t network_offset = 14U + packet.vlan_tags.size() * 4U;
    std::size_t ip_header_length = 0U;
    std::size_t transport_length = 0U;
    std::string source_address;
    std::string destination_address;
    const TransportInfo* transport = transport_of(packet);

    if (transport == nullptr) return std::nullopt;

    if (packet.ipv4) {
        const auto& ip = *packet.ipv4;
        if (ip.fragment_offset != 0U || ip.more_fragments) return std::nullopt;
        if (ip.total_length < ip.header_length) return std::nullopt;
        ip_header_length = ip.header_length;
        transport_length = static_cast<std::size_t>(ip.total_length) - ip.header_length;
        source_address = ip.source_address;
        destination_address = ip.destination_address;
    } else if (packet.ipv6) {
        const auto& ip = *packet.ipv6;
        if (ip.fragment.has_value() || ip.header_length < 40U) return std::nullopt;
        const std::size_t extension_length = ip.header_length - 40U;
        if (ip.payload_length < extension_length) return std::nullopt;
        ip_header_length = ip.header_length;
        transport_length = static_cast<std::size_t>(ip.payload_length) - extension_length;
        source_address = ip.source_address;
        destination_address = ip.destination_address;
    } else {
        return std::nullopt;
    }

    std::size_t transport_header_length = 0U;
    std::uint16_t source_port = 0U;
    std::uint16_t destination_port = 0U;

    if (tcp_payload) {
        const auto* tcp = std::get_if<TcpInfo>(transport);
        if (tcp == nullptr || tcp->header_length > transport_length) return std::nullopt;
        transport_header_length = tcp->header_length;
        source_port = tcp->source_port;
        destination_port = tcp->destination_port;
    } else {
        const auto* udp = std::get_if<UdpInfo>(transport);
        if (udp == nullptr || udp->length < 8U || udp->length > transport_length) return std::nullopt;
        transport_header_length = 8U;
        transport_length = udp->length;
        source_port = udp->source_port;
        destination_port = udp->destination_port;
    }

    if (network_offset > frame.size() || ip_header_length > frame.size() - network_offset)
        return std::nullopt;

    const std::size_t transport_offset = network_offset + ip_header_length;
    if (transport_header_length > frame.size() - transport_offset) return std::nullopt;
    const std::size_t payload_offset = transport_offset + transport_header_length;
    const std::size_t declared_payload_length = transport_length - transport_header_length;
    const std::size_t captured_payload_length =
        std::min(declared_payload_length, frame.size() - payload_offset);

    return PayloadView{
        Endpoint{std::move(source_address), source_port},
        Endpoint{std::move(destination_address), destination_port},
        frame.subspan(payload_offset, captured_payload_length)
    };
}

[[nodiscard]] bool parse_port(std::string_view text, std::uint16_t& port) {
    unsigned value = 0U;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value > 65535U)
        return false;
    port = static_cast<std::uint16_t>(value);
    return true;
}

} // namespace

AnalysisEngine::AnalysisEngine(std::uint64_t tcp_idle_timeout_us)
    : tcp_idle_timeout_us_(tcp_idle_timeout_us) {}

bool AnalysisEngine::ingest(CapturedPacket packet) {
    try {
        PacketRecord record;
        record.number = next_packet_number_++;
        record.decoded = decode_ethernet(packet.bytes, packet.wire_length);
        record.captured = std::move(packet);
        record.protocol = packet_protocol_name(record.decoded);
        record.info = packet_info_string(record.decoded);

        if (record.decoded.ipv4) {
            record.source.address = record.decoded.ipv4->source_address;
            record.destination.address = record.decoded.ipv4->destination_address;
        } else if (record.decoded.ipv6) {
            record.source.address = record.decoded.ipv6->source_address;
            record.destination.address = record.decoded.ipv6->destination_address;
        }

        const std::uint64_t timestamp = record.captured.timestamp_us;
        tcp_tracker_.observe(record.decoded, timestamp);
        static_cast<void>(tcp_tracker_.expire_idle(timestamp, tcp_idle_timeout_us_));

        const auto tcp_payload = extract_payload(record.decoded, record.captured.bytes, true);
        if (tcp_payload) {
            if (const auto* tcp_transport = transport_of(record.decoded)) {
                if (const auto* tcp = std::get_if<TcpInfo>(tcp_transport)) {
                    record.source = tcp_payload->source;
                    record.destination = tcp_payload->destination;
                    tcp_reassembler_.observe(
                        tcp_payload->source,
                        tcp_payload->destination,
                        *tcp,
                        tcp_payload->bytes,
                        timestamp
                    );
                }
            }
        }

        const auto udp_payload = extract_payload(record.decoded, record.captured.bytes, false);
        if (udp_payload && !udp_payload->bytes.empty()) {
            const auto* transport = transport_of(record.decoded);
            const auto* udp = transport == nullptr ? nullptr : std::get_if<UdpInfo>(transport);
            if (udp != nullptr) {
                record.source = udp_payload->source;
                record.destination = udp_payload->destination;
                if (udp->source_port == 53U || udp->destination_port == 53U ||
                    udp->source_port == 5353U || udp->destination_port == 5353U) {
                    const DnsResult dns = parse_dns(udp_payload->bytes);
                    if (dns) dns_messages_.push_back({record.number, udp_payload->source, udp_payload->destination, *dns.message});
                }
            }
        }

        if (record.source.address.empty() && record.decoded.ipv4) {
            record.source.address = record.decoded.ipv4->source_address;
            record.destination.address = record.decoded.ipv4->destination_address;
        } else if (record.source.address.empty() && record.decoded.ipv6) {
            record.source.address = record.decoded.ipv6->source_address;
            record.destination.address = record.decoded.ipv6->destination_address;
        }

        if (record.decoded.ipv4 && record.decoded.ipv4->transport) {
            if (const auto* tcp = std::get_if<TcpInfo>(&*record.decoded.ipv4->transport)) {
                record.source.port = tcp->source_port;
                record.destination.port = tcp->destination_port;
            } else if (const auto* udp = std::get_if<UdpInfo>(&*record.decoded.ipv4->transport)) {
                record.source.port = udp->source_port;
                record.destination.port = udp->destination_port;
            }
        } else if (record.decoded.ipv6 && record.decoded.ipv6->transport) {
            if (const auto* tcp = std::get_if<TcpInfo>(&*record.decoded.ipv6->transport)) {
                record.source.port = tcp->source_port;
                record.destination.port = tcp->destination_port;
            } else if (const auto* udp = std::get_if<UdpInfo>(&*record.decoded.ipv6->transport)) {
                record.source.port = udp->source_port;
                record.destination.port = udp->destination_port;
            }
        }

        const std::uint64_t wire = record.captured.wire_length;
        if (wire > std::numeric_limits<std::uint64_t>::max() - total_wire_bytes_)
            total_wire_bytes_ = std::numeric_limits<std::uint64_t>::max();
        else
            total_wire_bytes_ += wire;

        packets_.push_back(std::move(record));
        return true;
    } catch (...) {
        return false;
    }
}

void AnalysisEngine::expire_idle_connections(std::uint64_t now_us) {
    static_cast<void>(tcp_tracker_.expire_idle(now_us, tcp_idle_timeout_us_));
}

void AnalysisEngine::clear() {
    packets_.clear();
    dns_messages_.clear();
    tcp_tracker_ = TcpConnectionTracker{};
    tcp_reassembler_ = TcpStreamReassembler{};
    next_packet_number_ = 1U;
    total_wire_bytes_ = 0U;
}

void AnalysisEngine::set_tcp_idle_timeout(std::uint64_t timeout_us) noexcept {
    tcp_idle_timeout_us_ = timeout_us;
}

const std::vector<PacketRecord>& AnalysisEngine::packets() const noexcept { return packets_; }
const TcpConnectionTracker& AnalysisEngine::tcp_connections() const noexcept { return tcp_tracker_; }
const TcpStreamReassembler& AnalysisEngine::tcp_streams() const noexcept { return tcp_reassembler_; }
const std::vector<DnsObservation>& AnalysisEngine::dns_messages() const noexcept { return dns_messages_; }

std::vector<ApplicationStreamAnalysis> AnalysisEngine::application_streams() const {
    std::vector<ApplicationStreamAnalysis> result;
    const auto& streams = tcp_reassembler_.streams();
    result.reserve(streams.size());
    for (std::size_t index = 0U; index < streams.size(); ++index) {
        const auto& stream = streams[index];
        ApplicationStreamAnalysis analysis;
        analysis.index = index + 1U;
        analysis.source = stream.source;
        analysis.destination = stream.destination;
        analysis.http_messages = parse_http_stream(stream.payload);
        analysis.tls_client_hello = parse_tls_client_hello(stream.payload);
        if (!analysis.http_messages.empty() || analysis.tls_client_hello) {
            result.push_back(std::move(analysis));
        }
    }
    return result;
}

std::uint64_t AnalysisEngine::total_wire_bytes() const noexcept { return total_wire_bytes_; }

std::uint64_t AnalysisEngine::protocol_packet_count(const std::string& protocol) const noexcept {
    return static_cast<std::uint64_t>(std::count_if(
        packets_.begin(), packets_.end(), [&](const PacketRecord& record) {
            return record.protocol == protocol;
        }
    ));
}

bool packet_matches_filter(const PacketRecord& packet, const std::string& expression, std::string& error) {
    error.clear();
    std::istringstream input(expression);
    std::vector<std::string> words;
    for (std::string word; input >> word;) words.push_back(std::move(word));
    if (words.empty()) return true;

    const bool ipv4 = packet.decoded.ipv4.has_value();
    const bool ipv6 = packet.decoded.ipv6.has_value();
    const std::uint8_t ip_protocol = ipv4 ? packet.decoded.ipv4->protocol :
        (ipv6 ? packet.decoded.ipv6->upper_layer_protocol : 0U);
    const auto* transport = transport_of(packet.decoded);
    const bool tcp = transport != nullptr && std::holds_alternative<TcpInfo>(*transport);
    const bool udp = transport != nullptr && std::holds_alternative<UdpInfo>(*transport);
    const std::uint16_t source_port = packet.source.port;
    const std::uint16_t destination_port = packet.destination.port;

    bool matches = true;
    for (std::size_t index = 0U; index < words.size();) {
        if (words[index] == "and") { ++index; continue; }
        const std::string term = words[index++];
        if (term == "tcp" && !tcp) matches = false;
        if (term == "udp" && !udp) matches = false;
        if (term == "ip" && !ipv4) matches = false;
        if (term == "ip6" && !ipv6) matches = false;
        if (term == "icmp6" && ip_protocol != 58U) matches = false;
        if (term == "port" || term == "src" || term == "dst" || term == "host") {
            if (index >= words.size()) { error = "missing value after '" + term + "'"; return false; }
            if (term == "src" || term == "dst") {
                if (words[index++] != "port" || index >= words.size()) {
                    error = "expected 'src port N' or 'dst port N'"; return false;
                }
                const std::string value = words[index++];
                std::uint16_t port = 0U;
                if (!parse_port(value, port)) { error = "invalid port: " + value; return false; }
                if (term == "src" && source_port != port) matches = false;
                if (term == "dst" && destination_port != port) matches = false;
            } else if (term == "port") {
                const std::string value = words[index++];
                std::uint16_t port = 0U;
                if (!parse_port(value, port)) { error = "invalid port: " + value; return false; }
                if (source_port != port && destination_port != port) matches = false;
            } else {
                const std::string& address = words[index++];
                if (packet.source.address != address && packet.destination.address != address) matches = false;
            }
        } else if (term != "tcp" && term != "udp" && term != "ip" && term != "ip6" && term != "icmp6") {
            error = "unsupported filter token: " + term;
            return false;
        }
    }
    return matches;
}

std::string packet_protocol_name(const PacketSummary& packet) {
    if (packet.ipv4) {
        switch (packet.ipv4->protocol) {
            case 6U: return "TCP";
            case 17U: return "UDP";
            case 1U: return "ICMP";
            default: return "IPv4";
        }
    }
    if (packet.ipv6) {
        switch (packet.ipv6->upper_layer_protocol) {
            case 6U: return "TCP";
            case 17U: return "UDP";
            case 58U: return "ICMPv6";
            default: return "IPv6";
        }
    }
    return "OTHER";
}

std::string packet_info_string(const PacketSummary& packet) {
    const auto* transport = transport_of(packet);
    if (transport != nullptr) {
        if (const auto* tcp = std::get_if<TcpInfo>(transport)) {
            return "TCP " + std::to_string(tcp->source_port) + " → " +
                std::to_string(tcp->destination_port) + "  " + format_tcp_flags(tcp->flags) +
                "  Seq=" + std::to_string(tcp->sequence_number);
        }
        if (const auto* udp = std::get_if<UdpInfo>(transport)) {
            return "UDP " + std::to_string(udp->source_port) + " → " +
                std::to_string(udp->destination_port) + "  Length=" + std::to_string(udp->length);
        }
    }
    if (!packet.parse_error.empty()) return packet.parse_error;
    if (packet.ipv4) return "IPv4 total length=" + std::to_string(packet.ipv4->total_length);
    if (packet.ipv6) return "IPv6 payload length=" + std::to_string(packet.ipv6->payload_length);
    return "Ethernet frame";
}

} // namespace wirescope
