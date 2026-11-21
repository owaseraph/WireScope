
#include "wirescope/decoder.hpp"
#include "wirescope/tcp_tracker.hpp"
#include "wirescope/tcp_reassembler.hpp"

#include <pcap/pcap.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <type_traits>
#include <variant>

namespace {

constexpr int live_snapshot_length = 262144;
constexpr int live_read_timeout_ms = 250;

constexpr std::chrono::milliseconds live_poll_interval{50};

volatile std::sig_atomic_t stop_requested = 0;

void handle_sigint(int) {
    stop_requested = 1;
}

// Command-line configuration

struct CommandLineOptions {
    std::string capture_path;
    std::string interface_name;
    std::string filter_expression;

    std::string idle_timeout_label{"300s"};

    std::uint64_t idle_timeout_microseconds{
        300'000'000U
    };

    bool promiscuous{};
    bool show_help{};
    bool list_interfaces{};
};

// Idle timeout parsing

[[nodiscard]] bool parse_idle_timeout(
    std::string_view value,
    CommandLineOptions& options,
    std::string& error
) {
    const std::string original_value{value};

    std::uint64_t multiplier = 1'000'000U;

    if (value.ends_with("ms")) {
        multiplier = 1'000U;
        value.remove_suffix(2U);

    } else if (value.ends_with("s")) {
        multiplier = 1'000'000U;
        value.remove_suffix(1U);

    } else if (value.ends_with("m")) {
        multiplier = 60U * 1'000'000U;
        value.remove_suffix(1U);

    } else if (value.ends_with("h")) {
        multiplier = 3'600U * 1'000'000U;
        value.remove_suffix(1U);
    }

    if (value.empty()) {
        error = "idle timeout requires a numeric duration.";
        return false;
    }

    std::uint64_t duration_value = 0U;

    const char* const end =
        value.data() + value.size();

    const auto conversion = std::from_chars(
        value.data(),
        end,
        duration_value,
        10
    );

    if (
        conversion.ec != std::errc{} ||
        conversion.ptr != end
    ) {
        error =
            "invalid idle timeout. Use a positive integer "
            "followed optionally by ms, s, m, or h.";

        return false;
    }

    if (duration_value == 0U) {
        error = "idle timeout must be greater than zero.";
        return false;
    }

    constexpr std::uint64_t maximum_value =
        std::numeric_limits<std::uint64_t>::max();

    if (duration_value > maximum_value / multiplier) {
        error = "idle timeout is too large.";
        return false;
    }

    options.idle_timeout_microseconds =
        duration_value * multiplier;

    options.idle_timeout_label = original_value;

    return true;
}

// Command-line argument parsing

[[nodiscard]] bool parse_arguments(
    int argc,
    char* argv[],
    CommandLineOptions& options,
    std::string& error
) {
    bool timeout_option_seen = false;
    bool interface_option_seen = false;
    bool promiscuous_option_seen = false;
    bool filter_option_seen = false;

    for (int index = 1; index < argc; ++index) {
        const std::string_view argument{argv[index]};

        if (argument == "-h" || argument == "--help") {
            options.show_help = true;
            return true;
        }

        if (argument == "-L" || argument == "--list-interfaces") {
            options.list_interfaces = true;
            continue;
        }

        if (argument == "-i" || argument == "--interface") {
            if (interface_option_seen) {
                error = "--interface may only be specified once.";
                return false;
            }

            if (
                index + 1 >= argc ||
                argv[index + 1][0] == '\0' ||
                argv[index + 1][0] == '-'
            ) {
                error = "--interface requires an interface name.";
                return false;
            }

            options.interface_name = argv[++index];
            interface_option_seen = true;

            continue;
        }

        if (
            argument == "-p" ||
            argument == "--promiscuous" ||
            argument == "--no-promiscuous"
        ) {
            const bool enable =
                argument != "--no-promiscuous";

            if (
                promiscuous_option_seen &&
                options.promiscuous != enable
            ) {
                error = "conflicting promiscuous-mode options.";
                return false;
            }

            options.promiscuous = enable;
            promiscuous_option_seen = true;

            continue;
        }

        if (argument == "--filter") {
            if (filter_option_seen) {
                error = "--filter may only be specified once.";
                return false;
            }

            if (
                index + 1 >= argc ||
                argv[index + 1][0] == '\0' ||
                argv[index + 1][0] == '-'
            ) {
                error = "--filter requires a BPF expression.";
                return false;
            }

            options.filter_expression = argv[++index];
            filter_option_seen = true;

            continue;
        }

        constexpr std::string_view filter_prefix = "--filter=";

        if (argument.starts_with(filter_prefix)) {
            if (filter_option_seen) {
                error = "--filter may only be specified once.";
                return false;
            }

            const std::string_view expression =
                argument.substr(filter_prefix.size());

            if (expression.empty()) {
                error = "--filter requires a BPF expression.";
                return false;
            }

            options.filter_expression = std::string(expression);
            filter_option_seen = true;

            continue;
        }

        if (argument == "--idle-timeout") {
            if (timeout_option_seen) {
                error = "--idle-timeout may only be specified once.";
                return false;
            }

            if (
                index + 1 >= argc ||
                argv[index + 1][0] == '\0'
            ) {
                error = "--idle-timeout requires a duration.";
                return false;
            }

            const std::string_view duration{argv[++index]};

            if (!parse_idle_timeout(duration, options, error)) {
                return false;
            }

            timeout_option_seen = true;
            continue;
        }

        constexpr std::string_view timeout_prefix =
            "--idle-timeout=";

        if (argument.starts_with(timeout_prefix)) {
            if (timeout_option_seen) {
                error = "--idle-timeout may only be specified once.";
                return false;
            }

            const std::string_view duration =
                argument.substr(timeout_prefix.size());

            if (!parse_idle_timeout(duration, options, error)) {
                return false;
            }

            timeout_option_seen = true;
            continue;
        }

        if (!argument.empty() && argument.front() == '-') {
            error = "unknown option: " + std::string(argument);
            return false;
        }

        if (!options.capture_path.empty()) {
            error = "only one capture file may be specified.";
            return false;
        }

        options.capture_path = std::string(argument);
    }

    if (options.list_interfaces) {
        if (
            !options.capture_path.empty() ||
            !options.interface_name.empty() ||
            timeout_option_seen ||
            promiscuous_option_seen ||
            filter_option_seen
        ) {
            error =
                "--list-interfaces must be used without "
                "other capture options.";

            return false;
        }

        return true;
    }

    if (
        !options.capture_path.empty() &&
        !options.interface_name.empty()
    ) {
        error =
            "choose either an offline capture file or "
            "a live interface, not both.";

        return false;
    }

    if (
        options.capture_path.empty() &&
        options.interface_name.empty()
    ) {
        error =
            "missing input. Specify a PCAP file or "
            "use --interface <name>.";

        return false;
    }

    if (
        promiscuous_option_seen &&
        options.interface_name.empty()
    ) {
        error =
            "promiscuous-mode options only apply to live capture.";

        return false;
    }

    return true;
}

// Usage information

void print_usage(
    std::ostream& output,
    std::string_view program_name
) {
    output
        << "Usage:\n"
        << "  " << program_name
        << " [options] <capture.pcap>\n"

        << "  " << program_name
        << " [options] --interface <name>\n"

        << "  " << program_name
        << " --list-interfaces\n\n"

        << "Options:\n"

        << "  -i, --interface <name>\n"
        << "      Start live capture on the specified interface.\n\n"

        << "  -L, --list-interfaces\n"
        << "      List available capture interfaces.\n\n"

        << "  -p, --promiscuous\n"
        << "      Enable promiscuous mode for live capture.\n\n"

        << "      --no-promiscuous\n"
        << "      Disable promiscuous mode (default).\n\n"

        << "      --filter <expression>\n"
        << "      Apply a libpcap BPF packet filter.\n"
        << "      Works with offline and live capture.\n\n"

        << "      --idle-timeout <duration>\n"
        << "      Maximum TCP connection inactivity before expiration.\n"
        << "      Supported units: ms, s, m, h.\n"
        << "      A missing unit means seconds.\n"
        << "      Default: 300s.\n\n"

        << "  -h, --help\n"
        << "      Display this help message.\n\n"

        << "Examples:\n"

        << "  " << program_name
        << " capture.pcap\n"

        << "  " << program_name
        << " --filter \"tcp\" capture.pcap\n"

        << "  " << program_name
        << " --filter \"port 8080\" capture.pcap\n"

        << "  " << program_name
        << " --list-interfaces\n"

        << "  " << program_name
        << " --interface lo\n"

        << "  " << program_name
        << " --interface lo --filter \"tcp port 8080\"\n"

        << "  " << program_name
        << " --interface enp3s0 --promiscuous\n"

        << "  " << program_name
        << " --interface wlan0 --idle-timeout 60s\n"

        << "  " << program_name
        << " --idle-timeout 1ms capture.pcap\n";
}

// Interface enumeration

[[nodiscard]] int list_capture_interfaces() {
    char error_buffer[PCAP_ERRBUF_SIZE]{};

    pcap_if_t* devices = nullptr;

    if (pcap_findalldevs(&devices, error_buffer) == -1) {
        std::cerr << "Could not enumerate capture interfaces: "
                  << error_buffer << '\n';

        return 1;
    }

    if (devices == nullptr) {
        std::cout << "No capture interfaces found.\n";
        return 0;
    }

    std::cout << "Available capture interfaces:\n\n";

    std::size_t index = 1U;

    for (
        const pcap_if_t* device = devices;
        device != nullptr;
        device = device->next
    ) {
        std::cout << "  " << index << ". "
                  << device->name;

        if (device->description != nullptr) {
            std::cout << "\n     "
                      << device->description;
        }

        if ((device->flags & PCAP_IF_LOOPBACK) != 0U) {
            std::cout << "\n     [loopback]";
        }

        std::cout << '\n';

        ++index;
    }

    pcap_freealldevs(devices);

    std::cout << "\nUse --interface <name> to start capturing.\n";

    return 0;
}

// Protocol name helpers

[[nodiscard]] const char* ether_type_name(
    std::uint16_t ether_type
) {
    switch (ether_type) {
        case 0x0800U: return "IPv4";
        case 0x0806U: return "ARP";
        case 0x86DDU: return "IPv6";
        case 0x8100U: return "802.1Q VLAN";
        case 0x88A8U: return "802.1ad VLAN";
        default: return "unknown";
    }
}

[[nodiscard]] const char* ip_protocol_name(
    std::uint8_t protocol
) {
    switch (protocol) {
        case 1U: return "ICMP";
        case 6U: return "TCP";
        case 17U: return "UDP";
        case 58U: return "ICMPv6";
        default: return "other";
    }
}

[[nodiscard]] const char* ipv6_header_name(
    std::uint8_t header
) {
    switch (header) {
        case 0U: return "Hop-by-Hop Options";
        case 6U: return "TCP";
        case 17U: return "UDP";
        case 43U: return "Routing";
        case 44U: return "Fragment";
        case 50U: return "ESP";
        case 51U: return "AH";
        case 58U: return "ICMPv6";
        case 59U: return "No Next Header";
        case 60U: return "Destination Options";
        default: return "unknown";
    }
}

// Timestamp conversion

[[nodiscard]] std::uint64_t timestamp_to_microseconds(
    const pcap_pkthdr& header
) noexcept {
    const auto seconds =
        static_cast<std::uint64_t>(header.ts.tv_sec);

    const auto microseconds =
        static_cast<std::uint64_t>(header.ts.tv_usec);

    constexpr std::uint64_t micros_per_second = 1'000'000U;

    return seconds * micros_per_second + microseconds;
}

[[nodiscard]] std::uint64_t current_time_microseconds() noexcept {
    const auto elapsed =
        std::chrono::system_clock::now().time_since_epoch();

    const auto microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(
            elapsed
        ).count();

    if (microseconds <= 0) {
        return 0U;
    }

    return static_cast<std::uint64_t>(microseconds);
}

// Packet printing

void print_transport(
    const wirescope::TransportInfo& transport
) {
    std::visit(
        [](const auto& info) {
            using T = std::decay_t<decltype(info)>;

            if constexpr (std::is_same_v<T, wirescope::TcpInfo>) {
                std::cout << "    TCP       "
                          << info.source_port << " -> "
                          << info.destination_port
                          << "  seq=" << info.sequence_number
                          << "  ack=" << info.acknowledgement_number
                          << "  flags="
                          << wirescope::format_tcp_flags(info.flags)
                          << "  window=" << info.window_size
                          << "  header=" << info.header_length << " B\n";

            } else if constexpr (std::is_same_v<T, wirescope::UdpInfo>) {
                std::cout << "    UDP       "
                          << info.source_port << " -> "
                          << info.destination_port
                          << "  length=" << info.length << " B\n";
            }
        },
        transport
    );
}

void print_ipv4(const wirescope::Ipv4Info& ip) {
    std::cout << "    IPv4      "
              << ip.source_address << " -> " << ip.destination_address
              << "  ttl=" << static_cast<unsigned int>(ip.ttl)
              << "  protocol=" << static_cast<unsigned int>(ip.protocol)
              << " (" << ip_protocol_name(ip.protocol) << ')'
              << "  total_length=" << ip.total_length
              << "  id=" << ip.identification
              << "  fragment_offset=" << ip.fragment_offset
              << (ip.more_fragments ? " MF" : "")
              << '\n';

    if (ip.transport.has_value()) {
        print_transport(*ip.transport);
    }
}

void print_ipv6(const wirescope::Ipv6Info& ip) {
    std::cout << "    IPv6      "
              << ip.source_address << " -> " << ip.destination_address
              << "  hop_limit=" << static_cast<unsigned int>(ip.hop_limit)
              << "  traffic_class=0x" << std::hex
              << static_cast<unsigned int>(ip.traffic_class)
              << "  flow_label=0x" << ip.flow_label
              << std::dec
              << "  payload_length=" << ip.payload_length
              << " B\n";

    std::cout << "    IPv6 next  "
              << static_cast<unsigned int>(ip.next_header)
              << " (" << ipv6_header_name(ip.next_header) << ')'
              << "  upper_layer="
              << static_cast<unsigned int>(ip.upper_layer_protocol)
              << " (" << ipv6_header_name(ip.upper_layer_protocol) << ')'
              << "  parsed_header_length=" << ip.header_length
              << " B\n";

    for (
        std::size_t index = 0;
        index < ip.extension_headers.size();
        ++index
    ) {
        const auto& extension = ip.extension_headers[index];

        std::cout << "    IPv6 ext   #" << (index + 1U)
                  << " " << ipv6_header_name(extension.type)
                  << " (type=" << static_cast<unsigned int>(extension.type)
                  << ", length=" << extension.header_length
                  << " B, next="
                  << ipv6_header_name(extension.next_header)
                  << ")\n";
    }

    if (ip.fragment.has_value()) {
        const auto& fragment = *ip.fragment;

        std::cout << "    IPv6 frag  offset=" << fragment.offset
                  << " (8-byte units)"
                  << "  more_fragments="
                  << (fragment.more_fragments ? "yes" : "no")
                  << "  id=0x" << std::hex << fragment.identification
                  << std::dec << '\n';
    }

    if (ip.transport.has_value()) {
        print_transport(*ip.transport);
    }
}

void print_packet(
    std::size_t index,
    const pcap_pkthdr& header,
    const wirescope::PacketSummary& packet
) {
    std::cout << '#' << index
              << "  " << header.ts.tv_sec << '.'
              << std::setw(6) << std::setfill('0')
              << header.ts.tv_usec << std::setfill(' ')
              << "  caplen=" << packet.captured_length
              << " wirelen=" << packet.wire_length
              << '\n';

    if (!packet.source_mac.empty() || !packet.destination_mac.empty()) {
        std::cout << "    Ethernet  "
                  << packet.source_mac << " -> "
                  << packet.destination_mac
                  << "  type=" << ether_type_name(packet.ether_type)
                  << " (0x" << std::hex << std::setw(4)
                  << std::setfill('0') << packet.ether_type
                  << std::dec << std::setfill(' ') << ")\n";
    }

    for (
        std::size_t index = 0;
        index < packet.vlan_tags.size();
        ++index
    ) {
        const auto& tag = packet.vlan_tags[index];

        std::cout << "    VLAN      #" << (index + 1U)
                  << " TPID=" << ether_type_name(tag.tag_protocol_id)
                  << " VID=" << tag.vlan_id
                  << " PCP=" << static_cast<unsigned int>(tag.priority)
                  << " DEI=" << (tag.drop_eligible ? 1 : 0)
                  << " next=" << ether_type_name(tag.encapsulated_ether_type)
                  << " (0x" << std::hex << std::setw(4)
                  << std::setfill('0') << tag.encapsulated_ether_type
                  << std::dec << std::setfill(' ') << ")\n";
    }

    if (packet.ipv4.has_value()) {
        print_ipv4(*packet.ipv4);
    }

    if (packet.ipv6.has_value()) {
        print_ipv6(*packet.ipv6);
    }

    if (!packet.parse_error.empty()) {
        std::cout << "    [!]       " << packet.parse_error << '\n';
    }
}

// TCP payload extraction

struct DecodedTcpSegment {
    wirescope::TcpStreamEndpoint source;
    wirescope::TcpStreamEndpoint destination;

    wirescope::TcpInfo tcp;

    std::span<const std::uint8_t> payload;
};

[[nodiscard]] std::optional<DecodedTcpSegment> extract_tcp_segment(
    const wirescope::PacketSummary& packet,
    std::span<const std::uint8_t> frame
) {
    // Ethernet header plus all VLAN headers.
    const std::size_t network_offset =
        14U + packet.vlan_tags.size() * 4U;

    std::string source_address;
    std::string destination_address;

    const wirescope::TcpInfo* tcp = nullptr;

    std::size_t ip_header_length = 0U;
    std::size_t transport_length = 0U;

    if (packet.ipv4.has_value()) {
        const auto& ip = *packet.ipv4;

        // IP fragment reassembly is not implemented yet.
        if (
            ip.fragment_offset != 0U ||
            ip.more_fragments
        ) {
            return std::nullopt;
        }

        if (!ip.transport.has_value()) {
            return std::nullopt;
        }

        tcp = std::get_if<wirescope::TcpInfo>(&*ip.transport);

        if (tcp == nullptr) {
            return std::nullopt;
        }

        if (ip.total_length < ip.header_length) {
            return std::nullopt;
        }

        source_address = ip.source_address;
        destination_address = ip.destination_address;

        ip_header_length = ip.header_length;

        transport_length =
            static_cast<std::size_t>(ip.total_length) -
            ip.header_length;

    } else if (packet.ipv6.has_value()) {
        const auto& ip = *packet.ipv6;

        // This version skips IPv6 fragmented packets.
        if (ip.fragment.has_value()) {
            return std::nullopt;
        }

        if (!ip.transport.has_value()) {
            return std::nullopt;
        }

        tcp = std::get_if<wirescope::TcpInfo>(&*ip.transport);

        if (tcp == nullptr) {
            return std::nullopt;
        }

        constexpr std::size_t ipv6_base_header_length = 40U;

        if (ip.header_length < ipv6_base_header_length) {
            return std::nullopt;
        }

        const std::size_t extension_length =
            ip.header_length - ipv6_base_header_length;

        if (ip.payload_length < extension_length) {
            return std::nullopt;
        }

        source_address = ip.source_address;
        destination_address = ip.destination_address;

        ip_header_length = ip.header_length;

        transport_length =
            static_cast<std::size_t>(ip.payload_length) -
            extension_length;

    } else {
        return std::nullopt;
    }

    if (tcp->header_length > transport_length) {
        return std::nullopt;
    }

    if (network_offset > frame.size()) {
        return std::nullopt;
    }

    if (ip_header_length > frame.size() - network_offset) {
        return std::nullopt;
    }

    const std::size_t tcp_header_offset =
        network_offset + ip_header_length;

    if (tcp->header_length > frame.size() - tcp_header_offset) {
        return std::nullopt;
    }

    const std::size_t payload_offset =
        tcp_header_offset + tcp->header_length;

    const std::size_t declared_payload_length =
        transport_length - tcp->header_length;

    const std::size_t captured_payload_length =
        std::min(
            declared_payload_length,
            frame.size() - payload_offset
        );

    return DecodedTcpSegment{
        wirescope::TcpStreamEndpoint{
            source_address,
            tcp->source_port
        },
        wirescope::TcpStreamEndpoint{
            destination_address,
            tcp->destination_port
        },
        *tcp,
        frame.subspan(
            payload_offset,
            captured_payload_length
        )
    };
}

// Shared packet-processing pipeline

struct CaptureContext {
    wirescope::TcpConnectionTracker& tracker;
    wirescope::TcpStreamReassembler& reassembler;

    std::uint64_t idle_timeout_microseconds;
    std::string idle_timeout_label;

    std::size_t packet_count{};
};

void process_packet(
    CaptureContext& context,
    const pcap_pkthdr& header,
    const u_char* packet_data
) {
    ++context.packet_count;

    const auto* bytes =
        reinterpret_cast<const std::uint8_t*>(packet_data);

    const std::span<const std::uint8_t> frame(
        bytes,
        static_cast<std::size_t>(header.caplen)
    );

    const std::uint64_t packet_timestamp_us =
        timestamp_to_microseconds(header);

    const std::size_t expired_connections =
        context.tracker.expire_idle(
            packet_timestamp_us,
            context.idle_timeout_microseconds
        );

    if (expired_connections > 0U) {
        std::cout << "\n[TCP] Expired "
                  << expired_connections
                  << " idle connection(s) before packet #"
                  << context.packet_count
                  << " (idle timeout: "
                  << context.idle_timeout_label
                  << ").\n";
    }

    const wirescope::PacketSummary summary =
        wirescope::decode_ethernet(
            frame,
            static_cast<std::size_t>(header.len)
        );

    context.tracker.observe(
        summary,
        packet_timestamp_us
    );

    const auto tcp_segment =
        extract_tcp_segment(summary, frame);

    if (tcp_segment.has_value()) {
        context.reassembler.observe(
            tcp_segment->source,
            tcp_segment->destination,
            tcp_segment->tcp,
            tcp_segment->payload
        );
    }

    print_packet(
        context.packet_count,
        header,
        summary
    );
}

void packet_callback(
    u_char* user_data,
    const pcap_pkthdr* header,
    const u_char* packet_data
) {
    if (
        user_data == nullptr ||
        header == nullptr ||
        packet_data == nullptr
    ) {
        return;
    }

    auto* context =
        reinterpret_cast<CaptureContext*>(user_data);

    process_packet(
        *context,
        *header,
        packet_data
    );
}

// Live idle expiration

void expire_connections_during_idle(
    CaptureContext& context
) {
    const std::size_t expired_connections =
        context.tracker.expire_idle(
            current_time_microseconds(),
            context.idle_timeout_microseconds
        );

    if (expired_connections > 0U) {
        std::cout << "\n[TCP] Expired "
                  << expired_connections
                  << " idle connection(s) while waiting for packets"
                  << " (idle timeout: "
                  << context.idle_timeout_label
                  << ").\n";
    }
}

// TCP connection summary

void print_connections(
    const wirescope::TcpConnectionTracker& tracker
) {
    std::cout << "\n========================================\n";
    std::cout << "          TCP CONNECTIONS\n";
    std::cout << "========================================\n";

    if (tracker.size() == 0U) {
        std::cout << "No TCP connections observed.\n";
        return;
    }

    for (const auto& connection : tracker.connections()) {
        const std::uint64_t duration_us =
            connection.last_seen_us - connection.first_seen_us;

        std::cout << "\n#" << connection.id << '\n';

        std::cout << "    A           "
                  << connection.key.first.address << ':'
                  << connection.key.first.port << '\n';

        std::cout << "    B           "
                  << connection.key.second.address << ':'
                  << connection.key.second.port << '\n';

        std::cout << "    State A     "
                  << wirescope::tcp_endpoint_state_name(
                      connection.state_a
                  ) << '\n';

        std::cout << "    State B     "
                  << wirescope::tcp_endpoint_state_name(
                      connection.state_b
                  ) << '\n';

        std::cout << "    Tracking    "
                  << (connection.expired
                      ? "EXPIRED (idle timeout)"
                      : "INDEXED")
                  << '\n';

        if (connection.initiator.has_value()) {
            std::cout << "    Initiator   "
                      << connection.initiator->address << ':'
                      << connection.initiator->port << '\n';
        } else {
            std::cout << "    Initiator   unknown (midstream capture)\n";
        }

        std::cout << "    Packets     "
                  << connection.packet_count << '\n';

        std::cout << "    Bytes       "
                  << connection.captured_bytes << '\n';

        std::cout << "    A -> B      "
                  << connection.packets_a_to_b
                  << " packets / "
                  << connection.bytes_a_to_b
                  << " bytes\n";

        std::cout << "    B -> A      "
                  << connection.packets_b_to_a
                  << " packets / "
                  << connection.bytes_b_to_a
                  << " bytes\n";

        std::cout << "    SYN         "
                  << connection.syn_packets
                  << "  SYN-ACK="
                  << connection.syn_ack_packets << '\n';

        std::cout << "    ACK         "
                  << connection.ack_packets
                  << "  FIN="
                  << connection.fin_packets
                  << "  RST="
                  << connection.rst_packets << '\n';

        std::cout << "    Duration    "
                  << duration_us / 1000U << '.'
                  << std::setw(3) << std::setfill('0')
                  << duration_us % 1000U
                  << std::setfill(' ')
                  << " ms\n";
    }

    const std::size_t indexed_count = tracker.active_size();
    const std::size_t expired_count = tracker.size() - indexed_count;

    std::cout << "\n========================================\n";
    std::cout << "Total connection generations: "
              << tracker.size() << '\n';

    std::cout << "Currently indexed: "
              << indexed_count << '\n';

    std::cout << "Expired by idle timeout: "
              << expired_count << '\n';

    std::cout << "========================================\n";
}

// Reassembled TCP stream output

void print_payload_preview(
    std::span<const std::uint8_t> payload
) {
    constexpr std::size_t preview_limit = 512U;

    const std::size_t count =
        std::min(payload.size(), preview_limit);

    std::cout << "    Preview     \"";

    for (std::size_t index = 0U; index < count; ++index) {
        const std::uint8_t byte = payload[index];

        switch (byte) {
            case '\n':
                std::cout << "\\n";
                break;

            case '\r':
                std::cout << "\\r";
                break;

            case '\t':
                std::cout << "\\t";
                break;

            case '\\':
                std::cout << "\\\\";
                break;

            case '"':
                std::cout << "\\\"";
                break;

            default:
                if (byte >= 0x20U && byte <= 0x7EU) {
                    std::cout << static_cast<char>(byte);
                } else {
                    std::cout << '.';
                }
                break;
        }
    }

    std::cout << '"';

    if (payload.size() > count) {
        std::cout << " ... [preview truncated]";
    }

    std::cout << '\n';
}

void print_tcp_streams(
    const wirescope::TcpStreamReassembler& reassembler
) {
    const auto& streams = reassembler.streams();

    std::cout << "\n========================================\n";
    std::cout << "          REASSEMBLED TCP STREAMS\n";
    std::cout << "========================================\n";

    if (streams.empty()) {
        std::cout << "No TCP streams observed.\n";
        return;
    }

    for (
        std::size_t index = 0U;
        index < streams.size();
        ++index
    ) {
        const auto& stream = streams[index];

        std::cout << "\nStream #" << (index + 1U) << '\n';

        std::cout << "    Direction   "
                  << stream.source.address << ':'
                  << stream.source.port
                  << " -> "
                  << stream.destination.address << ':'
                  << stream.destination.port << '\n';

        std::cout << "    Segments    "
                  << stream.segments_observed << '\n';

        std::cout << "    Payload     "
                  << stream.payload.size() << " bytes\n";

        std::cout << "    Out of order "
                  << stream.out_of_order_segments << " segment(s)\n";

        std::cout << "    Retransmits "
                  << stream.retransmitted_bytes << " duplicate byte(s)\n";

        if (stream.pending_bytes > 0U) {
            std::cout << "    Pending     "
                      << stream.pending_bytes
                      << " byte(s) waiting for missing data\n";
        }

        if (stream.dropped_bytes > 0U) {
            std::cout << "    Dropped     "
                      << stream.dropped_bytes
                      << " byte(s) due to memory limits\n";
        }

        if (stream.payload.empty()) {
            std::cout << "    Data        No contiguous payload available.\n";
        } else {
            print_payload_preview(stream.payload);
        }
    }

    std::cout << "\n========================================\n";
}

// Ethernet datalink validation

[[nodiscard]] bool check_ethernet_datalink(
    pcap_t* capture,
    std::string_view capture_description
) {
    const int data_link_type = pcap_datalink(capture);

    if (data_link_type == DLT_EN10MB) {
        return true;
    }

    const char* description =
        pcap_datalink_val_to_description(data_link_type);

    std::cerr
        << "Unsupported capture link type for "
        << capture_description << ": "
        << (description != nullptr ? description : "unknown")
        << ".\n"
        << "This version expects Ethernet (DLT_EN10MB).\n";

    return false;
}

// BPF filter

[[nodiscard]] bool apply_capture_filter(
    pcap_t* capture,
    const std::string& expression,
    std::string_view capture_description
) {
    if (expression.empty()) {
        return true;
    }

    bpf_program compiled_filter{};

    if (
        pcap_compile(
            capture,
            &compiled_filter,
            expression.c_str(),
            1,
            PCAP_NETMASK_UNKNOWN
        ) == -1
    ) {
        std::cerr
            << "Could not compile BPF filter '"
            << expression << "' for "
            << capture_description << ": "
            << pcap_geterr(capture) << '\n';

        return false;
    }

    const int filter_status =
        pcap_setfilter(capture, &compiled_filter);

    pcap_freecode(&compiled_filter);

    if (filter_status == -1) {
        std::cerr
            << "Could not attach BPF filter '"
            << expression << "' to "
            << capture_description << ": "
            << pcap_geterr(capture) << '\n';

        return false;
    }

    return true;
}

// Offline PCAP mode

[[nodiscard]] int run_offline_capture(
    const CommandLineOptions& options,
    wirescope::TcpConnectionTracker& tracker,
    wirescope::TcpStreamReassembler& reassembler,
    std::size_t& packet_count
) {
    char error_buffer[PCAP_ERRBUF_SIZE]{};

    pcap_t* capture = pcap_open_offline(
        options.capture_path.c_str(),
        error_buffer
    );

    if (capture == nullptr) {
        std::cerr << "Could not open capture: "
                  << error_buffer << '\n';

        return 1;
    }

    if (!check_ethernet_datalink(capture, "offline capture")) {
        pcap_close(capture);
        return 1;
    }

    if (
        !apply_capture_filter(
            capture,
            options.filter_expression,
            "offline capture"
        )
    ) {
        pcap_close(capture);
        return 1;
    }

    std::cout << "Offline capture: "
              << options.capture_path << '\n';

    if (!options.filter_expression.empty()) {
        std::cout << "BPF filter: "
                  << options.filter_expression << '\n';
    }

    CaptureContext context{
        tracker,
        reassembler,
        options.idle_timeout_microseconds,
        options.idle_timeout_label
    };

    pcap_pkthdr* header = nullptr;
    const u_char* packet_data = nullptr;

    int status = 0;

    while (
        (status = pcap_next_ex(
            capture,
            &header,
            &packet_data
        )) == 1
    ) {
        process_packet(
            context,
            *header,
            packet_data
        );
    }

    if (status == PCAP_ERROR) {
        std::cerr << "Error reading capture: "
                  << pcap_geterr(capture)
                  << '\n';

        pcap_close(capture);
        packet_count = context.packet_count;

        return 1;
    }

    pcap_close(capture);

    packet_count = context.packet_count;

    return 0;
}

// Live interface mode

[[nodiscard]] int run_live_capture(
    const CommandLineOptions& options,
    wirescope::TcpConnectionTracker& tracker,
    wirescope::TcpStreamReassembler& reassembler,
    std::size_t& packet_count
) {
    char error_buffer[PCAP_ERRBUF_SIZE]{};

    pcap_t* capture = pcap_open_live(
        options.interface_name.c_str(),
        live_snapshot_length,
        options.promiscuous ? 1 : 0,
        live_read_timeout_ms,
        error_buffer
    );

    if (capture == nullptr) {
        std::cerr << "Could not open live capture on interface '"
                  << options.interface_name << "': "
                  << error_buffer << '\n';

        std::cerr
            << "Check that your account has permission "
            << "to capture traffic on this interface.\n";

        return 1;
    }

    if (!check_ethernet_datalink(capture, "live capture")) {
        pcap_close(capture);
        return 1;
    }

    if (
        !apply_capture_filter(
            capture,
            options.filter_expression,
            "live capture"
        )
    ) {
        pcap_close(capture);
        return 1;
    }

    char nonblocking_error[PCAP_ERRBUF_SIZE]{};

    if (
        pcap_setnonblock(
            capture,
            1,
            nonblocking_error
        ) == -1
    ) {
        std::cerr << "Could not enable nonblocking capture: "
                  << nonblocking_error << '\n';

        pcap_close(capture);
        return 1;
    }

    stop_requested = 0;

    const auto previous_handler =
        std::signal(SIGINT, handle_sigint);

    if (previous_handler == SIG_ERR) {
        std::cerr << "Could not install SIGINT handler.\n";

        pcap_close(capture);
        return 1;
    }

    std::cout << "Live capture interface: "
              << options.interface_name << '\n';

    std::cout << "Promiscuous mode: "
              << (options.promiscuous ? "enabled" : "disabled")
              << '\n';

    std::cout << "TCP idle timeout: "
              << options.idle_timeout_label << '\n';

    if (!options.filter_expression.empty()) {
        std::cout << "BPF filter: "
                  << options.filter_expression << '\n';
    }

    std::cout << "Press Ctrl+C to stop capturing.\n\n";

    CaptureContext context{
        tracker,
        reassembler,
        options.idle_timeout_microseconds,
        options.idle_timeout_label
    };

    u_char* user_data =
        reinterpret_cast<u_char*>(&context);

    int capture_result = 0;

    while (stop_requested == 0) {
        const int dispatch_status = pcap_dispatch(
            capture,
            0,
            packet_callback,
            user_data
        );

        if (dispatch_status == PCAP_ERROR) {
            std::cerr << "\nError during live capture: "
                      << pcap_geterr(capture) << '\n';

            capture_result = 1;
            break;
        }

        if (dispatch_status == PCAP_ERROR_BREAK) {
            break;
        }

        if (dispatch_status < 0) {
            std::cerr << "\nUnexpected live capture error: "
                      << pcap_geterr(capture) << '\n';

            capture_result = 1;
            break;
        }

        expire_connections_during_idle(context);

        if (dispatch_status == 0) {
            std::this_thread::sleep_for(live_poll_interval);
        }
    }

    static_cast<void>(
        std::signal(SIGINT, previous_handler)
    );

    expire_connections_during_idle(context);

    if (stop_requested != 0) {
        std::cout << "\nCapture stopped by user.\n";
    }

    pcap_close(capture);

    packet_count = context.packet_count;

    return capture_result;
}

} // namespace

int main(int argc, char* argv[]) {
    CommandLineOptions options;
    std::string argument_error;

    if (!parse_arguments(
        argc,
        argv,
        options,
        argument_error
    )) {
        std::cerr << "Error: "
                  << argument_error << "\n\n";

        print_usage(
            std::cerr,
            argc > 0 ? argv[0] : "wirescope"
        );

        return 2;
    }

    if (options.show_help) {
        print_usage(
            std::cout,
            argc > 0 ? argv[0] : "wirescope"
        );

        return 0;
    }

    if (options.list_interfaces) {
        return list_capture_interfaces();
    }

    wirescope::TcpConnectionTracker tcp_tracker;
    wirescope::TcpStreamReassembler tcp_reassembler;

    std::size_t packet_count = 0U;

    int capture_result = 0;

    if (!options.interface_name.empty()) {
        capture_result = run_live_capture(
            options,
            tcp_tracker,
            tcp_reassembler,
            packet_count
        );

    } else {
        capture_result = run_offline_capture(
            options,
            tcp_tracker,
            tcp_reassembler,
            packet_count
        );
    }

    if (capture_result != 0) {
        return capture_result;
    }

    print_connections(tcp_tracker);
    print_tcp_streams(tcp_reassembler);

    std::cout << "\nRead "
              << packet_count
              << " packet(s).\n";

    return 0;
}
