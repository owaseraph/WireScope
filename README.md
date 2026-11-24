# WireScope

**WireScope** is a C++20 packet analyzer for offline Ethernet PCAP files and live Linux network interfaces. It decodes packet headers, tracks TCP connections, reconstructs directional TCP streams, and performs first-pass HTTP, DNS and TLS ClientHello analysis.

The project builds without mandatory third-party libraries. When libpcap development files are present, WireScope uses libpcap to compile full Berkeley Packet Filter (BPF) expressions. Without libpcap, the built-in filter parser supports common protocol, host and port filters.

## Features

### Capture and packet decoding

- Classic PCAP offline capture (little-endian and big-endian, microsecond and nanosecond timestamps).
- Live Linux capture through `AF_PACKET` raw sockets.
- Interface enumeration and optional promiscuous mode.
- Ethernet II and stacked 802.1Q/802.1ad VLAN headers.
- IPv4 and IPv6 decoding, including supported IPv6 extension headers.
- TCP and UDP header decoding, IPv4/IPv6 endpoint formatting, TCP flags and parse-error reporting.
- Truncated-packet and malformed-header bounds checks.
- Configurable TCP idle timeout.
- Ctrl+C graceful shutdown for live capture.

### TCP analysis

- Bidirectional TCP connection tracking and canonical endpoint pairs.
- Handshake/control-flag counters, directional packet/byte counters and endpoint-state summaries.
- Idle connection expiration.
- Directional TCP stream reconstruction.
- Sequence-number wraparound-aware comparisons, out-of-order buffering, duplicate suppression and bounded memory.
- Default limits: 1 MiB pending data and 16 MiB retained stream data per direction.

### Application protocols

- **HTTP/1.x:** request and response start lines, headers, Content-Length framing, chunked transfer framing, pipelined messages, status codes and incomplete-message detection.
- **DNS/mDNS over UDP:** query/response metadata, compressed-name decoding, response codes, and common A, AAAA, CNAME, NS, PTR, MX and TXT records.
- **TLS ClientHello metadata:** legacy version, supported versions, SNI, ALPN and offered cipher-suite identifiers/names.

WireScope does not decrypt TLS traffic or display HTTP bodies. HTTP body framing and byte counts are reported. DNS over TCP, DoT and DoH are not decoded. IP fragment reassembly is not implemented, so fragmented transport datagrams are skipped by application analysis.

### Reporting

- Console summaries for packets, TCP connections, reassembled streams, DNS messages, HTTP messages and TLS ClientHello metadata.
- JSON export with packet, connection, stream, DNS and application-analysis sections.
- CSV export with packet-level metadata.

## Requirements

- CMake 3.20 or newer.
- A C++20 compiler (GCC 11+, Clang 14+, or a recent MSVC).
- Linux for live capture. Offline classic PCAP analysis is portable.
- Optional: libpcap development package to enable full BPF syntax.

### Arch Linux

```bash
sudo pacman -S --needed base-devel cmake libpcap
```

Live capture generally requires root or `CAP_NET_RAW`. For example, to grant the built executable raw-packet capability:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./build/wirescope
```

Use only on a binary you trust. Alternatively, run live capture with `sudo`.

## Prebuilt executable

A Linux x86-64 Release executable is included at `dist/wirescope-linux-x86_64`. It was built in the packaging environment and uses the system glibc/libstdc++ runtime. Rebuilding on your own Arch Linux installation is recommended for the most reliable runtime compatibility.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Run tests:

```bash
ctest --test-dir build --output-on-failure
```

A sanitizer build is available:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DWIRESCOPE_ENABLE_SANITIZERS=ON
cmake --build build-asan -j"$(nproc)"
ctest --test-dir build-asan --output-on-failure
```

## Usage

Offline PCAP:

```bash
./build/wirescope capture.pcap
```

Filtered capture:

```bash
./build/wirescope --filter "tcp and port 8080" capture.pcap
./build/wirescope --filter "udp port 53" capture.pcap
./build/wirescope --filter "ip6" capture.pcap
```

When libpcap is detected at configure time, these expressions use libpcap's BPF compiler and full BPF syntax is available. Without libpcap, supported built-in terms are `tcp`, `udp`, `ip`, `ip6`, `icmp6`, `port N`, `src port N`, `dst port N`, and `host IP`, joined with `and`.

List interfaces and start live capture:

```bash
./build/wirescope --list-interfaces
sudo ./build/wirescope --interface lo
sudo ./build/wirescope --interface enp3s0 --promiscuous --filter "tcp port 443"
```

Set TCP idle timeout:

```bash
./build/wirescope --idle-timeout 30s capture.pcap
```

Export reports:

```bash
./build/wirescope capture.pcap --export-json report.json --export-csv packets.csv
```

Use `--quiet` to suppress per-packet console lines while retaining final analysis.

## Demo captures

Two tiny generated captures are included in `fixtures/`:

- `dns-demo.pcap`: one DNS A query and response for `example.com`.
- `http-demo.pcap`: one HTTP GET request and a Content-Length response.
- `tls-clienthello-demo.pcap`: a TLS ClientHello containing SNI (`example.test`), ALPN (`h2`) and a TLS 1.3 supported-version offer.

Regenerate them with:

```bash
python tools/generate_demo_pcaps.py
```

The original local `tcp-test.pcap` and `ipv6-loopback.pcap` referenced in the development workflow were not present in the source bundle available for this packaging run, so they are not replaced with fabricated files. Place your original captures in the project directory to run the same manual checks:

```bash
./build/wirescope ./tcp-test.pcap
./build/wirescope ./ipv6-loopback.pcap
```

## Capture format and limitations

- The built-in offline reader supports classic PCAP with Ethernet link type (`DLT_EN10MB`). PCAPNG and non-Ethernet link types need conversion or a libpcap-based workflow.
- The built-in reader rejects capture records larger than 64 MiB.
- Linux live capture uses an `AF_PACKET` socket. The filter is evaluated in user space; for high-volume interfaces, narrow capture at the interface or use an environment with libpcap/kernel-level capture filtering.
- The built-in no-libpcap filter grammar does not implement parentheses, `or`, CIDR networks or arbitrary BPF primitives.
- TCP stream reconstruction cannot recover bytes sent before capture began. It retains directional streams independently and does not combine application requests and responses into a single transaction.
- IP fragmentation, DNS-over-TCP, HTTP/2, HTTP/3, QUIC decryption, TLS decryption, certificate-chain parsing and encrypted DNS are outside this release's scope.
- TLS SNI is visible only when the ClientHello contains a plaintext server_name extension; Encrypted ClientHello is not decoded.

## Project layout

```text
WireScope/
├── CMakeLists.txt
├── README.md
├── include/wirescope/
│   ├── common.hpp
│   ├── decoder.hpp
│   ├── dns_parser.hpp
│   ├── http_parser.hpp
│   ├── pcap_io.hpp
│   ├── tcp_reassembler.hpp
│   ├── tcp_tracker.hpp
│   └── tls_parser.hpp
├── src/
│   ├── decoder.cpp
│   ├── dns_parser.cpp
│   ├── http_parser.cpp
│   ├── main.cpp
│   ├── pcap_io.cpp
│   ├── tcp_reassembler.cpp
│   ├── tcp_tracker.cpp
│   └── tls_parser.cpp
├── tests/
├── tools/generate_demo_pcaps.py
└── fixtures/
```

## License

No license grant is included in this source bundle. Add a license before redistributing the project under an open-source license.
