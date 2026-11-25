# WireScope

**WireScope** is a C++20 packet analyzer for offline Ethernet PCAP files and live Linux network interfaces. It decodes packet headers, tracks TCP connections, reconstructs directional TCP streams, and performs first-pass HTTP, DNS and TLS ClientHello analysis.

The CLI and core libraries build without mandatory third-party libraries. The optional desktop application uses Qt 6 Widgets. The GUI uses the shared `AnalysisEngine`; the CLI has its own processing context and orchestration while reusing the shared decoder, TCP, and protocol libraries. When libpcap development files are present, the CLI can compile full Berkeley Packet Filter (BPF) expressions. Without libpcap, its built-in filter parser supports a limited set of protocol, host, and port terms joined with `and`.

Live and offline capture reads in the GUI run in a worker thread. Captured packets are delivered to the GUI thread, where `AnalysisEngine` currently ingests, decodes, and analyzes them. High-rate or large captures can therefore put processing work on the GUI thread.

## Features

### Implemented features — Desktop GUI

- Optional Qt 6 Widgets desktop application (`wirescope-gui`).
- Open classic Ethernet PCAP files or capture live traffic from a Linux interface.
- Start/stop controls, interface selection and optional promiscuous mode.
- Packet table with a display filter for protocol, address and port terms.
- Expandable Ethernet, VLAN, IPv4/IPv6, TCP and UDP protocol trees, including individual TCP flags and IPv6 extension headers.
- DNS questions and resource records embedded in the selected packet's protocol tree; HTTP headers and TLS ClientHello metadata are shown for matching TCP conversations.
- Hexadecimal and ASCII packet-byte viewer.
- Double-click a TCP connection to follow its directional streams; a packet context menu also offers **Follow TCP stream**. The viewer displays stream counters and separate ASCII/hex payload views.
- Double-click DNS, HTTP or TLS rows to inspect full message/handshake metadata.
- Statistics dashboard with packet/byte totals, capture duration, average packet and bit rates, protocol distribution, top TCP conversations and a 60-bucket traffic timeline.
- Background capture worker for PCAP reads and live packet reads. Packet ingestion, decoding, and analysis currently run on the GUI thread after delivery.
- CLI remains available as a separate executable and Qt is optional.


### Implemented features — Capture and packet decoding

- Classic PCAP offline capture (little-endian and big-endian, microsecond and nanosecond timestamps).
- Live Linux capture through `AF_PACKET` raw sockets.
- Interface enumeration and optional promiscuous mode.
- Ethernet II and stacked 802.1Q/802.1ad VLAN headers.
- IPv4 and IPv6 decoding, including supported IPv6 extension headers.
- TCP and UDP header decoding, IPv4/IPv6 endpoint formatting, TCP flags and parse-error reporting.
- Truncated-packet and malformed-header bounds checks.
- Configurable TCP idle timeout.
- Ctrl+C graceful shutdown for live capture.

### Implemented features — TCP analysis

- Bidirectional TCP connection tracking and canonical endpoint pairs.
- Handshake/control-flag counters, directional packet/byte counters and endpoint-state summaries.
- Idle connection expiration.
- Directional TCP stream reconstruction with first/last-seen timestamps, allowing the GUI to distinguish reused endpoint tuples when following a specific connection.
- Sequence-number wraparound-aware comparisons, out-of-order buffering, duplicate suppression and bounded memory.
- Default limits: 1 MiB pending data and 16 MiB retained stream data per direction.

### Implemented features — Application protocols

- **HTTP/1.x:** request and response start lines, headers, Content-Length framing, chunked transfer framing, pipelined messages, status codes and incomplete-message detection. Captured stream bytes can also be examined in the GUI's ASCII/hex stream viewer.
- **DNS/mDNS over UDP:** query/response metadata, compressed-name decoding, response codes, and common A, AAAA, CNAME, NS, PTR, MX and TXT records.
- **TLS ClientHello metadata:** legacy version, supported versions, SNI, ALPN and offered cipher-suite identifiers/names.

WireScope does not decrypt TLS traffic. HTTP body framing and byte counts are reported by the parser; the Follow TCP Stream viewer can inspect captured application payload bytes, including any unencrypted HTTP body bytes. Each directional stream view renders up to the first 2 MiB. DNS over TCP, DoT and DoH are not decoded. IP fragment reassembly is not implemented, so fragmented transport datagrams are skipped by application analysis.

### Implemented features — Reporting

- Console summaries for packets, TCP connections, reassembled streams, DNS messages, HTTP messages and TLS ClientHello metadata.
- JSON export with packet, connection, stream, DNS and application-analysis sections.
- CSV export with packet-level metadata.

## Requirements

- CMake 3.20 or newer.
- Qt 6 Widgets development package for the desktop GUI (optional).
- A C++20 compiler (GCC 11+, Clang 14+, or a recent MSVC).
- Linux for live capture. Offline classic PCAP analysis is portable.
- Optional: libpcap development package to enable full BPF syntax.

### Arch Linux

```bash
sudo pacman -S --needed base-devel cmake libpcap qt6-base
```

Live capture generally requires root or `CAP_NET_RAW`. For example, to grant the built executable raw-packet capability:

```bash
sudo setcap cap_net_raw+ep ./build/wirescope-gui
```

Use only on a binary you trust. Alternatively, run live capture with `sudo`.

## Prebuilt executable

A Linux x86-64 Release CLI executable is included at `dist/wirescope-linux-x86_64`. It uses the system glibc/libstdc++ runtime. Rebuilding on your own Arch Linux installation is recommended for the most reliable runtime compatibility. The Qt GUI is built locally when `qt6-base` is installed; it is not bundled as a prebuilt executable.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

When Qt 6 is installed, CMake also builds the GUI:

```bash
./build/wirescope-gui
```

If Qt 6 is not installed, the GUI target is skipped and the CLI still builds.

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

Three tiny generated captures are included in `fixtures/`:

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

## Current limitations (not implemented)

- The built-in offline reader supports classic PCAP with Ethernet link type (`DLT_EN10MB`) only. PCAPNG and other datalinks are unsupported.
- `CapturedPacket` does not carry explicit datalink metadata; current capture and analysis assume Ethernet frames.
- Live capture is Linux-specific and uses `AF_PACKET` raw sockets.
- Radiotap parsing, IEEE 802.11 decoding, and Wi-Fi monitor-mode capture are not implemented.
- The built-in reader rejects capture records larger than 64 MiB.
- The CLI's built-in no-libpcap filter grammar does not implement parentheses, `or`, CIDR networks, or arbitrary BPF primitives. Live capture filtering is evaluated in user space.
- TCP stream reconstruction cannot recover bytes sent before capture began. It retains directional streams independently and does not combine application requests and responses into a single transaction.
- TCP reassembly buffers are bounded, but packet history and overall analysis state have no retention limit.
- IP fragment reassembly is absent; fragmented transport datagrams are skipped by application analysis. DNS over TCP, DNS over TLS, and DNS over HTTPS are not decoded.
- HTTP/2 and HTTP/3 are not parsed. TLS decryption and certificate-chain parsing are absent.
- TLS SNI is available only when visible in a plaintext ClientHello; Encrypted ClientHello is not decoded.
- There is no automated GUI test target. Some test source files are not registered with CMake and are not run by the standard CTest suite.

## Planned features

The next planned milestone is datalink-aware Wi-Fi analysis: explicit datalink metadata; separate Ethernet and wireless decoding routes; independently tested Radiotap parsing; focused 802.11 frame-control, address-role, and management information-element decoding (including SSID); shared-core integration; and GUI presentation. Initial monitor-mode capture will use an already configured monitor interface. WireScope will not automatically change interface mode or channel. See [`IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) for the phased roadmap.

## Project layout

```text
WireScope/
├── CMakeLists.txt
├── README.md
├── include/wirescope/
│   ├── analysis_engine.hpp
│   ├── common.hpp
│   ├── decoder.hpp
│   ├── dns_parser.hpp
│   ├── http_parser.hpp
│   ├── pcap_io.hpp
│   ├── tcp_reassembler.hpp
│   ├── tcp_tracker.hpp
│   └── tls_parser.hpp
├── gui/
│   ├── main.cpp
│   ├── main_window.cpp/.hpp
│   ├── capture_worker.cpp/.hpp
│   ├── packet_table_model.cpp/.hpp
│   ├── tcp_stream_dialog.cpp/.hpp
│   └── statistics_widget.cpp/.hpp
│   ├── tcp_stream_dialog.cpp/.hpp
│   └── statistics_widget.cpp/.hpp
├── src/
│   ├── analysis_engine.cpp
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

WireScope is licensed under the MIT License. See [LICENSE](LICENSE) for details.
