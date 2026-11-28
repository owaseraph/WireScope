# Technical Requirements — WireScope

**Document status:** living specification  
**Project language:** C++20  
**Primary desktop target:** Linux / Arch Linux  
**Desktop framework:** Qt 6 Widgets (optional build target)

This document distinguishes implemented behavior from planned work. A requirement marked **Planned** must not be described as implemented until code, tests and documentation support it.

## 1. Product purpose

WireScope is a packet analyzer with two frontends:

- A CLI for scripted, terminal-based and offline analysis.
- A Qt desktop GUI for interactive capture, packet inspection, stream following and statistics.

Both frontends reuse the same capture, decoding, TCP, and protocol capabilities. The GUI uses `AnalysisEngine` and must not reimplement protocol parsers or invoke the CLI as its analysis backend. The CLI has its own processing context and orchestration and does not call `AnalysisEngine`.

## 2. Current architecture

```text
CLI frontend (src/main.cpp)       Qt GUI frontend (gui/)
             |                            |
 Own processing context          AnalysisEngine
             |                            |
             +--------- shared core -----+
             |       decoder / TCP /       |
             |       protocol parsers      |
             +-------------+---------------+
                           |
                      Capture I/O
                 PCAP / Linux AF_PACKET
```

### Source ownership

| Area | Responsibility |
|---|---|
| `include/wirescope/` | Public value types and API declarations |
| `src/decoder.cpp` | Ethernet, VLAN, IPv4/IPv6 and transport decoding |
| `src/tcp_tracker.cpp` | TCP connection state and counters |
| `src/tcp_reassembler.cpp` | Directional TCP payload reconstruction |
| `src/http_parser.cpp` | HTTP/1.x stream parsing |
| `src/dns_parser.cpp` | DNS/mDNS message parsing |
| `src/tls_parser.cpp` | TLS ClientHello metadata parsing |
| `src/pcap_io.cpp` | Classic PCAP reading, Linux live capture, interface listing |
| `src/analysis_engine.cpp` | Shared packet ingestion and analysis state |
| `src/main.cpp` | CLI argument handling and CLI report/export |
| `gui/` | Qt presentation, capture worker, packet table, stream dialog and statistics |
| `tests/` | Decoder, TCP, protocol and analysis-engine regression tests |

## 3. Implemented functional requirements

### Capture and packet decoding

- Read classic PCAP files and preserve the global link type on every captured packet.
- Decode Ethernet PCAP and Linux Ethernet live frames; retain unsupported link types with an explicit decode error.
- Support little-endian and big-endian PCAP and microsecond/nanosecond timestamps.
- On Linux, capture from a selected interface through `AF_PACKET` raw sockets and preserve the per-packet Linux hardware type reported by `sockaddr_ll`.
- Enumerate interfaces and optionally request promiscuous mode.
- Decode Ethernet II, stacked 802.1Q/802.1ad VLAN tags, IPv4, IPv6, supported IPv6 extension headers, TCP and UDP.
- Retain captured bytes and decoded metadata for GUI inspection.
- Report malformed/truncated packets defensively.
- Stop live capture cleanly.

### TCP analysis

- Track bidirectional TCP connections, endpoint states, counters and idle expiration.
- Reassemble directional TCP streams with bounded buffering, out-of-order handling, duplicate suppression and sequence-number wraparound handling.
- Keep stream timestamps so reused endpoint tuples can be distinguished when matching conversations.

### Application protocols

- HTTP/1.x request/response start lines, headers, Content-Length/chunked framing, pipelining and incomplete/malformed states.
- DNS/mDNS over UDP with compressed names, queries, responses and common resource records.
- TLS ClientHello metadata including SNI, ALPN, supported versions and cipher-suite identifiers.
- No TLS decryption.

### GUI

- Open classic PCAP files and capture live traffic on Linux.
- Choose interface, start/stop capture and set the supported display filter.
- Show a packet table, selected-packet protocol details and hexadecimal/ASCII bytes.
- Inspect TCP connections and follow reassembled directional streams.
- Inspect DNS observations and HTTP/TLS application-stream metadata.
- Show packet/byte totals, capture duration, average rates, protocol distribution, top TCP conversations and traffic timeline.
- Run capture reads in a worker thread. Captured packets are delivered to the GUI thread, where packet ingestion, decoding, and analysis currently run; this can affect responsiveness during high-rate captures.

### Reporting

- CLI console summaries.
- JSON analysis export.
- CSV packet-summary export.

## 4. Platform and build requirements

- CMake 3.20 or newer.
- C++20 compiler (GCC 11+ or Clang 14+ recommended for the Linux development environment).
- Qt 6 Widgets development package for `wirescope-gui`; Qt remains optional so CLI/core builds work without it.
- Linux for live `AF_PACKET` capture.
- Optional libpcap development package for full BPF compilation. Without libpcap, the built-in filter grammar supports a limited set of ANDed terms.

Arch Linux packages:

```bash
sudo pacman -S --needed base-devel cmake qt6-base libpcap
```

Build:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Live capture needs suitable privileges, normally `CAP_NET_RAW` or root. Never change capabilities or network interface configuration automatically.

## 5. Non-functional requirements

### Correctness and safety

- Treat packet bytes as untrusted input.
- Check all offsets, declared lengths, counts and conversions before reading packet data.
- Malformed packets must not crash the CLI or GUI.
- Distinguish unavailable/incomplete metadata from valid zero values.
- Do not fabricate missing packet, signal, protocol or timing information.

### Performance and memory

- Keep the GUI responsive during live capture.
- Avoid repeated full-table rebuilds for every packet when a batched model update is appropriate.
- Preserve bounded TCP stream reassembly limits. Packet history and overall analysis state currently have no retention limit.
- Before adding long-running high-volume capture features, evaluate packet-history retention and expose a bounded capture/buffering policy rather than silently allowing unbounded memory growth.

### Maintainability

- Core code must not depend on Qt.
- Keep CLI and GUI frontends separate.
- Follow strict compiler warnings: `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion`.
- Use RAII and explicit ownership.
- Prefer focused modules and tests over monolithic functions.

## 6. Known limitations / explicit non-goals for the current release

- Classic PCAP link types are preserved, but Ethernet is the only decoded link type; PCAPNG is unsupported.
- `CapturedPacket` carries a PCAP link type or Linux hardware type as distinct alternatives, plus Linux `sll_protocol` separately. These identifiers are not interchangeable. Unsupported hardware types are retained but not decoded.
- Live capture is Linux-specific through `AF_PACKET`.
- The built-in no-libpcap filter parser does not implement arbitrary BPF, parentheses or OR expressions.
- IP fragment reassembly is not implemented; fragmented transport datagrams are skipped by application analysis.
- DNS over TCP, DNS over TLS and DNS over HTTPS are not decoded.
- HTTP/2 and HTTP/3 are not parsed.
- TLS decryption and certificate-chain parsing are absent; encrypted application data is not inspected.
- SNI is available only when visible in a plaintext ClientHello; Encrypted ClientHello is not decoded.
- Current capture and analysis are Ethernet-oriented. Raw IEEE 802.11/Radiotap decoding and monitor mode are **not implemented yet**.
- There is no automated GUI test target. Additional test source files not registered by CMake are not part of the standard CTest run.

## 7. Next planned capability: Wi-Fi analysis

**Status: Planned — not implemented.**

Planned requirements for a future wireless milestone (not currently implemented):

1. Preserve Ethernet and PCAP behavior without regression.
2. Add bounded Radiotap header parsing, including present-bit/field alignment handling.
3. Add IEEE 802.11 frame-control parsing and management/control/data classification.
4. Parse available metadata such as BSSID, transmitter/receiver addresses, SSID information elements, frequency/channel and signal strength when present.
5. Initially use an already configured monitor interface. Do not automatically change interface mode or channel.
6. Route raw wireless frames to the 802.11 decoder, never to the Ethernet decoder.
7. Add synthetic parser tests and sample fixtures that do not require Wi-Fi hardware, root privileges or access points.
8. Surface wireless fields in the GUI and statistics without breaking Ethernet packet views.

Detailed delivery phases are in `IMPLEMENTATION.md`.
