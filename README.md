# WireScope

WireScope is a C++20 packet analyzer built incrementally
as a networking-systems portfolio project.

## Features

- Offline PCAP file analysis through libpcap.
- Live packet capture from a selected network interface.
- Ethernet II frame decoding.
- VLAN tag parsing.
- IPv4 and IPv6 packet decoding.
- TCP and UDP header decoding.
- TCP bidirectional connection tracking.
- TCP endpoint state tracking.
- TCP connection expiration based on configurable idle timeouts.
- Live interface enumeration.
- Optional promiscuous capture mode.
- BPF packet filtering through libpcap.
- Bidirectional TCP stream reassembly.
- Out-of-order TCP segment buffering.
- TCP retransmission and overlapping-byte handling.
- TCP sequence-number wraparound handling.
- Graceful live-capture shutdown with Ctrl+C.
- Defensive parsing of truncated and malformed packets.

## Requirements

On Arch Linux:

```bash
sudo pacman -S --needed base-devel cmake libpcap tcpdump
```

## Build

Configure the project:

```bash
cmake -S . -B build
```

Compile:

```bash
cmake --build build -j"$(nproc)"
```

Run tests:

```bash
ctest --test-dir build --output-on-failure
```

## Usage

### Offline PCAP analysis

```bash
./build/wirescope capture.pcap
```

### List available capture interfaces

```bash
./build/wirescope --list-interfaces
```

### Live packet capture

```bash
sudo ./build/wirescope --interface lo
```

Replace `lo` with the interface you want to capture from.

### Promiscuous mode

Enable promiscuous mode:

```bash
sudo ./build/wirescope --interface enp3s0 --promiscuous
```

Disable it explicitly:

```bash
sudo ./build/wirescope --interface enp3s0 --no-promiscuous
```

Promiscuous mode is disabled by default.

## BPF packet filtering

WireScope uses libpcap's Berkeley Packet Filter implementation.

Filters are applied before packets reach the decoder,
TCP tracker, and stream reassembler.

The `--filter` option works with both offline and live capture.

### Offline filtering

Only TCP packets:

```bash
./build/wirescope --filter "tcp" capture.pcap
```

Traffic involving port 8080:

```bash
./build/wirescope --filter "port 8080" capture.pcap
```

Only DNS traffic:

```bash
./build/wirescope --filter "udp port 53" capture.pcap
```

Only IPv6 traffic:

```bash
./build/wirescope --filter "ip6" capture.pcap
```

### Live filtering

Capture TCP traffic on port 8080:

```bash
sudo ./build/wirescope \
    --interface lo \
    --filter "tcp port 8080"
```

Filters use standard libpcap BPF syntax.

An invalid filter expression is reported before packet processing starts.

## TCP connection tracking

WireScope tracks TCP connections in both directions.

It records:

- Source and destination endpoints.
- TCP handshake states.
- FIN and RST transitions.
- Directional packet and byte counters.
- Connection duration.
- Idle expiration.

The default TCP connection idle timeout is 300 seconds.

Set a custom timeout:

```bash
sudo ./build/wirescope \
    --interface lo \
    --idle-timeout 30s
```

Supported timeout units:

- `ms`: milliseconds
- `s`: seconds
- `m`: minutes
- `h`: hours

## TCP stream reassembly

WireScope reconstructs TCP payloads separately for
each direction of a connection.

For each directional stream, it:

1. Tracks the next expected TCP sequence number.
2. Appends payload that arrives in sequence.
3. Buffers out-of-order bytes.
4. Flushes buffered bytes when missing data arrives.
5. Ignores already-delivered bytes from retransmissions
   and overlapping segments.
6. Handles 32-bit TCP sequence-number wraparound.

The capture summary displays:

- Stream endpoints.
- Number of observed TCP segments.
- Reassembled payload size.
- Out-of-order segment count.
- Duplicate/retransmitted byte count.
- Pending and dropped byte counts.
- A printable payload preview.

### Memory limits

To prevent unbounded buffering:

- Maximum pending out-of-order data: 1 MiB per direction.
- Maximum stored reassembled payload: 16 MiB per direction.

### Current limitations

- IPv4 and IPv6 fragment reassembly is not implemented.
- Fragmented IP packets are excluded from TCP stream reassembly.
- If capture begins midstream, the first observed payload
  establishes the initial sequence position. Earlier missing
  data cannot be reconstructed.
- The preview is limited to the first 512 bytes per direction.

## Graceful shutdown

Press Ctrl+C during live capture.

WireScope stops capturing and prints the TCP connection
and reassembled stream summaries.

## CLI help

Display all supported options:

```bash
./build/wirescope --help
```

## Testing

The decoder, TCP tracker, and stream reassembler tests use
handcrafted packets and do not require root privileges or
a live network interface.

Run the complete test suite:

```bash
ctest --test-dir build --output-on-failure
```

## Manual PCAP tests

The project has two existing local test captures.

### TCP HTTP exchange

```bash
./build/wirescope ./tcp-test.pcap
```

Expected stream directions:

- Client `127.0.0.1:50664` to server `127.0.0.1:8080`.
- Server `127.0.0.1:8080` to client `127.0.0.1:50664`.

The capture contains payload in both directions.

### IPv6 loopback

```bash
./build/wirescope ./ipv6-loopback.pcap
```

This capture contains ICMPv6 packets and should not produce
any reassembled TCP streams.

## Project structure

```text
WireScope/
├── include/
│   └── wirescope/
│       ├── decoder.hpp
│       ├── tcp_tracker.hpp
│       └── tcp_reassembler.hpp
├── src/
│   ├── decoder.cpp
│   ├── tcp_tracker.cpp
│   ├── tcp_reassembler.cpp
│   └── main.cpp
├── tests/
│   ├── decoder_tests.cpp
│   ├── tcp_tracker_tests.cpp
│   └── tcp_reassembler_tests.cpp
├── CMakeLists.txt
└── README.md
```
