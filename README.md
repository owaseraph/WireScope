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
Filters are applied before packets reach the decoder and TCP tracker.

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

Capture DNS traffic:

```bash
sudo ./build/wirescope \
    --interface enp3s0 \
    --filter "udp port 53"
```

Combine filter conditions:

```bash
sudo ./build/wirescope \
    --interface enp3s0 \
    --filter "tcp and (port 80 or port 443)"
```

Filters use standard libpcap BPF syntax.
See the `pcap-filter` manual for the complete expression language.

An invalid filter expression is reported before packet processing starts.

## TCP idle timeout

The default TCP connection idle timeout is 300 seconds.

Set a custom timeout:

```bash
sudo ./build/wirescope \
    --interface lo \
    --idle-timeout 30s
```

Supported units:

- `ms`: milliseconds
- `s`: seconds
- `m`: minutes
- `h`: hours

A missing unit means seconds.

Example:

```bash
./build/wirescope --idle-timeout 500ms capture.pcap
```

## Graceful shutdown

Press Ctrl+C during live capture.

WireScope stops capturing and prints the TCP connection summary.

## CLI help

Display all supported options:

```bash
./build/wirescope --help
```

## Testing

The decoder and TCP tracker tests use handcrafted packets and do not
require root privileges or a live network interface.

Run the complete test suite:

```bash
ctest --test-dir build --output-on-failure
```

## Project structure

```text
WireScope/
├── include/
│   └── wirescope/
│       ├── decoder.hpp
│       └── tcp_tracker.hpp
├── src/
│   ├── decoder.cpp
│   ├── tcp_tracker.cpp
│   └── main.cpp
├── tests/
│   ├── decoder_tests.cpp
│   └── tcp_tracker_tests.cpp
├── CMakeLists.txt
└── README.md
```
