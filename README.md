# WireScope

WireScope is a C++20 packet analyzer built incrementally
as a networking-systems portfolio project.

## Current milestone: offline Ethernet packet decoding

This version:

- Reads offline packet captures through libpcap.
- Expects Ethernet frames (`DLT_EN10MB`).
- Decodes Ethernet II, IPv4, TCP, and UDP headers.
- Reports truncated or malformed headers without reading
  beyond the captured buffer.
- Tests the decoder with handcrafted packets; unit tests
  do not need root privileges or a live network interface.

Not implemented yet: VLAN parsing, IPv6, live capture,
TCP stream tracking, packet filtering, and a graphical interface.

The decoder and its tests can still be built without libpcap.
When libpcap is unavailable, CMake omits only the `wirescope`
capture-file executable.

## Build on Linux

Install the required packages:

```bash
sudo pacman -S --needed base-devel cmake libpcap tcpdump