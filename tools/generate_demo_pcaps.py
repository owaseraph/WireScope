#!/usr/bin/env python3
"""Generate small, deterministic Ethernet PCAP fixtures for WireScope demos."""
from __future__ import annotations
import argparse
import ipaddress
import struct
from pathlib import Path

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")

def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def ethernet_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_ip, dst_ip = ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0x4000, 64, proto, 0, src_ip, dst_ip)
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    src_mac, dst_mac = (CLIENT_MAC, SERVER_MAC) if src.endswith(".10") else (SERVER_MAC, CLIENT_MAC)
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + hdr + payload

def udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload

def tcp(src_port: int, dst_port: int, seq: int, payload: bytes) -> bytes:
    off_flags = (5 << 12) | 0x18  # data offset=5, PSH+ACK
    hdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, 0, off_flags, 65535, 0, 0)
    return hdr + payload

def write_pcap(path: Path, frames: list[tuple[int, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, frame in frames:
            f.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
            f.write(frame)

def dns_query() -> bytes:
    name = b"\x07example\x03com\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)

def dns_answer() -> bytes:
    q = dns_query()[12:]
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes((93, 184, 216, 34))
    return struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q + rr

def make_dns(path: Path) -> None:
    frames = [
        (1, ethernet_ipv4("192.0.2.10", "192.0.2.53", 17, udp(53000, 53, dns_query()))),
        (2, ethernet_ipv4("192.0.2.53", "192.0.2.10", 17, udp(53, 53000, dns_answer()))),
    ]
    write_pcap(path, frames)

def make_http(path: Path) -> None:
    request = b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"
    frames = [
        (1, ethernet_ipv4("192.0.2.10", "192.0.2.80", 6, tcp(40000, 80, 1001, request))),
        (2, ethernet_ipv4("192.0.2.80", "192.0.2.10", 6, tcp(80, 40000, 9001, response))),
    ]
    write_pcap(path, frames)

def make_tls(path: Path) -> None:
    host = b"example.test"
    sni_data = struct.pack("!H", 1 + 2 + len(host)) + b"\x00" + struct.pack("!H", len(host)) + host
    extensions = struct.pack("!HH", 0, len(sni_data)) + sni_data
    alpn = b"\x00\x03\x02h2"
    extensions += struct.pack("!HH", 16, len(alpn)) + alpn
    versions = b"\x02\x03\x04"
    extensions += struct.pack("!HH", 43, len(versions)) + versions
    body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    frame = ethernet_ipv4("198.51.100.10", "198.51.100.20", 6, tcp(50000, 443, 1001, record))
    write_pcap(path, [(1, frame)])

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="fixtures")
    args = parser.parse_args()
    out = Path(args.output_dir)
    make_dns(out / "dns-demo.pcap")
    make_http(out / "http-demo.pcap")
    make_tls(out / "tls-clienthello-demo.pcap")
    print(f"Wrote demo captures to {out.resolve()}")

if __name__ == "__main__":
    main()
