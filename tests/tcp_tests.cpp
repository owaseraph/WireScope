#include "wirescope/tcp_reassembler.hpp"
#include "wirescope/tcp_tracker.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
using namespace wirescope;
int main(){PacketSummary p;p.captured_length=60;Ipv4Info ip;ip.source_address="192.0.2.1";ip.destination_address="192.0.2.2";TcpInfo t;t.source_port=12345;t.destination_port=80;t.sequence_number=100;t.flags=0x02;ip.transport=TransportInfo{t};p.ipv4=ip;TcpConnectionTracker tracker;tracker.observe(p,1000);assert(tracker.size()==1);assert(tracker.connections()[0].syn==1);assert(tracker.expire_idle(2000,500)==1);assert(tracker.active_size()==0);
 TcpStreamReassembler r;Endpoint a{"192.0.2.1",12345},b{"192.0.2.2",80};TcpInfo x;x.sequence_number=100;x.flags=0x02;r.observe(a,b,x,{});x.flags=0x18;x.sequence_number=104;std::array<std::uint8_t,2> tail{'d','e'};r.observe(a,b,x,tail);x.sequence_number=101;std::array<std::uint8_t,3> head{'a','b','c'};r.observe(a,b,x,head);assert(r.streams().size()==1);const auto& bytes=r.streams()[0].payload;assert(bytes.size()==5);assert(bytes[0]=='a'&&bytes[1]=='b'&&bytes[2]=='c'&&bytes[3]=='d'&&bytes[4]=='e');
 TcpStreamReassembler wrap;TcpInfo syn;syn.sequence_number=0xfffffffeU;syn.flags=0x02;wrap.observe(a,b,syn,{});
 TcpInfo segment;segment.sequence_number=2;segment.flags=0x18;std::array<std::uint8_t,2> end{'d','e'};wrap.observe(a,b,segment,end);
 segment.sequence_number=0xffffffffU;std::array<std::uint8_t,3> begin{'a','b','c'};wrap.observe(a,b,segment,begin);
 const auto& wb=wrap.streams()[0].payload;assert(wb.size()==5&&wb[0]=='a'&&wb[1]=='b'&&wb[2]=='c'&&wb[3]=='d'&&wb[4]=='e');
 std::cout<<"TCP tests passed\n";}
