#include "wirescope/pcap_io.hpp"
#include <array>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <limits>
#include <utility>

#ifdef __linux__
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <ifaddrs.h>
#endif

namespace wirescope { namespace {
std::uint16_t rd16(const std::uint8_t* p,bool le){return le?std::uint16_t(p[0]|(std::uint16_t(p[1])<<8U)):std::uint16_t((std::uint16_t(p[0])<<8U)|p[1]);}
std::uint32_t rd32(const std::uint8_t* p,bool le){return le?(std::uint32_t(p[0])|(std::uint32_t(p[1])<<8U)|(std::uint32_t(p[2])<<16U)|(std::uint32_t(p[3])<<24U)):(std::uint32_t(p[0])<<24U)|(std::uint32_t(p[1])<<16U)|(std::uint32_t(p[2])<<8U)|p[3];}
}
bool read_pcap_file(const std::string& path,const PacketHandler& handler,std::string& error){
 std::ifstream f(path,std::ios::binary);if(!f){error="cannot open PCAP file: "+path;return false;}
 std::array<std::uint8_t,24> g{};if(!f.read(reinterpret_cast<char*>(g.data()),static_cast<std::streamsize>(g.size()))){error="truncated PCAP global header";return false;}
 const std::array<std::uint8_t,4> m{g[0],g[1],g[2],g[3]};bool le=false,nano=false;
 if(m==std::array<std::uint8_t,4>{0xd4,0xc3,0xb2,0xa1})le=true;
 else if(m==std::array<std::uint8_t,4>{0xa1,0xb2,0xc3,0xd4})le=false;
 else if(m==std::array<std::uint8_t,4>{0x4d,0x3c,0xb2,0xa1}){le=true;nano=true;}
 else if(m==std::array<std::uint8_t,4>{0xa1,0xb2,0x3c,0x4d}){le=false;nano=true;}
 else{error="unsupported PCAP magic (PCAPNG is not supported by the built-in reader)";return false;}
 if(rd16(g.data()+4,le)!=2||rd16(g.data()+6,le)!=4){error="unsupported PCAP version";return false;}
 const auto snap=rd32(g.data()+16,le);const auto link=rd32(g.data()+20,le);if(link!=1U){error="unsupported PCAP link type; Ethernet is required";return false;}if(snap==0U||snap>64U*1024U*1024U){error="invalid PCAP snapshot length";return false;}
 std::array<std::uint8_t,16> h{};
 while(true){
   f.read(reinterpret_cast<char*>(h.data()),static_cast<std::streamsize>(h.size()));
   const auto header_bytes=f.gcount();
   if(header_bytes==0&&f.eof())break;
   if(header_bytes!=static_cast<std::streamsize>(h.size())){error="truncated PCAP packet header";return false;}
   const auto sec=rd32(h.data(),le),frac=rd32(h.data()+4,le),incl=rd32(h.data()+8,le),orig=rd32(h.data()+12,le);
   const std::uint32_t fraction_limit=nano?1000000000U:1000000U;
   if(frac>=fraction_limit){error="invalid PCAP timestamp fraction";return false;}
   if(incl>snap||incl>64U*1024U*1024U||orig<incl){error="PCAP packet length exceeds its declared bounds";return false;}
   CapturedPacket p;p.timestamp_us=std::uint64_t(sec)*1000000U+(nano?frac/1000U:frac);p.wire_length=orig;p.bytes.resize(incl);
   if(incl&&!f.read(reinterpret_cast<char*>(p.bytes.data()),static_cast<std::streamsize>(incl))){error="truncated PCAP packet data";return false;}
   if(!handler(p))return true;
 }
 if(!f.eof()){error="error reading PCAP file";return false;}return true;
}
std::vector<std::string> list_interfaces(){std::vector<std::string> out;
#ifdef __linux__
 ifaddrs* addrs=nullptr;if(getifaddrs(&addrs)==0){for(auto* p=addrs;p;p=p->ifa_next){if(p->ifa_name){std::string n=p->ifa_name;if(std::find(out.begin(),out.end(),n)==out.end())out.push_back(std::move(n));}}freeifaddrs(addrs);}
#endif
 return out;
}
bool capture_live(const std::string& name,bool promiscuous,const PacketHandler& handler,volatile std::sig_atomic_t& stop,std::string& error){
#ifdef __linux__
 const unsigned idx=if_nametoindex(name.c_str());if(idx==0U){error="unknown network interface: "+name;return false;}
 const int fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));if(fd<0){error="could not open raw packet socket (try running with CAP_NET_RAW or sudo)";return false;}
 timeval timeout{0,250000};(void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));sockaddr_ll addr{};addr.sll_family=AF_PACKET;addr.sll_protocol=htons(ETH_P_ALL);addr.sll_ifindex=static_cast<int>(idx);
 if(bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))<0){error="could not bind raw socket to interface";close(fd);return false;}
 packet_mreq mr{};if(promiscuous){mr.mr_ifindex=static_cast<int>(idx);mr.mr_type=PACKET_MR_PROMISC;if(setsockopt(fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&mr,sizeof(mr))<0){error="could not enable promiscuous mode";close(fd);return false;}}
 std::vector<std::uint8_t> buf(262144);while(stop==0){const auto n=recv(fd,buf.data(),buf.size(),0);if(n<0){if(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR)continue;error="raw packet receive failed";close(fd);return false;}CapturedPacket p;auto now=std::chrono::system_clock::now().time_since_epoch();p.timestamp_us=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(now).count());p.wire_length=static_cast<std::uint32_t>(n);p.bytes.assign(buf.begin(),buf.begin()+n);if(!handler(p))break;}
 if(promiscuous) { (void)setsockopt(fd,SOL_PACKET,PACKET_DROP_MEMBERSHIP,&mr,sizeof(mr)); }
 close(fd);
 return true;
#else
 (void)name;(void)promiscuous;(void)handler;(void)stop;error="live capture is currently supported on Linux only";return false;
#endif
}
}
