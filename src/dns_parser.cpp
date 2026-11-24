#include "wirescope/dns_parser.hpp"
#include <arpa/inet.h>
#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
namespace wirescope { namespace {
bool u16(std::span<const std::uint8_t>b,std::size_t p,std::uint16_t&v){if(p>b.size()||b.size()-p<2)return false;v=static_cast<std::uint16_t>((b[p]<<8U)|b[p+1]);return true;}
bool u32(std::span<const std::uint8_t>b,std::size_t p,std::uint32_t&v){if(p>b.size()||b.size()-p<4)return false;v=(std::uint32_t(b[p])<<24U)|(std::uint32_t(b[p+1])<<16U)|(std::uint32_t(b[p+2])<<8U)|b[p+3];return true;}
bool name(std::span<const std::uint8_t>b,std::size_t& off,std::string& out,std::string& err){if(off>=b.size()){err="name outside packet";return false;}std::size_t p=off,consumed=0,jumps=0;bool jump=false;std::vector<bool> seen(b.size());out.clear();while(true){if(p>=b.size()||seen[p]){err="bad or cyclic DNS name";return false;}seen[p]=true;auto n=b[p];if(n==0){if(!jump)consumed=p+1-off;off+=consumed;if(out.empty())out=".";return true;}if((n&0xc0U)==0xc0U){if(p+1>=b.size()||++jumps>64){err="bad DNS compression pointer";return false;}auto dest=(std::size_t(n&0x3fU)<<8U)|b[p+1];if(dest>=b.size()){err="DNS pointer out of range";return false;}if(!jump){consumed=p+2-off;jump=true;}p=dest;continue;}if(n&0xc0U||n>63||std::size_t(n)>b.size()-p-1){err="invalid DNS label";return false;}if(!out.empty())out+='.';for(std::size_t i=0;i<n;++i){unsigned char c=b[p+1+i];out+=c>=0x21&&c<=0x7e?char(c):'?';}p+=std::size_t(n)+1;if(out.size()>255){err="DNS name too long";return false;}}}
bool record(std::span<const std::uint8_t>b,std::size_t& p,DnsRecord&r,std::string&e){if(!name(b,p,r.name,e))return false;std::uint16_t len;if(!u16(b,p,r.type)||!u16(b,p+2,r.class_code)||!u32(b,p+4,r.ttl)||!u16(b,p+8,len)){e="truncated RR";return false;}p+=10;auto end=p+len;if(end>b.size()){e="truncated RDATA";return false;}std::array<char,INET6_ADDRSTRLEN> text{};
 if(r.type==1){if(len!=4){e="bad A length";return false;}r.value=std::to_string(b[p])+"."+std::to_string(b[p+1])+"."+std::to_string(b[p+2])+"."+std::to_string(b[p+3]);}
 else if(r.type==28){if(len!=16){e="bad AAAA length";return false;}if(!inet_ntop(AF_INET6,b.data()+p,text.data(),text.size())){e="bad AAAA";return false;}r.value=text.data();}
 else if(r.type==2||r.type==5||r.type==12){auto q=p;if(!name(b,q,r.value,e)||q>end){if(e.empty())e="bad name RDATA";return false;}}
 else if(r.type==15){std::uint16_t pref;if(len<3||!u16(b,p,pref)){e="bad MX";return false;}auto q=p+2;std::string ex;if(!name(b,q,ex,e)||q>end){e="bad MX exchange";return false;}r.value=std::to_string(pref)+" "+ex;}
 else if(r.type==16){std::size_t q=p;while(q<end){auto n=b[q++];if(n>end-q){e="bad TXT";return false;}if(!r.value.empty())r.value+=" | ";r.value.append(reinterpret_cast<const char*>(b.data()+q),n);q+=n;}}
 else r.value="RDATA("+std::to_string(len)+" bytes)";
 p=end;return true;}
}
DnsResult parse_dns(std::span<const std::uint8_t>b){DnsResult r;if(b.size()<12){r.error="DNS header truncated";return r;}DnsMessage m;std::uint16_t f,qd,an,ns,ar;u16(b,0,m.id);u16(b,2,f);u16(b,4,qd);u16(b,6,an);u16(b,8,ns);u16(b,10,ar);m.response=f&0x8000;m.opcode=std::uint8_t((f>>11)&15);m.authoritative=f&0x400;m.truncated=f&0x200;m.recursion_desired=f&0x100;m.recursion_available=f&0x80;m.rcode=std::uint8_t(f&15);
 if(qd>128||std::size_t(an)+ns+ar>512){r.error="DNS section count limit exceeded";return r;}std::size_t p=12;
 for(unsigned i=0;i<qd;++i){DnsQuestion q;if(!name(b,p,q.name,r.error)||!u16(b,p,q.type)||!u16(b,p+2,q.class_code)){if(r.error.empty())r.error="question truncated";return r;}p+=4;m.questions.push_back(std::move(q));}
 auto section=[&](unsigned count,std::vector<DnsRecord>& v){for(unsigned i=0;i<count;++i){DnsRecord x;if(!record(b,p,x,r.error))return false;v.push_back(std::move(x));}return true;};
 if(!section(an,m.answers)||!section(ns,m.authorities)||!section(ar,m.additional)) return r;
 r.message=std::move(m);
 return r; }
std::string dns_type_name(std::uint16_t t){switch(t){case 1:return"A";case 2:return"NS";case 5:return"CNAME";case 6:return"SOA";case 12:return"PTR";case 15:return"MX";case 16:return"TXT";case 28:return"AAAA";case 33:return"SRV";case 41:return"OPT";default:return"TYPE"+std::to_string(t);}}
std::string dns_rcode_name(std::uint8_t c){switch(c){case 0:return"NOERROR";case 1:return"FORMERR";case 2:return"SERVFAIL";case 3:return"NXDOMAIN";case 4:return"NOTIMP";case 5:return"REFUSED";default:return"RCODE"+std::to_string(c);}}
}
