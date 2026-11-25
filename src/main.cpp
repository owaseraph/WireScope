#include "wirescope/decoder.hpp"
#include "wirescope/dns_parser.hpp"
#include "wirescope/http_parser.hpp"
#include "wirescope/pcap_io.hpp"
#include "wirescope/tcp_reassembler.hpp"
#include "wirescope/tcp_tracker.hpp"
#include "wirescope/tls_parser.hpp"

#include <algorithm>
#include <charconv>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#ifdef WIRESCOPE_HAS_LIBPCAP
#include <pcap/pcap.h>
#endif

namespace {
volatile std::sig_atomic_t stop_requested=0;
void on_signal(int){stop_requested=1;}
struct Options {
    std::string input,interface_name,filter,json_path,csv_path,timeout_label{"300s"};
    std::uint64_t timeout_us{300000000};
    bool promiscuous{},list_interfaces{},help{},quiet{};
};
struct Term {std::string kind,value;};
struct PacketFilter {
    std::vector<Term> terms;
#ifdef WIRESCOPE_HAS_LIBPCAP
    bpf_program compiled{};
    bool has_compiled{};
    ~PacketFilter() { if (has_compiled) pcap_freecode(&compiled); }
    bool compile_bpf(const std::string& expression, std::string& error) {
        pcap_t* dead = pcap_open_dead(DLT_EN10MB, 262144);
        if (dead == nullptr) { error = "pcap_open_dead failed"; return false; }
        const int status = pcap_compile(dead, &compiled, expression.c_str(), 1, PCAP_NETMASK_UNKNOWN);
        if (status != 0) error = pcap_geterr(dead);
        pcap_close(dead);
        has_compiled = status == 0;
        return has_compiled;
    }
    bool matches(const wirescope::PacketSummary& p, const wirescope::CapturedPacket& raw) const {
        if (has_compiled) {
            pcap_pkthdr h{};
            h.caplen = static_cast<bpf_u_int32>(raw.bytes.size());
            h.len = raw.wire_length;
            h.ts.tv_sec = static_cast<decltype(h.ts.tv_sec)>(raw.timestamp_us / 1000000U);
            h.ts.tv_usec = static_cast<decltype(h.ts.tv_usec)>(raw.timestamp_us % 1000000U);
            return pcap_offline_filter(&compiled, &h, raw.bytes.data()) != 0;
        }
#else
    bool matches(const wirescope::PacketSummary& p, const wirescope::CapturedPacket&) const {
#endif
        const auto* v4=p.ipv4?&*p.ipv4:nullptr;const auto* v6=p.ipv6?&*p.ipv6:nullptr;
        const std::string src=v4?v4->source_address:(v6?v6->source_address:"");
        const std::string dst=v4?v4->destination_address:(v6?v6->destination_address:"");
        const std::uint8_t proto=v4?v4->protocol:(v6?v6->upper_layer_protocol:0U);
        const wirescope::TransportInfo* tr=nullptr;if(v4&&v4->transport)tr=&*v4->transport;if(v6&&v6->transport)tr=&*v6->transport;
        std::uint16_t sp=0,dp=0;bool tcp=false,udp=false;
        if(tr){if(const auto* t=std::get_if<wirescope::TcpInfo>(tr)){tcp=true;sp=t->source_port;dp=t->destination_port;}if(const auto* u=std::get_if<wirescope::UdpInfo>(tr)){udp=true;sp=u->source_port;dp=u->destination_port;}}
        for(const auto& t:terms){
            if(t.kind=="tcp"&&!tcp) return false;
            if(t.kind=="udp"&&!udp) return false;
            if(t.kind=="ip"&&!v4) return false;
            if(t.kind=="ip6"&&!v6) return false;
            if(t.kind=="icmp6"&&proto!=58U)return false;
            if(t.kind=="port"||t.kind=="srcport"||t.kind=="dstport") {unsigned n=0;auto [e,ec]=std::from_chars(t.value.data(),t.value.data()+t.value.size(),n);if(ec!=std::errc{}||e!=t.value.data()+t.value.size()||n>65535U)return false;const auto port=static_cast<std::uint16_t>(n);if(t.kind=="port"&&sp!=port&&dp!=port)return false;if(t.kind=="srcport"&&sp!=port)return false;if(t.kind=="dstport"&&dp!=port)return false;}
            if(t.kind=="host"&&src!=t.value&&dst!=t.value)return false;
        }return true;
    }
};
std::vector<std::string> words(std::string_view s){std::istringstream in{std::string(s)};std::vector<std::string> out;std::string x;while(in>>x)out.push_back(x);return out;}
bool parse_filter(const std::string& s,PacketFilter& f,std::string& err){auto w=words(s);for(std::size_t i=0;i<w.size();){if(w[i]=="and"){++i;continue;}if(w[i]=="tcp"||w[i]=="udp"||w[i]=="ip"||w[i]=="ip6"||w[i]=="icmp6"){f.terms.push_back({w[i],{}});++i;if(i<w.size()&&w[i]=="port"){if(i+1>=w.size()){err="expected port number after 'port'";return false;}f.terms.push_back({"port",w[i+1]});i+=2;}continue;}if(w[i]=="port"){if(i+1>=w.size()){err="expected port number";return false;}f.terms.push_back({"port",w[i+1]});i+=2;continue;}if(w[i]=="src"||w[i]=="dst"){if(i+2>=w.size()||w[i+1]!="port"){err="expected 'src port N' or 'dst port N'";return false;}f.terms.push_back({w[i]+"port",w[i+2]});i+=3;continue;}if(w[i]=="host"){if(i+1>=w.size()){err="expected host address";return false;}f.terms.push_back({"host",w[i+1]});i+=2;continue;}err="unsupported filter token: "+w[i]+" (supported: tcp, udp, ip, ip6, icmp6, port N, src/dst port N, host IP)";return false;}return true;}
bool parse_duration(std::string s,std::uint64_t& us){std::uint64_t mult=1000000;std::string_view v=s;if(v.ends_with("ms")){mult=1000;v.remove_suffix(2);}else if(v.ends_with("s")){mult=1000000;v.remove_suffix(1);}else if(v.ends_with("m")){mult=60000000;v.remove_suffix(1);}else if(v.ends_with("h")){mult=3600000000ULL;v.remove_suffix(1);}std::uint64_t n{};auto [p,e]=std::from_chars(v.data(),v.data()+v.size(),n);if(e!=std::errc{}||p!=v.data()+v.size()||n>UINT64_MAX/mult)return false;us=n*mult;return true;}
void usage(const char* exe){std::cout<<"WireScope — C++20 packet analyzer\n\nUsage: "<<exe<<" [options] <capture.pcap>\n\nOptions:\n  -r, --read FILE          Read classic PCAP file\n  -i, --interface NAME    Live capture on Linux interface\n      --list-interfaces   List network interfaces\n      --filter EXPR       Filter: tcp, udp, ip, ip6, icmp6, port N,\n                          src/dst port N, host IP; combine with 'and'\n      --idle-timeout TIME TCP idle timeout (ms, s, m, h; default 300s)\n      --promiscuous       Enable promiscuous mode for live capture\n      --no-promiscuous    Disable promiscuous mode (default)\n      --export-json FILE  Write full analysis report as JSON\n      --export-csv FILE   Write packet summary as CSV\n      --quiet             Suppress per-packet console output\n  -h, --help              Show this help\n\nExamples:\n  "<<exe<<" tcp-test.pcap\n  "<<exe<<" --filter 'tcp and port 8080' tcp-test.pcap\n  "<<exe<<" -i lo --filter 'udp port 53'\n  "<<exe<<" capture.pcap --export-json report.json --export-csv packets.csv\n";}
bool parse_args(int argc,char**argv,Options&o,std::string&err){for(int i=1;i<argc;++i){std::string a=argv[i];auto value=[&](std::string&dst){if(i+1>=argc){err="missing value after "+a;return false;}dst=argv[++i];return true;};if(a=="-h"||a=="--help")o.help=true;else if(a=="--list-interfaces")o.list_interfaces=true;else if(a=="--promiscuous")o.promiscuous=true;else if(a=="--no-promiscuous")o.promiscuous=false;else if(a=="--quiet")o.quiet=true;else if(a=="-r"||a=="--read"){if(!value(o.input))return false;}else if(a=="-i"||a=="--interface"){if(!value(o.interface_name))return false;}else if(a=="--filter"){if(!value(o.filter))return false;}else if(a=="--export-json"){if(!value(o.json_path))return false;}else if(a=="--export-csv"){if(!value(o.csv_path))return false;}else if(a=="--idle-timeout"){if(!value(o.timeout_label))return false;if(!parse_duration(o.timeout_label,o.timeout_us)){err="invalid idle timeout";return false;}}else if(!a.empty()&&a[0]=='-'){err="unknown option: "+a;return false;}else if(o.input.empty())o.input=a;else{err="more than one input capture was specified";return false;}}if(o.input.empty()&&o.interface_name.empty()&&!o.list_interfaces&&!o.help){err="specify a capture file or --interface";return false;}if(!o.input.empty()&&!o.interface_name.empty()){err="choose offline file or live interface, not both";return false;}return true;}

struct PacketRow {std::uint64_t number{},timestamp{};std::size_t caplen{};std::uint32_t wirelen{};std::string src,dst,protocol,error;std::uint16_t sport{},dport{};};
struct DnsRow {wirescope::Endpoint src,dst;wirescope::DnsMessage message;};
struct StreamAnalysis {std::size_t index{};wirescope::Endpoint src,dst;std::vector<wirescope::HttpMessage> http;std::optional<wirescope::TlsClientHello> tls;};
struct Context {wirescope::TcpConnectionTracker tracker;wirescope::TcpStreamReassembler reassembler;std::vector<PacketRow> packets;std::vector<DnsRow> dns;std::uint64_t count{},timeout_us{300000000};PacketFilter filter;bool quiet{};};
struct PayloadView {wirescope::Endpoint src,dst;std::span<const std::uint8_t> data;};
std::optional<PayloadView> transport_payload(const wirescope::PacketSummary&p,std::span<const std::uint8_t> frame,bool want_tcp){
 const std::size_t net=14U+p.vlan_tags.size()*4U;std::string sa,da;std::size_t hlen=0,transport=0;const wirescope::TransportInfo* tr=nullptr;
 if(p.ipv4){const auto&ip=*p.ipv4;if(ip.fragment_offset!=0||ip.more_fragments||!ip.transport)return std::nullopt;tr=&*ip.transport;sa=ip.source_address;da=ip.destination_address;hlen=ip.header_length;if(ip.total_length<hlen)return std::nullopt;transport=ip.total_length-hlen;}
 else if(p.ipv6){const auto&ip=*p.ipv6;if(ip.fragment||!ip.transport||ip.header_length<40U)return std::nullopt;tr=&*ip.transport;sa=ip.source_address;da=ip.destination_address;hlen=ip.header_length;const auto ext=hlen-40U;if(ip.payload_length<ext)return std::nullopt;transport=ip.payload_length-ext;}
 else return std::nullopt;
 std::size_t hdr=0;std::uint16_t sp=0,dp=0;
 if(want_tcp){auto*t=std::get_if<wirescope::TcpInfo>(tr);if(!t||t->header_length>transport)return std::nullopt;hdr=t->header_length;sp=t->source_port;dp=t->destination_port;}
 else{auto*u=std::get_if<wirescope::UdpInfo>(tr);if(!u||u->length<8U||u->length>transport)return std::nullopt;hdr=8;transport=u->length;sp=u->source_port;dp=u->destination_port;}
 if(net>frame.size()||hlen>frame.size()-net) return std::nullopt;
 const auto off=net+hlen;
 if(hdr>frame.size()-off) return std::nullopt;
 const auto po=off+hdr;
 const auto declared=transport-hdr;
 const auto captured=std::min(declared,frame.size()-po);
 return PayloadView{{sa,sp},{da,dp},frame.subspan(po,captured)};
}
std::string protocol_of(const wirescope::PacketSummary&p){if(p.ipv4){switch(p.ipv4->protocol){case 6:return"TCP";case 17:return"UDP";case 1:return"ICMP";default:return"IPv4";}}if(p.ipv6){switch(p.ipv6->upper_layer_protocol){case 6:return"TCP";case 17:return"UDP";case 58:return"ICMPv6";default:return"IPv6";}}return "OTHER";}
void print_packet(const PacketRow&r,const wirescope::PacketSummary&p){std::cout<<'#'<<r.number<<"  ts="<<r.timestamp<<"us  caplen="<<r.caplen<<" wirelen="<<r.wirelen<<'\n';std::cout<<"    Ethernet  "<<p.source_mac<<" -> "<<p.destination_mac<<"  ether=0x"<<std::hex<<p.ether_type<<std::dec<<'\n';if(p.ipv4)std::cout<<"    IPv4      "<<p.ipv4->source_address<<" -> "<<p.ipv4->destination_address<<"  ttl="<<unsigned(p.ipv4->ttl)<<"  protocol="<<unsigned(p.ipv4->protocol)<<'\n';if(p.ipv6)std::cout<<"    IPv6      "<<p.ipv6->source_address<<" -> "<<p.ipv6->destination_address<<"  hop_limit="<<unsigned(p.ipv6->hop_limit)<<"  payload="<<p.ipv6->payload_length<<" B\n";if(p.ipv4&&p.ipv4->transport){if(auto*t=std::get_if<wirescope::TcpInfo>(&*p.ipv4->transport))std::cout<<"    TCP       "<<t->source_port<<" -> "<<t->destination_port<<" flags="<<wirescope::format_tcp_flags(t->flags)<<" seq="<<t->sequence_number<<'\n';else if(auto*u=std::get_if<wirescope::UdpInfo>(&*p.ipv4->transport))std::cout<<"    UDP       "<<u->source_port<<" -> "<<u->destination_port<<" length="<<u->length<<'\n';}else if(p.ipv6&&p.ipv6->transport){if(auto*t=std::get_if<wirescope::TcpInfo>(&*p.ipv6->transport))std::cout<<"    TCP       "<<t->source_port<<" -> "<<t->destination_port<<" flags="<<wirescope::format_tcp_flags(t->flags)<<" seq="<<t->sequence_number<<'\n';else if(auto*u=std::get_if<wirescope::UdpInfo>(&*p.ipv6->transport))std::cout<<"    UDP       "<<u->source_port<<" -> "<<u->destination_port<<" length="<<u->length<<'\n';}if(!p.parse_error.empty())std::cout<<"    Parse     "<<p.parse_error<<'\n';}
bool process(Context&c,const wirescope::CapturedPacket& raw){const auto frame=std::span<const std::uint8_t>(raw.bytes);auto summary=wirescope::decode_ethernet(frame,raw.wire_length);if(!c.filter.matches(summary,raw))return true;++c.count;c.tracker.observe(summary,raw.timestamp_us);PacketRow row;row.number=c.count;row.timestamp=raw.timestamp_us;row.caplen=frame.size();row.wirelen=raw.wire_length;row.protocol=protocol_of(summary);row.error=summary.parse_error;auto setip=[&](const std::string&s,const std::string&d){row.src=s;row.dst=d;};if(summary.ipv4)setip(summary.ipv4->source_address,summary.ipv4->destination_address);if(summary.ipv6)setip(summary.ipv6->source_address,summary.ipv6->destination_address);
 if(auto tcp=transport_payload(summary,frame,true)){const auto* t=summary.ipv4&&summary.ipv4->transport?std::get_if<wirescope::TcpInfo>(&*summary.ipv4->transport):nullptr; if(!t&&summary.ipv6&&summary.ipv6->transport)t=std::get_if<wirescope::TcpInfo>(&*summary.ipv6->transport);if(t){row.sport=t->source_port;row.dport=t->destination_port;c.reassembler.observe(tcp->src,tcp->dst,*t,tcp->data,raw.timestamp_us);}}
 if(auto udp=transport_payload(summary,frame,false)){const auto* u=summary.ipv4&&summary.ipv4->transport?std::get_if<wirescope::UdpInfo>(&*summary.ipv4->transport):nullptr;if(!u&&summary.ipv6&&summary.ipv6->transport)u=std::get_if<wirescope::UdpInfo>(&*summary.ipv6->transport);if(u){row.sport=u->source_port;row.dport=u->destination_port;if((u->source_port==53||u->destination_port==53||u->source_port==5353||u->destination_port==5353)&&!udp->data.empty()){auto result=wirescope::parse_dns(udp->data);if(result)c.dns.push_back({udp->src,udp->dst,*result.message});}}}
 c.packets.push_back(row);if(!c.quiet)print_packet(row,summary);return true;}
std::string json_escape(std::string_view s){std::string r="\"";for(char ch:s){const auto c=static_cast<unsigned char>(ch);switch(c){case '"':r+="\\\"";break;case '\\':r+="\\\\";break;case '\n':r+="\\n";break;case '\r':r+="\\r";break;case '\t':r+="\\t";break;default:if(c<0x20)r+=' ';else r+=static_cast<char>(c);}}r+='"';return r;}
std::string csv_escape(std::string_view s){std::string r="\"";for(char c:s){if(c=='"')r+="\"\"";else r+=c;}r+='"';return r;}
void print_records(const std::string& section,const std::vector<wirescope::DnsRecord>&rs){if(rs.empty())return;std::cout<<"  "<<section<<":\n";for(const auto&r:rs)std::cout<<"    "<<r.name<<"  "<<wirescope::dns_type_name(r.type)<<"  ttl="<<r.ttl<<"  "<<r.value<<'\n';}
std::vector<StreamAnalysis> analyze_streams(const Context& c){std::vector<StreamAnalysis> out;const auto& ss=c.reassembler.streams();for(std::size_t i=0;i<ss.size();++i){const auto&s=ss[i];StreamAnalysis a;a.index=i+1;a.src=s.source;a.dst=s.destination;a.http=wirescope::parse_http_stream(s.payload);a.tls=wirescope::parse_tls_client_hello(s.payload);if(!a.http.empty()||a.tls)out.push_back(std::move(a));}return out;}
void print_report(const Context& c,const std::vector<StreamAnalysis>& analysis){
 std::cout<<"\n========================================\nTCP CONNECTIONS ("<<c.tracker.size()<<")\n========================================\n";
 for(const auto&x:c.tracker.connections())std::cout<<'#'<<x.id<<"  "<<wirescope::endpoint_string(x.a)<<" <-> "<<wirescope::endpoint_string(x.b)<<"  "<<wirescope::tcp_state_name(x.state_a)<<'/'<<wirescope::tcp_state_name(x.state_b)<<"  packets="<<x.packets<<" bytes="<<x.bytes<<(x.expired?"  [expired]":"")<<'\n';
 std::cout<<"\n========================================\nREASSEMBLED TCP STREAMS ("<<c.reassembler.streams().size()<<")\n========================================\n";
 for(std::size_t i=0;i<c.reassembler.streams().size();++i){const auto&s=c.reassembler.streams()[i];std::cout<<"#"<<i+1<<" "<<wirescope::endpoint_string(s.source)<<" -> "<<wirescope::endpoint_string(s.destination)<<" payload="<<s.payload.size()<<"B segments="<<s.segments<<" out-of-order="<<s.out_of_order_segments<<" retransmitted-bytes="<<s.retransmitted_bytes<<" pending="<<s.pending_bytes<<" dropped="<<s.dropped_bytes<<'\n';}
 for(const auto&a:analysis){if(!a.http.empty()){std::cout<<"\n[HTTP] stream #"<<a.index<<" "<<wirescope::endpoint_string(a.src)<<" -> "<<wirescope::endpoint_string(a.dst)<<'\n';for(const auto&m:a.http){std::cout<<"  "<<(m.request?m.method+" "+m.target:"HTTP "+std::to_string(m.status)+" "+m.reason)<<"  "<<m.version<<"  body="<<m.body_bytes<<"B"<<(m.chunked?" chunked":"")<<(m.complete?" complete":" incomplete")<<(m.malformed?" malformed":"")<<'\n';for(const auto&h:m.headers)std::cout<<"    "<<h.first<<": "<<h.second<<'\n';}}
 if(a.tls){std::cout<<"\n[TLS] ClientHello stream #"<<a.index<<" "<<wirescope::endpoint_string(a.src)<<" -> "<<wirescope::endpoint_string(a.dst)<<'\n';std::cout<<"  Legacy version: "<<a.tls->legacy_version<<"\n  SNI: "<<(a.tls->server_name.empty()?"(not provided)":a.tls->server_name)<<'\n';if(!a.tls->supported_versions.empty()){std::cout<<"  Supported versions:";for(auto&v:a.tls->supported_versions)std::cout<<' '<<v;std::cout<<'\n';}if(!a.tls->alpn_protocols.empty()){std::cout<<"  ALPN:";for(auto&v:a.tls->alpn_protocols)std::cout<<' '<<v;std::cout<<'\n';}std::cout<<"  Cipher suites:";for(auto v:a.tls->cipher_suites)std::cout<<' '<<wirescope::tls_cipher_name(v);std::cout<<'\n';}}
 std::cout<<"\n========================================\nDNS / mDNS MESSAGES ("<<c.dns.size()<<")\n========================================\n";
 for(const auto&d:c.dns){const auto&m=d.message;std::cout<<"ID="<<m.id<<' '<<(m.response?"response":"query")<<' '<<wirescope::endpoint_string(d.src)<<" -> "<<wirescope::endpoint_string(d.dst);if(m.response)std::cout<<" rcode="<<wirescope::dns_rcode_name(m.rcode);std::cout<<'\n';for(const auto&q:m.questions)std::cout<<"  Q "<<q.name<<' '<<wirescope::dns_type_name(q.type)<<'\n';print_records("Answers",m.answers);print_records("Authority",m.authorities);print_records("Additional",m.additional);}
 std::cout<<"\nPackets processed: "<<c.count<<'\n';
}
void export_json(const std::string& path, const Context& c,
                 const std::vector<StreamAnalysis>& analysis) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("cannot write JSON report: " + path);
    const auto write_records = [&](const std::vector<wirescope::DnsRecord>& records) {
        f << '[';
        for (std::size_t i = 0; i < records.size(); ++i) {
            const auto& r = records[i];
            if (i) f << ',';
            f << "{\"name\":" << json_escape(r.name)
              << ",\"type\":" << r.type
              << ",\"type_name\":" << json_escape(wirescope::dns_type_name(r.type))
              << ",\"ttl\":" << r.ttl
              << ",\"value\":" << json_escape(r.value) << '}';
        }
        f << ']';
    };

    f << "{\n  \"packets\": [\n";
    for (std::size_t i = 0; i < c.packets.size(); ++i) {
        const auto& p = c.packets[i];
        f << "    {\"number\":" << p.number
          << ",\"timestamp_us\":" << p.timestamp
          << ",\"captured_length\":" << p.caplen
          << ",\"wire_length\":" << p.wirelen
          << ",\"source\":" << json_escape(p.src)
          << ",\"destination\":" << json_escape(p.dst)
          << ",\"protocol\":" << json_escape(p.protocol)
          << ",\"source_port\":" << p.sport
          << ",\"destination_port\":" << p.dport
          << ",\"parse_error\":" << json_escape(p.error) << "}"
          << (i + 1 < c.packets.size() ? "," : "") << '\n';
    }

    f << "  ],\n  \"tcp_connections\": [\n";
    for (std::size_t i = 0; i < c.tracker.connections().size(); ++i) {
        const auto& x = c.tracker.connections()[i];
        f << "    {\"id\":" << x.id
          << ",\"endpoint_a\":" << json_escape(wirescope::endpoint_string(x.a))
          << ",\"endpoint_b\":" << json_escape(wirescope::endpoint_string(x.b))
          << ",\"packets\":" << x.packets
          << ",\"bytes\":" << x.bytes
          << ",\"state_a\":" << json_escape(wirescope::tcp_state_name(x.state_a))
          << ",\"state_b\":" << json_escape(wirescope::tcp_state_name(x.state_b))
          << ",\"expired\":" << (x.expired ? "true" : "false") << "}"
          << (i + 1 < c.tracker.connections().size() ? "," : "") << '\n';
    }

    f << "  ],\n  \"tcp_streams\": [\n";
    const auto& streams = c.reassembler.streams();
    for (std::size_t i = 0; i < streams.size(); ++i) {
        const auto& s = streams[i];
        f << "    {\"source\":" << json_escape(wirescope::endpoint_string(s.source))
          << ",\"destination\":" << json_escape(wirescope::endpoint_string(s.destination))
          << ",\"payload_bytes\":" << s.payload.size()
          << ",\"first_seen_us\":" << s.first_seen_us
          << ",\"last_seen_us\":" << s.last_seen_us
          << ",\"segments\":" << s.segments
          << ",\"out_of_order_segments\":" << s.out_of_order_segments
          << ",\"retransmitted_bytes\":" << s.retransmitted_bytes
          << ",\"dropped_bytes\":" << s.dropped_bytes << "}"
          << (i + 1 < streams.size() ? "," : "") << '\n';
    }

    f << "  ],\n  \"dns_messages\": [\n";
    for (std::size_t i = 0; i < c.dns.size(); ++i) {
        const auto& d = c.dns[i];
        f << "    {\"id\":" << d.message.id
          << ",\"response\":" << (d.message.response ? "true" : "false")
          << ",\"source\":" << json_escape(wirescope::endpoint_string(d.src))
          << ",\"destination\":" << json_escape(wirescope::endpoint_string(d.dst))
          << ",\"rcode\":" << json_escape(wirescope::dns_rcode_name(d.message.rcode))
          << ",\"questions\":[";
        for (std::size_t q = 0; q < d.message.questions.size(); ++q) {
            if (q) f << ',';
            const auto& question = d.message.questions[q];
            f << "{\"name\":" << json_escape(question.name)
              << ",\"type\":" << question.type
              << ",\"type_name\":" << json_escape(wirescope::dns_type_name(question.type)) << '}';
        }
        f << "],\"answers\":"; write_records(d.message.answers);
        f << ",\"authorities\":"; write_records(d.message.authorities);
        f << ",\"additional\":"; write_records(d.message.additional);
        f << "}" << (i + 1 < c.dns.size() ? "," : "") << '\n';
    }

    f << "  ],\n  \"application_analysis\": [\n";
    for (std::size_t i = 0; i < analysis.size(); ++i) {
        const auto& a = analysis[i];
        f << "    {\"stream\":" << a.index
          << ",\"source\":" << json_escape(wirescope::endpoint_string(a.src))
          << ",\"destination\":" << json_escape(wirescope::endpoint_string(a.dst))
          << ",\"http_messages\":[";
        for (std::size_t j = 0; j < a.http.size(); ++j) {
            const auto& h = a.http[j];
            if (j) f << ',';
            f << "{\"kind\":" << json_escape(h.request ? "request" : "response")
              << ",\"method\":" << json_escape(h.method)
              << ",\"target\":" << json_escape(h.target)
              << ",\"version\":" << json_escape(h.version)
              << ",\"status\":" << h.status
              << ",\"reason\":" << json_escape(h.reason)
              << ",\"body_bytes\":" << h.body_bytes
              << ",\"chunked\":" << (h.chunked ? "true" : "false")
              << ",\"complete\":" << (h.complete ? "true" : "false")
              << ",\"malformed\":" << (h.malformed ? "true" : "false") << '}';
        }
        f << "],\"tls_client_hello\":";
        if (!a.tls) {
            f << "null";
        } else {
            f << "{\"legacy_version\":" << json_escape(a.tls->legacy_version)
              << ",\"server_name\":" << json_escape(a.tls->server_name)
              << ",\"supported_versions\":[";
            for (std::size_t j = 0; j < a.tls->supported_versions.size(); ++j) {
                if (j) f << ',';
                f << json_escape(a.tls->supported_versions[j]);
            }
            f << "],\"alpn\":[";
            for (std::size_t j = 0; j < a.tls->alpn_protocols.size(); ++j) {
                if (j) f << ',';
                f << json_escape(a.tls->alpn_protocols[j]);
            }
            f << "],\"cipher_suites\":[";
            for (std::size_t j = 0; j < a.tls->cipher_suites.size(); ++j) {
                if (j) f << ',';
                f << a.tls->cipher_suites[j];
            }
            f << "]}";
        }
        f << '}' << (i + 1 < analysis.size() ? "," : "") << '\n';
    }
    f << "  ]\n}\n";
}
void export_csv(const std::string&path,const Context&c){std::ofstream f(path);if(!f)throw std::runtime_error("cannot write CSV report: "+path);f<<"number,timestamp_us,captured_length,wire_length,source,destination,protocol,source_port,destination_port,parse_error\n";for(const auto&p:c.packets)f<<p.number<<','<<p.timestamp<<','<<p.caplen<<','<<p.wirelen<<','<<csv_escape(p.src)<<','<<csv_escape(p.dst)<<','<<csv_escape(p.protocol)<<','<<p.sport<<','<<p.dport<<','<<csv_escape(p.error)<<'\n';}
}
int main(int argc,char**argv){Options o;std::string err;if(!parse_args(argc,argv,o,err)){std::cerr<<"Error: "<<err<<"\n\n";usage(argv[0]);return 2;}if(o.help){usage(argv[0]);return 0;}if(o.list_interfaces){for(const auto&i:wirescope::list_interfaces())std::cout<<i<<'\n';return 0;}Context c;c.timeout_us=o.timeout_us;c.quiet=o.quiet;if(!o.filter.empty()) {
#ifdef WIRESCOPE_HAS_LIBPCAP
 if(!c.filter.compile_bpf(o.filter,err)){std::cerr<<"Filter error: "<<err<<'\n';return 2;}
#else
 if(!parse_filter(o.filter,c.filter,err)){std::cerr<<"Filter error: "<<err<<'\n';return 2;}
#endif
 std::cout<<"Filter: "<<o.filter<<"\n";
}
 bool ok=false;if(!o.input.empty()){std::cout<<"Offline capture: "<<o.input<<"\n";ok=wirescope::read_pcap_file(o.input,[&](const auto&p){return process(c,p);},err);}else{std::cout<<"Live capture: interface="<<o.interface_name<<" promiscuous="<<(o.promiscuous?"yes":"no")<<"\nPress Ctrl+C to stop.\n";auto previous=std::signal(SIGINT,on_signal);ok=wirescope::capture_live(o.interface_name,o.promiscuous,[&](const auto&p){return process(c,p);},[] { return stop_requested != 0; },err);std::signal(SIGINT,previous);}
 if(!ok){std::cerr<<"Capture error: "<<err<<'\n';return 1;}if(!c.packets.empty())(void)c.tracker.expire_idle(c.packets.back().timestamp,c.timeout_us);auto analysis=analyze_streams(c);print_report(c,analysis);try{if(!o.json_path.empty()){export_json(o.json_path,c,analysis);std::cout<<"JSON report: "<<o.json_path<<'\n';}if(!o.csv_path.empty()){export_csv(o.csv_path,c);std::cout<<"CSV report: "<<o.csv_path<<'\n';}}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}return 0;}
