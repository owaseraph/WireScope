#include "wirescope/tcp_tracker.hpp"
#include <algorithm>
#include <limits>
#include <variant>

namespace wirescope {
const char* tcp_state_name(TcpState s) noexcept {
    switch(s) {
        case TcpState::SynSent:return "SYN_SENT"; case TcpState::SynReceived:return "SYN_RECEIVED";
        case TcpState::Established:return "ESTABLISHED"; case TcpState::FinWait:return "FIN_WAIT";
        case TcpState::CloseWait:return "CLOSE_WAIT"; case TcpState::TimeWait:return "TIME_WAIT";
        case TcpState::Closed:return "CLOSED"; case TcpState::Reset:return "RESET";
        case TcpState::Midstream:return "MIDSTREAM"; default:return "UNKNOWN";
    }
}
namespace {
void sat_add(std::uint64_t& x, std::uint64_t n) { x = n > UINT64_MAX-x ? UINT64_MAX : x+n; }
}
void TcpConnectionTracker::observe(const PacketSummary& p, std::uint64_t ts) {
    const Ipv4Info* v4=p.ipv4 ? &*p.ipv4 : nullptr;
    const Ipv6Info* v6=p.ipv6 ? &*p.ipv6 : nullptr;
    const std::optional<TransportInfo>* tr=v4 ? &v4->transport : (v6 ? &v6->transport : nullptr);
    if (!tr || !tr->has_value()) return;
    const auto* t=std::get_if<TcpInfo>(&**tr); if(!t) return;
    Endpoint src{v4?v4->source_address:v6->source_address,t->source_port};
    Endpoint dst{v4?v4->destination_address:v6->destination_address,t->destination_port};
    Key key{src,dst}; if(dst<key.a) std::swap(key.a,key.b);
    auto it=active_.find(key);
    constexpr std::uint8_t SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04;
    const bool syn=(t->flags&SYN)!=0, ack=(t->flags&ACK)!=0;
    if(it!=active_.end() && syn && !ack) {
        auto& old=connections_[it->second];
        if(old.has_initiator && old.initiator==src && old.has_syn_sequence &&
           old.initial_syn_sequence!=t->sequence_number) {
            old.expired=true; active_.erase(it); it=active_.end();
        }
    }
    if(it==active_.end()) {
        TcpConnection c; c.id=next_id_++; c.a=key.a;c.b=key.b;c.first_seen_us=ts;c.last_seen_us=ts;
        if(syn&&!ack){c.initiator=src;c.has_initiator=true;c.state_a=(src==key.a?TcpState::SynSent:TcpState::Unknown);c.state_b=(src==key.b?TcpState::SynSent:TcpState::Unknown);}
        else {c.state_a=TcpState::Midstream;c.state_b=TcpState::Midstream;}
        connections_.push_back(c); const auto idx=connections_.size()-1; it=active_.emplace(key,idx).first;
    }
    auto& c=connections_[it->second]; c.last_seen_us=std::max(c.last_seen_us,ts); sat_add(c.packets,1); sat_add(c.bytes,p.captured_length);
    const bool ab=src==c.a; sat_add(ab?c.packets_a_to_b:c.packets_b_to_a,1);sat_add(ab?c.bytes_a_to_b:c.bytes_b_to_a,p.captured_length);
    if(syn&&!ack){sat_add(c.syn,1);c.initiator=src;c.has_initiator=true;c.initial_syn_sequence=t->sequence_number;c.has_syn_sequence=true;(ab?c.state_a:c.state_b)=TcpState::SynSent;(ab?c.state_b:c.state_a)=TcpState::SynReceived;}
    if(syn&&ack){sat_add(c.syn_ack,1);(ab?c.state_a:c.state_b)=TcpState::SynReceived;(ab?c.state_b:c.state_a)=TcpState::SynSent;}
    if(ack){sat_add(c.ack,1); if(c.state_a==TcpState::SynReceived||c.state_a==TcpState::SynSent)c.state_a=TcpState::Established; if(c.state_b==TcpState::SynReceived||c.state_b==TcpState::SynSent)c.state_b=TcpState::Established;}
    if(t->flags&FIN){sat_add(c.fin,1);(ab?c.state_a:c.state_b)=TcpState::FinWait;(ab?c.state_b:c.state_a)=TcpState::CloseWait;}
    if(t->flags&RST){sat_add(c.rst,1);c.state_a=TcpState::Reset;c.state_b=TcpState::Reset;}
    if(c.state_a==TcpState::FinWait&&c.state_b==TcpState::FinWait){c.state_a=TcpState::TimeWait;c.state_b=TcpState::Closed;}
}
std::size_t TcpConnectionTracker::expire_idle(std::uint64_t now,std::uint64_t timeout){
    std::size_t n=0; for(auto it=active_.begin();it!=active_.end();) {
        auto& c=connections_[it->second]; if(now>=c.last_seen_us && now-c.last_seen_us>=timeout){c.expired=true;it=active_.erase(it);++n;}else ++it;
    } return n;
}
}
