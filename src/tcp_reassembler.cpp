#include "wirescope/tcp_reassembler.hpp"
#include <limits>
#include <algorithm>
namespace wirescope {
namespace { constexpr std::size_t max_pending=1024U*1024U,max_payload=16U*1024U*1024U;
void sat(std::uint64_t& x){if(x<UINT64_MAX)++x;}
bool ahead(std::uint32_t a,std::uint32_t b){auto d=static_cast<std::uint32_t>(a-b);return d!=0U&&d<0x80000000U;}
}
void TcpStreamReassembler::observe(const Endpoint& src, const Endpoint& dst, const TcpInfo& tcp,
                                   std::span<const std::uint8_t> data, std::uint64_t timestamp_us){
    const auto key=std::pair{src,dst}; auto it=indices_.find(key);
    const bool syn=(tcp.flags&0x02U)!=0; const std::uint32_t begin=tcp.sequence_number+(syn?1U:0U);
    if(it!=indices_.end()&&syn){
        const auto& previous=states_[it->second];
        if(previous.initial_syn&&*previous.initial_syn!=tcp.sequence_number){
            TcpStream s;s.source=src;s.destination=dst;streams_.push_back(std::move(s));states_.push_back({});it->second=streams_.size()-1U;
        }
    }
    if(it==indices_.end()){
        if(data.empty()&&!syn)return;
        TcpStream s;s.source=src;s.destination=dst;streams_.push_back(std::move(s));states_.push_back({});it=indices_.emplace(key,streams_.size()-1U).first;
    }
    auto idx=it->second;auto& s=streams_[idx];auto& st=states_[idx];sat(s.segments);
    if (!s.has_timestamps) {
        s.first_seen_us = timestamp_us;
        s.last_seen_us = timestamp_us;
        s.has_timestamps = true;
    } else {
        s.first_seen_us = std::min(s.first_seen_us, timestamp_us);
        s.last_seen_us = std::max(s.last_seen_us, timestamp_us);
    }
    if(syn&&!st.initial_syn)st.initial_syn=tcp.sequence_number;
    if(!st.next){if(data.empty()&&!syn)return;st.next=begin;}
    if(data.empty())return;
    if(ahead(begin,*st.next))sat(s.out_of_order_segments);
    for(std::size_t i=0;i<data.size();++i){auto seq=begin+static_cast<std::uint32_t>(i);auto d=static_cast<std::uint32_t>(seq-*st.next);
        if(d==0U){
            const auto buffered=st.pending.find(seq);
            if(buffered!=st.pending.end()){
                if(s.payload.size()<max_payload)s.payload.push_back(buffered->second);else sat(s.dropped_bytes);
                st.pending.erase(buffered);
                sat(s.retransmitted_bytes);
            }else if(s.payload.size()<max_payload)s.payload.push_back(data[i]);
            else sat(s.dropped_bytes);
            ++*st.next;
            while(true){
                auto p=st.pending.find(*st.next);
                if(p==st.pending.end())break;
                if(s.payload.size()<max_payload)s.payload.push_back(p->second);else sat(s.dropped_bytes);
                st.pending.erase(p);
                ++*st.next;
            }
        }else if(d<0x80000000U){if(st.pending.contains(seq)){sat(s.retransmitted_bytes);continue;}if(st.pending.size()>=max_pending){sat(s.dropped_bytes);continue;}st.pending.emplace(seq,data[i]);}
        else sat(s.retransmitted_bytes);
    }
    s.pending_bytes=st.pending.size();
}
}
