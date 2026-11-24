#include "wirescope/http_parser.hpp"
#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <string_view>
namespace wirescope { namespace {
constexpr std::size_t max_header=65536,max_headers=128,max_messages=256;
bool line(std::string_view s,std::size_t& p,std::string_view& out){auto e=s.find("\r\n",p);if(e==s.npos)return false;out=s.substr(p,e-p);p=e+2;return true;}
std::string lower(std::string_view s){std::string r(s);for(char& c:r)c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));return r;}
std::string trim(std::string_view s){while(!s.empty()&&(s.front()==' '||s.front()=='\t'))s.remove_prefix(1);while(!s.empty()&&(s.back()==' '||s.back()=='\t'))s.remove_suffix(1);return std::string(s);}
std::size_t find_header_end(std::string_view s,std::size_t p){auto e=s.find("\r\n\r\n",p);return e;}
}
std::vector<HttpMessage> parse_http_stream(std::span<const std::uint8_t> bytes){
 std::vector<HttpMessage> out; if(bytes.empty()) return out;std::string_view s(reinterpret_cast<const char*>(bytes.data()),bytes.size());std::size_t pos=0;
 while(pos<s.size()&&out.size()<max_messages){
   HttpMessage m;const auto start=pos;auto hend=find_header_end(s,pos);if(hend==s.npos||hend-start>max_header)break;
   std::size_t p=pos;std::string_view first;if(!line(s,p,first)){break;}
   if(first.starts_with("HTTP/")){m.request=false;auto a=first.find(' ');if(a==s.npos){m.malformed=true;out.push_back(m);break;}m.version=std::string(first.substr(0,a));auto b=first.find(' ',a+1);auto code=first.substr(a+1,b==s.npos?first.size()-a-1:b-a-1);unsigned status=0;auto [ep,ec]=std::from_chars(code.data(),code.data()+code.size(),status);if(ec!=std::errc{}||ep!=code.data()+code.size()){m.malformed=true;out.push_back(m);break;}m.status=status;if(b!=s.npos)m.reason=std::string(first.substr(b+1));
   }else{m.request=true;auto a=first.find(' '),b=a==s.npos?a:first.find(' ',a+1);if(a==s.npos||b==s.npos||!first.substr(b+1).starts_with("HTTP/")){m.malformed=true;out.push_back(m);break;}m.method=std::string(first.substr(0,a));m.target=std::string(first.substr(a+1,b-a-1));m.version=std::string(first.substr(b+1));}
   std::size_t count=0;while(p<hend){std::string_view h;if(!line(s,p,h)||h.empty())break;if(++count>max_headers){m.malformed=true;break;}auto colon=h.find(':');if(colon==s.npos||colon==0){m.malformed=true;break;}m.headers.emplace_back(lower(trim(h.substr(0,colon))),trim(h.substr(colon+1)));}
   if(m.malformed){out.push_back(m);break;}
   bool has_length=false;std::size_t content_length=0;bool chunked=false;
   for(const auto& [k,v]:m.headers){if(k=="content-length"){std::size_t n{};auto [ep,ec]=std::from_chars(v.data(),v.data()+v.size(),n);if(ec!=std::errc{}||ep!=v.data()+v.size()||(has_length&&n!=content_length)){m.malformed=true;break;}has_length=true;content_length=n;}if(k=="transfer-encoding"&&lower(v).find("chunked")!=std::string::npos)chunked=true;}
   m.chunked=chunked;pos=hend+4;
   if(m.malformed){out.push_back(m);break;}
   if(!m.request&&(m.status<200U||m.status==204U||m.status==304U)){m.complete=true;out.push_back(std::move(m));continue;}
   if(chunked){std::size_t q=pos,total=0;bool done=false;while(q<s.size()) {auto e=s.find("\r\n",q);if(e==s.npos)break;auto token=s.substr(q,e-q);auto semi=token.find(';');if(semi!=s.npos)token=token.substr(0,semi);std::size_t n{};auto [ep,ec]=std::from_chars(token.data(),token.data()+token.size(),n,16);if(ec!=std::errc{}||ep!=token.data()+token.size()){m.malformed=true;break;}q=e+2;if(n==0){auto trailer=s.find("\r\n\r\n",q);if(q+2<=s.size()&&s.substr(q,2)=="\r\n"){q+=2;done=true;}else if(trailer!=s.npos){q=trailer+4;done=true;}break;}if(n>s.size()-q||s.size()-q-n<2U)break;total+=n;q+=n;if(s.substr(q,2)!="\r\n"){m.malformed=true;break;}q+=2;}m.body_bytes=total;m.complete=done;if(done)pos=q;else{out.push_back(std::move(m));break;}}
   else if(has_length){m.body_bytes=std::min(content_length,s.size()-pos);m.complete=m.body_bytes==content_length;if(m.complete)pos+=content_length;else{out.push_back(std::move(m));break;}}
   else if(m.request){m.complete=true;}
   else{m.close_delimited=true;m.body_bytes=s.size()-pos;m.complete=false;out.push_back(std::move(m));break;}
   out.push_back(std::move(m));if(pos==start)break;
 }
 return out;
}
}
