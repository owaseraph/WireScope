#include "wirescope/http_parser.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>
using namespace wirescope;
int main(){std::string s="POST /submit HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\ndata";std::vector<std::uint8_t>b(s.begin(),s.end());auto v=parse_http_stream(b);assert(v.size()==1&&v[0].request&&v[0].complete&&v[0].body_bytes==4);std::string c="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";b.assign(c.begin(),c.end());v=parse_http_stream(b);assert(v.size()==1&&v[0].complete&&v[0].chunked&&v[0].body_bytes==4);std::cout<<"HTTP tests passed\n";}
