#include "wirescope/dns_parser.hpp"
#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>
using namespace wirescope;
int main(){std::vector<std::uint8_t>q{0x12,0x34,0x01,0x00,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};auto r=parse_dns(q);assert(r&&r.message->questions.size()==1&&r.message->questions[0].name=="example.com");std::vector<std::uint8_t>a{0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1,0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,93,184,216,34};r=parse_dns(a);assert(r&&r.message->answers.size()==1&&r.message->answers[0].value=="93.184.216.34");std::vector<std::uint8_t>bad{0,1,1,0,0,1,0,0,0,0,0,0,0xc0,0x0c,0,1,0,1};assert(!parse_dns(bad));std::cout<<"DNS tests passed\n";}
