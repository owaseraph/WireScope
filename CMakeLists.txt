cmake_minimum_required(VERSION 3.20)
project(WireScope VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)

add_library(wirescope_decoder
    src/decoder.cpp
)
target_include_directories(wirescope_decoder
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_options(wirescope_decoder PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    add_executable(wirescope src/main.cpp)
    target_include_directories(wirescope PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(wirescope PRIVATE wirescope_decoder ${PCAP_LIBRARY})
    target_compile_options(wirescope PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
    )
else()
    message(STATUS "libpcap not found: building decoder and tests only; install libpcap-dev for the capture-file CLI")
endif()

enable_testing()
add_executable(decoder_tests tests/decoder_tests.cpp)
target_link_libraries(decoder_tests PRIVATE wirescope_decoder)
target_compile_options(decoder_tests PRIVATE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
)
add_test(NAME decoder_tests COMMAND decoder_tests)
