cmake_minimum_required(VERSION 3.20)

project(WireScope
    VERSION 0.1.0
    DESCRIPTION "A C++20 packet analyzer"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

function(wirescope_enable_warnings target)
    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
    )
endfunction()

# Core packet decoder

add_library(wirescope_decoder
    src/decoder.cpp
)

add_library(WireScope::Decoder ALIAS wirescope_decoder)

target_include_directories(wirescope_decoder
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

wirescope_enable_warnings(wirescope_decoder)

# TCP connection tracker

add_library(wirescope_tcp_tracker
    src/tcp_tracker.cpp
)

add_library(WireScope::TcpTracker ALIAS wirescope_tcp_tracker)

target_link_libraries(wirescope_tcp_tracker
    PUBLIC WireScope::Decoder
)

wirescope_enable_warnings(wirescope_tcp_tracker)

# TCP stream reassembler

add_library(wirescope_tcp_reassembler
    src/tcp_reassembler.cpp
)

add_library(
    WireScope::TcpReassembler
    ALIAS wirescope_tcp_reassembler
)

target_link_libraries(wirescope_tcp_reassembler
    PUBLIC WireScope::Decoder
)

wirescope_enable_warnings(wirescope_tcp_reassembler)

# Unit tests

enable_testing()

# Packet decoder tests

add_executable(decoder_tests
    tests/decoder_tests.cpp
)

target_link_libraries(decoder_tests
    PRIVATE WireScope::Decoder
)

wirescope_enable_warnings(decoder_tests)

add_test(
    NAME decoder_tests
    COMMAND decoder_tests
)

# TCP tracker tests

add_executable(tcp_tracker_tests
    tests/tcp_tracker_tests.cpp
)

target_link_libraries(tcp_tracker_tests
    PRIVATE WireScope::TcpTracker
)

wirescope_enable_warnings(tcp_tracker_tests)

add_test(
    NAME tcp_tracker_tests
    COMMAND tcp_tracker_tests
)

# TCP stream reassembler tests

add_executable(tcp_reassembler_tests
    tests/tcp_reassembler_tests.cpp
)

target_link_libraries(tcp_reassembler_tests
    PRIVATE WireScope::TcpReassembler
)

wirescope_enable_warnings(tcp_reassembler_tests)

add_test(
    NAME tcp_reassembler_tests
    COMMAND tcp_reassembler_tests
)

# Capture-file and live-capture application

find_path(PCAP_INCLUDE_DIR
    NAMES pcap/pcap.h
)

find_library(PCAP_LIBRARY
    NAMES pcap
)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)

    find_package(Threads REQUIRED)

    add_executable(wirescope
        src/main.cpp
    )

    target_include_directories(wirescope
        PRIVATE ${PCAP_INCLUDE_DIR}
    )

    target_link_libraries(wirescope
        PRIVATE
            WireScope::Decoder
            WireScope::TcpTracker
            WireScope::TcpReassembler
            ${PCAP_LIBRARY}
            Threads::Threads
    )

    wirescope_enable_warnings(wirescope)

else()

    message(STATUS
        "libpcap not found: skipping the capture-file and live-capture CLI"
    )

endif()
