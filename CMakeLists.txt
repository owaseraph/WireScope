cmake_minimum_required(VERSION 3.20)
project(WireScope VERSION 1.2.0 DESCRIPTION "C++20 packet analyzer with Qt desktop interface" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WIRESCOPE_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(WIRESCOPE_BUILD_TESTS "Build unit and smoke tests" ON)
option(WIRESCOPE_BUILD_GUI "Build the Qt 6 desktop application when Qt is available" ON)

function(wirescope_target target)
  target_compile_options(${target} PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wsign-conversion>
  )
  if(WIRESCOPE_ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

# Core packet decoder
add_library(wirescope_decoder src/decoder.cpp)
add_library(WireScope::Decoder ALIAS wirescope_decoder)
target_include_directories(wirescope_decoder PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(wirescope_decoder PUBLIC cxx_std_20)
wirescope_target(wirescope_decoder)

# TCP connection tracking and stream reconstruction
add_library(wirescope_tcp src/tcp_tracker.cpp src/tcp_reassembler.cpp)
add_library(WireScope::TCP ALIAS wirescope_tcp)
target_link_libraries(wirescope_tcp PUBLIC WireScope::Decoder)
target_include_directories(wirescope_tcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
wirescope_target(wirescope_tcp)

# Application protocol parsers
add_library(wirescope_protocols src/http_parser.cpp src/dns_parser.cpp src/tls_parser.cpp)
add_library(WireScope::Protocols ALIAS wirescope_protocols)
target_include_directories(wirescope_protocols PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
wirescope_target(wirescope_protocols)

# PCAP file I/O and Linux live capture
add_library(wirescope_capture_io src/pcap_io.cpp)
add_library(WireScope::CaptureIO ALIAS wirescope_capture_io)
target_include_directories(wirescope_capture_io PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
wirescope_target(wirescope_capture_io)

# Shared processing API used by the desktop frontend
add_library(wirescope_analysis src/analysis_engine.cpp)
add_library(WireScope::Analysis ALIAS wirescope_analysis)
target_include_directories(wirescope_analysis PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(wirescope_analysis PUBLIC
  WireScope::Decoder WireScope::TCP WireScope::Protocols WireScope::CaptureIO
)
wirescope_target(wirescope_analysis)

# Existing CLI remains available independently of Qt
add_executable(wirescope src/main.cpp)
target_link_libraries(wirescope PRIVATE WireScope::Decoder WireScope::TCP WireScope::Protocols WireScope::CaptureIO)
find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
  target_include_directories(wirescope PRIVATE ${PCAP_INCLUDE_DIR})
  target_link_libraries(wirescope PRIVATE ${PCAP_LIBRARY})
  target_compile_definitions(wirescope PRIVATE WIRESCOPE_HAS_LIBPCAP=1)
  message(STATUS "libpcap found: enabling full BPF filter expressions")
else()
  message(STATUS "libpcap not found: using WireScope built-in filter expressions")
endif()
wirescope_target(wirescope)

# Qt desktop frontend is optional so the core and CLI still build on systems
# without Qt development packages.
if(WIRESCOPE_BUILD_GUI)
  find_package(Qt6 6.2 COMPONENTS Widgets QUIET)
  if(Qt6_FOUND)
    add_executable(wirescope-gui
      gui/main.cpp
      gui/main_window.cpp
      gui/main_window.hpp
      gui/capture_worker.cpp
      gui/capture_worker.hpp
      gui/packet_table_model.cpp
      gui/packet_table_model.hpp
      gui/tcp_stream_dialog.cpp
      gui/tcp_stream_dialog.hpp
      gui/statistics_widget.cpp
      gui/statistics_widget.hpp
    )
    set_target_properties(wirescope-gui PROPERTIES AUTOMOC ON)
    target_link_libraries(wirescope-gui PRIVATE WireScope::Analysis Qt6::Widgets)
    wirescope_target(wirescope-gui)
    message(STATUS "Qt 6 found: enabling wirescope-gui")
  else()
    message(STATUS "Qt 6 Widgets not found: skipping wirescope-gui; install qt6-base to enable it")
  endif()
endif()

if(WIRESCOPE_BUILD_TESTS)
  enable_testing()
  foreach(test_name IN ITEMS decoder tcp http dns tls)
    add_executable(${test_name}_tests tests/${test_name}_tests.cpp)
    if(test_name STREQUAL "decoder")
      target_link_libraries(${test_name}_tests PRIVATE WireScope::Decoder)
    elseif(test_name STREQUAL "tcp")
      target_link_libraries(${test_name}_tests PRIVATE WireScope::TCP)
    else()
      target_link_libraries(${test_name}_tests PRIVATE WireScope::Protocols)
    endif()
    wirescope_target(${test_name}_tests)
    target_compile_options(${test_name}_tests PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-UNDEBUG>)
    add_test(NAME ${test_name}_tests COMMAND ${test_name}_tests)
  endforeach()

  add_executable(analysis_engine_tests tests/analysis_engine_tests.cpp)
  target_link_libraries(analysis_engine_tests PRIVATE WireScope::Analysis)
  target_compile_definitions(analysis_engine_tests PRIVATE
    WIRESCOPE_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
  )
  wirescope_target(analysis_engine_tests)
  target_compile_options(analysis_engine_tests PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-UNDEBUG>)
  add_test(NAME analysis_engine_tests COMMAND analysis_engine_tests)

  add_executable(pcap_io_tests tests/pcap_io_tests.cpp)
  target_link_libraries(pcap_io_tests PRIVATE WireScope::CaptureIO)
  wirescope_target(pcap_io_tests)
  target_compile_options(pcap_io_tests PRIVATE $<$<CXX_COMPILER_ID:GNU,Clang>:-UNDEBUG>)
  add_test(NAME pcap_io_tests COMMAND pcap_io_tests)
endif()
