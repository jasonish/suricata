# References:
# - https://michael-f-bryan.github.io/rust-ffi-guide/setting_up.html

cmake_minimum_required(VERSION 3.10)

project(Suricata)
set(SURICATA_VERSION 7.0.0-dev)

set(e_rustdir ${CMAKE_SOURCE_DIR}/rust)
set(PACKAGE_VERSION ${SURICATA_VERSION})

configure_file(rust/derive/Cargo.toml.in rust/derive/Cargo.toml)
configure_file(rust/Cargo.toml.in rust/Cargo.toml)

find_library(WPCAP wpcap)
find_library(PCAP pcap)

add_subdirectory(rust)

add_executable(suricata src/suricata.c)