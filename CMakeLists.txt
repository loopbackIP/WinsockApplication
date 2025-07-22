cmake_minimum_required(VERSION 3.31)
project(Winsock_Project)

set(CMAKE_CXX_STANDARD 11)

# 기본 Winsock 라이브러리
set(WINSOCK_LIBS ws2_32 Mswsock Advapi32)

# OpenSSL 라이브러리
set(OPENSSL_ROOT "C:/Program Files/OpenSSL-Win64")
include_directories("${OPENSSL_ROOT}/include")
link_directories("${OPENSSL_ROOT}/lib/VC/x64/MD")

# 일반
#add_executable(server server.cpp)
#target_link_libraries(server ${WINSOCK_LIBS})
#
#add_executable(client client.cpp)
#target_link_libraries(client ${WINSOCK_LIBS})

# TLS 서버/클라이언트
add_executable(server server.cpp)
target_link_libraries(server ${WINSOCK_LIBS} libssl.lib libcrypto.lib)

add_executable(client client.cpp)
target_link_libraries(client ${WINSOCK_LIBS} libssl.lib libcrypto.lib)