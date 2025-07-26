cmake_minimum_required(VERSION 3.31)
project(Winsock_Project)

set(CMAKE_CXX_STANDARD 17)

# 기본 Winsock 라이브러리
set(WINSOCK_LIBS ws2_32 Mswsock Advapi32)

# OpenSSL 라이브러리
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIB_DIR "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD")

include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIB_DIR})

# 로그
message(STATUS "Using OpenSSL include path: ${OPENSSL_ROOT}/include")

## 라이브러리 설정
#set(OPENSSL_LIBS
#        "${OPENSSL_LIB_DIR}/libssl.lib"
#        "${OPENSSL_LIB_DIR}/libcrypto.lib"
#)
# 동적 DLL 테스트
set(OPENSSL_LIBS
        "${OPENSSL_LIB_DIR}/libssl-3-x64.lib"
        "${OPENSSL_LIB_DIR}/libcrypto-3-x64.lib"
)


# TLS 서버/클라이언트
add_executable(server server.cpp)
target_include_directories(server PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_directories(server PRIVATE ${OPENSSL_LIB_DIR})
target_link_libraries(server ${WINSOCK_LIBS} ${OPENSSL_LIBS})

add_executable(client client.cpp)
target_include_directories(client PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_directories(client PRIVATE ${OPENSSL_LIB_DIR})
target_link_libraries(client ${WINSOCK_LIBS} ${OPENSSL_LIBS})