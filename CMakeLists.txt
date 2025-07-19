cmake_minimum_required(VERSION 3.31)
project(Winsock_Project)

set(CMAKE_CXX_STANDARD 11)

set(WINSOCK_LIBS ws2_32 Mswsock Advapi32)


add_executable(server server.cpp)
target_link_libraries(server ${WINSOCK_LIBS})

add_executable(client client.cpp)
target_link_libraries(client ${WINSOCK_LIBS})
