#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"


int main(int argc, char **argv) {
    WSADATA wsaData;
    using Socket = SOCKET;
    Socket ConnectSocket = INVALID_SOCKET;

    struct addrinfo *result = nullptr;
    struct addrinfo *ptr = nullptr;
    struct addrinfo hints{}; // value initialization

    const char *sendbuf = "this is a test";
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;

    // Validate the parameters
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <hostname>\n";
        return 1;
    }

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed with error: " << iResult << std::endl;
        return 1;
    }

    ZeroMemory( &hints, sizeof(hints) ); // 주소 전달
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(argv[1], DEFAULT_PORT, &hints, &result);
    if ( iResult != 0 ) {
        std::cerr << "getaddrinfo failed with error: " << iResult << std::endl;
        WSACleanup();
        return 1;
    }

    for(ptr=result; ptr != nullptr ;ptr=ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cerr << "socket failed with error: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        std::cout << "connect failed with error: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
    iResult = send( ConnectSocket, sendbuf, (int)strlen(sendbuf), 0 );
    if (iResult == SOCKET_ERROR) {
        std::cerr << "send failed with error: " << WSAGetLastError() << std::endl;
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Bytes Sent: " << iResult << "\n";

    // shutdown the connection since no more data will be sent
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "shutdown failed with error: " << WSAGetLastError() << std::endl;
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Receive until the peer closes the connection
    do {
        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if ( iResult > 0 )
            std::cout << "Bytes received: " << iResult << "\n";
        else if ( iResult == 0 )
            std::cout << "Connection closed" << "\n";
        else
            std::cerr << "recv failed with error: " << WSAGetLastError() << std::endl;

    } while( iResult > 0 );

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}