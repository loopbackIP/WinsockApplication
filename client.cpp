#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"


int main(int argc, char **argv) {
    // Validate the parameters
    if (argc != 2) {
        std::cout << "usage: " << argv[0] << " <hostname>\n";
        return 1;
    }

    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    // value initialization
    struct addrinfo hints{}, * result = nullptr, * ptr = nullptr;

    const char *sendbuf = "this is a test";
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;


    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed with error: " << iResult << std::endl;
        return 1;
    }

    // OpenSSL init
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // address setting
    ZeroMemory( &hints, sizeof(hints) );
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

    // Connection try
    for(ptr = result; ptr != nullptr ;ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cerr << "socket failed with error: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen));
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

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, static_cast<int>(ConnectSocket));

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "TLS handshake failed." << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "TLS connection established." << "\n";

    int bytesRead = SSL_read(ssl, recvbuf, DEFAULT_BUFLEN);
    if (bytesRead > 0) {
        std::cout << "Bytes Received: " << bytesRead << "\n";
    } else {
        std::cerr << "SSL_read failed." << std::endl;
        ERR_print_errors_fp(stderr);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}