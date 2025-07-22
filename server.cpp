#undef  UNICODE

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

int main() {
    WSADATA wsaData;

    int iSendResult;
    // int recvbuflen = DEFAULT_BUFLEN;

    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Unable to load certificate and private key files\n";
        SSL_CTX_free(ctx);
    }

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;
    struct addrinfo* result = nullptr;
    struct addrinfo hints{};

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(nullptr, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create a SOCKET for the server to listen for client connections.
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << std::endl;
        freeaddrinfo(result);
        WSACleanup();
        SSL_CTX_free(ctx);
        return 1;
    }

    // Set up the TCP listening socket
    iResult = bind( ListenSocket, result->ai_addr, static_cast<int>(result->ai_addrlen));
    freeaddrinfo(result);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "bind failed: " << WSAGetLastError() << std::endl;
        // freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        SSL_CTX_free(ctx);
        return 1;
    }

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "listen failed: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        WSACleanup();
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "Server started. Waiting for TLS connection on port " << DEFAULT_PORT << "...\n";

    // Accept a client socket
    ClientSocket = accept(ListenSocket, nullptr, nullptr);
    if (ClientSocket == INVALID_SOCKET) {
        std::cerr << "accept failed: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        WSACleanup();
        SSL_CTX_free(ctx);
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // TLS 연결 설정
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, static_cast<int>(ClientSocket));

    if (SSL_accept(ssl) <= 0) {
        std::cerr << "SSL_accept failed: " << WSAGetLastError() << std::endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        closesocket(ClientSocket);
        WSACleanup();
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "TLS handshake successful!\n";

    char recvbuf[DEFAULT_BUFLEN];
    int bytesRead;

    while ((bytesRead = SSL_read(ssl, recvbuf, DEFAULT_BUFLEN)) > 0) {
        std::cout << "Received: " << std::string(recvbuf, bytesRead) << "\n";

        const int bytesSent = SSL_write(ssl, recvbuf, bytesRead);
        if (bytesSent != bytesRead) {
            std::cerr << "SSL_write failed: " << WSAGetLastError() << std::endl;
            break;
        }
    }


    // cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(ClientSocket);
    SSL_CTX_free(ctx);
    WSACleanup();

    return 0;
}