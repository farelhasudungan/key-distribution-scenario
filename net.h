// net.h
// Pembungkus socket TCP lintas platform (Winsock di Windows, BSD socket di Linux).
#pragma once
#include <string>
#include <cstring>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define BAD_SOCK INVALID_SOCKET
  #define SEND_FLAGS 0
  typedef int sock_len_t;
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  typedef int sock_t;
  #define BAD_SOCK (-1)
  #ifdef MSG_NOSIGNAL
    #define SEND_FLAGS MSG_NOSIGNAL
  #else
    #define SEND_FLAGS 0
  #endif
  typedef socklen_t sock_len_t;
#endif

namespace net {

inline bool init() {
#ifdef _WIN32
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0;
#else
    return true;
#endif
}

inline void closeSock(sock_t s) {
    if (s == BAD_SOCK) return;
#ifdef _WIN32
    shutdown(s, SD_BOTH);
    closesocket(s);
#else
    shutdown(s, SHUT_RDWR);
    close(s);
#endif
}

// Server: dengarkan di semua interface (0.0.0.0)
inline sock_t listenOn(int port, std::string& err) {
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == BAD_SOCK) { err = "socket() gagal"; return BAD_SOCK; }
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    sockaddr_in a;
    std::memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons((unsigned short)port);
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) { err = "bind() gagal (port dipakai?)"; closeSock(s); return BAD_SOCK; }
    if (listen(s, 8) != 0) { err = "listen() gagal"; closeSock(s); return BAD_SOCK; }
    return s;
}

inline sock_t acceptOne(sock_t ls, std::string& peer) {
    sockaddr_in a;
    sock_len_t len = sizeof(a);
    sock_t c = accept(ls, (sockaddr*)&a, &len);
    if (c == BAD_SOCK) return BAD_SOCK;
    char ip[64] = {0};
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
    peer = std::string(ip) + ":" + std::to_string(ntohs(a.sin_port));
    return c;
}

inline sock_t connectTo(const std::string& host, int port, std::string& err) {
    addrinfo hints, *res = nullptr;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        err = "alamat tidak dapat di-resolve: " + host;
        return BAD_SOCK;
    }
    sock_t s = BAD_SOCK;
    for (addrinfo* p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == BAD_SOCK) continue;
        if (connect(s, p->ai_addr, (sock_len_t)p->ai_addrlen) == 0) break;
        closeSock(s);
        s = BAD_SOCK;
    }
    freeaddrinfo(res);
    if (s == BAD_SOCK) err = "tidak bisa terhubung ke " + host + ":" + std::to_string(port);
    return s;
}

// Koneksi dengan protokol berbasis baris teks (diakhiri '\n'), mudah dibaca di Wireshark.
struct Conn {
    sock_t s = BAD_SOCK;
    std::string buf;

    bool sendLine(const std::string& line) {
        std::string d = line + "\n";
        size_t sent = 0;
        while (sent < d.size()) {
            int n = (int)send(s, d.data() + sent, (int)(d.size() - sent), SEND_FLAGS);
            if (n <= 0) return false;
            sent += (size_t)n;
        }
        return true;
    }

    bool recvLine(std::string& line) {
        while (true) {
            size_t pos = buf.find('\n');
            if (pos != std::string::npos) {
                line = buf.substr(0, pos);
                buf.erase(0, pos + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                return true;
            }
            if (buf.size() > (1u << 20)) return false;
            char tmp[4096];
            int n = (int)recv(s, tmp, sizeof(tmp), 0);
            if (n <= 0) return false;
            buf.append(tmp, (size_t)n);
        }
    }

    void close() {
        closeSock(s);
        s = BAD_SOCK;
    }
};

}  // namespace net
