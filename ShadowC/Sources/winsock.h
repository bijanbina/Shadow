#ifndef _WINSOCK_H
#define _WINSOCK_H

#ifdef __MINGW32__

// Target NT6
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

// Winsock headers
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

// Override POSIX error number
#define errno WSAGetLastError()

#define EWOULDBLOCK WSAEWOULDBLOCK

#define CONNECT_IN_PROGRESS WSAEWOULDBLOCK

#define EOPNOTSUPP WSAEOPNOTSUPP

#define EPROTONOSUPPORT WSAEPROTONOSUPPORT

#define ENOPROTOOPT WSAENOPROTOOPT

// Override close function
#define close(fd) closesocket(fd)

// Override MinGW functions
#define setsockopt(a, b, c, d, e) setsockopt(a, b, c, (const char *)(d), e)
#define inet_ntop(a, b, c, d) inet_ntop(a, (void *)(b), c, d)

// Override Windows built-in functions
#ifdef ERROR
#undef ERROR
#endif
#define ERROR(s) ss_error(s)

#ifdef gai_strerror
#undef gai_strerror
#endif
#define gai_strerror(e) ss_gai_strerror(e)
char *ss_gai_strerror(int ecode);

// Missing Unix functions
#define sleep(x) Sleep((x) * 1000)
#define bzero(s, n) memset(s, 0, n)
#define strndup(s, n) ss_strndup(s, n)

// Winsock compatibility functions
int setnonblocking(SOCKET socket);
void winsock_init(void);
void winsock_cleanup(void);

#endif // __MINGW32__

#endif // _WINSOCK_H
