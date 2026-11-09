#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Test-only LD_PRELOAD guard. It records network entry points into a file so a
 * test can prove that `angara check` / `angara serve` never call them. It always
 * forwards to the real implementation; it does not block or alter behavior.
 */

static void record(const char *name) {
    const char *path = getenv("ANGARA_NETGUARD_MARKER");
    if (path == NULL || path[0] == '\0') {
        return;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        return;
    }
    (void)write(fd, name, strlen(name));
    (void)write(fd, "\n", 1);
    close(fd);
}

__attribute__((constructor)) static void netguard_loaded(void) {
    record("loaded");
}

typedef int (*socket_fn)(int, int, int);
static socket_fn real_socket = NULL;

int socket(int domain, int type, int protocol) {
    record("socket");
    if (real_socket == NULL) {
        real_socket = (socket_fn)dlsym(RTLD_NEXT, "socket");
    }
    if (real_socket == NULL) {
        return -1;
    }
    return real_socket(domain, type, protocol);
}

typedef int (*bind_fn)(int, const struct sockaddr *, socklen_t);
static bind_fn real_bind = NULL;

int bind(int fd, const struct sockaddr *address, socklen_t length) {
    record("bind");
    if (real_bind == NULL) {
        real_bind = (bind_fn)dlsym(RTLD_NEXT, "bind");
    }
    if (real_bind == NULL) {
        return -1;
    }
    return real_bind(fd, address, length);
}

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
static connect_fn real_connect = NULL;

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    record("connect");
    if (real_connect == NULL) {
        real_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");
    }
    if (real_connect == NULL) {
        return -1;
    }
    return real_connect(fd, address, length);
}

typedef int (*getaddrinfo_fn)(const char *, const char *, const struct addrinfo *,
                              struct addrinfo **);
static getaddrinfo_fn real_getaddrinfo = NULL;

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **result) {
    record("getaddrinfo");
    if (real_getaddrinfo == NULL) {
        real_getaddrinfo = (getaddrinfo_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    }
    if (real_getaddrinfo == NULL) {
        return EAI_FAIL;
    }
    return real_getaddrinfo(node, service, hints, result);
}

typedef struct hostent *(*gethostbyname_fn)(const char *);
static gethostbyname_fn real_gethostbyname = NULL;

struct hostent *gethostbyname(const char *name) {
    record("gethostbyname");
    if (real_gethostbyname == NULL) {
        real_gethostbyname = (gethostbyname_fn)dlsym(RTLD_NEXT, "gethostbyname");
    }
    if (real_gethostbyname == NULL) {
        return NULL;
    }
    return real_gethostbyname(name);
}
