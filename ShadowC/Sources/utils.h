#ifndef _UTILS_H
#define _UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#define PORTSTRLEN 16
#define SS_ADDRSTRLEN (INET6_ADDRSTRLEN + PORTSTRLEN + 1)

#define STR(x) # x
#define TOSTR(x) STR(x)


#define USE_TTY()
#define USE_SYSLOG(ident, _cond)
#define USE_LOGFILE(ident)
#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"

// Workaround for "%z" in Windows printf
#ifdef __MINGW32__
#define SSIZE_FMT "%Id"
#define SIZE_FMT "%Iu"
#endif

#define ERROR(s) ss_error(s)
void ss_error(const char *s);
void ss_color_info(void);
void ss_color_error(void);
void ss_color_reset(void);

char *ss_itoa(int i);
int ss_isnumeric(const char *s);
int run_as(const char *user);
void usage(void);
void daemonize(const char *path);
char *ss_strndup(const char *s, size_t n);

void *ss_malloc(size_t size);
void *ss_aligned_malloc(size_t size);
void *ss_realloc(void *ptr, size_t new_size);

#define ss_free(ptr) \
    { \
        free(ptr); \
        ptr = NULL; \
    }

#ifdef __MINGW32__
#define ss_aligned_free(ptr) \
    { \
        _aligned_free(ptr); \
        ptr = NULL; \
    }
#endif

#endif // _UTILS_H
