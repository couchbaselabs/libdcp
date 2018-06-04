/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2017 Couchbase, Inc.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include "logging.h"
#include "internal.h"
#include <stdarg.h>

#ifdef _WIN32
#    define flockfile(x) (void)0
#    define funlockfile(x) (void)0
#endif

#if defined(unix) || defined(__unix__) || defined(__unix) || defined(_POSIX_VERSION)
#    include <unistd.h>
#    include <pthread.h>
#    include <sys/types.h>
#    if defined(__linux__)
#        include <sys/syscall.h>
#        define GET_THREAD_ID() (long)syscall(SYS_gettid)
#        define THREAD_ID_FMT "ld"
#    elif defined(__APPLE__)
#        define GET_THREAD_ID() getpid(), pthread_mach_thread_np(pthread_self())
#        define THREAD_ID_FMT "d/%x"
#    elif defined(__sun) && defined(__SVR4)
#        include <thread.h>
#        define GET_THREAD_ID() getpid(), thr_self()
#        define THREAD_ID_FMT "ld/%u"
#    elif defined(__FreeBSD__)
#        include <sys/thr.h>
static long ret_thr_self(void)
{
    long tmp;
    thr_self(&tmp);
    return tmp;
}
#        define GET_THREAD_ID() getpid(), ret_thr_self()
#        define THREAD_ID_FMT "d/%ld"
#    else
#        define GET_THREAD_ID() 0
#        define THREAD_ID_FMT "d"
#    endif
#elif defined(_WIN32)
#    define GET_THREAD_ID() GetCurrentThreadId()
#    define THREAD_ID_FMT "d"
#else
#    define GET_THREAD_ID() 0
#    define THREAD_ID_FMT "d"
#endif

static hrtime_t start_time = 0;
struct ldcp_CONSOLELOGGER {
    struct ldcp_LOGGER base;
    FILE *fp;
    int minlevel;
};

static void console_log(struct ldcp_LOGGER *procs, unsigned int iid, const char *subsys, int severity,
                        const char *srcfile, int srcline, const char *fmt, va_list ap);

static ldcp_STATUS console_minlevel(struct ldcp_LOGGER *procs, ldcp_LOG_SEVERITY level);

// clang-format off
static struct ldcp_CONSOLELOGGER console_logger = {
    {
        0 /* version */,
        {
            {
                console_log,
                console_minlevel
            } /* v1 */
        } /* v */
    },
    NULL,
    LDCP_LOG_INFO /* Minimum severity */
};
// clang-format on

struct ldcp_LOGGER *ldcp_console_logger = &console_logger.base;

/**
 * Return a string representation of the severity level
 */
static const char *level_to_string(int severity)
{
    switch (severity) {
        case LDCP_LOG_TRACE:
            return "TRACE";
        case LDCP_LOG_DEBUG:
            return "DEBUG";
        case LDCP_LOG_INFO:
            return "INFO";
        case LDCP_LOG_WARN:
            return "WARN";
        case LDCP_LOG_ERROR:
            return "ERROR";
        case LDCP_LOG_FATAL:
            return "FATAL";
        default:
            return "";
    }
}

static ldcp_STATUS console_minlevel(struct ldcp_LOGGER *logger, ldcp_LOG_SEVERITY level)
{
    if (logger) {
        struct ldcp_CONSOLELOGGER *clogger = (struct ldcp_CONSOLELOGGER *)logger;
        clogger->minlevel = level;
    }
    return LDCP_OK;
}

/**
 * Default logging callback for the verbose logger.
 */
static void console_log(struct ldcp_LOGGER *procs, unsigned int iid, const char *subsys, int severity,
                        const char *srcfile, int srcline, const char *fmt, va_list ap)
{
    FILE *fp;
    hrtime_t now;
    struct ldcp_CONSOLELOGGER *vprocs = (struct ldcp_CONSOLELOGGER *)procs;

    if (severity > vprocs->minlevel) {
        return;
    }

    if (!start_time) {
        start_time = gethrtime();
    }

    now = gethrtime();
    if (now == start_time) {
        now++;
    }

    fp = vprocs->fp ? vprocs->fp : stderr;

    flockfile(fp);
    fprintf(fp, "%lums ", (unsigned long)(now - start_time) / 1000000);

    fprintf(fp, "[I%d] {%" THREAD_ID_FMT "} [%s] (%s - L:%d) ", iid, GET_THREAD_ID(), level_to_string(severity), subsys,
            srcline);
    vfprintf(fp, fmt, ap);
    fprintf(fp, "\n");
    funlockfile(fp);

    (void)procs;
    (void)srcfile;
}

LDCP_INTERNAL_API
void ldcp_log(const ldcp_SETTINGS *settings, const char *subsys, int severity, const char *srcfile, int srcline,
              const char *fmt, ...)
{
    va_list ap;
    ldcp_LOG_CALLBACK callback;

    if (!settings->logger) {
        return;
    }

    if (settings->logger->version != 0) {
        return;
    }

    callback = settings->logger->v.v0.callback;

    va_start(ap, fmt);
    callback(settings->logger, settings->iid, subsys, severity, srcfile, srcline, fmt, ap);
    va_end(ap);
}

ldcp_STATUS ldcp_log_minlevel(const ldcp_SETTINGS *settings, ldcp_LOG_SEVERITY level)
{
    if (!settings->logger) {
        return LDCP_BADARG;
    }
    if (settings->logger->version != 0) {
        return LDCP_BADARG;
    }
    return settings->logger->v.v0.set_minlevel(settings->logger, level);
}

LDCP_INTERNAL_API
struct ldcp_LOGGER *ldcp_init_console_logger(void)
{
    char vbuf[1024];
    char namebuf[PATH_MAX] = {0};
    int has_file = 0;

    has_file = ldcp_getenv_nonempty("LDCP_LOGFILE", namebuf, sizeof(namebuf));
    if (has_file && console_logger.fp == NULL) {
        FILE *fp = fopen(namebuf, "a");
        if (!fp) {
            fprintf(stderr, "libcouchbase: could not open file '%s' for logging output. (%s)\n", namebuf,
                    strerror(errno));
        }
        console_logger.fp = fp;
    }

    if (ldcp_getenv_nonempty("LDCP_LOGLEVEL", vbuf, sizeof(vbuf))) {
        int lvl = 0;
        if (sscanf(vbuf, "%d", &lvl)) {
            if (lvl > LDCP_LOG__MAX) {
                lvl = LDCP_LOG_TRACE;
            }
            if (lvl < LDCP_LOG_ERROR) {
                lvl = LDCP_LOG_ERROR;
            }
            console_logger.minlevel = lvl;
        }
    }

    return ldcp_console_logger;
}

LDCP_INTERNAL_API
void ldcp_dump_bytes(FILE *stream, const char *msg, const void *ptr, size_t len)
{

    int width = 16;
    const unsigned char *buf = (const unsigned char *)ptr;
    size_t full_rows = len / width;
    size_t remainder = len % width;

    flockfile(stream);
    fprintf(stream,
            "%s, %d bytes\n"
            "         +-------------------------------------------------+\n"
            "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
            "+--------+-------------------------------------------------+----------------+",
            msg, len);

    unsigned int row = 0;
    while (row < full_rows) {
        int row_start_index = row * width;
        // prefix
        fprintf(stream, "\n|%08x|", row_start_index);
        int row_end_index = row_start_index + width;
        // hex
        int i = row_start_index;
        while (i < row_end_index) {
            fprintf(stream, " %02x", (unsigned int)buf[i++]);
        }
        fprintf(stream, " |");
        // ascii
        i = row_start_index;
        while (i < row_end_index) {
            char b = buf[i++];
            if ((b <= 0x1f) || (b >= 0x7f)) {
                fprintf(stream, ".");
            } else {
                fprintf(stream, "%c", b);
            }
        }
        fprintf(stream, "|");
        row++;
    }
    if (remainder != 0) {
        int row_start_index = full_rows * width;
        // prefix
        fprintf(stream, "\n|%08x|", row_start_index);
        int row_end_index = row_start_index + remainder;
        // hex
        int i = row_start_index;
        while (i < row_end_index) {
            fprintf(stream, " %02x", (unsigned int)buf[i++]);
        }
        i = width - remainder;
        while (i > 0) {
            fprintf(stream, "   ");
            i--;
        }
        fprintf(stream, " |");
        // ascii
        i = row_start_index;
        while (i < row_end_index) {
            char b = buf[i++];
            if ((b <= 0x1f) || (b >= 0x7f)) {
                fprintf(stream, ".");
            } else {
                fprintf(stream, "%c", b);
            }
        }
        i = width - remainder;
        while (i > 0) {
            fprintf(stream, " ");
            i--;
        }
        fprintf(stream, "|");
    }
    fprintf(stream, "\n+--------+-------------------------------------------------+----------------+\n");
    funlockfile(stream);
}
