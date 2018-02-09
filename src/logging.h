/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014 Couchbase, Inc.
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

#ifndef LDCP_LOGGING_H
#define LDCP_LOGGING_H

#include <stdarg.h>
#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @name Logging
 *
 * Verbose logging may be enabled by default using the environment variable
 * `LDCP_LOGLEVEL` and setting it to a number > 1; higher values produce more
 * verbose output. The maximum level is `5`.
 *
 * You may also install your own logger using ldcp_cntl() and the
 * @ref LDCP_CNTL_LOGGER constant. Note that
 * the logger functions will not be called rapidly from within hot paths.
 * @{
 */

/** @brief Logging Levels */
typedef enum {
    LDCP_LOG_TRACE = 0,
    LDCP_LOG_DEBUG,
    LDCP_LOG_INFO,
    LDCP_LOG_WARN,
    LDCP_LOG_ERROR,
    LDCP_LOG_FATAL,
    LDCP_LOG_MAX
} ldcp_LOG_SEVERITY;

struct ldcp_LOGGER;

/**
 * @brief Logger callback
 *
 * This callback is invoked for each logging message emitted
 * @param procs the logging structure provided
 * @param iid instance id
 * @param subsys a string describing the module which emitted the message
 * @param severity one of the LDCP_LOG_* severity constants.
 * @param srcfile the source file which emitted this message
 * @param srcline the line of the file for the message
 * @param fmt a printf format string
 * @param ap a va_list for vprintf
 */
typedef void (*ldcp_LOG_CALLBACK)(struct ldcp_LOGGER *procs, unsigned int iid, const char *subsys, int severity,
                                  const char *srcfile, int srcline, const char *fmt, va_list ap);

/**
 * @brief Logging context
 * @volatile
 *
 * This structure defines the logging handlers. Currently there is only
 * a single field defined which is the default callback for the loggers.
 * This API may change.
 */
struct ldcp_LOGGER {
    int version;
    union {
        struct {
            ldcp_LOG_CALLBACK callback;
        } v0;
    } v;
};

/**@}*/

/**
 * Default printf logger which is enabled via LDCP_LOGLEVEL in the
 * environment
 */
extern struct ldcp_LOGGER *ldcp_console_logger;
LDCP_INTERNAL_API
struct ldcp_LOGGER *ldcp_init_console_logger(void);

/**
 * Log a message via the installed logger. The parameters correlate to the
 * arguments passed to the ldcp_logging_callback function.
 *
 * Typically a subsystem may wish to define macros in order to reduce the
 * number of arguments manually passed for each message.
 */
LDCP_INTERNAL_API
void ldcp_log(const ldcp_SETTINGS *settings, const char *subsys, int severity, const char *srcfile, int srcline,
              const char *fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 6, 7)))
#endif
    ;

LDCP_INTERNAL_API struct ldcp_LOGGER *ldcp_init_console_logger(void);

#define LDCP_LOGS(settings, subsys, severity, msg) ldcp_log(settings, subsys, severity, __FILE__, __LINE__, msg)
#define LDCP_LOG_EX(settings, subsys, severity, msg) ldcp_log(settings, subsys, severity, __FILE__, __LINE__, msg)
#define LDCP_LOG_BASIC(settings, msg) ldcp_log(settings, "unknown", 0, __FILE__, __LINE__, msg)


LDCP_INTERNAL_API
void ldcp_dump_bytes(FILE *stream, const char *msg, const void *ptr, size_t len);

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LDCP_LOGGING_H */
