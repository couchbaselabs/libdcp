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

#include "internal.h"

extern uint64_t ldcp_byteswap64(uint64_t val)
{
    size_t ii;
    uint64_t ret = 0;
    for (ii = 0; ii < sizeof(uint64_t); ii++) {
        ret <<= 8;
        ret |= val & 0xff;
        val >>= 8;
    }
    return ret;
}

/**
 * While the C standard library uses 'putenv' for environment variable
 * manipulation, POSIX defines setenv (which works sanely) but Windows
 * only has putenv (via the CRT interface).
 * However Windows also has the 'GetEnvironmentVariable' etc. API - which
 * actually uses a different interface.
 *
 * We prefer to use actual API calls rather than hack into a poor excuse
 * of conformance. Since putenv requires ownership of the string, its use
 * is discouraged (and _putenv_s isn't available in MinGW); thus the
 * assumption that the most common APIs are GetEnvironmentVariable and
 * SetEnvironmentVariable. We try to abstract this away from the rest of the
 * library.
 */

#ifdef _WIN32
int ldcp_getenv_nonempty(const char *key, char *buf, size_t len)
{
    DWORD nvalue = GetEnvironmentVariable(key, buf, (DWORD)len);

    if (nvalue == 0 || nvalue >= len) {
        return 0;
    }

    if (!buf[0]) {
        return 0;
    }
    return 1;
}

#else
int ldcp_getenv_nonempty(const char *key, char *buf, size_t len)
{
    const char *cur = getenv(key);
    if (cur == NULL || *cur == '\0') {
        return 0;
    }

    strncpy(buf, cur, len);
    return 1;
}
#endif

int ldcp_getenv_boolean(const char *key)
{
    char value[4096] = {0};
    int rv;
    rv = ldcp_getenv_nonempty(key, value, sizeof(value));
    return rv != 0 && value[0] != '\0' && value[0] != '0';
}

int ldcp_getenv_nonempty_multi(char *buf, size_t nbuf, ...)
{
    va_list ap;
    const char *cur;
    int found = 0;

    va_start(ap, nbuf);
    while ((cur = va_arg(ap, const char *))) {
        if ((found = ldcp_getenv_nonempty(cur, buf, nbuf))) {
            break;
        }
    }
    va_end(ap);
    return found;
}

int ldcp_getenv_boolean_multi(const char *key, ...)
{
    va_list ap;
    const char *cur;
    int ret = 0;

    va_start(ap, key);
    if (ldcp_getenv_boolean(key)) {
        va_end(ap);
        return 1;
    }

    while ((cur = va_arg(ap, const char *))) {
        if ((ret = ldcp_getenv_boolean(cur))) {
            break;
        }
    }
    va_end(ap);
    return ret;
}
