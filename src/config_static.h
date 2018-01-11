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

#ifndef LIBDCP_CONFIG_STATIC_H
#define LIBDCP_CONFIG_STATIC_H 1

#ifdef HAVE_SYS_TYPES_H
#    include <sys/types.h>
#endif

#ifdef HAVE_STDINT_H
#    include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#endif

#ifdef HAVE_INTTYPES_H
#    include <inttypes.h>
#endif

#ifdef HAVE_NETDB_H
#    include <netdb.h>
#endif

#ifdef HAVE_UNISTD_H
#    include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
#    include <sys/time.h>
#endif

#ifdef HAVE_SYS_UIO_H
#    include <sys/uio.h>
#endif

#ifdef HAVE_STRINGS_H
#    include <strings.h>
#endif

#ifdef HAVE_FCNTL_H
#    include <fcntl.h>
#endif

#ifdef HAVE_DLFCN_H
#    include <dlfcn.h>
#endif

#ifdef HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#endif

/* Standard C includes */
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#ifndef PATH_MAX
#    define PATH_MAX 1024
#endif

#if defined(HAVE_HTONLL)
#    define ldcp_htonll htonll
#    define ldcp_ntohll ntohll
#elif defined(WORDS_BIGENDIAN)
#    define ldcp_ntohll(a) a
#    define ldcp_htonll(a) a
#else
#    define ldcp_ntohll(a) ldcp_byteswap64(a)
#    define ldcp_htonll(a) ldcp_byteswap64(a)
#endif /* HAVE_HTONLL */

#ifdef __cplusplus
extern "C" {
#endif

extern uint64_t ldcp_byteswap64(uint64_t val);

#ifndef HAVE_GETHRTIME
typedef uint64_t hrtime_t;
extern hrtime_t gethrtime(void);
#endif

#ifdef __cplusplus
}
#    endif

#endif /* LIBDCP_CONFIG_STATIC_H */
