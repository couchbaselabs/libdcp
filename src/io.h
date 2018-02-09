/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2018 Couchbase, Inc.
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

#ifndef LDCP_IO_H
#define LDCP_IO_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct ldcp_ADDRINFO;
typedef struct ldcp_ADDRINFO {
    int family; /* AF_INET, AF_INET6 */
    size_t addrlen;
    struct sockaddr *addr;
    struct ldcp_ADDRINFO *next;
} ldcp_ADDRINFO;

typedef struct {
    struct event_base *evbase;
    struct evdns_base *evdns_base;
} ldcp_IO;

LDCP_INTERNAL_API
ldcp_IO *ldcp_io_new();

LDCP_INTERNAL_API
void ldcp_io_free(ldcp_IO *io);

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LDCP_CHANNEL_H */
