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

#ifndef LDCP_SESSION_H
#define LDCP_SESSION_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct ldcp_FAILOVER_ENTRY;
typedef struct ldcp_FAILOVER_ENTRY {
    uint64_t uuid;
    uint64_t seqno;
    struct ldcp_FAILOVER_ENTRY *prev;
} ldcp_FAILOVER_ENTRY;

typedef struct {
    ldcp_FAILOVER_ENTRY *newest;
    ldcp_FAILOVER_ENTRY *oldest;
    size_t size;
} ldcp_FAILOVER_LOG;

typedef struct {
    char *name;
    int16_t npartitions;
    ldcp_FAILOVER_LOG *failover_logs;
} ldcp_SESSION;

LDCP_INTERNAL_API
ldcp_SESSION *ldcp_session_new(char *name);
LDCP_INTERNAL_API
void ldcp_session_init_failover_logs(ldcp_SESSION *session, int16_t npartitions);
LDCP_INTERNAL_API
void ldcp_session_free(ldcp_SESSION *session);
LDCP_INTERNAL_API
void ldcp_failover_log_append(ldcp_FAILOVER_LOG *log, uint64_t uuid, uint64_t seqno);

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LDCP_SESSION_H */
