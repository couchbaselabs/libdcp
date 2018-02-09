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

#include "internal.h"

LDCP_INTERNAL_API
ldcp_SESSION *ldcp_session_new(char *name)
{
    ldcp_SESSION *session;
    session = calloc(1, sizeof(ldcp_SESSION));
    if (name) {
        session->name = strdup(name);
    } else {
#define _NAME_SZ sizeof(LDCP_ID) + 22
        session->name = calloc(_NAME_SZ, sizeof(char));
        snprintf(session->name, _NAME_SZ, LDCP_ID "/%lld", (unsigned long long)gethrtime());
#undef _NAME_SZ
    }
    return session;
}

LDCP_INTERNAL_API
void ldcp_session_init_failover_logs(ldcp_SESSION *session, int16_t npartitions)
{
    session->npartitions = npartitions;
    session->failover_logs = calloc(npartitions, sizeof(ldcp_FAILOVER_LOG));
}

LDCP_INTERNAL_API
void ldcp_session_free(ldcp_SESSION *session)
{
    if (session) {
        free(session->name);
        if (session->failover_logs) {
            int16_t ii;
            for (ii = 0; ii < session->npartitions; ii++) {
                ldcp_FAILOVER_ENTRY *entry = session->failover_logs[ii].newest;
                while (entry) {
                    ldcp_FAILOVER_ENTRY *tmp = entry;
                    entry = entry->prev;
                    free(tmp);
                }
            }
        }
        free(session->failover_logs);
    }
    free(session);
}

LDCP_INTERNAL_API
void ldcp_failover_log_append(ldcp_FAILOVER_LOG *log, uint64_t uuid, uint64_t seqno)
{
    ldcp_FAILOVER_ENTRY *entry = calloc(1, sizeof(ldcp_FAILOVER_ENTRY));
    entry->uuid = uuid;
    entry->seqno = seqno;
    if (log->oldest == NULL) {
        log->newest = log->oldest = entry;
    } else {
        log->oldest->prev = entry;
        entry->prev = NULL; /* just make sure it is the last one to avoid cycles */
    }
    log->size++;
}
