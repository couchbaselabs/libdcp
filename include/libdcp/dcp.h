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

#ifndef LIBDCP_DCP_H
#define LIBDCP_DCP_H 1

#include <stddef.h>
#include <stdint.h>
#include <libdcp/configuration.h>
#include <libdcp/visibility.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LDCP_EVENT_BASE                                                                                                \
    uint32_t version;                                                                                                  \
    uint16_t partition;

typedef struct ldcp_EVENT {
    LDCP_EVENT_BASE
} ldcp_EVENT;

typedef struct ldcp_MUTATION {
    LDCP_EVENT_BASE
    uint64_t by_seqno;
    uint64_t rev_seqno;
    uint64_t cas;
    uint8_t datatype;
    uint32_t flags;
    uint32_t expiration;
    uint32_t lock_time;
    void *key;
    uint32_t key_len;
    void *value;
    uint32_t value_len;
} ldcp_MUTATION;

typedef struct ldcp_DELETION {
    LDCP_EVENT_BASE
    uint64_t by_seqno;
    uint64_t rev_seqno;
    uint64_t cas;
    void *key;
    uint32_t key_len;
} ldcp_DELETION;

typedef struct ldcp_SNAPSHOT {
    LDCP_EVENT_BASE
    uint64_t start_seqno;
    uint64_t end_seqno;
    uint32_t flags;
} ldcp_SNAPSHOT;

typedef enum {
    LDCP_CALLBACK_DEFAULT = 0, /**< default fallback */
    LDCP_CALLBACK_SNAPSHOT,
    LDCP_CALLBACK_MUTATION,
    LDCP_CALLBACK_DELETION,
    LDCP_CALLBACK__MAX
} ldcp_CALLBACK;

typedef enum { LDCP_TYPE_CONSUMER = 0x00, LDCP_TYPE_PRODUCER = 0x01, LDCP_TYPE_NOTIFIER = 0x02 } ldcp_CLIENT_TYPE;

typedef enum { LDCP_OK = 0, LDCP_BADARG = 1, LDCP_NOCONFIG = 2, LDCP_UNSUPPORTED = 3 } ldcp_STATUS;

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LIBDCP_DCP_H */
