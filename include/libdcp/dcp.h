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

typedef enum { LDCP_TYPE_BASIC = 0x00, LDCP_TYPE_CONSUMER = 0x01 } ldcp_CLIENT_TYPE;

typedef enum { LDCP_OK = 0, LDCP_BADARG = 1, LDCP_NOCONFIG = 2, LDCP_UNSUPPORTED = 3 } ldcp_STATUS;

typedef enum {
    LDCP_EVENT_DEFAULT = 0, /**< default fallback */
    LDCP_EVENT_SNAPSHOT,
    LDCP_EVENT_MUTATION,
    LDCP_EVENT_DELETION,
    LDCP_EVENT_STARTSTREAM,
    LDCP_EVENT__MAX
} ldcp_EVENT_CALLBACK;

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
    uint32_t xattrs_num;
    void *xattrs;
    uint32_t xattrs_len;
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

typedef struct ldcp_START_STREAM {
    LDCP_EVENT_BASE
    uint64_t start_seqno;
    uint64_t end_seqno;
    uint64_t snap_start_seqno;
    uint64_t snap_end_seqno;
    uint64_t partition_uuid;
} ldcp_START_STREAM;

#define LDCP_RESP_BASE                                                                                                 \
    uint32_t version;                                                                                                  \
    ldcp_STATUS status;                                                                                                \
    void *cookie;

typedef struct ldcp_RESP {
    LDCP_RESP_BASE
} ldcp_RESP;

typedef enum {
    LDCP_RESP_DEFAULT = 0, /**< default fallback */
    LDCP_RESP_SETWITHMETA,
    LDCP_RESP__MAX
} ldcp_RESP_CALLBACK;

#define LDCP_CMD_BASE                                                                                                  \
    uint32_t version;                                                                                                  \
    uint16_t partition;

typedef struct ldcp_CMD_SETWITHMETA {
    LDCP_CMD_BASE
    void *cookie;
    uint32_t flags;
    uint32_t expiration;
    uint64_t rev_seqno;
    uint64_t cas;

    /*
    SKIP_CONFLICT_RESOLUTION_FLAG 0x01
    FORCE_ACCEPT_WITH_META_OPS 0x02
    REGENERATE_CAS 0x04
    */

    uint32_t options;
    uint16_t meta_len;
    void *key;
    uint32_t key_len;
    void *xattrs; /**< properly encoded XATTRs, might be changed in future */
    uint32_t xattrs_len;
    void *value;
    uint32_t value_len;
} ldcp_CMD_SETWITHMETA;

typedef struct ldcp_RESP_SETWITHMETA {
    LDCP_RESP_BASE
} ldcp_RESP_SETWITHMETA;

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LIBDCP_DCP_H */
