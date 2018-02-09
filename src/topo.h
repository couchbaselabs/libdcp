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

#ifndef LDCP_TOPO_H
#define LDCP_TOPO_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct ldcp_CLIENT;

typedef struct {
    char host[NI_MAXHOST + 1];
    struct {
        uint16_t kv_s;
        uint16_t kv;
    } port;
} ldcp_SERVER;

typedef struct {
    int16_t master;
    int16_t replica[3];
} ldcp_PARTITION;

typedef struct {
    uint32_t rev;
    char *uuid;
    int16_t idx; /* this node index */
    int16_t nservers;
    int16_t npartitions;
    ldcp_SERVER *servers;
    ldcp_PARTITION *partitions;
} ldcp_CONFIG;

LDCP_INTERNAL_API
ldcp_CONFIG *ldcp_config_new();

LDCP_INTERNAL_API
void ldcp_config_free(ldcp_CONFIG *config);

LDCP_INTERNAL_API
ldcp_CONFIG *ldcp_config_parse(const char *body, const char *this_host);

LDCP_INTERNAL_API
void ldcp_handle_rebalance(struct ldcp_CLIENT *client, ldcp_CONFIG *config);

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LDCP_SESSION_H */
