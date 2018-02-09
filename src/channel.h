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

#ifndef LDCP_CHANNEL_H
#define LDCP_CHANNEL_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum { STREAM_NONE, STREAM_OPENING, STREAM_OPEN } ldcp_STREAM_STATE;

#define CHANNEL_STATES(X)                                                                                              \
    X(NEW)                                                                                                             \
    X(ERROR)                                                                                                           \
    X(CONNECTING)                                                                                                      \
    X(CONNECTED)                                                                                                       \
    X(EOF)                                                                                                             \
    X(HELLO)                                                                                                           \
    X(CONTROL0)                                                                                                        \
    X(CONTROL1)                                                                                                        \
    X(CONTROL2)                                                                                                        \
    X(CONTROL3)                                                                                                        \
    X(READY)

typedef enum {
#define X(n) CHAN_##n,
    CHANNEL_STATES(X)
#undef X
        CHAN__MAX
} ldcp_CHANNEL_STATE;

LDCP_INTERNAL_API
const char *ldcp_channel_state2str(ldcp_CHANNEL_STATE state);

struct ldcp_CLIENT;

typedef struct {
    ldcp_SOCKET fd;
    struct event *evt;
    struct event *tmo;
    ldcp_RINGBUFFER in;
    ldcp_RINGBUFFER out;
    ldcp_ADDRINFO *ai_root;
    ldcp_ADDRINFO *ai;
    char host[NI_MAXHOST + 1];
    char port[NI_MAXSERV + 1];
    struct ldcp_CLIENT *client;
    ldcp_CONFIG *config;
    ldcp_CHANNEL_STATE state;
    uint32_t nbytes; /* number of received bytes */

    ldcp_STREAM_STATE streams[1024];

    int tcp_nodelay : 1;
    int tcp_keepalive : 1;

    int srvfeat_tls : 1;
    int srvfeat_tcpnodelay : 1;
    int srvfeat_mutation_seqno : 1;
    int srvfeat_tcpdelay : 1;
    int srvfeat_xattr : 1;
    int srvfeat_xerror : 1;
    int srvfeat_select_bucket : 1;
    int srvfeat_collections : 1;
    int srvfeat_snappy : 1;
    int srvfeat_json : 1;
    int srvfeat_duplex : 1;
    int srvfeat_clustermap_notif : 1;
    int srvfeat_unordered_exec : 1;
    int srvfeat_tracing : 1;
} ldcp_CHANNEL;

LDCP_INTERNAL_API
ldcp_CHANNEL *ldcp_channel_new(struct ldcp_CLIENT *client, const char *host, const char *port);

LDCP_INTERNAL_API
void ldcp_channel_free(ldcp_CHANNEL *chan);

LDCP_INTERNAL_API
void ldcp_channel_start(ldcp_CHANNEL *chan);

LDCP_INTERNAL_API
void ldcp_channel_ack(ldcp_CHANNEL *chan, uint32_t nbytes);

LDCP_INTERNAL_API
void ldcp_channel_handle_read(ldcp_CHANNEL *chan);

LDCP_INTERNAL_API
void ldcp_channel_connect(ldcp_CHANNEL *chan);

LDCP_INTERNAL_API
void ldcp_channel_start_connect(ldcp_CHANNEL *chan);

LDCP_INTERNAL_API
void ldcp_channel_start_stream(ldcp_CHANNEL *chan, int16_t partition);

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LDCP_CHANNEL_H */
