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

#ifndef LDCP_CLIENT_H
#define LDCP_CLIENT_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef void (*ldcp_EVTCALLBACK)(struct ldcp_CLIENT *client, ldcp_CALLBACK type, const ldcp_EVENT *evt);
typedef void (*ldcp_CFGCALLBACK)(struct ldcp_CLIENT *client);

typedef struct ldcp_CLIENT {
    ldcp_SETTINGS *settings;
    ldcp_IO *io;
    ldcp_SESSION *session;
    ldcp_CHANNEL **channels;
    int nchannels;
    int config_rev;
    ldcp_CONFIG *config;
    ldcp_CLIENT_TYPE type;
    char *username;
    char *password;
    char *bucket;
    char *uuid;
    /* bootstrap address */
    char host[NI_MAXHOST + 1];
    char port[NI_MAXSERV + 1];
    ldcp_CFGCALLBACK on_config;
    ldcp_EVTCALLBACK callbacks[LDCP_CALLBACK__MAX];
    void *cookie; /**< user specified opaque cookie */
} ldcp_CLIENT;

typedef struct ldcp_OPTIONS {
    uint32_t version;
    ldcp_SETTINGS *settings;
    ldcp_CLIENT_TYPE type;
    const char *host;
    const char *port;
    const char *bucket;
    const char *username;
    const char *password;
    void *cookie;
} ldcp_OPTIONS;

ldcp_OPTIONS *ldcp_options_new();
ldcp_STATUS ldcp_options_free(ldcp_OPTIONS *options);

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_new(ldcp_OPTIONS *options, ldcp_CLIENT **client);

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_dispatch(ldcp_CLIENT *client);

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_stop(ldcp_CLIENT *client);

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_bootstrap(ldcp_CLIENT *client);

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_free(ldcp_CLIENT *client);

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_number_partitions(ldcp_CLIENT *client, uint32_t *out);

LDCP_INTERNAL_API
ldcp_EVTCALLBACK ldcp_install_event_callback(ldcp_CLIENT *client, ldcp_CALLBACK type, ldcp_EVTCALLBACK cb);

LDCP_INTERNAL_API
ldcp_CFGCALLBACK ldcp_install_config_callback(ldcp_CLIENT *client, ldcp_CFGCALLBACK cb);

#ifdef __cplusplus
}
#    endif /* __cplusplus */

#endif /* LDCP_CLIENT_H */
