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

#include <event2/event.h>

static void dummy_event_callback(ldcp_CLIENT *client, ldcp_EVENT_CALLBACK type, const ldcp_EVENT *evt)
{
    (void)client;
    (void)type;
    (void)evt;
}

static void dummy_resp_callback(ldcp_CLIENT *client, ldcp_RESP_CALLBACK type, const ldcp_RESP *resp)
{
    (void)client;
    (void)type;
    (void)resp;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_new(ldcp_OPTIONS *options, ldcp_CLIENT **client)
{
    if (options->version != 0) {
        return LDCP_BADARG;
    }

    ldcp_CLIENT *obj = calloc(1, sizeof(ldcp_CLIENT));
    obj->settings = options->settings;
    obj->type = options->type;
    strncpy(obj->host, options->host, sizeof(obj->host));
    strncpy(obj->port, options->port, sizeof(obj->port));
    obj->username = strdup(options->username);
    obj->password = strdup(options->password);
    obj->bucket = strdup(options->bucket);
    obj->session = ldcp_session_new(NULL);
    obj->io = ldcp_io_new();
    int cc;
    for (cc = 0; cc < LDCP_EVENT__MAX; cc++) {
        obj->on_event[cc] = dummy_event_callback;
    }
    for (cc = 0; cc < LDCP_RESP__MAX; cc++) {
        obj->on_resp[cc] = dummy_resp_callback;
    }
    obj->on_config = NULL;
    obj->cookie = options->cookie;
    *client = obj;
    return LDCP_OK;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_dispatch(ldcp_CLIENT *client)
{
    event_base_dispatch(client->io->evbase);
    return LDCP_OK;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_stop(ldcp_CLIENT *client)
{
    event_base_loopbreak(client->io->evbase);
    return LDCP_OK;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_bootstrap(ldcp_CLIENT *client)
{
    ldcp_CHANNEL *chan = ldcp_channel_new(client, client->host, client->port);
    client->nchannels = 1;
    client->channels = calloc(client->nchannels, sizeof(ldcp_CHANNEL *));
    client->channels[0] = chan;
    ldcp_channel_start(chan);
    return LDCP_OK;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_free(ldcp_CLIENT *client)
{
    if (client) {
        free(client->username);
        free(client->password);
        free(client->bucket);
        free(client->uuid);
        ldcp_session_free(client->session);
        if (client->nchannels && client->channels) {
            int ii;
            for (ii = 0; ii < client->nchannels; ii++) {
                ldcp_channel_free(client->channels[ii]);
                client->channels[ii] = NULL;
            }
        }
    }
    free(client);
    return LDCP_OK;
}

LDCP_INTERNAL_API
ldcp_CFGCALLBACK ldcp_install_config_callback(ldcp_CLIENT *client, ldcp_CFGCALLBACK cb)
{
    ldcp_CFGCALLBACK old = client->on_config;
    client->on_config = cb;
    return old;
}

LDCP_INTERNAL_API
ldcp_EVTCALLBACK ldcp_install_event_callback(ldcp_CLIENT *client, ldcp_EVENT_CALLBACK type, ldcp_EVTCALLBACK cb)
{
    if (type >= LDCP_CALLBACK__MAX || type < 0) {
        return NULL;
    }
    ldcp_EVTCALLBACK old = client->on_event[type];
    if (cb == NULL) {
        cb = dummy_event_callback;
    }
    client->on_event[type] = cb;
    if (old == dummy_event_callback) {
        return NULL;
    }
    return old;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_set_with_meta(ldcp_CLIENT *client, ldcp_CMD_SETWITHMETA *cmd, void *opaque)
{
    return LDCP_OK;
}

LDCP_INTERNAL_API
ldcp_RESPCALLBACK ldcp_install_resp_callback(ldcp_CLIENT *client, ldcp_RESP_CALLBACK type, ldcp_RESPCALLBACK cb)
{
    if (type >= LDCP_RESP_CALLBACK__MAX || type < 0) {
        return NULL;
    }
    ldcp_RESPCALLBACK old = client->on_resp[type];
    if (cb == NULL) {
        cb = dummy_resp_callback;
    }
    client->on_resp[type] = cb;
    if (old == dummy_resp_callback) {
        return NULL;
    }
    return old;
}

LDCP_INTERNAL_API
ldcp_OPTIONS *ldcp_options_new()
{
    ldcp_OPTIONS *obj = calloc(1, sizeof(ldcp_OPTIONS));
    obj->version = 0;
    return obj;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_options_free(ldcp_OPTIONS *options)
{
    free(options);
    return LDCP_OK;
}

LDCP_INTERNAL_API
ldcp_STATUS ldcp_client_number_partitions(ldcp_CLIENT *client, uint32_t *out)
{
    if (client->config == NULL) {
        return LDCP_NOCONFIG;
    }
    *out = client->config->npartitions;
    return LDCP_OK;
}
