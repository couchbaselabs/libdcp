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

LDCP_INTERNAL_API
ldcp_CLIENT *ldcp_client_new(ldcp_SETTINGS *settings, const char *host, const char *port, const char *bucket,
                             const char *username, const char *password)
{
    ldcp_CLIENT *client = calloc(1, sizeof(ldcp_CLIENT));
    client->settings = settings;
    strncpy(client->host, host, sizeof(client->host));
    strncpy(client->port, port, sizeof(client->port));
    client->username = strdup(username);
    client->password = strdup(password);
    client->bucket = strdup(bucket);
    client->session = ldcp_session_new(NULL);
    client->io = ldcp_io_new();
}

LDCP_INTERNAL_API
void ldcp_client_dispatch(ldcp_CLIENT *client)
{
    event_base_dispatch(client->io->evbase);
}

LDCP_INTERNAL_API
void ldcp_client_stop(ldcp_CLIENT *client)
{
    event_base_loopbreak(client->io->evbase);
}

LDCP_INTERNAL_API
void ldcp_client_bootstrap(ldcp_CLIENT *client)
{
    ldcp_CHANNEL *chan = ldcp_channel_new(client, client->host, client->port);
    client->nchannels = 1;
    client->channels = calloc(client->nchannels, sizeof(ldcp_CHANNEL *));
    client->channels[0] = chan;
    ldcp_channel_start(chan);
}

LDCP_INTERNAL_API
void ldcp_client_free(ldcp_CLIENT *client)
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
}
