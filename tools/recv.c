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

#include <libdcp/dcp.h>
#include "internal.h"

#include <signal.h>

#define LOGARGS(lvl) settings, "recv", LDCP_LOG_##lvl, __FILE__, __LINE__

static ldcp_SETTINGS *settings = NULL;
static ldcp_CLIENT *client = NULL;

static int terminating = 0;

static void sigint_handler(int signum)
{
    ldcp_log(LOGARGS(INFO), "Terminating");
    if (!terminating) {
        ldcp_client_stop(client);
        terminating = 1;
    }
    (void)signum;
}

static void setup_sigint_handler()
{
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_handler = sigint_handler;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
}

static void sigquit_handler(int signum)
{
    fprintf(stderr, "\n");
    for (int ii = 0; ii < client->nchannels; ii++) {
        ldcp_CHANNEL *chan = client->channels[ii];
        fprintf(stderr, "[chan-%d] \"%s:%s\" idx=%d, bytes=%d, state=%s\n\t", ii, chan->host, chan->port,
                chan->config->idx, (int)chan->nbytes, ldcp_channel_state2str(chan->state));
        for (int jj = 0, cnt = 0; jj < sizeof(chan->streams) / sizeof(chan->streams[0]); jj++) {
            if (chan->streams[jj] != STREAM_NONE) {
                fprintf(stderr, "%03x ", jj);
                cnt++;
                if (cnt % 16 == 0) {
                    fprintf(stderr, "\n\t");
                }
            }
        }
        fprintf(stderr, "\n");
    }
    signal(SIGQUIT, sigquit_handler); // Reinstall
    (void)signum;
}

static void setup_sigquit_handler()
{
    struct sigaction action;
    sigemptyset(&action.sa_mask);
    action.sa_handler = sigquit_handler;
    action.sa_flags = 0;
    sigaction(SIGQUIT, &action, NULL);
}

int main(int argc, char *argv[])
{
    settings = ldcp_settings_new();
    ldcp_log(LOGARGS(INFO), "Starting up");

    setup_sigint_handler();
    setup_sigquit_handler();

    const char *host = "127.0.0.1";
    const char *port = "11210";
    const char *bucket = "default";
    const char *user = "Administrator";
    const char *password = "password";

    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = argv[2];
    }
    if (argc > 3) {
        bucket = argv[3];
    }
    if (argc > 4) {
        user = argv[4];
    }
    if (argc > 5) {
        password = argv[5];
    }

    client = ldcp_client_new(settings, host, port, bucket, user, password);
    ldcp_client_bootstrap(client);
    ldcp_client_dispatch(client);

    ldcp_log(LOGARGS(INFO), "Exiting");

    ldcp_client_free(client);
    ldcp_settings_unref(settings);
    return 0;
}
