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

#include <event2/event.h>

#define BUFSIZE 10
#define TIMEOUT_SEC 3

#define LOGARGS(lvl) settings, "send", LDCP_LOG_##lvl, __FILE__, __LINE__

static int counter = 0;

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

static void event_handle_read(ldcp_RINGBUFFER *rb)
{
    size_t nkey;
    char *key;

    nkey = rb->nbytes;
    key = malloc(nkey);

    ldcp_rb_read(rb, key, nkey);
    key[--nkey] = '\0';

    int idx = 0;
    uint16_t partition = 0;
    ldcp_config_map_key(client->config, key, nkey, &idx, &partition);
    fprintf(stderr, "key: \"%s\", idx=%d, partition=%d\n", key, idx, (int)partition);
    ldcp_CHANNEL *chan = client->channels[idx];
    {
        protocol_binary_request_dcp_snapshot_marker frame = {0};

        frame.message.header.request.magic = PROTOCOL_BINARY_REQ;
        frame.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
        frame.message.header.request.opcode = PROTOCOL_BINARY_CMD_DCP_SNAPSHOT_MARKER;
        frame.message.header.request.vbucket = htons(partition);
        frame.message.header.request.extlen = 20;
        frame.message.header.request.bodylen = htonl(frame.message.header.request.extlen);
        frame.message.body.start_seqno = ldcp_htonll(counter);
        frame.message.body.end_seqno = ldcp_htonll(counter + 1);
        ldcp_rb_ensure_capacity(&chan->out, sizeof(frame.bytes));
        ldcp_rb_write(&chan->out, frame.bytes, sizeof(frame.bytes));
    }
    {
        char val[256] = {0};
        snprintf(val, sizeof(val), "{\"counter\":%d}", (int)counter);
        size_t nval = strlen(val);

        protocol_binary_request_dcp_mutation frame = {0};
        frame.message.header.request.magic = PROTOCOL_BINARY_REQ;
        frame.message.header.request.datatype = PROTOCOL_BINARY_DATATYPE_JSON;
        frame.message.header.request.opcode = PROTOCOL_BINARY_CMD_DCP_MUTATION;
        frame.message.header.request.vbucket = htons(partition);
        frame.message.header.request.extlen = 32;
        frame.message.header.request.keylen = htons(nkey);
        frame.message.header.request.bodylen = htonl(frame.message.header.request.extlen + nkey + nval);
        frame.message.body.by_seqno = ldcp_htonll(counter);
        frame.message.body.rev_seqno = ldcp_htonll(counter);
        ldcp_rb_ensure_capacity(&chan->out, sizeof(frame.bytes) + nkey + nval);
        ldcp_rb_write(&chan->out, frame.bytes, sizeof(frame.bytes));
        ldcp_rb_write(&chan->out, key, nkey);
        ldcp_rb_write(&chan->out, val, nval);
    }

    counter += 1;

    free(key);
}

static void event_handler(int fd, short event, void *arg)
{
    ldcp_RINGBUFFER *rb = arg;

    if (event & EV_READ) {
        do {
            ldcp_IOV iov[2] = {0};
            if (rb->nbytes == rb->size) {
                ldcp_rb_ensure_capacity(rb, 1);
            }
            ldcp_rb_get_iov(rb, LDCP_RINGBUFFER_WRITE, iov);
            ssize_t rv;
        DO_READ_AGAIN:
            rv = readv(fd, (struct iovec *)iov, 2);
            if (rv > 0) {
                ldcp_rb_produced(rb, rv);
            } else if (rv < 0) {
                switch (errno) {
                    case EINTR:
                        goto DO_READ_AGAIN;
                    case EWOULDBLOCK:
#ifdef USE_EAGAIN
                    case EAGAIN:
#endif
                        event_handle_read(rb);
                        return;
                    default:
                        ldcp_log(LOGARGS(ERROR), "Failed to read data from stdin: %s", strerror(errno));
                        return;
                }
            } else {
                return;
            }
        } while (1);
    }
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

    client = ldcp_client_new(settings, TYPE_CONSUMER, host, port, bucket, user, password);
    ldcp_client_bootstrap(client);

    ldcp_RINGBUFFER rb;
    ldcp_rb_init(&rb, 8192);

    struct event *ev;
    fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) | O_NONBLOCK);
    ev = event_new(client->io->evbase, fileno(stdin), EV_TIMEOUT | EV_READ | EV_PERSIST, event_handler, &rb);
    event_add(ev, NULL);

    ldcp_client_dispatch(client);

    ldcp_log(LOGARGS(INFO), "Exiting");

    ldcp_client_free(client);
    ldcp_settings_unref(settings);
    return 0;
}
