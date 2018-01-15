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
#include <event2/listener.h>
#include <event2/dns.h>

static ldcp_SETTINGS *settings = NULL;

#define LOGARGS(lvl) settings, "recv", LDCP_LOG_##lvl, __FILE__, __LINE__

#ifdef _WIN32
#    define flockfile(x) (void)0
#    define funlockfile(x) (void)0
#endif

static void dump_bytes(const char *msg, const void *ptr, size_t len)
{

    int width = 16;
    const unsigned char *buf = (const unsigned char *)ptr;
    size_t full_rows = len / width;
    size_t remainder = len % width;

    flockfile(stderr);
    fprintf(stderr,
            "%s, %d bytes\n"
            "         +-------------------------------------------------+\n"
            "         |  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f |\n"
            "+--------+-------------------------------------------------+----------------+",
            msg, len);

    unsigned int row = 0;
    while (row < full_rows) {
        int row_start_index = row * width;
        // prefix
        fprintf(stderr, "\n|%08x|", row_start_index);
        int row_end_index = row_start_index + width;
        // hex
        int i = row_start_index;
        while (i < row_end_index) {
            fprintf(stderr, " %02x", (unsigned int)buf[i++]);
        }
        fprintf(stderr, " |");
        // ascii
        i = row_start_index;
        while (i < row_end_index) {
            char b = buf[i++];
            if ((b <= 0x1f) || (b >= 0x7f)) {
                fprintf(stderr, ".");
            } else {
                fprintf(stderr, "%c", b);
            }
        }
        fprintf(stderr, "|");
        row++;
    }
    if (remainder != 0) {
        int row_start_index = full_rows * width;
        // prefix
        fprintf(stderr, "\n|%08x|", row_start_index);
        int row_end_index = row_start_index + remainder;
        // hex
        int i = row_start_index;
        while (i < row_end_index) {
            fprintf(stderr, " %02x", (unsigned int)buf[i++]);
        }
        i = width - remainder;
        while (i > 0) {
            fprintf(stderr, "   ");
            i--;
        }
        fprintf(stderr, " |");
        // ascii
        i = row_start_index;
        while (i < row_end_index) {
            char b = buf[i++];
            if ((b <= 0x1f) || (b >= 0x7f)) {
                fprintf(stderr, ".");
            } else {
                fprintf(stderr, "%c", b);
            }
        }
        i = width - remainder;
        while (i > 0) {
            fprintf(stderr, " ");
            i--;
        }
        fprintf(stderr, "|");
    }
    fprintf(stderr, "\n+--------+-------------------------------------------------+----------------+\n");
    funlockfile(stderr);
}

struct ldcp_ADDRINFO;
typedef struct ldcp_ADDRINFO {
    int family; /* AF_INET, AF_INET6 */
    size_t addrlen;
    struct sockaddr *addr;
    struct ldcp_ADDRINFO *next;
} ldcp_ADDRINFO;

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

static const char *ldcp_channel_state2str(ldcp_CHANNEL_STATE state)
{
    switch (state) {
#define X(n)                                                                                                           \
    case CHAN_##n:                                                                                                     \
        return #n;
        CHANNEL_STATES(X)
#undef X
    }
    return "UNKNOWN";
}

struct ldcp_FAILOVER_ENTRY;
typedef struct ldcp_FAILOVER_ENTRY {
    uint64_t uuid;
    uint64_t seqno;
    struct ldcp_FAILOVER_ENTRY *prev;
} ldcp_FAILOVER_ENTRY;

typedef struct {
    ldcp_FAILOVER_ENTRY *newest;
    ldcp_FAILOVER_ENTRY *oldest;
    size_t size;
} ldcp_FAILOVER_LOG;

static void ldcp_failover_log_append(ldcp_FAILOVER_LOG *log, uint64_t uuid, uint64_t seqno)
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

typedef struct {
    char *name;
    int16_t npartitions;
    ldcp_FAILOVER_LOG *failover_logs;
} ldcp_SESSION;

static ldcp_SESSION *ldcp_session_new(char *name)
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

static void ldcp_session_init_failover_logs(ldcp_SESSION *session, int16_t npartitions)
{
    session->npartitions = npartitions;
    session->failover_logs = calloc(npartitions, sizeof(ldcp_FAILOVER_LOG));
}

static void ldcp_session_free(ldcp_SESSION *session)
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

static ldcp_CONFIG *ldcp_config_new()
{
    return calloc(1, sizeof(ldcp_CONFIG));
}

static void ldcp_config_free(ldcp_CONFIG *config)
{
    if (config) {
        free(config->uuid);
        free(config->servers);
        free(config->partitions);
    }
    free(config);
}

static ldcp_CONFIG *ldcp_config_parse(const char *body, const char *this_host)
{
    ldcp_CONFIG *config = NULL;
    cJSON *root = cJSON_Parse(body);
    /* printf("%s\n", body); */
    if (root) {
        cJSON *val;
        config = ldcp_config_new();

        val = cJSON_GetObjectItem(root, "uuid");
        if (val && val->type == cJSON_String) {
            config->uuid = strdup(val->valuestring);
        }
        val = cJSON_GetObjectItem(root, "rev");
        if (val && val->type == cJSON_Number) {
            config->rev = val->valueint;
        }

        cJSON *nodes = cJSON_GetObjectItem(root, "nodesExt");
        if (nodes && nodes->type == cJSON_Array) {
            config->nservers = cJSON_GetArraySize(nodes);
            config->servers = calloc(config->nservers, sizeof(ldcp_SERVER));
            int ii;
            for (ii = 0; ii < config->nservers; ii++) {
                cJSON *srv = cJSON_GetArrayItem(nodes, ii);
                if (srv && srv->type == cJSON_Object) {
                    cJSON *tmp = cJSON_GetObjectItem(srv, "hostname");
                    strcpy(config->servers[ii].host, (tmp && tmp->type == cJSON_String) ? tmp->valuestring : this_host);
                    val = cJSON_GetObjectItem(srv, "services");
                    if (val && val->type == cJSON_Object) {
                        tmp = cJSON_GetObjectItem(val, "kv");
                        if (tmp && tmp->type == cJSON_Number) {
                            config->servers[ii].port.kv = tmp->valueint;
                        }
                        tmp = cJSON_GetObjectItem(val, "kvSSL");
                        if (tmp && tmp->type == cJSON_Number) {
                            config->servers[ii].port.kv_s = tmp->valueint;
                        }
                    }
                    tmp = cJSON_GetObjectItem(srv, "thisNode");
                    if (tmp && tmp->type == cJSON_True) {
                        config->idx = ii;
                    }
                }
            }
        }

        val = cJSON_GetObjectItem(root, "vBucketServerMap");
        if (val && val->type == cJSON_Object) {
            cJSON *map;
            map = cJSON_GetObjectItem(val, "vBucketMap");
            /* fprintf(stderr, "%s\n", cJSON_PrintUnformatted(map)); */
            if (map && map->type == cJSON_Array) {
                config->npartitions = cJSON_GetArraySize(map);
                config->partitions = malloc(config->npartitions * sizeof(ldcp_PARTITION));
                int ii;
                for (ii = 0; ii < config->npartitions; ii++) {
                    cJSON *pp = cJSON_GetArrayItem(map, ii);
                    if (pp && pp->type == cJSON_Array) {
                        cJSON *tmp;
                        tmp = cJSON_GetArrayItem(pp, 0);
                        config->partitions[ii].master = (tmp && tmp->type == cJSON_Number) ? tmp->valueint : -1;
                        tmp = cJSON_GetArrayItem(pp, 1);
                        config->partitions[ii].replica[0] = (tmp && tmp->type == cJSON_Number) ? tmp->valueint : -1;
                        tmp = cJSON_GetArrayItem(pp, 2);
                        config->partitions[ii].replica[1] = (tmp && tmp->type == cJSON_Number) ? tmp->valueint : -1;
                        tmp = cJSON_GetArrayItem(pp, 3);
                        config->partitions[ii].replica[2] = (tmp && tmp->type == cJSON_Number) ? tmp->valueint : -1;
                    }
                }
            }
        }
        cJSON_Delete(root);
    }
    return config;
}

static void dns_logfn(int is_warn, const char *msg);
static void gai_callback(int err, struct evutil_addrinfo *ai, void *arg);

typedef struct {
    struct event_base *evbase;
    struct evdns_base *evdns_base;
} ldcp_IO;

static ldcp_IO *ldcp_io_new()
{
    ldcp_IO *io = calloc(1, sizeof(ldcp_IO));

    io->evbase = event_base_new();
    io->evdns_base = evdns_base_new(io->evbase, 1);
    evdns_set_log_fn(dns_logfn);

    return io;
}

static void ldcp_io_free(ldcp_IO *io)
{
    evdns_base_free(io->evdns_base, 1);
    event_base_free(io->evbase);
    free(io);
}

typedef enum { STREAM_NONE, STREAM_OPENING, STREAM_OPEN } ldcp_STREAM_STATE;

#define DEFAULT_DCP_CONNECTION_BUFFER_SIZE 20971520
#define DEFAULT_DCP_CONNECTION_ACK_THRESHOLD (DEFAULT_DCP_CONNECTION_BUFFER_SIZE / 100 * 80)

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

typedef struct ldcp_CLIENT {
    ldcp_IO *io;
    ldcp_SESSION *session;
    ldcp_CHANNEL **channels;
    int nchannels;
    char *username;
    char *password;
    char *bucket;
    char *uuid;
    /* bootstrap address */
    char host[NI_MAXHOST + 1];
    char port[NI_MAXSERV + 1];
    int config_rev;
} ldcp_CLIENT;

static ldcp_CLIENT *client = NULL;

static void dns_logfn(int is_warn, const char *msg)
{
    if (is_warn) {
        ldcp_log(LOGARGS(WARN), msg);
    } else {
        ldcp_log(LOGARGS(INFO), msg);
    }
}

static ldcp_CHANNEL *ldcp_channel_new(ldcp_CLIENT *client, const char *host, const char *port)
{
    ldcp_CHANNEL *chan = calloc(1, sizeof(ldcp_CHANNEL));
    chan->client = client;
    chan->evt = event_new(client->io->evbase, INVALID_SOCKET, 0, NULL, NULL);
    chan->tmo = evtimer_new(client->io->evbase, NULL, NULL);
    chan->fd = socket(PF_INET, SOCK_STREAM, 0);
    if (chan->fd == INVALID_SOCKET) {
        ldcp_log(LOGARGS(ERROR), "Failed to create socket: %s", strerror(errno));
        return NULL;
    }
    evutil_make_socket_nonblocking(chan->fd);
    chan->evt = event_new(client->io->evbase, chan->fd, 0, NULL, NULL);
    strncpy(chan->host, host, sizeof(chan->host));
    strncpy(chan->port, port, sizeof(chan->port));
    ldcp_rb_ensure_capacity(&chan->in, 8192);
    ldcp_rb_ensure_capacity(&chan->out, 8192);
    return chan;
}

static void ldcp_channel_free(ldcp_CHANNEL *chan)
{
    if (chan) {
        if (chan->fd != INVALID_SOCKET) {
            close(chan->fd);
            chan->fd = INVALID_SOCKET;
        }
        ldcp_ADDRINFO *ai;
        for (ai = chan->ai_root; ai;) {
            if (ai->addr) {
                free(ai->addr);
                ai->addr = NULL;
            }
            ldcp_ADDRINFO *tmp = ai;
            ai = ai->next;
            free(tmp);
        }
        ldcp_rb_destruct(&chan->in);
        ldcp_rb_destruct(&chan->out);
    }
    free(chan);
}

static void ldcp_channel_start(ldcp_CHANNEL *chan)
{
    struct evutil_addrinfo hints = {0};
    hints.ai_family = PF_UNSPEC;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    evdns_getaddrinfo(client->io->evdns_base, chan->host, chan->port, &hints, gai_callback, chan);
}

static void send_start_stream(ldcp_CHANNEL *chan, int16_t partition);

static void handle_rebalance(ldcp_CLIENT *client, ldcp_CONFIG *config)
{

    if (config->rev <= client->config_rev) {
        ldcp_log(LOGARGS(DEBUG), "Skip new configuration rev. %d (active rev. %d)", config->rev, client->config_rev);
        return;
    }
    client->config_rev = config->rev;

    ldcp_CHANNEL **new = NULL;

    new = calloc(config->nservers, sizeof(ldcp_CHANNEL *));
    for (int ii = 0; ii < client->nchannels; ii++) {
        ldcp_CHANNEL *chan = client->channels[ii];
        if (chan->state == CHAN_ERROR || chan->state == CHAN_EOF) {
            continue;
        }
        ldcp_SERVER *srv = &chan->config->servers[chan->config->idx];
        int idx = -1;
        for (int jj = 0; jj < config->nservers; jj++) {
            if (new[jj] == NULL && srv->port.kv == config->servers[jj].port.kv &&
                (strcmp(srv->host, config->servers[jj].host) == 0)) {
                idx = jj;
                break;
            }
        }
        if (idx >= 0) {
            ldcp_PARTITION *cur = chan->config->partitions;
            for (int pp = 0; pp < config->npartitions; pp++) {
                if (config->partitions[pp].master != cur[pp].master && config->partitions[pp].master == idx &&
                    chan->streams[pp] == STREAM_NONE) {
                    send_start_stream(chan, pp);
                }
            }
            new[idx] = chan;
        }
    }
    for (int ii = 0; ii < config->nservers; ii++) {
        if (new[ii] == NULL) {
            char port[NI_MAXSERV + 1] = {0};
            snprintf(port, sizeof(port), "%d", (int)config->servers[ii].port.kv);
            new[ii] = ldcp_channel_new(client, config->servers[ii].host, port);
            ldcp_channel_start(new[ii]);
        }
    }
    free(client->channels);
    client->channels = new;
    client->nchannels = config->nservers;
}

static ldcp_CLIENT *ldcp_client_new(const char *host, const char *port, const char *bucket, const char *username,
                                    const char *password)
{
    ldcp_CLIENT *client = calloc(1, sizeof(ldcp_CLIENT));
    strncpy(client->host, host, sizeof(client->host));
    strncpy(client->port, port, sizeof(client->port));
    client->username = strdup(username);
    client->password = strdup(password);
    client->bucket = strdup(bucket);
    client->session = ldcp_session_new(NULL);
    client->io = ldcp_io_new();
}

static void ldcp_client_dispatch(ldcp_CLIENT *client)
{
    event_base_dispatch(client->io->evbase);
}

static void ldcp_client_stop(ldcp_CLIENT *client)
{
    event_base_loopbreak(client->io->evbase);
}

static void ldcp_client_bootstrap(ldcp_CLIENT *client)
{
    ldcp_CHANNEL *chan = ldcp_channel_new(client, client->host, client->port);
    client->nchannels = 1;
    client->channels = calloc(client->nchannels, sizeof(ldcp_CHANNEL *));
    client->channels[0] = chan;
    ldcp_channel_start(chan);
}

static void ldcp_client_free(ldcp_CLIENT *client)
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

#define LDCP_HELLO_DEFL_STRING LDCP_ID
#define LDCP_HELLO_DEFL_LENGTH (sizeof(LDCP_HELLO_DEFL_STRING) - 1)

#define HELLO_FEATURES(X)                                                                                              \
    X(PROTOCOL_BINARY_FEATURE_TLS, tls, "TLS")                                                                         \
    X(PROTOCOL_BINARY_FEATURE_TCPNODELAY, tcpnodelay, "TCPNODELAY")                                                    \
    X(PROTOCOL_BINARY_FEATURE_MUTATION_SEQNO, mutation_seqno, "MUTATION_SEQNO")                                        \
    X(PROTOCOL_BINARY_FEATURE_TCPDELAY, tcpdelay, "TCPDELAY")                                                          \
    X(PROTOCOL_BINARY_FEATURE_XATTR, xattr, "XATTR")                                                                   \
    X(PROTOCOL_BINARY_FEATURE_XERROR, xerror, "XERROR")                                                                \
    X(PROTOCOL_BINARY_FEATURE_SELECT_BUCKET, select_bucket, "SELECT_BUCKET")                                           \
    X(PROTOCOL_BINARY_FEATURE_COLLECTIONS, collections, "COLLECTIONS")                                                 \
    X(PROTOCOL_BINARY_FEATURE_SNAPPY, snappy, "SNAPPY")                                                                \
    X(PROTOCOL_BINARY_FEATURE_JSON, json, "JSON")                                                                      \
    X(PROTOCOL_BINARY_FEATURE_DUPLEX, duplex, "DUPLEX")                                                                \
    X(PROTOCOL_BINARY_FEATURE_CLUSTERMAP_CHANGE_NOTIFICATION, clustermap_notif, "CLUSTERMAP_NOTIF")                    \
    X(PROTOCOL_BINARY_FEATURE_UNORDERED_EXECUTION, unordered_exec, "UNORDERED_EXEC")                                   \
    X(PROTOCOL_BINARY_FEATURE_TRACING, tracing, "TRACING")

static void send_hello(ldcp_CHANNEL *chan)
{
    uint16_t features[MEMCACHED_TOTAL_HELLO_FEATURES];
    unsigned nfeatures = 0;

    if (chan->tcp_nodelay) {
        features[nfeatures++] = PROTOCOL_BINARY_FEATURE_TCPNODELAY;
    }
    features[nfeatures++] = PROTOCOL_BINARY_FEATURE_XATTR;
    features[nfeatures++] = PROTOCOL_BINARY_FEATURE_SELECT_BUCKET;
    features[nfeatures++] = PROTOCOL_BINARY_FEATURE_DUPLEX;
    features[nfeatures++] = PROTOCOL_BINARY_FEATURE_CLUSTERMAP_CHANGE_NOTIFICATION;

    protocol_binary_request_header hdr = {0};
    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_HELLO;
    hdr.request.keylen = htons(LDCP_HELLO_DEFL_LENGTH);
    uint32_t bodylen = LDCP_HELLO_DEFL_LENGTH + sizeof(features[0]) * nfeatures;
    hdr.request.bodylen = htonl(bodylen);

    ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr) + bodylen);
    ldcp_rb_write(&chan->out, &hdr, sizeof(hdr));
    ldcp_rb_write(&chan->out, LDCP_HELLO_DEFL_STRING, LDCP_HELLO_DEFL_LENGTH);

    char list[256] = {0};
    int off = 0;
    for (unsigned ii = 0; ii < nfeatures; ii++) {
        uint16_t tmp = htons(features[ii]);
        ldcp_rb_write(&chan->out, &tmp, sizeof(tmp));
        switch (features[ii]) {
#define X(FEAT, FLAG, NAME)                                                                                            \
    case FEAT:                                                                                                         \
        off += snprintf(list + off, sizeof(list) - off, "%s" NAME "(0x%02x)", off ? "," : "", FEAT);                   \
        break;

            HELLO_FEATURES(X)
#undef X
        }
    }

    ldcp_log(LOGARGS(DEBUG), "HELLO \"%s\", features: [%s]", LDCP_HELLO_DEFL_STRING, list);
}

static int read_hello(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void *body, uint32_t nbody)
{
    if (nbody % 2 != 0) {
        return -1;
    }
    const char *payload = (char *)body;
    const char *cur;
    const char *limit = payload + nbody;
    char list[256] = {0};
    int off = 0;

    for (cur = payload; cur < limit; cur += 2) {
        uint16_t tmp;
        memcpy(&tmp, cur, sizeof(tmp));
        tmp = ntohs(tmp);
        switch (tmp) {
#define X(FEAT, FLAG, NAME)                                                                                            \
    case FEAT:                                                                                                         \
        chan->srvfeat_##FLAG = 1;                                                                                      \
        off += snprintf(list + off, sizeof(list) - off, "%s" NAME "(0x%02x)", off ? "," : "", FEAT);                   \
        break;

            HELLO_FEATURES(X)
#undef X
        }
    }
    ldcp_log(LOGARGS(DEBUG), "Server supports features: [%s], fd=%d", list, chan->fd);
    if (chan->srvfeat_select_bucket == 0) {
        ldcp_log(LOGARGS(ERROR), "Server does not support SELECT_BUCKET: fd=%d", chan->fd);
        return -1;
    }
    return 0;
}

static void read_and_upgrade_config(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void *body,
                                    uint32_t nbody)
{
    const char *payload = (char *)body;
    ldcp_CONFIG *config = NULL;

    if (hdr->response.extlen >= sizeof(uint32_t)) {
        uint32_t rev;
        memcpy(&rev, payload, sizeof(rev));
        rev = ntohl(rev);
        if (chan->config && chan->config->rev >= rev) {
            return;
        }
        payload += sizeof(rev);
    }
    payload += ntohs(hdr->response.keylen); /* ignore bucket name */

    config = ldcp_config_parse(payload, chan->host);
    if (config) {
        if (chan->config) {
            ldcp_config_free(chan->config);
        }
        chan->config = config;
        if (chan->client->session->failover_logs == NULL) {
            ldcp_session_init_failover_logs(chan->client->session, config->npartitions);
        }
        if (chan->client->uuid == NULL) {
            chan->client->uuid = strdup(config->uuid);
        } // else check for matching UUID
        ldcp_log(LOGARGS(DEBUG), "New config rev=%d, uuid=0x%s, fd=%d", config->rev, config->uuid, chan->fd);
    }

    handle_rebalance(chan->client, config);
    return;
}

#define LDCP_AUTH_MECH "PLAIN"
#define LDCP_AUTH_MECH_LENGTH (sizeof(LDCP_AUTH_MECH) - 1)

static void send_auth(ldcp_CHANNEL *chan)
{
    protocol_binary_request_header hdr = {0};
    uint32_t nusername = strlen(chan->client->username);
    uint32_t npassword = strlen(chan->client->password);

    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_SASL_AUTH;
    hdr.request.keylen = htons(LDCP_AUTH_MECH_LENGTH);
    uint32_t bodylen = LDCP_AUTH_MECH_LENGTH + nusername + npassword + 2;
    hdr.request.bodylen = htonl(bodylen);

    ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr) + bodylen);
    ldcp_rb_write(&chan->out, &hdr, sizeof(hdr));
    ldcp_rb_write(&chan->out, LDCP_AUTH_MECH, LDCP_AUTH_MECH_LENGTH);

    char sep = '\0';
    ldcp_rb_write(&chan->out, &sep, 1);
    ldcp_rb_write(&chan->out, chan->client->username, nusername);
    ldcp_rb_write(&chan->out, &sep, 1);
    ldcp_rb_write(&chan->out, chan->client->password, npassword);
}

static void send_select_bucket(ldcp_CHANNEL *chan)
{
    protocol_binary_request_header hdr = {0};
    uint32_t nbucket = strlen(chan->client->bucket);

    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_SELECT_BUCKET;
    hdr.request.keylen = htons(nbucket);
    hdr.request.bodylen = htonl(nbucket);

    ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr) + nbucket);
    ldcp_rb_write(&chan->out, &hdr, sizeof(hdr));
    ldcp_rb_write(&chan->out, chan->client->bucket, nbucket);
}

static void send_get_config(ldcp_CHANNEL *chan)
{
    protocol_binary_request_header hdr = {0};
    uint32_t nbucket = strlen(chan->client->bucket);

    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG;

    ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr));
    ldcp_rb_write(&chan->out, &hdr, sizeof(hdr));
}

static void send_dcp_open(ldcp_CHANNEL *chan)
{
    protocol_binary_request_dcp_open frame = {0};
    uint16_t keylen = strlen(chan->client->session->name);

    frame.message.header.request.magic = PROTOCOL_BINARY_REQ;
    frame.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    frame.message.header.request.opcode = PROTOCOL_BINARY_CMD_DCP_OPEN;
    frame.message.header.request.extlen = sizeof(frame.message.body);
    frame.message.header.request.keylen = htons(keylen);
    frame.message.header.request.bodylen = htonl(sizeof(frame.message.body) + keylen);
    frame.message.body.flags = htonl(DCP_OPEN_PRODUCER | DCP_OPEN_INCLUDE_XATTRS);

    ldcp_rb_ensure_capacity(&chan->out, sizeof(frame.bytes) + keylen);
    ldcp_rb_write(&chan->out, frame.bytes, sizeof(frame.bytes));
    ldcp_rb_write(&chan->out, chan->client->session->name, keylen);
}

static void send_dcp_control(ldcp_CHANNEL *chan)
{
    protocol_binary_request_header hdr = {0};
    uint16_t keylen = strlen(chan->client->session->name);

    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_DCP_CONTROL;

#define STRLEN(s) sizeof(s) - 1
    {
        const char key[] = "enable_noop";
        const char val[] = "true";
        hdr.request.keylen = htons(STRLEN(key));
        hdr.request.bodylen = htonl(STRLEN(key) + STRLEN(val));
        ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr.bytes) + STRLEN(key) + STRLEN(val));
        ldcp_rb_write(&chan->out, hdr.bytes, sizeof(hdr.bytes));
        ldcp_rb_write(&chan->out, key, STRLEN(key));
        ldcp_rb_write(&chan->out, val, STRLEN(val));
    }
    {
        const char key[] = "set_noop_interval";
        const char val[] = "120"; /* seconds */
        hdr.request.keylen = htons(STRLEN(key));
        hdr.request.bodylen = htonl(STRLEN(key) + STRLEN(val));
        ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr.bytes) + STRLEN(key) + STRLEN(val));
        ldcp_rb_write(&chan->out, hdr.bytes, sizeof(hdr.bytes));
        ldcp_rb_write(&chan->out, key, STRLEN(key));
        ldcp_rb_write(&chan->out, val, STRLEN(val));
    }
    {
        const char key[] = "connection_buffer_size";
        char val[11] = {0}; /* max uint32, in bytes */
        snprintf(val, sizeof(val), "%d", DEFAULT_DCP_CONNECTION_BUFFER_SIZE);
        hdr.request.keylen = htons(STRLEN(key));
        hdr.request.bodylen = htonl(STRLEN(key) + STRLEN(val));
        ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr.bytes) + STRLEN(key) + STRLEN(val));
        ldcp_rb_write(&chan->out, hdr.bytes, sizeof(hdr.bytes));
        ldcp_rb_write(&chan->out, key, STRLEN(key));
        ldcp_rb_write(&chan->out, val, STRLEN(val));
    }
#undef STRLEN
    chan->state = CHAN_CONTROL0;
}

static void send_get_failover_logs(ldcp_CHANNEL *chan)
{
    ldcp_CONFIG *config = chan->config;
    protocol_binary_request_header hdr = {0};

    hdr.request.magic = PROTOCOL_BINARY_REQ;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_DCP_GET_FAILOVER_LOG;

    ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr) * (config->npartitions / config->nservers));
    int16_t ii;
    for (ii = 0; ii < config->npartitions; ii++) {
        if (config->partitions[ii].master == config->idx) {
            hdr.request.vbucket = htons(ii);
            hdr.request.opaque = htonl(ii);
            ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr));
            ldcp_rb_write(&chan->out, &hdr, sizeof(hdr));
        }
    }
}

static int read_failover_log(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void *body, uint32_t nbody)
{
    int16_t partition = (int16_t)ntohl(hdr->response.opaque);
    ldcp_SESSION *session = chan->client->session;

    if (nbody % 16 != 0) {
        return -1;
    }
    const char *cur, *end = body + nbody;
    for (cur = body; cur < end; cur += 16) {
        uint64_t uuid;
        uint64_t seqno;
        memcpy(&uuid, cur, sizeof(uuid));
        uuid = ldcp_ntohll(uuid);
        memcpy(&seqno, cur + 8, sizeof(seqno));
        seqno = ldcp_ntohll(seqno);
        ldcp_failover_log_append(&session->failover_logs[partition], uuid, seqno);
    }
    return 0;
}

#define SEQNO_MIN 0x0000000000000000ull
#define SEQNO_MAX 0xffffffffffffffffull

static void send_start_stream(ldcp_CHANNEL *chan, int16_t partition)
{
    if (chan->streams[partition] != STREAM_NONE) {
        return;
    }
    ldcp_SESSION *session = chan->client->session;
    ldcp_CONFIG *config = chan->config;
    protocol_binary_request_dcp_stream_req frame = {0};
    frame.message.header.request.magic = PROTOCOL_BINARY_REQ;
    frame.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    frame.message.header.request.opcode = PROTOCOL_BINARY_CMD_DCP_STREAM_REQ;
    frame.message.header.request.opaque = htonl(partition);
    frame.message.header.request.extlen = sizeof(frame.message.body);
    frame.message.header.request.bodylen = htonl(frame.message.header.request.extlen);
    frame.message.header.request.vbucket = htons(partition);
    frame.message.body.flags = DCP_STREAM_ACTIVE_VB_ONLY | DCP_STREAM_STRICT_VBUUID;
    frame.message.body.start_seqno = SEQNO_MIN;
    frame.message.body.end_seqno = SEQNO_MAX;
    frame.message.body.vbucket_uuid = session->failover_logs[partition].newest->uuid;
    ldcp_rb_ensure_capacity(&chan->out, sizeof(frame.bytes));
    ldcp_rb_write(&chan->out, frame.bytes, sizeof(frame.bytes));
}

static void send_snapshot_marker_response(ldcp_CHANNEL *chan, uint32_t opaque)
{
    protocol_binary_request_header hdr = {0};

    hdr.request.magic = PROTOCOL_BINARY_RES;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_DCP_SNAPSHOT_MARKER;
    hdr.request.opaque = opaque;
    ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr.bytes));
    ldcp_rb_write(&chan->out, hdr.bytes, sizeof(hdr.bytes));
}

static void send_noop(ldcp_CHANNEL *chan, uint32_t opaque)
{
    protocol_binary_request_header hdr = {0};

    hdr.request.magic = PROTOCOL_BINARY_RES;
    hdr.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    hdr.request.opcode = PROTOCOL_BINARY_CMD_DCP_NOOP;
    hdr.request.opaque = opaque;
    ldcp_rb_ensure_capacity(&chan->out, sizeof(hdr.bytes));
    ldcp_rb_write(&chan->out, hdr.bytes, sizeof(hdr.bytes));
}

static void send_dcp_buffer_ack(ldcp_CHANNEL *chan, uint32_t nbytes)
{
    protocol_binary_request_dcp_buffer_acknowledgement frame = {0};

    frame.message.header.request.magic = PROTOCOL_BINARY_REQ;
    frame.message.header.request.datatype = PROTOCOL_BINARY_RAW_BYTES;
    frame.message.header.request.opcode = PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT;
    frame.message.header.request.extlen = sizeof(frame.message.body);
    frame.message.header.request.bodylen = htonl(frame.message.header.request.extlen);
    frame.message.body.buffer_bytes = htonl(nbytes);
    ldcp_rb_ensure_capacity(&chan->out, sizeof(frame.bytes));
    ldcp_rb_write(&chan->out, frame.bytes, sizeof(frame.bytes));
}

static void ldcp_channel_ack(ldcp_CHANNEL *chan, uint32_t nbytes)
{
    chan->nbytes += nbytes;
    if (chan->nbytes > DEFAULT_DCP_CONNECTION_ACK_THRESHOLD) {
        send_dcp_buffer_ack(chan, chan->nbytes);
        chan->nbytes = 0;
    }
}

static void read_dcp_snapshot_marker(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void *body,
                                     uint32_t nbody)
{
    int16_t partition = (int16_t)ntohs(hdr->response.status);
    uint64_t start_seqno, end_seqno;
    uint32_t flags;
    char list[100] = {0};
    int off = 0;

    if (nbody != 20) {
        return;
    }

    memcpy(&start_seqno, body, sizeof(uint64_t));
    start_seqno = ldcp_ntohll(start_seqno);
    body += sizeof(uint64_t);

    memcpy(&end_seqno, body, sizeof(uint64_t));
    end_seqno = ldcp_ntohll(end_seqno);
    body += sizeof(uint64_t);

    memcpy(&flags, body, sizeof(uint32_t));
    flags = ntohl(flags);

    if (flags & DCP_SNAPSHOT_MARKER_MEMORY) {
        off += snprintf(list + off, sizeof(list) - off, "%sMEMORY(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_MEMORY);
    }
    if (flags & DCP_SNAPSHOT_MARKER_DISK) {
        off += snprintf(list + off, sizeof(list) - off, "%sDISK(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_DISK);
    }
    if (flags & DCP_SNAPSHOT_MARKER_CHK) {
        off += snprintf(list + off, sizeof(list) - off, "%sCHK(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_CHK);
    }
    if (flags & DCP_SNAPSHOT_MARKER_ACK) {
        off += snprintf(list + off, sizeof(list) - off, "%sACK(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_ACK);
        send_snapshot_marker_response(chan, hdr->response.opaque);
    }
    ldcp_log(LOGARGS(TRACE), "SNAPSHOT [0x%016" PRIx64 ", 0x%016" PRIx64 "], part=%d, flags=%s, fd=%d", start_seqno,
             end_seqno, partition, off ? list : "(none)", chan->fd);
}

static void read_dcp_mutation(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void *body, uint32_t nbody)
{
    int16_t partition = (int16_t)ntohs(hdr->response.status);
    uint16_t keylen = ntohs(hdr->response.keylen);
    uint8_t extlen = hdr->response.extlen;
    uint64_t cas = ldcp_ntohll(hdr->response.cas);
    uint64_t by_seqno, rev_seqno;
    uint32_t flags, expiration, lock_time;
    char list[100] = {0};
    int off = 0;

    if (extlen != 31 || extlen + keylen > nbody) {
        return;
    }

    memcpy(&by_seqno, body, sizeof(uint64_t));
    by_seqno = ldcp_ntohll(by_seqno);
    body += sizeof(uint64_t);

    memcpy(&rev_seqno, body, sizeof(uint64_t));
    rev_seqno = ldcp_ntohll(rev_seqno);
    body += sizeof(uint64_t);

    memcpy(&flags, body, sizeof(flags));
    flags = ntohl(flags);
    body += sizeof(uint32_t);

    memcpy(&expiration, body, sizeof(expiration));
    expiration = ntohl(expiration);
    body += sizeof(uint32_t);

    memcpy(&lock_time, body, sizeof(lock_time));
    lock_time = ntohl(lock_time);
    body += sizeof(uint32_t);

    body += sizeof(uint16_t); // nmeta
    body += sizeof(uint8_t);  // nru

    char *key = body;
    fprintf(stderr,
            "MUTATION \"%.*s\", part=%" PRId16 ", cas=0x%016" PRIx64 ", flags=0x%08" PRIx32 ", expiration=%" PRIu32
            ", lock_time=%" PRIu32 ", by_seqno=0x%016" PRIx64 ", rev_seqno=%" PRIu64 "\n",
            (int)keylen, key, partition, cas, flags, expiration, lock_time, by_seqno, rev_seqno);

    char *val = body + keylen;
    uint32_t vallen = ntohl(hdr->response.bodylen) - keylen - extlen;
    fwrite(val, vallen, sizeof(char), stdout);
    fwrite("\n", 1, sizeof(char), stdout);
    fflush(stdout);
}

static void read_dcp_deletion(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void *body, uint32_t nbody)
{
    int16_t partition = (int16_t)ntohs(hdr->response.status);
    uint16_t keylen = ntohs(hdr->response.keylen);
    uint8_t extlen = hdr->response.extlen;
    uint32_t vallen = ntohl(hdr->response.bodylen) - keylen - extlen;
    uint64_t cas = ldcp_ntohll(hdr->response.cas);
    uint64_t by_seqno, rev_seqno;
    char list[100] = {0};
    int off = 0;

    if (extlen != 18 || extlen + keylen > nbody) {
        return;
    }

    memcpy(&by_seqno, body, sizeof(uint64_t));
    by_seqno = ldcp_ntohll(by_seqno);
    body += sizeof(uint64_t);

    memcpy(&rev_seqno, body, sizeof(uint64_t));
    rev_seqno = ldcp_ntohll(rev_seqno);
    body += sizeof(uint64_t);

    body += sizeof(uint16_t); // nmeta

    char *key = body;
    fprintf(stderr,
            "DELETION \"%.*s\", part=%" PRId16 ", cas=0x%016" PRIx64 ", by_seqno=0x%016" PRIx64 ", rev_seqno=%" PRIu64
            "\n",
            (int)keylen, key, partition, cas, by_seqno, rev_seqno);
}

#define STREAM_CLOSED_STATUSES(X)                                                                                      \
    X(0x00, OK, "The stream has finished without error")                                                               \
    X(0x01, CLOSED,                                                                                                    \
      "This indicates that the close stream command was invoked on this stream causing it to be closed by force")      \
    X(0x02, STATE_CHANGED,                                                                                             \
      "The state of the VBucket that is being streamed has changed to state that the consumer does not want to "       \
      "receive")                                                                                                       \
    X(0x03, DISCONNECTED, "The stream is closing because the connection is being disconnected")                        \
    X(0x04, TOO_SLOW, "The stream is closing because the client cannot read from the stream fast enough")

static void read_dcp_stream_end(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void *body, uint32_t nbody)
{
    int16_t partition = (int16_t)ntohs(hdr->response.status);
    uint8_t extlen = hdr->response.extlen;
    uint32_t flags;
    const char *status = "UNKNOWN";

    if (extlen != sizeof(uint32_t)) {
        return;
    }

    chan->streams[ntohl(hdr->response.opaque)] = STREAM_NONE;
    memcpy(&flags, body, sizeof(uint32_t));
    flags = ntohl(flags);
    switch (flags) {
#define X(C, N, D)                                                                                                     \
    case C:                                                                                                            \
        status = #N;                                                                                                   \
        break;
        STREAM_CLOSED_STATUSES(X)
#undef X
    }
    ldcp_log(LOGARGS(INFO), "End of stream for partition %d, status=0x%02x (%s) fd=%d", (int)partition, flags, status,
             chan->fd);
}

static int load_packet(ldcp_CHANNEL *chan, protocol_binary_response_header *hdr, void **body, uint32_t *nbody)
{
    size_t hdrlen = sizeof(protocol_binary_response_header);
    size_t total = ldcp_rb_get_nbytes(&chan->in);

    if (total < hdrlen) {
        return -1;
    }

    ldcp_rb_peek(&chan->in, hdr, hdrlen);
    uint32_t bodylen = ntohl(hdr->response.bodylen);
    if (total < hdrlen + bodylen) {
        return -1;
    }
    ldcp_rb_consumed(&chan->in, hdrlen);
    *nbody = bodylen;
    *body = calloc(bodylen + 1, sizeof(char)); /* make sure that body always zero terminated */
    ldcp_rb_read(&chan->in, *body, bodylen);
    return 0;
}

static void handle_read(ldcp_CHANNEL *chan)
{
    while (1) {
        protocol_binary_response_header hdr = {0};
        void *body = NULL;
        uint32_t nbody = 0;

        int rv = load_packet(chan, &hdr, &body, &nbody);
        if (rv != 0) {
            return;
        }

        uint16_t status = ntohs(hdr.response.status);
        switch (hdr.response.magic) {
            case PROTOCOL_BINARY_RES:
                switch (hdr.response.opcode) {
                    case PROTOCOL_BINARY_CMD_HELLO:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                if (read_hello(chan, &hdr, body, nbody) != 0) {
                                    ldcp_log(LOGARGS(ERROR), "Failed to parse HELLO response fd=%d", chan->fd);
                                    chan->state = CHAN_ERROR;
                                } else {
                                    send_auth(chan);
                                }
                                break;
                            case PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED:
                            case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
                            case PROTOCOL_BINARY_RESPONSE_EACCESS:
                                ldcp_log(LOGARGS(WARN), "Server does not support HELLO");
                                break;
                            default:
                                ldcp_log(LOGARGS(ERROR), "Unexpected status 0x%02x received for HELLO command fd=%d",
                                         chan->fd);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_SASL_AUTH:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                send_select_bucket(chan);
                                break;
                            case PROTOCOL_BINARY_RESPONSE_AUTH_ERROR:
                                ldcp_log(LOGARGS(ERROR),
                                         "Unable to authenticate on the server, check credentials fd=%d. %.*s",
                                         chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                            default:
                                ldcp_log(LOGARGS(ERROR),
                                         "Unexpected status 0x%02x received for SASL_AUTH command fd=%d. %.*s", status,
                                         chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_SELECT_BUCKET:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                send_get_config(chan);
                                break;
                            case PROTOCOL_BINARY_RESPONSE_EACCESS:
                                ldcp_log(LOGARGS(ERROR), "Provided credentials not allowed for bucket fd=%d. %.*s",
                                         chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                            default:
                                ldcp_log(
                                    LOGARGS(ERROR),
                                    "Unexpected status 0x%02x received for SELECT_BUCKET(\"%s\") command fd=%d. %.*s",
                                    status, chan->client->bucket, chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_GET_CLUSTER_CONFIG:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                read_and_upgrade_config(chan, &hdr, body, nbody);
                                send_dcp_open(chan);
                                break;
                            default:
                                ldcp_log(LOGARGS(ERROR),
                                         "Unexpected status 0x%02x received for GET_CLUSTER_CONFIG command fd=%d. %.*s",
                                         status, chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_OPEN:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                send_dcp_control(chan);
                                break;
                            default:
                                ldcp_log(LOGARGS(ERROR),
                                         "Unexpected status 0x%02x received for DCP_OPEN command fd=%d. %.*s", status,
                                         chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_CONTROL:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                chan->state++;
                                if (chan->state == CHAN_CONTROL3) {
                                    send_get_failover_logs(chan);
                                    chan->state = CHAN_READY;
                                }
                                break;
                            default:
                                ldcp_log(LOGARGS(ERROR),
                                         "Unexpected status 0x%02x received for DCP_CONTROL command fd=%d. %.*s",
                                         status, chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_GET_FAILOVER_LOG:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                if (read_failover_log(chan, &hdr, body, nbody) != 0) {
                                    ldcp_log(LOGARGS(ERROR), "Failed to parse failover log fd=%d", chan->fd);
                                    chan->state = CHAN_ERROR;
                                } else {
                                    int32_t partition = (int32_t)ntohl(hdr.response.opaque);
                                    send_start_stream(chan, partition);
                                }
                                break;
                            case PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET:
                                ldcp_log(LOGARGS(ERROR), "FIXME: Not my vbucket for vb=%d fd=%d", chan->fd,
                                         (int)ntohl(hdr.response.opaque));
                                chan->state = CHAN_ERROR;
                                break;
                            default:
                                ldcp_log(LOGARGS(ERROR),
                                         "Unexpected status 0x%02x received for DCP_OPEN command fd=%d. %.*s", status,
                                         chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_STREAM_REQ:
                        switch (status) {
                            case PROTOCOL_BINARY_RESPONSE_SUCCESS:
                                chan->streams[ntohl(hdr.response.opaque)] = STREAM_OPEN;
                                break;
                            case PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS:
                                ldcp_log(LOGARGS(WARN), "FIXME: Already have stream for partition %d, ignoring. fd=%d",
                                         ntohl(hdr.response.opaque), chan->fd);
                                break;
                            default:
                                chan->streams[ntohl(hdr.response.opaque)] = STREAM_NONE;
                                ldcp_log(LOGARGS(ERROR),
                                         "Unexpected status 0x%02x received for DCP_STREAM_REQ(%d) command fd=%d. %.*s",
                                         status, (int)ntohl(hdr.response.opaque), chan->fd, (int)nbody, (char *)body);
                                chan->state = CHAN_ERROR;
                                break;
                        }
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_BUFFER_ACKNOWLEDGEMENT:
                        if (status != PROTOCOL_BINARY_RESPONSE_SUCCESS) {
                            ldcp_log(
                                LOGARGS(ERROR),
                                "Unexpected status 0x%02x received for DCP_BUFFER_ACKNOWLEDGEMENT command fd=%d. %.*s",
                                status, chan->fd, (int)nbody, (char *)body);
                            chan->state = CHAN_ERROR;
                        }
                        break;
                    default:
                        dump_bytes("RES (0x81) header", &hdr, sizeof(hdr));
                        if (nbody) {
                            dump_bytes("RES (0x81) body", body, nbody);
                        }
                        break;
                }
                break;
            case PROTOCOL_BINARY_REQ:
                switch (hdr.response.opcode) {
                    case PROTOCOL_BINARY_CMD_DCP_SNAPSHOT_MARKER:
                        read_dcp_snapshot_marker(chan, &hdr, body, nbody);
                        ldcp_channel_ack(chan, nbody + sizeof(hdr));
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_MUTATION:
                        read_dcp_mutation(chan, &hdr, body, nbody);
                        ldcp_channel_ack(chan, nbody + sizeof(hdr));
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_DELETION:
                        read_dcp_deletion(chan, &hdr, body, nbody);
                        ldcp_channel_ack(chan, nbody + sizeof(hdr));
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_NOOP:
                        send_noop(chan, hdr.response.opaque);
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_STREAM_END:
                        read_dcp_stream_end(chan, &hdr, body, nbody);
                        ldcp_channel_ack(chan, nbody + sizeof(hdr));
                        break;
                    case PROTOCOL_BINARY_CMD_DCP_CLOSE_STREAM:
                    case PROTOCOL_BINARY_CMD_DCP_EXPIRATION:
                        ldcp_channel_ack(chan, nbody + sizeof(hdr));
                        /* fall-through */
                    default:
                        dump_bytes("REQ (0x80) header", &hdr, sizeof(hdr));
                        if (nbody) {
                            dump_bytes("REQ (0x80) body", body, nbody);
                        }
                        break;
                }
                break;
            case PROTOCOL_BINARY_SREQ:
                switch (hdr.response.opcode) {
                    case PROTOCOL_BINARY_SCMD_CLUSTERMAP_CHANGE_NOTIFICATION:
                        read_and_upgrade_config(chan, &hdr, body, nbody);
                        break;
                    default:
                        dump_bytes("SREQ (0x82) header", &hdr, sizeof(hdr));
                        if (nbody) {
                            dump_bytes("SREQ (0x82) body", body, nbody);
                        }
                        break;
                }
                break;
        }
        free(body);
    }
}

static void channel_callback(evutil_socket_t fd, short events, void *arg)
{
    ldcp_CHANNEL *chan = arg;

    /* TODO: track last activity time, and close connection if it larger than noop_interval*2 */
    if (events & EV_WRITE) {
        do {
            ldcp_IOV iov[2] = {0};
            ldcp_rb_get_iov(&chan->out, LDCP_RINGBUFFER_READ, iov);
            if (iov[0].iov_len + iov[1].iov_len == 0) {
                break;
            }
            struct msghdr mh;
            memset(&mh, 0, sizeof(mh));
            mh.msg_iov = (struct iovec *)iov;
            mh.msg_iovlen = iov[1].iov_len ? 2 : 1;
            ssize_t rv;
        DO_WRITE_AGAIN:
            rv = sendmsg(chan->fd, &mh, 0);
            if (rv > 0) {
                ldcp_rb_consumed(&chan->out, rv);
            } else if (rv < 0) {
                switch (errno) {
                    case EINTR:
                        goto DO_WRITE_AGAIN;
                    case EWOULDBLOCK:
#ifdef USE_EAGAIN
                    case EAGAIN:
#endif
                        goto DO_READ;
                    default:
                        ldcp_log(LOGARGS(ERROR), "Failed to write data to \"%s:%s\" fd=%d: %s", chan->host, chan->port,
                                 chan->fd, strerror(errno));
                        chan->state = CHAN_ERROR;
                        goto DONE;
                }
            } else {
                chan->state = CHAN_EOF;
                goto DONE;
            }
        } while (1);
    }
DO_READ:
    if (events & EV_READ) {
        do {
            ldcp_IOV iov[2] = {0};
            if (chan->in.nbytes == chan->in.size) {
                ldcp_rb_ensure_capacity(&chan->in, 1);
            }
            ldcp_rb_get_iov(&chan->in, LDCP_RINGBUFFER_WRITE, iov);
            struct msghdr mh;
            memset(&mh, 0, sizeof(mh));
            mh.msg_iov = (struct iovec *)iov;
            mh.msg_iovlen = iov[1].iov_len ? 2 : 1;
            ssize_t rv;
        DO_READ_AGAIN:
            rv = recvmsg(chan->fd, &mh, 0);
            if (rv > 0) {
                ldcp_rb_produced(&chan->in, rv);
            } else if (rv < 0) {
                switch (errno) {
                    case EINTR:
                        goto DO_READ_AGAIN;
                    case EWOULDBLOCK:
#ifdef USE_EAGAIN
                    case EAGAIN:
#endif
                        handle_read(chan);
                        goto DONE;
                    default:
                        ldcp_log(LOGARGS(ERROR), "Failed to read data from fd=%d: %s", chan->fd, strerror(errno));
                        chan->state = CHAN_ERROR;
                        goto DONE;
                }
            } else {
                chan->state = CHAN_EOF;
                goto DONE;
            }
        } while (1);
    }
DONE:
    switch (chan->state) {
        case CHAN_ERROR:
        case CHAN_EOF:
            ldcp_log(LOGARGS(ERROR), "Detaching IO fd=%d (%s)", chan->fd, chan->state == CHAN_ERROR ? "error" : "eof");
            event_del(chan->evt);
            close(chan->fd);
            break;
    }
}

static void ldcp_channel_connect(ldcp_CHANNEL *chan);

static void connect_callback(evutil_socket_t fd, short events, void *arg)
{
    ldcp_CHANNEL *chan = arg;
    if (events & EV_WRITE) {
        ldcp_channel_connect(chan);
    }
}

static void ldcp_channel_connect(ldcp_CHANNEL *chan)
{
    int ret;

    ret = connect(chan->fd, chan->ai->addr, chan->ai->addrlen);
    if (ret == 0 || errno == EISCONN) {
        ldcp_log(LOGARGS(INFO), "Successfully connected to \"%s:%s\", fd=%d", chan->host, chan->port, chan->fd);
        event_assign(chan->evt, chan->client->io->evbase, chan->fd, EV_READ | EV_WRITE | EV_PERSIST, channel_callback,
                     chan);
        event_add(chan->evt, NULL);
        int enabled = 1;
        ret = setsockopt(chan->fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        if (ret != 0) {
            ldcp_log(LOGARGS(WARN), "Failed to set TCP_NODELAY for \"%s:%s\": %s, fd=%d", chan->host, chan->port,
                     strerror(errno), chan->fd);
            chan->tcp_nodelay = 0;
        } else {
            chan->tcp_nodelay = 1;
        }
        ret = setsockopt(chan->fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));
        if (ret != 0) {
            ldcp_log(LOGARGS(WARN), "Failed to set SO_KEEPALIVE for \"%s:%s\": %s, fd=%d", chan->host, chan->port,
                     strerror(errno), chan->fd);
            chan->tcp_keepalive = 0;
        } else {
            chan->tcp_keepalive = 1;
        }
        chan->state = CHAN_CONNECTED;
        send_hello(chan);
    } else {
        switch (errno) {
            case EINTR:
                ldcp_log(LOGARGS(INFO), "Connection to \"%s:%s\" has been interrupted, fd=%d", chan->host, chan->port,
                         chan->fd);
                break;

            case EWOULDBLOCK:
#ifdef USE_EAGAIN
            case EAGAIN:
#endif
            case EINPROGRESS:
            case EALREADY:
                event_assign(chan->evt, chan->client->io->evbase, chan->fd, EV_WRITE, connect_callback, chan);
                event_add(chan->evt, NULL);
                chan->state = CHAN_CONNECTING;
                return;

#ifdef _WIN32
            case EINVAL:
#endif
            default:
                ldcp_log(LOGARGS(ERROR), "Failed to connect to \"%s:%s\": %s, fd=%d", chan->host, chan->port,
                         strerror(errno), chan->fd);
                break;
        }
        chan->state = CHAN_ERROR;
        event_del(chan->evt);
    }
}

static void ldcp_channel_start_connect(ldcp_CHANNEL *chan)
{
    ldcp_ADDRINFO *ai = chan->ai;
    if (ai->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)ai->addr;
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ai->addr;
        evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, chan->host, sizeof(chan->host));
    }
    ldcp_log(LOGARGS(INFO), "Connecting socket to \"%s:%s\", fd=%d", chan->host, chan->port, chan->fd);
    ldcp_channel_connect(chan);
}

static void gai_callback(int err, struct evutil_addrinfo *ai, void *arg)
{
    ldcp_CHANNEL *chan = arg;

    if (err) {
        ldcp_log(LOGARGS(ERROR), "Failed to resolve address \"%s\": %s", chan->host, evutil_gai_strerror(err));
        return;
    }
    ldcp_ADDRINFO *root = NULL, *prev = NULL;
    for (; ai; ai = ai->ai_next) {
        ldcp_ADDRINFO *addr = calloc(1, sizeof(ldcp_ADDRINFO));
        addr->addrlen = ai->ai_addrlen;
        addr->addr = calloc(addr->addrlen, sizeof(uint8_t));
        memcpy(addr->addr, ai->ai_addr, addr->addrlen);
        addr->family = (ai->ai_family == PF_INET) ? AF_INET : AF_INET6;
        if (root == NULL) {
            root = addr;
        }
        if (prev) {
            prev->next = addr;
        }
    }
    ldcp_assert(chan->ai_root == NULL);
    chan->ai_root = root;
    chan->ai = root;
    ldcp_channel_start_connect(chan);
}

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

    client = ldcp_client_new(host, port, bucket, user, password);
    ldcp_client_bootstrap(client);
    ldcp_client_dispatch(client);

    ldcp_log(LOGARGS(INFO), "Exiting");

    ldcp_client_free(client);
    ldcp_settings_unref(settings);
    return 0;
}
