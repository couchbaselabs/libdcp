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
#include "crc32-inl.h"

#define LOGARGS(client, lvl) client->settings, "topo", LDCP_LOG_##lvl, __FILE__, __LINE__

LDCP_INTERNAL_API
ldcp_CONFIG *ldcp_config_new()
{
    return calloc(1, sizeof(ldcp_CONFIG));
}

LDCP_INTERNAL_API
void ldcp_config_free(ldcp_CONFIG *config)
{
    if (config) {
        free(config->uuid);
        free(config->servers);
        free(config->partitions);
    }
    free(config);
}

LDCP_INTERNAL_API
ldcp_CONFIG *ldcp_config_parse(const char *body, const char *this_host)
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

LDCP_INTERNAL_API
void ldcp_handle_rebalance(ldcp_CLIENT *client, ldcp_CONFIG *config)
{

    if (config->rev <= client->config_rev) {
        ldcp_log(LOGARGS(client, DEBUG), "Skip new configuration rev. %d (active rev. %d)", config->rev,
                 client->config_rev);
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
                    ldcp_channel_start_stream(chan, pp);
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
    client->config = config;
    if (client->on_config) {
        client->on_config(client);
    }
}

LDCP_INTERNAL_API
void ldcp_config_map_key(ldcp_CONFIG *config, const char *key, size_t nkey, int *index, int16_t *partition)
{
    *partition = hash_crc32(key, nkey) % config->npartitions;
    *index = config->partitions[*partition].master;
}
