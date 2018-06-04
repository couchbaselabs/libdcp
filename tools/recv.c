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

#include <signal.h>
#include <libdcp/dcp.h>
#include <git2.h>

#include "internal.h"

#define LOGARGS(lvl) settings, "recv", LDCP_LOG_##lvl, __FILE__, __LINE__

static ldcp_SETTINGS *settings = NULL;
static ldcp_CLIENT *client = NULL;

static int terminating = 0;

static void sigint_handler(int signum)
{
    fprintf(stderr, "\n");
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

typedef struct recv_STATE {
    char *repo_path;
    git_repository *repo;
    uint32_t num_indexes;
    git_index **indexes;
} recv_STATE;

static recv_STATE *state_new(const char *repo_path)
{
    recv_STATE *obj = calloc(1, sizeof(recv_STATE));
    int rc;

    rc = git_libgit2_init();
    if (rc < 0) {
        ldcp_log(LOGARGS(ERROR), "Failed to initialize libgit2. rc=%d %s", rc);
        return NULL;
    }

    git_repository_init_options initopts = GIT_REPOSITORY_INIT_OPTIONS_INIT;
    initopts.flags = GIT_REPOSITORY_INIT_MKPATH;
    rc = git_repository_init_ext(&obj->repo, repo_path, &initopts);
    if (rc) {
        const git_error *err;
        const char *msg;
        err = giterr_last();
        if (err) {
            msg = err->message;
        }
        ldcp_log(LOGARGS(ERROR), "Failed to initialize git repository. rc=%d %s", rc, msg ? msg : "");
        return NULL;
    }
    {
        repo_path = git_repository_path(obj->repo);
        int len = strlen(repo_path);
        const char *trail = strstr(repo_path, ".git/");
        if (trail) {
            len = trail - repo_path;
        }
        ldcp_log(LOGARGS(INFO), "Using git repo at \"%.*s\"", len, repo_path);
    }

    git_object *head = NULL;
    rc = git_revparse_single(&head, obj->repo, "HEAD");
    if (rc == GIT_ENOTFOUND) {
        ldcp_log(LOGARGS(DEBUG), "HEAD object is not found. Will try to create empty object");

        git_signature *sig;
        rc = git_signature_default(&sig, obj->repo);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR),
                     "Unable to create commit signature (missing user.{email,name} in git config?). rc=%d", rc);
            return NULL;
        }

        git_index *index;
        rc = git_repository_index(&index, obj->repo);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to open repository index. rc=%d", rc);
            return NULL;
        }

        git_oid tree_id;
        rc = git_index_write_tree(&tree_id, index);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to write initial tree from index. rc=%d", rc);
            return NULL;
        }
        git_index_free(index);

        git_tree *tree;
        rc = git_tree_lookup(&tree, obj->repo, &tree_id);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to lookup initial tree. rc=%d", rc);
            return NULL;
        }

        git_oid commit_id;
        rc = git_commit_create_v(&commit_id, obj->repo, "HEAD", sig, sig, NULL, "root commit", tree, 0);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to create the initial commit. rc=%d", rc);
            return NULL;
        }

        char sha1[GIT_OID_HEXSZ + 1] = {0};
        git_oid_tostr(sha1, sizeof(sha1), &commit_id);
        ldcp_log(LOGARGS(INFO), "Created root commit %s", sha1);

        git_tree_free(tree);
        git_signature_free(sig);
    }
    if (head) {
        git_object_free(head);
    }

    return obj;
}

static void state_free(recv_STATE *state)
{
    if (state) {
        if (state->repo) {
            git_repository_free(state->repo);
        }
        if (state->indexes) {
            uint32_t i;
            for (i = 0; i < state->num_indexes; i++) {
                if (state->indexes[i]) {
                    git_index_free(state->indexes[i]);
                    state->indexes[i] = NULL;
                }
            }
            free(state->indexes);
        }
        free(state);
    }
    git_libgit2_shutdown();
}

static void bootstrap_callback(ldcp_CLIENT *client)
{
    recv_STATE *state = (recv_STATE *)client->cookie;

    state->num_indexes = 0;
    ldcp_client_number_partitions(client, &state->num_indexes);
    if (state->num_indexes) {
        state->indexes = calloc(state->num_indexes, sizeof(git_index *));
        ldcp_install_config_callback(client, NULL);
    }
}

static void mutation_callback(ldcp_CLIENT *client, ldcp_CALLBACK type, const ldcp_EVENT *evt)
{
    ldcp_MUTATION *mut = (ldcp_MUTATION *)evt;
    fprintf(stderr,
            "MUTATION \"%.*s\", part=%" PRId16 ", cas=0x%016" PRIx64 ", datatype=0x%02" PRIx8 ", flags=0x%08" PRIx32
            ", expiration=%" PRIu32 ", lock_time=%" PRIu32 ", by_seqno=0x%016" PRIx64 ", rev_seqno=%" PRIu64 "\n",
            (int)mut->key_len, mut->key, mut->partition, mut->cas, mut->datatype, mut->flags, mut->expiration,
            mut->lock_time, mut->by_seqno, mut->rev_seqno);
    if (mut->datatype & PROTOCOL_BINARY_DATATYPE_COMPRESSED) {
        ldcp_dump_bytes(stdout, "snappy compressed", mut->value, mut->value_len);
    } else {
        fwrite(mut->value, mut->value_len, sizeof(char), stdout);
        fwrite("\n", 1, sizeof(char), stdout);
        fflush(stdout);
    }
    (void)type;
}

static void deletion_callback(ldcp_CLIENT *client, ldcp_CALLBACK type, const ldcp_EVENT *evt)
{
    ldcp_DELETION *del = (ldcp_DELETION *)evt;
    fprintf(stderr,
            "DELETION \"%.*s\", part=%" PRId16 ", cas=0x%016" PRIx64 ", by_seqno=0x%016" PRIx64 ", rev_seqno=%" PRIu64
            "\n",
            (int)del->key_len, del->key, del->partition, del->cas, del->by_seqno, del->rev_seqno);
    (void)type;
}

static void snapshot_callback(ldcp_CLIENT *client, ldcp_CALLBACK type, const ldcp_EVENT *evt)
{
    ldcp_SNAPSHOT *snap = (ldcp_SNAPSHOT *)evt;
    recv_STATE *state = (recv_STATE *)client->cookie;

    if (snap->partition >= state->num_indexes) {
        ldcp_log(LOGARGS(ERROR), "Snapshot partition (%d) is greater than number of allocated indexes (%d). Skipping",
                 (int)snap->partition, (int)state->num_indexes);
        return;
    }
    if (state->indexes[snap->partition]) {
        ldcp_log(LOGARGS(WARN), "Found uncommitted index for partition %d. Wiping it", (int)snap->partition);
        git_index_free(state->indexes[snap->partition]);
        state->indexes[snap->partition] = NULL;
    }
    int rc;
    rc = git_index_new(&state->indexes[snap->partition]);
    if (rc != 0) {
        ldcp_log(LOGARGS(ERROR), "Unable to create the index for partition %d. rc=%d", (int)snap->partition, rc);
        return;
    }

    char list[100] = {0};
    int off = 0;

    if (snap->flags & DCP_SNAPSHOT_MARKER_MEMORY) {
        off += snprintf(list + off, sizeof(list) - off, "%sMEMORY(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_MEMORY);
    }
    if (snap->flags & DCP_SNAPSHOT_MARKER_DISK) {
        off += snprintf(list + off, sizeof(list) - off, "%sDISK(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_DISK);
    }
    if (snap->flags & DCP_SNAPSHOT_MARKER_CHK) {
        off += snprintf(list + off, sizeof(list) - off, "%sCHK(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_CHK);
    }
    if (snap->flags & DCP_SNAPSHOT_MARKER_ACK) {
        off += snprintf(list + off, sizeof(list) - off, "%sACK(0x%02x)", off ? "," : "", DCP_SNAPSHOT_MARKER_ACK);
    }

    fprintf(stderr, "SNAPSHOT [0x%016" PRIx64 ", 0x%016" PRIx64 "], part=%d, flags=%s\n", snap->start_seqno,
            snap->end_seqno, snap->partition, off ? list : "(none)");
    (void)type;
}

int main(int argc, char *argv[])
{
    settings = ldcp_settings_new();

    setup_sigint_handler();
    setup_sigquit_handler();

    ldcp_OPTIONS *options = ldcp_options_new();
    options->settings = settings;
    options->type = LDCP_TYPE_PRODUCER;
    options->host = "127.0.0.1";
    options->port = "11210";
    options->bucket = "default";
    options->username = "Administrator";
    options->password = "password";

    if (argc > 1) {
        options->host = argv[1];
    }
    if (argc > 2) {
        options->port = argv[2];
    }
    if (argc > 3) {
        options->bucket = argv[3];
    }
    if (argc > 4) {
        options->username = argv[4];
    }
    if (argc > 5) {
        options->password = argv[5];
    }

    const char *repo_path = NULL;

    if (argc > 6) {
        repo_path = argv[6];
    }
    if (repo_path == NULL) {
        repo_path = options->bucket;
    }
    recv_STATE *state = state_new(repo_path);
    options->cookie = state;

    ldcp_STATUS rc;
    rc = ldcp_client_new(options, &client);
    if (rc != LDCP_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to initialize DCP client. rc=%d", rc);
        exit(EXIT_FAILURE);
    }
    ldcp_install_config_callback(client, bootstrap_callback);
    ldcp_install_event_callback(client, LDCP_CALLBACK_SNAPSHOT, snapshot_callback);
    ldcp_install_event_callback(client, LDCP_CALLBACK_MUTATION, mutation_callback);
    ldcp_install_event_callback(client, LDCP_CALLBACK_DELETION, deletion_callback);
    ldcp_client_bootstrap(client);
    ldcp_client_dispatch(client);

    state_free(state);
    ldcp_client_free(client);
    ldcp_settings_unref(settings);
    return 0;
}
