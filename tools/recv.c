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
#include <assert.h>
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

typedef struct recv_SNAPSHOT {
    git_reference *ref;
    git_treebuilder *builder;
    ldcp_RINGBUFFER buf;
    uint16_t partition;
    uint64_t start_seqno;
    uint64_t end_seqno;
} recv_SNAPSHOT;

typedef struct recv_STATE {
    char *repo_path;
    git_repository *repo;
    uint32_t num_snapshots;
    recv_SNAPSHOT *snapshots;
} recv_STATE;

static git_signature *recv_get_signature(git_repository *repo)
{
    git_signature *sig = NULL;
    int rc = git_signature_default(&sig, repo);
    if (rc != GIT_OK) {
        git_signature_now(&sig, "recv", "cbc@couchbase");
    }
    return sig;
}

static recv_STATE *state_new(const char *repo_path)
{
    recv_STATE *obj;
    int rc, success = 0;

    rc = git_libgit2_init();
    if (rc < 0) {
        ldcp_log(LOGARGS(ERROR), "Failed to initialize libgit2. rc=%d", rc);
        return NULL;
    }
    obj = calloc(1, sizeof(recv_STATE));
    git_repository_init_options initopts = GIT_REPOSITORY_INIT_OPTIONS_INIT;
    initopts.flags = GIT_REPOSITORY_INIT_MKPATH | GIT_REPOSITORY_INIT_BARE;
    rc = git_repository_init_ext(&obj->repo, repo_path, &initopts);
    if (rc != GIT_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to initialize git repository. rc=%d", rc);
        goto CLEANUP;
    }
    ldcp_log(LOGARGS(INFO), "Using git repo at \"%s\"", git_repository_path(obj->repo));

    git_object *head = NULL;
    rc = git_revparse_single(&head, obj->repo, "HEAD");
    if (rc == GIT_ENOTFOUND) {
        ldcp_log(LOGARGS(DEBUG), "HEAD object is not found. Will try to create empty object");

        git_index *index;
        rc = git_repository_index(&index, obj->repo);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to open repository index. rc=%d", rc);
            goto CLEANUP;
        }

        git_oid tree_id;
        rc = git_index_write_tree(&tree_id, index);
        git_index_free(index);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to write initial tree from index. rc=%d", rc);
            goto CLEANUP;
        }

        git_tree *tree;
        rc = git_tree_lookup(&tree, obj->repo, &tree_id);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to lookup initial tree. rc=%d", rc);
            goto CLEANUP;
        }

        git_signature *sig = recv_get_signature(obj->repo);
        git_oid commit_id;
        rc = git_commit_create_v(&commit_id, obj->repo, "HEAD", sig, sig, NULL, "root commit", tree, 0);
        git_tree_free(tree);
        if (rc < 0) {
            git_signature_free(sig);
            ldcp_log(LOGARGS(ERROR), "Unable to create the initial commit. rc=%d", rc);
            goto CLEANUP;
        }

        git_commit *commit;
        rc = git_commit_lookup(&commit, obj->repo, &commit_id);
        if (rc < 0) {
            git_signature_free(sig);
            ldcp_log(LOGARGS(ERROR), "Unable to lookup the initial commit. rc=%d", rc);
            goto CLEANUP;
        }

        git_oid tag;
        rc = git_tag_create(&tag, obj->repo, "root", (git_object *)commit, sig, "beginning of the history", 1);
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Unable to tag the initial commit. rc=%d", rc);
            goto CLEANUP;
        }
        git_commit_free(commit);
        git_signature_free(sig);

        char sha1[GIT_OID_HEXSZ + 1] = {0};
        git_oid_tostr(sha1, sizeof(sha1), &commit_id);
        ldcp_log(LOGARGS(INFO), "Created root commit %s", sha1);
    }
    success = 1;

CLEANUP:
    if (head) {
        git_object_free(head);
    }
    if (!success) {
        free(obj);
        return NULL;
    }

    return obj;
}

static void state_free(recv_STATE *state)
{
    if (state) {
        if (state->repo) {
            git_repository_free(state->repo);
        }
        if (state->snapshots) {
            uint32_t i;
            for (i = 0; i < state->num_snapshots; i++) {
                if (state->snapshots[i].ref) {
                    git_reference_free(state->snapshots[i].ref);
                    state->snapshots[i].ref = NULL;
                }
                if (state->snapshots[i].builder) {
                    git_treebuilder_free(state->snapshots[i].builder);
                    state->snapshots[i].builder = NULL;
                }
                ldcp_rb_destruct(&state->snapshots[i].buf);
            }
            free(state->snapshots);
        }
        free(state);
    }
    git_libgit2_shutdown();
}

static void bootstrap_callback(ldcp_CLIENT *client)
{
    recv_STATE *state = (recv_STATE *)client->cookie;

    state->num_snapshots = 0;
    ldcp_client_number_partitions(client, &state->num_snapshots);
    if (state->num_snapshots) {
        state->snapshots = calloc(state->num_snapshots, sizeof(recv_SNAPSHOT));
        ldcp_install_config_callback(client, NULL);
    }
}

static void state_commit_snapshot(recv_STATE *state, recv_SNAPSHOT *snap)
{
    int rc;
    git_oid updater;

    rc = git_treebuilder_write(&updater, snap->builder);
    git_treebuilder_free(snap->builder);
    snap->builder = NULL;
    if (rc != GIT_OK) {
        git_reference_free(snap->ref);
        snap->ref = NULL;
        ldcp_log(LOGARGS(ERROR), "Failed to create updated tree for partition %d, rc=%d", (int)snap->partition,
                 (int)rc);
        return;
    }

    git_tree *updated_tree;
    rc = git_tree_lookup(&updated_tree, state->repo, &updater);
    if (rc != GIT_OK) {
        git_reference_free(snap->ref);
        snap->ref = NULL;
        ldcp_log(LOGARGS(ERROR), "Failed to lookup updated tree for partition %d, rc=%d", (int)snap->partition,
                 (int)rc);
        return;
    }

    git_signature *sig = recv_get_signature(state->repo);
    char commit_msg[100] = {0};
    snprintf(commit_msg, sizeof(commit_msg), "s:%" PRId64 ", e:%" PRId64 ", u:%" PRId64, snap->start_seqno,
             snap->end_seqno, client->session->failover_logs[snap->partition].newest->uuid);

    git_oid commit;
    rc = git_commit_create_v(&commit, state->repo, git_reference_name(snap->ref), sig, sig, NULL, commit_msg,
                             updated_tree, 1, git_reference_target(snap->ref));
    git_reference_free(snap->ref);
    snap->ref = NULL;
    git_tree_free(updated_tree);
    if (rc != GIT_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to create commit for snapshot %s in partition %d, rc=%d", commit_msg,
                 (int)snap->partition, (int)rc);
        return;
    }
}

static void mutation_callback(ldcp_CLIENT *client, ldcp_CALLBACK type, const ldcp_EVENT *evt)
{
    ldcp_MUTATION *mut = (ldcp_MUTATION *)evt;
    recv_STATE *state = (recv_STATE *)client->cookie;
    recv_SNAPSHOT *snap = &state->snapshots[mut->partition];

    if (snap->ref == NULL || snap->builder == NULL) {
        ldcp_log(LOGARGS(ERROR), "Detected mutation outside of the snapshot for partition %d, skipping",
                 (int)mut->partition);
        return;
    }

    ldcp_rb_reset(&snap->buf);

    char tag[50] = {0};

    ldcp_rb_ensure_capacity(&snap->buf, sizeof(tag) * 8);

    snprintf(tag, sizeof(tag), "partition: %" PRIu16 "\n", mut->partition);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "cas: %" PRIu64 "\n", mut->cas);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "datatype: %" PRIu8 "\n", mut->datatype);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "flags: %" PRIu32 "\n", mut->flags);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "expiration: %" PRIu32 "\n", mut->expiration);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "lock_time: %" PRIu32 "\n", mut->lock_time);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "by_seqno: %" PRIu64 "\n", mut->by_seqno);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "rev_seqno: %" PRIu64 "\n", mut->rev_seqno);
    ldcp_rb_strcat(&snap->buf, tag);

    ldcp_rb_ensure_capacity(&snap->buf, mut->key_len + sizeof(tag) + 1);
    snprintf(tag, sizeof(tag), "key(%d): ", mut->key_len);
    ldcp_rb_strcat(&snap->buf, tag);
    ldcp_rb_write(&snap->buf, mut->key, mut->key_len);
    ldcp_rb_strcat(&snap->buf, "\n");

    ldcp_rb_ensure_capacity(&snap->buf, mut->value_len + sizeof(tag) + 1);
    snprintf(tag, sizeof(tag), "value(%d)\n", mut->value_len);
    ldcp_rb_strcat(&snap->buf, tag);
    ldcp_rb_write(&snap->buf, mut->value, mut->value_len);
    ldcp_rb_strcat(&snap->buf, "\n");

    size_t data_len = ldcp_rb_get_nbytes(&snap->buf);
    char *data = malloc(data_len);
    assert(ldcp_rb_read(&snap->buf, data, data_len) == data_len);

    int rc;
    git_oid blob;

    rc = git_blob_create_frombuffer(&blob, state->repo, data, data_len);
    if (rc != GIT_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to create blob for key \"%.*s\" in partition %d, rc=%d", (int)mut->key_len,
                 mut->key, (int)mut->partition, (int)rc);
        return;
    }
    char *path = calloc(mut->key_len + 1, sizeof(char));
    strncpy(path, mut->key, mut->key_len);
    int ii;
    for (ii = 0; ii < mut->key_len; ii++) {
        if (path[ii] == '\0') {
            path[ii] = '_';
        }
    }
    rc = git_treebuilder_insert(NULL, snap->builder, path, &blob, GIT_FILEMODE_BLOB);
    free(path);
    if (rc != GIT_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to insert blob for key \"%.*s\" in partition %d, rc=%d", (int)mut->key_len,
                 mut->key, (int)mut->partition, (int)rc);
        return;
    }
    if (mut->by_seqno == snap->end_seqno) {
        state_commit_snapshot(state, snap);
    }
    (void)type;
}

static void deletion_callback(ldcp_CLIENT *client, ldcp_CALLBACK type, const ldcp_EVENT *evt)
{
    ldcp_DELETION *del = (ldcp_DELETION *)evt;
    recv_STATE *state = (recv_STATE *)client->cookie;
    recv_SNAPSHOT *snap = &state->snapshots[del->partition];

    if (snap->ref == NULL || snap->builder == NULL) {
        ldcp_log(LOGARGS(ERROR), "Detected deletion outside of the snapshot for partition %d, skipping",
                 (int)del->partition);
        return;
    }

    ldcp_rb_reset(&snap->buf);

    char tag[50] = {0};

    ldcp_rb_ensure_capacity(&snap->buf, sizeof(tag) * 8);

    snprintf(tag, sizeof(tag), "partition: %" PRIu16 "\n", del->partition);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "cas: %" PRIu64 "\n", del->cas);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "by_seqno: %" PRIu64 "\n", del->by_seqno);
    ldcp_rb_strcat(&snap->buf, tag);

    snprintf(tag, sizeof(tag), "rev_seqno: %" PRIu64 "\n", del->rev_seqno);
    ldcp_rb_strcat(&snap->buf, tag);

    ldcp_rb_ensure_capacity(&snap->buf, del->key_len + sizeof(tag) + 1);
    snprintf(tag, sizeof(tag), "key(%d): ", del->key_len);
    ldcp_rb_strcat(&snap->buf, tag);
    ldcp_rb_write(&snap->buf, del->key, del->key_len);
    ldcp_rb_strcat(&snap->buf, "\n");

    size_t data_len = ldcp_rb_get_nbytes(&snap->buf);
    char *data = malloc(data_len);
    assert(ldcp_rb_read(&snap->buf, data, data_len) == data_len);

    int rc;
    git_oid blob;

    rc = git_blob_create_frombuffer(&blob, state->repo, data, data_len);
    if (rc != GIT_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to create blob for key \"%.*s\" in partition %d, rc=%d", (int)del->key_len,
                 del->key, (int)del->partition, (int)rc);
        return;
    }
    char *path = calloc(del->key_len + 1, sizeof(char));
    strncpy(path, del->key, del->key_len);
    int ii;
    for (ii = 0; ii < del->key_len; ii++) {
        if (path[ii] == '\0') {
            path[ii] = '_';
        }
    }
    rc = git_treebuilder_insert(NULL, snap->builder, path, &blob, GIT_FILEMODE_BLOB);
    free(path);
    if (rc != GIT_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to insert blob for key \"%.*s\" in partition %d, rc=%d", (int)del->key_len,
                 del->key, (int)del->partition, (int)rc);
        return;
    }
    if (del->by_seqno == snap->end_seqno) {
        state_commit_snapshot(state, snap);
    }
    (void)type;
}

static git_reference *get_partition_branch(recv_STATE *state, uint16_t partition)
{
    git_reference *ref = NULL;
    int rc;
    char branch_name[20] = {0};

    snprintf(branch_name, sizeof(branch_name), "p%d", (int)partition);
    rc = git_branch_lookup(&ref, state->repo, branch_name, GIT_BRANCH_LOCAL);
    switch (rc) {
        case GIT_ENOTFOUND:
            ldcp_log(LOGARGS(DEBUG), "branch \"%s\" is not found and will be created\n", branch_name);

            git_object *root;
            rc = git_revparse_single(&root, state->repo, "root");
            assert(git_object_type(root) == GIT_OBJ_TAG);
            if (rc != GIT_OK) {
                git_reference_free(ref);
                ldcp_log(LOGARGS(ERROR), "Failed to lookup root tag, rc=%d", (int)partition, (int)rc);
                return NULL;
            }

            const git_oid *root_id = git_tag_target_id((git_tag *)root);
            git_commit *root_commit;
            rc = git_commit_lookup(&root_commit, state->repo, root_id);
            git_object_free(root);
            if (rc != GIT_OK) {
                git_reference_free(ref);
                ldcp_log(LOGARGS(ERROR), "Failed to lookup root commit, rc=%d", (int)partition, (int)rc);
                return NULL;
            }

            rc = git_branch_create(&ref, state->repo, branch_name, root_commit, 1);
            git_commit_free(root_commit);
            if (rc != GIT_OK) {
                git_reference_free(ref);
                ldcp_log(LOGARGS(ERROR), "Failed to create git branch for partition (%d), rc=%d", (int)partition,
                         (int)rc);
                return NULL;
            }
            break;
        case GIT_OK:
            break;
        default:
            git_reference_free(ref);
            ldcp_log(LOGARGS(ERROR), "Failed to lookup git branch for partition (%d), rc=%d", (int)partition, (int)rc);
            return NULL;
    }

    git_reference *peeled = NULL;
    rc = git_reference_resolve(&peeled, ref);
    git_reference_free(ref);
    if (rc != GIT_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to lookup git branch for partition (%d), rc=%d", (int)partition, (int)rc);
    }
    assert(git_reference_type(peeled) == GIT_REF_OID);

    return peeled;
}

static void snapshot_callback(ldcp_CLIENT *client, ldcp_CALLBACK type, const ldcp_EVENT *evt)
{
    ldcp_SNAPSHOT *msg = (ldcp_SNAPSHOT *)evt;
    recv_STATE *state = (recv_STATE *)client->cookie;

    if (msg->partition >= state->num_snapshots) {
        ldcp_log(LOGARGS(ERROR), "Snapshot partition (%d) is greater than number of allocated indexes (%d). Skipping",
                 (int)msg->partition, (int)state->num_snapshots);
        return;
    }

    recv_SNAPSHOT *snap = &state->snapshots[msg->partition];

    if (snap->ref || snap->builder) {
        ldcp_log(LOGARGS(ERROR), "Detected unfinished snapshot for partition %d. Discarding it", (int)msg->partition);
        if (snap->ref) {
            git_reference_free(snap->ref);
            snap->ref = NULL;
        }
        if (snap->builder) {
            git_treebuilder_free(snap->builder);
            snap->builder = NULL;
        }
    }
    snap->partition = msg->partition;
    snap->start_seqno = msg->start_seqno;
    snap->end_seqno = msg->end_seqno;
    if (ldcp_rb_get_size(&snap->buf) == 0) {
        ldcp_rb_init(&snap->buf, 256);
    }

    snap->ref = get_partition_branch(state, msg->partition);
    if (snap->ref == NULL) {
        return;
    }

    int rc;
    git_commit *parent_commit;
    rc = git_commit_lookup(&parent_commit, state->repo, git_reference_target(snap->ref));
    if (rc != GIT_OK) {
        git_reference_free(snap->ref);
        snap->ref = NULL;
        ldcp_log(LOGARGS(ERROR), "Failed to lookup parent commit for partition (%d), rc=%d", (int)msg->partition,
                 (int)rc);
        return;
    }

    git_tree *parent_tree;
    rc = git_commit_tree(&parent_tree, parent_commit);
    git_commit_free(parent_commit);
    if (rc != GIT_OK) {
        git_reference_free(snap->ref);
        snap->ref = NULL;
        ldcp_log(LOGARGS(ERROR), "Failed to get commit tree for partition (%d), rc=%d", (int)msg->partition, (int)rc);
        return;
    }

    git_treebuilder *builder;
    rc = git_treebuilder_new(&snap->builder, state->repo, parent_tree);
    git_tree_free(parent_tree);
    if (rc != GIT_OK) {
        git_reference_free(snap->ref);
        snap->ref = NULL;
        ldcp_log(LOGARGS(ERROR), "Failed to create tree builder for partition (%d), rc=%d", (int)msg->partition,
                 (int)rc);
    }
    (void)type;
}

int main(int argc, char *argv[])
{
    settings = ldcp_settings_new();
    ldcp_settings_set_option(settings, "enable_snappy", "false");

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

    char *repo_path = NULL;

    if (argc > 6) {
        repo_path = argv[6];
    }
    if (repo_path == NULL) {
        repo_path = calloc(strlen(options->bucket) + strlen("/tmp/.git"), sizeof(char));
        sprintf(repo_path, "/tmp/%s.git", options->bucket);
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
    free(repo_path);
    ldcp_client_free(client);
    ldcp_settings_unref(settings);
    return 0;
}
