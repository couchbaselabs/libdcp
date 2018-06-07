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
#include <git2.h>

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

int tree_walk_callback(const char *root, const git_tree_entry *entry, void *payload)
{
    printf("name: %s\n", git_tree_entry_name(entry));
}

static void bootstrap_callback(ldcp_CLIENT *client)
{
    ldcp_SET_WITH_META cmd = {0};
    cmd.flags = 0;
    cmd.expiration = 0;
    cmd.rev_seqno = 0;
    cmd.cas = 0;
    cmd.options = 0;
    cmd.meta_len = 0;
    cmd.meta = NULL;
    cmd.key_len = 0;
    cmd.key = NULL;
    cmd.xattrs_len = 0;
    cmd.xattrs = NULL;
    cmd.value_len = 0;
    cmd.value = NULL;
    ldcp_set_with_meta(client, &cmd, NULL);
    ldcp_install_config_callback(client, NULL);
}

static void set_with_meta_callback(ldcp_CLIENT *client, ldcp_RESP_CALLBACK type, const ldcp_RESP *resp)
{
    (void)client;
    (void)type;
    (void)resp;
}

int main(int argc, char *argv[])
{
    settings = ldcp_settings_new();
    ldcp_settings_set_option(settings, "enable_snappy", "false");

    setup_sigint_handler();
    setup_sigquit_handler();

    ldcp_OPTIONS *options = ldcp_options_new();
    options->settings = settings;
    options->type = LDCP_TYPE_BASIC;
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
        repo_path = calloc(strlen(options->bucket) + strlen("/tmp/.git") + 1, sizeof(char));
        sprintf(repo_path, "/tmp/%s.git", options->bucket);
    }

    ldcp_STATUS status;
    status = ldcp_client_new(options, &client);
    if (status != LDCP_OK) {
        ldcp_log(LOGARGS(ERROR), "Failed to initialize DCP client. status=%d", status);
        exit(EXIT_FAILURE);
    }
    ldcp_install_config_callback(client, bootstrap_callback);
    ldcp_install_resp_callback(client, LDCP_RESP_SETWITHMETA, set_with_meta_callback);
    ldcp_client_bootstrap(client);

    ldcp_log(LOGARGS(INFO), "Running");
    ldcp_client_dispatch(client);

#ifdef 0
    {
        int rc, success = 0;
        git_repository *repo;

        rc = git_libgit2_init();
        if (rc < 0) {
            ldcp_log(LOGARGS(ERROR), "Failed to initialize libgit2. rc=%d", rc);
            exit(1);
        }
        git_repository_init_options initopts = GIT_REPOSITORY_INIT_OPTIONS_INIT;
        initopts.flags = GIT_REPOSITORY_INIT_MKPATH | GIT_REPOSITORY_INIT_BARE;
        rc = git_repository_init_ext(&repo, repo_path, &initopts);
        if (rc != GIT_OK) {
            ldcp_log(LOGARGS(ERROR), "Failed to initialize git repository. rc=%d", rc);
            exit(1);
        }
        ldcp_log(LOGARGS(INFO), "Using git repo at \"%s\"", git_repository_path(repo));

        git_branch_iterator *iter;
        rc = git_branch_iterator_new(&iter, repo, GIT_BRANCH_LOCAL);
        if (rc != GIT_OK) {
            ldcp_log(LOGARGS(ERROR), "Failed to create branch iterator. rc=%d", rc);
            exit(1);
        }

        git_reference *ref;
        git_branch_t type;
        while (1) {
            rc = git_branch_next(&ref, &type, iter);
            if (rc == GIT_ITEROVER) {
                break;
            } else if (rc == GIT_OK) {
                const char *name = git_reference_name(ref);
                if (strncmp(name, "refs/heads/p", sizeof("refs/heads/p") - 1) == 0) {
                    uint16_t partition = (uint16_t)strtoul(name + sizeof("refs/heads/p") - 1, NULL, 10);

                    git_commit *commit;
                    rc = git_commit_lookup(&commit, repo, git_reference_target(ref));
                    if (rc != GIT_OK) {
                        ldcp_log(LOGARGS(ERROR), "Failed to lookup top commit for partition (%d), rc=%d",
                                 (int)partition, (int)rc);
                        exit(1);
                    }

                    const char *commit_msg = git_commit_summary(commit);
                    const char *commit_msg_end = commit_msg + strlen(commit_msg);
                    char *ptr;
                    ptr = strstr(commit_msg, "u:");
                    if (ptr == NULL || ptr + 2 >= commit_msg_end) {
                        exit(1);
                    }
                    uint64_t partition_uuid = strtoull(ptr + 2, NULL, 10);

                    printf("branch: %s, partition: %d, uuid: %" PRIu64 "\n", name, partition, partition_uuid);

                    git_tree *tree;
                    rc = git_commit_tree(&tree, commit);
                    git_commit_free(commit);
                    if (rc != GIT_OK) {
                        ldcp_log(LOGARGS(ERROR), "Failed to get commit tree for partition (%d), rc=%d", (int)partition,
                                 (int)rc);
                        exit(1);
                    }

                    git_tree_walk(tree, GIT_TREEWALK_PRE, tree_walk_callback, NULL);

                    git_tree_free(tree);
                }
            } else {
                ldcp_log(LOGARGS(ERROR), "Failed to iterate branches. rc=%d", rc);
                exit(1);
            }
        }

        git_branch_iterator_free(iter);
    }
#endif

    ldcp_log(LOGARGS(INFO), "Exiting");

    ldcp_client_free(client);
    ldcp_settings_unref(settings);
    return 0;
}
