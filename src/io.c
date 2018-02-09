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
#include <event2/dns.h>

#if 0
#    define LOGARGS(chan, lvl) chan->client->settings, "chan", LDCP_LOG_##lvl, __FILE__, __LINE__

static void dns_logfn(int is_warn, const char *msg)
{
    if (is_warn) {
        ldcp_log(LOGARGS(WARN), msg);
    } else {
        ldcp_log(LOGARGS(INFO), msg);
    }
}
#endif

LDCP_INTERNAL_API
ldcp_IO *ldcp_io_new()
{
    ldcp_IO *io = calloc(1, sizeof(ldcp_IO));

    io->evbase = event_base_new();
    io->evdns_base = evdns_base_new(io->evbase, 1);
#if 0
    evdns_set_log_fn(dns_logfn);
#endif

    return io;
}

LDCP_INTERNAL_API
void ldcp_io_free(ldcp_IO *io)
{
    evdns_base_free(io->evdns_base, 1);
    event_base_free(io->evbase);
    free(io);
}
