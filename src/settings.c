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

#include "internal.h"

LDCP_INTERNAL_API
ldcp_SETTINGS *ldcp_settings_new(void)
{
    ldcp_SETTINGS *settings = calloc(1, sizeof(*settings));
    settings->refcount = 1;
    settings->logger = ldcp_init_console_logger();
    return settings;
}

LDCP_INTERNAL_API
void ldcp_settings_unref(ldcp_SETTINGS *settings)
{
    if (--settings->refcount) {
        return;
    }
    if (settings->dtorcb) {
        settings->dtorcb(settings->dtorarg);
    }
    free(settings);
}
