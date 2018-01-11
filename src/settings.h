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

#ifndef LDCP_SETTINGS_H
#define LDCP_SETTINGS_H

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ldcp_LOGGER;

/**
 * Handy macros for converting between different time resolutions
 */

/** Convert seconds to millis */
#define LDCP_S2MS(s) (((uint32_t)s) * 1000)
/** Convert seconds to microseconds */
#define LDCP_S2US(s) (((uint32_t)s) * 1000000)
/** Convert seconds to nanoseconds */
#define LDCP_S2NS(s) (((hrtime_t)s) * 1000000000)
/** Convert nanoseconds to microseconds */
#define LDCP_NS2US(s) ((uint32_t)((s) / 1000))
/** Convert milliseconds to microseconds */
#define LDCP_MS2US(s) ((s)*1000)
/** Convert microseconds to nanoseconds */
#define LDCP_US2NS(s) (((hrtime_t)s) * 1000)
/** Convert milliseconds to nanoseconds */
#define LDCP_MS2NS(s) (((hrtime_t)s) * 1000000)

/**
 * Stateless setting structure.
 * Specifically this contains the 'environment' of the instance for things
 * which are intended to be passed around to other objects.
 */
typedef struct {
    uint16_t iid;
    uint16_t refcount;
    struct ldcp_LOGGER *logger;
    void (*dtorcb)(const void *);
    void *dtorarg;
} ldcp_SETTINGS;

LDCP_INTERNAL_API ldcp_SETTINGS *ldcp_settings_new(void);

#define ldcp_settings_ref(settings) ((void)(settings)->refcount++)
LDCP_INTERNAL_API void ldcp_settings_unref(ldcp_SETTINGS *);

#ifdef __cplusplus
}
#    endif

#endif // LDCP_SETTINGS_H
