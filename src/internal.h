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
#ifndef LDCP_INTERNAL_H
#define LDCP_INTERNAL_H 1

/* System/Standard includes */
#include "config.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

/* Global Project Dependencies/Includes */
#include <libdcp/dcp.h>

/**
 * This symbol declares internal APIs as accessible from other modules.
 * It should still not be used.
 */
#define LDCP_INTERNAL_API LDCP_PUBLIC_API

#include "assertion.h"
#include "settings.h"
#include "logging.h"
#include "ringbuffer.h"
#include "protocol_binary.h"
#include "cJSON/cJSON.h"

/* Internal dependencies */
LDCP_INTERNAL_API int ldcp_getenv_nonempty(const char *key, char *buf, size_t len);
LDCP_INTERNAL_API int ldcp_getenv_boolean(const char *key);
LDCP_INTERNAL_API int ldcp_getenv_nonempty_multi(char *buf, size_t nbuf, ...);
LDCP_INTERNAL_API int ldcp_getenv_boolean_multi(const char *key, ...);
LDCP_INTERNAL_API uint64_t ldcp_nstime(void);

#endif /* LDCP_INTERNAL_H */
