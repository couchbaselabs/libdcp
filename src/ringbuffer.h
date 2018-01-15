/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2011-2017 Couchbase, Inc.
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

#ifndef LDCP_RINGBUFFER_H
#define LDCP_RINGBUFFER_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *root;
    char *read_head;
    char *write_head;
    size_t size;
    size_t nbytes;
} ldcp_RINGBUFFER;

typedef enum { LDCP_RINGBUFFER_READ = 0x01, LDCP_RINGBUFFER_WRITE = 0x02 } ldcp_RINGBUFFER_DIRECTION;

int ldcp_rb_init(ldcp_RINGBUFFER *buffer, size_t size);

/**
 * Initialize a ringbuffer, taking ownership of an allocated char buffer.
 * This function always succeeds.
 * @param buffer a ldcp_RINGBUFFER to be initialized
 * @param buf the buffer to steal
 * @param size the allocated size of the buffer
 */
void ldcp_rb_take_buffer(ldcp_RINGBUFFER *buffer, char *buf, size_t size);
void ldcp_rb_reset(ldcp_RINGBUFFER *buffer);

void ldcp_rb_destruct(ldcp_RINGBUFFER *buffer);
int ldcp_rb_ensure_capacity(ldcp_RINGBUFFER *buffer, size_t size);
size_t ldcp_rb_get_size(ldcp_RINGBUFFER *buffer);
void *ldcp_rb_get_start(ldcp_RINGBUFFER *buffer);
void *ldcp_rb_get_read_head(ldcp_RINGBUFFER *buffer);
void *ldcp_rb_get_write_head(ldcp_RINGBUFFER *buffer);
size_t ldcp_rb_write(ldcp_RINGBUFFER *buffer, const void *src, size_t nb);
size_t ldcp_rb_strcat(ldcp_RINGBUFFER *buffer, const char *str);
size_t ldcp_rb_read(ldcp_RINGBUFFER *buffer, void *dest, size_t nb);
size_t ldcp_rb_peek(ldcp_RINGBUFFER *buffer, void *dest, size_t nb);
size_t ldcp_rb_peek_at(ldcp_RINGBUFFER *buffer, size_t offset, void *dest, size_t nb);
/* replace +nb+ bytes on +direction+ end of the buffer with src */
size_t ldcp_rb_update(ldcp_RINGBUFFER *buffer, ldcp_RINGBUFFER_DIRECTION direction, const void *src, size_t nb);
void ldcp_rb_get_iov(ldcp_RINGBUFFER *buffer, ldcp_RINGBUFFER_DIRECTION direction, ldcp_IOV *iov);
void ldcp_rb_produced(ldcp_RINGBUFFER *buffer, size_t nb);
void ldcp_rb_consumed(ldcp_RINGBUFFER *buffer, size_t nb);
size_t ldcp_rb_get_nbytes(ldcp_RINGBUFFER *buffer);
int ldcp_rb_is_continous(ldcp_RINGBUFFER *buffer, ldcp_RINGBUFFER_DIRECTION direction, size_t nb);

int ldcp_rb_append(ldcp_RINGBUFFER *src, ldcp_RINGBUFFER *dest);
int ldcp_rb_memcpy(ldcp_RINGBUFFER *dst, ldcp_RINGBUFFER *src, size_t nbytes);

/* Align the read head of the ringbuffer for platforms where it's needed */
int ldcp_rb_ensure_alignment(ldcp_RINGBUFFER *src);

#ifdef __cplusplus
}
#    endif

#endif
