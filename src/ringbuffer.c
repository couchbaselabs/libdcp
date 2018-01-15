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

#include "internal.h"

static size_t minimum(size_t a, size_t b)
{
    return (a < b) ? a : b;
}

int ldcp_rb_init(ldcp_RINGBUFFER *buffer, size_t size)
{
    char *root = malloc(size);
    if (root == NULL) {
        return 0;
    }
    ldcp_rb_take_buffer(buffer, root, size);
    return 1;
}

void ldcp_rb_take_buffer(ldcp_RINGBUFFER *buffer, char *buf, size_t size)
{
    memset(buffer, 0, sizeof(ldcp_RINGBUFFER));
    buffer->root = buf;
    buffer->size = size;
    buffer->write_head = buffer->root;
    buffer->read_head = buffer->root;
}

void ldcp_rb_reset(ldcp_RINGBUFFER *buffer)
{
    ldcp_rb_consumed(buffer, ldcp_rb_get_nbytes(buffer));
}

void ldcp_rb_destruct(ldcp_RINGBUFFER *buffer)
{
    free(buffer->root);
    buffer->root = buffer->read_head = buffer->write_head = NULL;
    buffer->size = buffer->nbytes = 0;
}

int ldcp_rb_ensure_capacity(ldcp_RINGBUFFER *buffer, size_t size)
{
    char *new_root;
    size_t new_size = buffer->size << 1;
    if (new_size == 0) {
        new_size = 128;
    }

    if (size < (buffer->size - buffer->nbytes)) {
        /* we've got capacity! */
        return 1;
    }

    /* determine the new buffer size... */
    while ((new_size - buffer->nbytes) < size) {
        new_size <<= 1;
    }

    /* go ahead and allocate a bigger block */
    if ((new_root = malloc(new_size)) == NULL) {
        /* Allocation failed! */
        return 0;
    } else {
        /* copy the data over :) */
        char *old;
        size_t nbytes = buffer->nbytes;
        size_t nr = ldcp_rb_read(buffer, new_root, nbytes);
        ldcp_assert(nr == nbytes);
        old = buffer->root;
        buffer->size = new_size;
        buffer->root = new_root;
        buffer->nbytes = nbytes;
        buffer->read_head = buffer->root;
        buffer->write_head = buffer->root + nbytes;
        free(old);
        return 1;
    }
}

size_t ldcp_rb_get_size(ldcp_RINGBUFFER *buffer)
{
    return buffer->size;
}

void *ldcp_rb_get_start(ldcp_RINGBUFFER *buffer)
{
    return buffer->root;
}

void *ldcp_rb_get_read_head(ldcp_RINGBUFFER *buffer)
{
    return buffer->read_head;
}

void *ldcp_rb_get_write_head(ldcp_RINGBUFFER *buffer)
{
    return buffer->write_head;
}

size_t ldcp_rb_write(ldcp_RINGBUFFER *buffer, const void *src, size_t nb)
{
    const char *s = src;
    size_t nw = 0;
    size_t space;
    size_t toWrite;

    if (buffer->write_head >= buffer->read_head) {
        /* write up to the end with data.. */
        space = buffer->size - (size_t)(buffer->write_head - buffer->root);
        toWrite = minimum(space, nb);

        if (src != NULL) {
            memcpy(buffer->write_head, s, toWrite);
        }
        buffer->nbytes += toWrite;
        buffer->write_head += toWrite;
        nw = toWrite;

        if (buffer->write_head == (buffer->root + buffer->size)) {
            buffer->write_head = buffer->root;
        }

        if (nw == nb) {
            /* everything is written to the buffer.. */
            return nw;
        }

        nb -= toWrite;
        s += toWrite;
    }

    /* Copy data up until we catch up with the read head */
    space = (size_t)(buffer->read_head - buffer->write_head);
    toWrite = minimum(space, nb);
    if (src != NULL) {
        memcpy(buffer->write_head, s, toWrite);
    }
    buffer->nbytes += toWrite;
    buffer->write_head += toWrite;
    nw += toWrite;

    if (buffer->write_head == (buffer->root + buffer->size)) {
        buffer->write_head = buffer->root;
    }

    return nw;
}

size_t ldcp_rb_strcat(ldcp_RINGBUFFER *buffer, const char *str)
{
    size_t len = strlen(str);
    if (!ldcp_rb_ensure_capacity(buffer, len)) {
        return 0;
    }
    return ldcp_rb_write(buffer, str, len);
}

static void maybe_reset(ldcp_RINGBUFFER *buffer)
{
    if (buffer->nbytes == 0) {
        buffer->write_head = buffer->root;
        buffer->read_head = buffer->root;
    }
}

size_t ldcp_rb_read(ldcp_RINGBUFFER *buffer, void *dest, size_t nb)
{
    char *d = dest;
    size_t nr = 0;
    size_t space;
    size_t toRead;

    if (buffer->nbytes == 0) {
        return 0;
    }
    if (buffer->read_head >= buffer->write_head) {
        /* read up to the wrap point */
        space = buffer->size - (size_t)(buffer->read_head - buffer->root);
        toRead = minimum(space, nb);

        if (dest != NULL) {
            memcpy(d, buffer->read_head, toRead);
        }
        buffer->nbytes -= toRead;
        buffer->read_head += toRead;
        nr = toRead;

        if (buffer->read_head == (buffer->root + buffer->size)) {
            buffer->read_head = buffer->root;
        }

        if (nr == nb) {
            maybe_reset(buffer);
            return nr;
        }

        nb -= toRead;
        d += toRead;
    }

    space = (size_t)(buffer->write_head - buffer->read_head);
    toRead = minimum(space, nb);

    if (dest != NULL) {
        memcpy(d, buffer->read_head, toRead);
    }
    buffer->nbytes -= toRead;
    buffer->read_head += toRead;
    nr += toRead;

    if (buffer->read_head == (buffer->root + buffer->size)) {
        buffer->read_head = buffer->root;
    }

    maybe_reset(buffer);
    return nr;
}

size_t ldcp_rb_peek(ldcp_RINGBUFFER *buffer, void *dest, size_t nb)
{
    ldcp_RINGBUFFER copy = *buffer;
    return ldcp_rb_read(&copy, dest, nb);
}

size_t ldcp_rb_peek_at(ldcp_RINGBUFFER *buffer, size_t offset, void *dest, size_t nb)
{
    ldcp_RINGBUFFER copy = *buffer;
    size_t n = ldcp_rb_read(&copy, NULL, offset);
    if (n != offset) {
        return -1;
    }
    return ldcp_rb_read(&copy, dest, nb);
}

void ldcp_rb_produced(ldcp_RINGBUFFER *buffer, size_t nb)
{
    size_t n = ldcp_rb_write(buffer, NULL, nb);
    ldcp_assert(n == nb);
}

void ldcp_rb_consumed(ldcp_RINGBUFFER *buffer, size_t nb)
{
    size_t n = ldcp_rb_read(buffer, NULL, nb);
    ldcp_assert(n == nb);
}

size_t ldcp_rb_get_nbytes(ldcp_RINGBUFFER *buffer)
{
    return buffer->nbytes;
}

size_t ldcp_rb_update(ldcp_RINGBUFFER *buffer, ldcp_RINGBUFFER_DIRECTION direction, const void *src, size_t nb)
{
    const char *s = src;
    size_t nw, ret = 0;

    if (direction == LDCP_RINGBUFFER_READ) {
        if (buffer->read_head <= buffer->write_head) {
            nw = minimum(nb, buffer->nbytes);
            memcpy(buffer->read_head, s, nw);
            ret += nw;
        } else {
            nw = minimum(nb, buffer->size - (size_t)(buffer->read_head - buffer->root));
            memcpy(buffer->read_head, s, nw);
            nb -= nw;
            s += nw;
            ret += nw;
            if (nb) {
                nw = minimum(nb, (size_t)(buffer->write_head - buffer->root));
                memcpy(buffer->root, s, nw);
                ret += nw;
            }
        }
    } else {
        if (buffer->write_head >= buffer->read_head) {
            nw = minimum(nb, buffer->nbytes);
            memcpy(buffer->write_head - nw, s, nw);
            ret += nw;
        } else {
            nb = minimum(nb, buffer->nbytes);
            nw = minimum(nb, (size_t)(buffer->write_head - buffer->root));
            memcpy(buffer->write_head - nw, s + nb - nw, nw);
            nb -= nw;
            ret += nw;
            if (nb) {
                nw = minimum(nb, buffer->size - (size_t)(buffer->read_head - buffer->root));
                memcpy(buffer->root + buffer->size - nw, s, nw);
                ret += nw;
            }
        }
    }
    return ret;
}

void ldcp_rb_get_iov(ldcp_RINGBUFFER *buffer, ldcp_RINGBUFFER_DIRECTION direction, ldcp_IOV *iov)
{
    iov[1].iov_base = buffer->root;
    iov[1].iov_len = 0;

    if (direction == LDCP_RINGBUFFER_READ) {
        iov[0].iov_base = buffer->read_head;
        iov[0].iov_len = buffer->nbytes;
        if (buffer->read_head >= buffer->write_head) {
            ptrdiff_t chunk = buffer->root + buffer->size - buffer->read_head;
            if (buffer->nbytes > (size_t)chunk) {
                iov[0].iov_len = (size_t)chunk;
                iov[1].iov_len = buffer->nbytes - (size_t)chunk;
            }
        }
    } else {
        ldcp_assert(direction == LDCP_RINGBUFFER_WRITE);
        iov[0].iov_base = buffer->write_head;
        iov[0].iov_len = buffer->size - buffer->nbytes;
        if (buffer->write_head >= buffer->read_head) {
            /* I may write all the way to the end! */
            iov[0].iov_len = (size_t)((buffer->root + buffer->size) - buffer->write_head);
            /* And all the way up to the read head */
            iov[1].iov_len = (size_t)(buffer->read_head - buffer->root);
        }
    }
}

int ldcp_rb_is_continous(ldcp_RINGBUFFER *buffer, ldcp_RINGBUFFER_DIRECTION direction, size_t nb)
{
    int ret;

    if (direction == LDCP_RINGBUFFER_READ) {
        ret = (nb <= buffer->nbytes);

        if (buffer->read_head >= buffer->write_head) {
            ptrdiff_t chunk = buffer->root + buffer->size - buffer->read_head;
            if (nb > (size_t)chunk) {
                ret = 0;
            }
        }
    } else {
        ret = (nb <= buffer->size - buffer->nbytes);
        if (buffer->write_head >= buffer->read_head) {
            ptrdiff_t chunk = buffer->root + buffer->size - buffer->write_head;
            if (nb > (size_t)chunk) {
                ret = 0;
            }
        }
    }
    return ret;
}

int ldcp_rb_append(ldcp_RINGBUFFER *src, ldcp_RINGBUFFER *dest)
{
    char buffer[1024];
    size_t nr, nw;

    while ((nr = ldcp_rb_read(src, buffer, sizeof(buffer))) != 0) {
        ldcp_assert(ldcp_rb_ensure_capacity(dest, nr));
        nw = ldcp_rb_write(dest, buffer, nr);
        ldcp_assert(nw == nr);
    }

    return 1;
}

int ldcp_rb_memcpy(ldcp_RINGBUFFER *dst, ldcp_RINGBUFFER *src, size_t nbytes)
{
    ldcp_RINGBUFFER copy = *src;
    ldcp_IOV iov[2];
    int ii = 0;
    size_t towrite = nbytes;
    size_t toread, nb;

    if (nbytes > ldcp_rb_get_nbytes(src)) {
        /* EINVAL */
        return -1;
    }

    if (!ldcp_rb_ensure_capacity(dst, nbytes)) {
        /* Failed to allocate space */
        return -1;
    }

    ldcp_rb_get_iov(dst, LDCP_RINGBUFFER_WRITE, iov);
    toread = minimum(iov[ii].iov_len, nbytes);
    do {
        ldcp_assert(ii < 2);
        nb = ldcp_rb_read(&copy, iov[ii].iov_base, toread);
        toread -= nb;
        towrite -= nb;
        ++ii;
    } while (towrite > 0);
    ldcp_rb_produced(dst, nbytes);
    return 0;
}

int ldcp_rb_ensure_alignment(ldcp_RINGBUFFER *c)
{
#if defined(__hpux__) || defined(__hpux) || defined(__sparc__) || defined(__sparc)
    intptr_t addr = (intptr_t)c->read_head;

    if (addr % 8 != 0) {
        ldcp_RINGBUFFER copy;
        if (ldcp_rb_initialize(&copy, c->size) == 0 || ldcp_rb_memcpy(&copy, c, ldcp_rb_get_nbytes(c)) == -1) {
            return -1;
        }
        ldcp_rb_destruct(c);
        *c = copy;
    }
#else
    (void)c;
#endif
    return 0;
}
