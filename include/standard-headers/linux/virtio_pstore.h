#ifndef _LINUX_VIRTIO_PSTORE_H
#define _LINUX_VIRTIO_PSTORE_H
/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. */
#include "standard-headers/linux/types.h"
#include "standard-headers/linux/virtio_types.h"
#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_config.h"

#define VIRTIO_PSTORE_TYPE_UNKNOWN  0
#define VIRTIO_PSTORE_TYPE_DMESG    1

#define VIRTIO_PSTORE_CMD_NULL   0
#define VIRTIO_PSTORE_CMD_OPEN   1
#define VIRTIO_PSTORE_CMD_READ   2
#define VIRTIO_PSTORE_CMD_WRITE  3
#define VIRTIO_PSTORE_CMD_ERASE  4
#define VIRTIO_PSTORE_CMD_CLOSE  5

#define VIRTIO_PSTORE_FL_COMPRESSED  1

struct virtio_pstore_hdr {
    __virtio64 id;
    __virtio32 flags;
    __virtio16 cmd;
    __virtio16 type;
    __virtio64 time_sec;
    __virtio32 time_nsec;
    __virtio32 unused;
};

#endif /* _LINUX_VIRTIO_PSTORE_H */
