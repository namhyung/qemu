/*
 * Virtio Pstore Support
 *
 * Authors:
 *  Namhyung Kim      <namhyung@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _QEMU_VIRTIO_PSTORE_H
#define _QEMU_VIRTIO_PSTORE_H

#include "standard-headers/linux/virtio_pstore.h"
#include "hw/virtio/virtio.h"
#include "hw/pci/pci.h"

#define TYPE_VIRTIO_PSTORE "virtio-pstore-device"
#define VIRTIO_PSTORE(obj) \
        OBJECT_CHECK(VirtIOPstore, (obj), TYPE_VIRTIO_PSTORE)

typedef struct VirtIOPstore {
    VirtIODevice    parent_obj;
    VirtQueue      *rvq;
    VirtQueue      *wvq;
    char           *directory;
    int             file_idx;
    int             num_file;
    struct dirent **files;
    uint64_t        id;
    uint64_t        bufsize;
    uint64_t        file_max;
} VirtIOPstore;

#endif
