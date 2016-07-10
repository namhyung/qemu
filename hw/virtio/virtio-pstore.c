/*
 * Virtio Pstore Device
 *
 * Copyright (C) 2016  LG Electronics
 *
 * Authors:
 *  Namhyung Kim  <namhyung@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <stdio.h>

#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "qemu-common.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "sysemu/kvm.h"
#include "qapi/visitor.h"
#include "qapi-event.h"
#include "trace.h"

#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"
#include "hw/virtio/virtio-pstore.h"


static void virtio_pstore_to_filename(VirtIOPstore *s, char *buf, size_t sz,
                                      struct virtio_pstore_hdr *hdr)
{
    const char *basename;

    switch (hdr->type) {
    case VIRTIO_PSTORE_TYPE_DMESG:
        basename = "dmesg";
        break;
    default:
        basename = "unknown";
        break;
    }

    snprintf(buf, sz, "%s/%s-%llu%s", s->directory, basename,
             (unsigned long long) hdr->id,
             hdr->flags & VIRTIO_PSTORE_FL_COMPRESSED ? ".enc.z" : "");
}

static void virtio_pstore_from_filename(VirtIOPstore *s, char *name,
                                        char *buf, size_t sz,
                                        struct virtio_pstore_hdr *hdr)
{
    size_t len = strlen(name);

    hdr->flags = 0;
    if (!strncmp(name + len - 6, ".enc.z", 6)) {
        hdr->flags |= VIRTIO_PSTORE_FL_COMPRESSED;
    }

    snprintf(buf, sz, "%s/%s", s->directory, name);

    if (!strncmp(name, "dmesg-", 6)) {
        hdr->type = cpu_to_le16(VIRTIO_PSTORE_TYPE_DMESG);
        name += 6;
    } else if (!strncmp(name, "unknown-", 8)) {
        hdr->type = cpu_to_le16(VIRTIO_PSTORE_TYPE_UNKNOWN);
        name += 8;
    }

    qemu_strtoull(name, NULL, 0, &hdr->id);
}

static ssize_t virtio_pstore_do_open(VirtIOPstore *s)
{
    s->dir = opendir(s->directory);
    if (s->dir == NULL) {
        return -1;
    }

    return 0;
}

static ssize_t virtio_pstore_do_read(VirtIOPstore *s, void *buf, size_t sz,
                                      struct virtio_pstore_hdr *hdr)
{
    char path[PATH_MAX];
    FILE *fp;
    ssize_t len;
    struct stat stbuf;
    struct dirent *dent;

    if (s->dir == NULL) {
        return -1;
    }

    dent = readdir(s->dir);
    while (dent) {
        if (dent->d_name[0] != '.') {
            break;
        }
        dent = readdir(s->dir);
    }

    if (dent == NULL) {
        return 0;
    }

    virtio_pstore_from_filename(s, dent->d_name, path, sizeof(path), hdr);
    if (stat(path, &stbuf) < 0) {
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        error_report("cannot open %s (%p %p)", path, s, s->directory);
        return -1;
    }

    len = fread(buf, 1, sz, fp);
    if (len < 0 && errno == EAGAIN) {
        len = 0;
    }

    hdr->id = cpu_to_le64(hdr->id);
    hdr->flags = cpu_to_le32(hdr->flags);
    hdr->time_sec = cpu_to_le64(stbuf.st_ctim.tv_sec);
    hdr->time_nsec = cpu_to_le32(stbuf.st_ctim.tv_nsec);

    fclose(fp);
    return len;
}

static ssize_t virtio_pstore_do_write(VirtIOPstore *s, void *buf, size_t sz,
                                      struct virtio_pstore_hdr *hdr)
{
    char path[PATH_MAX];
    FILE *fp;

    virtio_pstore_to_filename(s, path, sizeof(path), hdr);

    fp = fopen(path, "w");
    if (fp == NULL) {
        error_report("cannot open %s (%p %p)", path, s, s->directory);
        return -1;
    }
    fwrite(buf, 1, sz, fp);
    fclose(fp);

    return sz;
}

static ssize_t virtio_pstore_do_close(VirtIOPstore *s)
{
    if (s->dir == NULL) {
        return 0;
    }

    closedir(s->dir);
    s->dir = NULL;

    return 0;
}

static ssize_t virtio_pstore_do_erase(VirtIOPstore *s,
                                      struct virtio_pstore_hdr *hdr)
{
    char path[PATH_MAX];

    virtio_pstore_to_filename(s, path, sizeof(path), hdr);

    return unlink(path);
}

static void virtio_pstore_handle_io(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOPstore *s = VIRTIO_PSTORE(vdev);
    VirtQueueElement *elem;
    struct virtio_pstore_hdr *hdr;
    ssize_t len;

    for (;;) {
        elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        if (!elem) {
            return;
        }

        hdr = elem->out_sg[0].iov_base;
        if (elem->out_sg[0].iov_len != sizeof(*hdr)) {
            error_report("invalid header size: %u",
                         (unsigned)elem->out_sg[0].iov_len);
            exit(1);
        }

        switch (hdr->cmd) {
        case VIRTIO_PSTORE_CMD_OPEN:
            len = virtio_pstore_do_open(s);
            break;
        case VIRTIO_PSTORE_CMD_READ:
            len = virtio_pstore_do_read(s, elem->in_sg[0].iov_base,
                                        elem->in_sg[0].iov_len, hdr);
            break;
        case VIRTIO_PSTORE_CMD_WRITE:
            len = virtio_pstore_do_write(s, elem->out_sg[1].iov_base,
                                         elem->out_sg[1].iov_len, hdr);
            break;
        case VIRTIO_PSTORE_CMD_CLOSE:
            len = virtio_pstore_do_close(s);
            break;
        case VIRTIO_PSTORE_CMD_ERASE:
            len = virtio_pstore_do_erase(s, hdr);
            break;
        default:
            len = -1;
            break;
        }

        if (len < 0) {
            return;
        }

        virtqueue_push(vq, elem, len);

        virtio_notify(vdev, vq);
        g_free(elem);
    }
}

static void virtio_pstore_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOPstore *s = VIRTIO_PSTORE(dev);

    virtio_init(vdev, "virtio-pstore", VIRTIO_ID_PSTORE, 0);

    s->vq = virtio_add_queue(vdev, 128, virtio_pstore_handle_io);
}

static void virtio_pstore_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    virtio_cleanup(vdev);
}

static uint64_t get_features(VirtIODevice *vdev, uint64_t f, Error **errp)
{
    return f;
}

static void pstore_get_directory(Object *obj, Visitor *v,
                                 const char *name, void *opaque,
                                 Error **errp)
{
    VirtIOPstore *s = opaque;

    visit_type_str(v, name, &s->directory, errp);
}

static void pstore_set_directory(Object *obj, Visitor *v,
                                 const char *name, void *opaque,
                                 Error **errp)
{
    VirtIOPstore *s = opaque;
    Error *local_err = NULL;
    char *value;

    visit_type_str(v, name, &value, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    g_free(s->directory);
    s->directory = strdup(value);

    g_free(value);
}

static void pstore_release_directory(Object *obj, const char *name,
                                     void *opaque)
{
    VirtIOPstore *s = opaque;

    g_free(s->directory);
    s->directory = NULL;
}

static Property virtio_pstore_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_pstore_instance_init(Object *obj)
{
    VirtIOPstore *s = VIRTIO_PSTORE(obj);

    object_property_add(obj, "directory", "str",
                        pstore_get_directory, pstore_set_directory,
                        pstore_release_directory, s, NULL);
}

static void virtio_pstore_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_pstore_properties;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_pstore_device_realize;
    vdc->unrealize = virtio_pstore_device_unrealize;
    vdc->get_features = get_features;
}

static const TypeInfo virtio_pstore_info = {
    .name = TYPE_VIRTIO_PSTORE,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOPstore),
    .instance_init = virtio_pstore_instance_init,
    .class_init = virtio_pstore_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_pstore_info);
}

type_init(virtio_register_types)
