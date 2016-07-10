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
                                      struct virtio_pstore_req *req)
{
    const char *basename;
    unsigned long long id = 0;
    unsigned int flags = le32_to_cpu(req->flags);

    switch (le16_to_cpu(req->type)) {
    case VIRTIO_PSTORE_TYPE_DMESG:
        basename = "dmesg";
        id = s->id++;
        break;
    case VIRTIO_PSTORE_TYPE_CONSOLE:
        basename = "console";
        if (s->console_id) {
            id = s->console_id;
        } else {
            id = s->console_id = s->id++;
        }
        break;
    default:
        basename = "unknown";
        break;
    }

    snprintf(buf, sz, "%s/%s-%llu%s", s->directory, basename, id,
             flags & VIRTIO_PSTORE_FL_COMPRESSED ? ".enc.z" : "");
}

static void virtio_pstore_from_filename(VirtIOPstore *s, char *name,
                                        char *buf, size_t sz,
                                        struct virtio_pstore_fileinfo *info)
{
    snprintf(buf, sz, "%s/%s", s->directory, name);

    if (g_str_has_prefix(name, "dmesg-")) {
        info->type = VIRTIO_PSTORE_TYPE_DMESG;
        name += strlen("dmesg-");
    } else if (g_str_has_prefix(name, "console-")) {
        info->type = VIRTIO_PSTORE_TYPE_CONSOLE;
        name += strlen("console-");
    } else if (g_str_has_prefix(name, "unknown-")) {
        info->type = VIRTIO_PSTORE_TYPE_UNKNOWN;
        name += strlen("unknown-");
    }

    qemu_strtoull(name, NULL, 0, &info->id);

    info->flags = 0;
    if (g_str_has_suffix(name, ".enc.z")) {
        info->flags |= VIRTIO_PSTORE_FL_COMPRESSED;
    }
}

static ssize_t virtio_pstore_do_open(VirtIOPstore *s)
{
    s->dirp = opendir(s->directory);
    if (s->dirp == NULL) {
        return -1;
    }

    return 0;
}

static ssize_t virtio_pstore_do_read(VirtIOPstore *s, struct iovec *in_sg,
                                     unsigned int in_num,
                                     struct virtio_pstore_res *res)
{
    char path[PATH_MAX];
    int fd;
    ssize_t len;
    struct stat stbuf;
    struct dirent *dent;
    int sg_num = in_num;
    struct iovec sg[sg_num];
    struct virtio_pstore_fileinfo info;
    size_t offset = sizeof(*res) + sizeof(info);

    if (s->dirp == NULL) {
        return -1;
    }

    dent = readdir(s->dirp);
    while (dent) {
        if (dent->d_name[0] != '.') {
            break;
        }
        dent = readdir(s->dirp);
    }

    if (dent == NULL) {
        return 0;
    }

    /* skip res and fileinfo */
    sg_num = iov_copy(sg, sg_num, in_sg, in_num, offset,
                      iov_size(in_sg, in_num) - offset);

    virtio_pstore_from_filename(s, dent->d_name, path, sizeof(path), &info);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        error_report("cannot open %s", path);
        return -1;
    }

    if (fstat(fd, &stbuf) < 0) {
        len = -1;
        goto out;
    }

    len = readv(fd, sg, sg_num);
    if (len < 0) {
        if (errno == EAGAIN) {
            len = 0;
        }
        goto out;
    }

    info.id        = cpu_to_le64(info.id);
    info.type      = cpu_to_le16(info.type);
    info.flags     = cpu_to_le32(info.flags);
    info.len       = cpu_to_le32(len);
    info.time_sec  = cpu_to_le64(stbuf.st_ctim.tv_sec);
    info.time_nsec = cpu_to_le32(stbuf.st_ctim.tv_nsec);

    iov_from_buf(in_sg, in_num, sizeof(*res), &info, sizeof(info));
    len += sizeof(info);

 out:
    close(fd);
    return len;
}

static ssize_t virtio_pstore_do_write(VirtIOPstore *s, struct iovec *out_sg,
                                      unsigned int out_num,
                                      struct virtio_pstore_req *req)
{
    char path[PATH_MAX];
    int fd;
    ssize_t len;
    unsigned short type;
    int flags = O_WRONLY | O_CREAT;

    /* we already consume the req */
    iov_discard_front(&out_sg, &out_num, sizeof(*req));

    virtio_pstore_to_filename(s, path, sizeof(path), req);

    type = le16_to_cpu(req->type);

    if (type == VIRTIO_PSTORE_TYPE_DMESG) {
        flags |= O_TRUNC;
    } else if (type == VIRTIO_PSTORE_TYPE_CONSOLE) {
        flags |= O_APPEND;
    }

    fd = open(path, flags, 0644);
    if (fd < 0) {
        error_report("cannot open %s", path);
        return -1;
    }
    len = writev(fd, out_sg, out_num);
    close(fd);

    return len;
}

static ssize_t virtio_pstore_do_close(VirtIOPstore *s)
{
    if (s->dirp == NULL) {
        return 0;
    }

    closedir(s->dirp);
    s->dirp = NULL;

    return 0;
}

static ssize_t virtio_pstore_do_erase(VirtIOPstore *s,
                                      struct virtio_pstore_req *req)
{
    char path[PATH_MAX];

    virtio_pstore_to_filename(s, path, sizeof(path), req);

    return unlink(path);
}

static void virtio_pstore_handle_io(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOPstore *s = VIRTIO_PSTORE(vdev);
    VirtQueueElement *elem;
    struct virtio_pstore_req req;
    struct virtio_pstore_res res;
    ssize_t len = 0;
    int ret;

    for (;;) {
        elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        if (!elem) {
            return;
        }

        if (elem->out_num < 1 || elem->in_num < 1) {
            error_report("request or response buffer is missing");
            exit(1);
        }

        len = iov_to_buf(elem->out_sg, elem->out_num, 0, &req, sizeof(req));
        if (len != (ssize_t)sizeof(req)) {
            error_report("invalid request size: %ld", (long)len);
            exit(1);
        }
        res.cmd  = req.cmd;
        res.type = req.type;

        switch (le16_to_cpu(req.cmd)) {
        case VIRTIO_PSTORE_CMD_OPEN:
            ret = virtio_pstore_do_open(s);
            break;
        case VIRTIO_PSTORE_CMD_READ:
            ret = virtio_pstore_do_read(s, elem->in_sg, elem->in_num, &res);
            if (ret > 0) {
                len = ret;
                ret = 0;
            }
            break;
        case VIRTIO_PSTORE_CMD_WRITE:
            ret = virtio_pstore_do_write(s, elem->out_sg, elem->out_num, &req);
            break;
        case VIRTIO_PSTORE_CMD_CLOSE:
            ret = virtio_pstore_do_close(s);
            break;
        case VIRTIO_PSTORE_CMD_ERASE:
            ret = virtio_pstore_do_erase(s, &req);
            break;
        default:
            ret = -1;
            break;
        }

        res.ret  = ret;

        iov_from_buf(elem->in_sg, elem->in_num, 0, &res, sizeof(res));
        virtqueue_push(vq, elem, sizeof(res) + len);

        virtio_notify(vdev, vq);
        g_free(elem);

        if (ret < 0) {
            return;
        }
    }
}

static void virtio_pstore_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOPstore *s = VIRTIO_PSTORE(dev);

    virtio_init(vdev, "virtio-pstore", VIRTIO_ID_PSTORE,
                sizeof(struct virtio_pstore_config));

    s->id = 1;
    s->console_id = 0;

    s->vq[0] = virtio_add_queue(vdev, 128, virtio_pstore_handle_io);
    s->vq[1] = virtio_add_queue(vdev, 128, virtio_pstore_handle_io);
}

static void virtio_pstore_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

    virtio_cleanup(vdev);
}

static void virtio_pstore_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    VirtIOPstore *dev = VIRTIO_PSTORE(vdev);
    struct virtio_pstore_config config;

    config.bufsize = cpu_to_le32(dev->bufsize);
    if (dev->console) {
        config.flags |= cpu_to_le32(VIRTIO_PSTORE_CONFIG_FL_CONSOLE);
    }

    memcpy(config_data, &config, sizeof(struct virtio_pstore_config));
}

static void virtio_pstore_set_config(VirtIODevice *vdev,
                                     const uint8_t *config_data)
{
    VirtIOPstore *dev = VIRTIO_PSTORE(vdev);
    struct virtio_pstore_config config;

    memcpy(&config, config_data, sizeof(struct virtio_pstore_config));

    dev->bufsize = le32_to_cpu(config.bufsize);
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
    s->directory = value;
}

static void pstore_release_directory(Object *obj, const char *name,
                                     void *opaque)
{
    VirtIOPstore *s = opaque;

    g_free(s->directory);
    s->directory = NULL;
}

static void pstore_get_bufsize(Object *obj, Visitor *v,
                               const char *name, void *opaque,
                               Error **errp)
{
    VirtIOPstore *s = opaque;
    uint64_t value = s->bufsize;

    visit_type_size(v, name, &value, errp);
}

static void pstore_set_bufsize(Object *obj, Visitor *v,
                               const char *name, void *opaque,
                               Error **errp)
{
    VirtIOPstore *s = opaque;
    Error *error = NULL;
    uint64_t value;

    visit_type_size(v, name, &value, &error);
    if (error) {
        error_propagate(errp, error);
        return;
    }

    if (value < 4096) {
        error_report("Warning: too small buffer size: %"PRIu64, value);
    }

    s->bufsize = value;
}

static void pstore_get_console(Object *obj, Visitor *v,
                               const char *name, void *opaque,
                               Error **errp)
{
    VirtIOPstore *s = opaque;
    bool value = s->console;

    visit_type_bool(v, name, &value, errp);
}

static void pstore_set_console(Object *obj, Visitor *v,
                               const char *name, void *opaque,
                               Error **errp)
{
    VirtIOPstore *s = opaque;
    Error *error = NULL;
    bool value;

    visit_type_bool(v, name, &value, &error);
    if (error) {
        error_propagate(errp, error);
        return;
    }

    s->console = value;
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
    object_property_add(obj, "bufsize", "size",
                        pstore_get_bufsize, pstore_set_bufsize, NULL, s, NULL);
    object_property_add(obj, "console", "bool",
                        pstore_get_console, pstore_set_console, NULL, s, NULL);
}

static void virtio_pstore_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_pstore_properties;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_pstore_device_realize;
    vdc->unrealize = virtio_pstore_device_unrealize;
    vdc->get_config = virtio_pstore_get_config;
    vdc->set_config = virtio_pstore_set_config;
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
