/*
 * Virtio Pstore Device
 *
 * Copyright (C) 2016  LG Electronics
 *
 * Authors:
 *  Namhyung Kim  <namhyung@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
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
#include "io/channel-util.h"
#include "trace.h"

#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-access.h"
#include "hw/virtio/virtio-pstore.h"

#define PSTORE_DEFAULT_BUFSIZE   (16 * 1024)
#define PSTORE_DEFAULT_FILE_MAX  5

/* the index should match to the type value */
static const char *virtio_pstore_file_prefix[] = {
    "unknown-",		/* VIRTIO_PSTORE_TYPE_UNKNOWN */
    "dmesg-",		/* VIRTIO_PSTORE_TYPE_DMESG */
};

static char *virtio_pstore_to_filename(VirtIOPstore *s,
                                       struct virtio_pstore_req *req)
{
    const char *basename;
    unsigned long long id;
    unsigned int type = le16_to_cpu(req->type);
    unsigned int flags = le32_to_cpu(req->flags);

    if (type < ARRAY_SIZE(virtio_pstore_file_prefix)) {
        basename = virtio_pstore_file_prefix[type];
    } else {
        basename = "unknown-";
    }

    id = s->id++;
    return g_strdup_printf("%s/%s%llu%s", s->directory, basename, id,
                            flags & VIRTIO_PSTORE_FL_COMPRESSED ? ".enc.z" : "");
}

static char *virtio_pstore_from_filename(VirtIOPstore *s, char *name,
                                         struct virtio_pstore_fileinfo *info)
{
    char *filename;
    unsigned int idx;

    filename = g_strdup_printf("%s/%s", s->directory, name);
    if (filename == NULL)
        return NULL;

    for (idx = 0; idx < ARRAY_SIZE(virtio_pstore_file_prefix); idx++) {
        if (g_str_has_prefix(name, virtio_pstore_file_prefix[idx])) {
            info->type = idx;
            name += strlen(virtio_pstore_file_prefix[idx]);
            break;
        }
    }

    if (idx == ARRAY_SIZE(virtio_pstore_file_prefix)) {
        g_free(filename);
        return NULL;
    }

    qemu_strtoull(name, NULL, 0, &info->id);

    info->flags = 0;
    if (g_str_has_suffix(name, ".enc.z")) {
        info->flags |= VIRTIO_PSTORE_FL_COMPRESSED;
    }

    return filename;
}

static int prefix_idx;
static int prefix_count;
static int prefix_len;

static int filter_pstore(const struct dirent *de)
{
    int i;

    for (i = 0; i < prefix_count; i++) {
        const char *prefix = virtio_pstore_file_prefix[prefix_idx + i];

        if (g_str_has_prefix(de->d_name, prefix)) {
            return 1;
        }
    }
    return 0;
}

static int sort_pstore(const struct dirent **a, const struct dirent **b)
{
    uint64_t id_a, id_b;

    qemu_strtoull((*a)->d_name + prefix_len, NULL, 0, &id_a);
    qemu_strtoull((*b)->d_name + prefix_len, NULL, 0, &id_b);

    return id_a - id_b;
}

static int rotate_pstore_file(VirtIOPstore *s, unsigned short type)
{
    int ret = 0;
    int i, num;
    char *filename;
    struct dirent **files;

    if (type >= ARRAY_SIZE(virtio_pstore_file_prefix)) {
        type = VIRTIO_PSTORE_TYPE_UNKNOWN;
    }

    prefix_idx = type;
    prefix_len = strlen(virtio_pstore_file_prefix[type]);
    prefix_count = 1;  /* only scan current type */

    /* delete the oldest file in the same type */
    num = scandir(s->directory, &files, filter_pstore, sort_pstore);
    if (num < 0)
        return num;
    if (num < (int)s->file_max)
        goto out;

    filename = g_strdup_printf("%s/%s", s->directory, files[0]->d_name);
    if (filename == NULL) {
        ret = -1;
        goto out;
    }

    ret = unlink(filename);

out:
    for (i = 0; i < num; i++) {
        g_free(files[i]);
    }
    g_free(files);

    return ret;
}

static ssize_t virtio_pstore_do_open(VirtIOPstore *s)
{
    /* scan all pstore files */
    prefix_idx = 0;
    prefix_count = ARRAY_SIZE(virtio_pstore_file_prefix);

    s->file_idx = 0;
    s->num_file = scandir(s->directory, &s->files, filter_pstore, alphasort);

    return s->num_file >= 0 ? 0 : -1;
}

static ssize_t virtio_pstore_do_close(VirtIOPstore *s)
{
    int i;

    for (i = 0; i < s->num_file; i++) {
        g_free(s->files[i]);
    }
    g_free(s->files);
    s->files = NULL;

    s->num_file = 0;
    return 0;
}

static ssize_t virtio_pstore_do_erase(VirtIOPstore *s,
                                      struct virtio_pstore_req *req)
{
    char *filename;
    int ret;

    filename = virtio_pstore_to_filename(s, req);
    if (filename == NULL)
        return -1;

    ret = unlink(filename);

    g_free(filename);
    return ret;
}

struct pstore_read_arg {
    VirtIOPstore *vps;
    VirtQueueElement *elem;
    struct virtio_pstore_fileinfo info;
    QIOChannel *ioc;
};

static gboolean pstore_async_read_fn(QIOChannel *ioc, GIOCondition condition,
                                     gpointer data)
{
    struct pstore_read_arg *rarg = data;
    struct virtio_pstore_fileinfo *info = &rarg->info;
    VirtIOPstore *vps = rarg->vps;
    VirtQueueElement *elem = rarg->elem;
    struct virtio_pstore_res res;
    size_t offset = sizeof(res) + sizeof(*info);
    struct iovec *sg = elem->in_sg;
    unsigned int sg_num = elem->in_num;
    Error *err = NULL;
    ssize_t len;
    int ret;

    /* skip res and fileinfo */
    iov_discard_front(&sg, &sg_num, sizeof(res) + sizeof(*info));

    len = qio_channel_readv(rarg->ioc, sg, sg_num, &err);
    if (len < 0) {
        if (errno == EAGAIN) {
            len = 0;
        }
        ret = -1;
    } else {
        info->len = cpu_to_le32(len);
        ret = 0;
    }

    res.cmd  = cpu_to_le16(VIRTIO_PSTORE_CMD_READ);
    res.type = cpu_to_le16(VIRTIO_PSTORE_TYPE_UNKNOWN);
    res.ret  = cpu_to_le32(ret);

    /* now copy res and fileinfo */
    iov_from_buf(elem->in_sg, elem->in_num, 0, &res, sizeof(res));
    iov_from_buf(elem->in_sg, elem->in_num, sizeof(res), info, sizeof(*info));

    len += offset;
    virtqueue_push(vps->rvq, elem, len);
    virtio_notify(VIRTIO_DEVICE(vps), vps->rvq);

    return G_SOURCE_REMOVE;
}

static void free_rarg_fn(gpointer data)
{
    struct pstore_read_arg *rarg = data;

    qio_channel_close(rarg->ioc, NULL);

    g_free(rarg->elem);
    g_free(rarg);
}

static ssize_t virtio_pstore_do_read(VirtIOPstore *s, VirtQueueElement *elem)
{
    char *filename = NULL;
    int fd, idx;
    struct stat stbuf;
    struct pstore_read_arg *rarg = NULL;
    Error *err = NULL;
    int ret = -1;

    if (s->file_idx >= s->num_file) {
        return 0;
    }

    rarg = g_malloc(sizeof(*rarg));
    if (rarg == NULL) {
        return -1;
    }

    idx = s->file_idx++;
    filename = virtio_pstore_from_filename(s, s->files[idx]->d_name,
                                           &rarg->info);
    if (filename == NULL) {
        goto out;
    }

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        error_report("cannot open %s", filename);
        goto out;
    }

    if (fstat(fd, &stbuf) < 0) {
        goto out;
    }

    rarg->vps            = s;
    rarg->elem           = elem;
    rarg->info.id        = cpu_to_le64(rarg->info.id);
    rarg->info.type      = cpu_to_le16(rarg->info.type);
    rarg->info.flags     = cpu_to_le32(rarg->info.flags);
    rarg->info.time_sec  = cpu_to_le64(stbuf.st_ctim.tv_sec);
    rarg->info.time_nsec = cpu_to_le32(stbuf.st_ctim.tv_nsec);

    rarg->ioc = qio_channel_new_fd(fd, &err);
    if (err) {
        error_reportf_err(err, "cannot create io channel: ");
        goto out;
    }

    qio_channel_set_blocking(rarg->ioc, false, &err);
    qio_channel_add_watch(rarg->ioc, G_IO_IN, pstore_async_read_fn, rarg,
                          free_rarg_fn);
    g_free(filename);
    return 1;

out:
    g_free(filename);
    g_free(rarg);

    return ret;
}

struct pstore_write_arg {
    VirtIOPstore *vps;
    VirtQueueElement *elem;
    struct virtio_pstore_req *req;
    QIOChannel *ioc;
};

static gboolean pstore_async_write_fn(QIOChannel *ioc, GIOCondition condition,
                                      gpointer data)
{
    struct pstore_write_arg *warg = data;
    VirtIOPstore *vps = warg->vps;
    VirtQueueElement *elem = warg->elem;
    struct iovec *sg = elem->out_sg;
    unsigned int sg_num = elem->out_num;
    struct virtio_pstore_res res;
    Error *err = NULL;
    ssize_t len;
    int ret;

    /* we already consumed the req */
    iov_discard_front(&sg, &sg_num, sizeof(*warg->req));

    len = qio_channel_writev(warg->ioc, sg, sg_num, &err);
    if (len < 0) {
        ret = -1;
    } else {
        ret = 0;
    }

    res.cmd  = cpu_to_le16(VIRTIO_PSTORE_CMD_WRITE);
    res.type = warg->req->type;
    res.ret  = cpu_to_le32(ret);

    /* tell the result to guest */
    iov_from_buf(elem->in_sg, elem->in_num, 0, &res, sizeof(res));

    virtqueue_push(vps->wvq, elem, sizeof(res));
    virtio_notify(VIRTIO_DEVICE(vps), vps->wvq);

    return G_SOURCE_REMOVE;
}

static void free_warg_fn(gpointer data)
{
    struct pstore_write_arg *warg = data;

    qio_channel_close(warg->ioc, NULL);

    g_free(warg->elem);
    g_free(warg);
}

static ssize_t virtio_pstore_do_write(VirtIOPstore *s, VirtQueueElement *elem,
                                      struct virtio_pstore_req *req)
{
    unsigned short type = le16_to_cpu(req->type);
    char *filename = NULL;
    int fd;
    int flags = O_WRONLY | O_CREAT | O_TRUNC;
    struct pstore_write_arg *warg = NULL;
    Error *err = NULL;
    int ret = -1;

    /* do not keep same type of files more than 'file-max' */
    rotate_pstore_file(s, type);

    filename = virtio_pstore_to_filename(s, req);
    if (filename == NULL) {
        return -1;
    }

    warg = g_malloc(sizeof(*warg));
    if (warg == NULL) {
        goto out;
    }

    fd = open(filename, flags, 0644);
    if (fd < 0) {
        error_report("cannot open %s", filename);
        ret = fd;
        goto out;
    }

    warg->vps            = s;
    warg->elem           = elem;
    warg->req            = req;

    warg->ioc = qio_channel_new_fd(fd, &err);
    if (err) {
        error_reportf_err(err, "cannot create io channel: ");
        goto out;
    }

    qio_channel_set_blocking(warg->ioc, false, &err);
    qio_channel_add_watch(warg->ioc, G_IO_OUT, pstore_async_write_fn, warg,
                          free_warg_fn);
    g_free(filename);
    return 1;

out:
    g_free(filename);
    g_free(warg);
    return ret;
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

        if (elem->out_num > 2 || elem->in_num > 3) {
            error_report("invalid number of input/output buffer");
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
        case VIRTIO_PSTORE_CMD_CLOSE:
            ret = virtio_pstore_do_close(s);
            break;
        case VIRTIO_PSTORE_CMD_ERASE:
            ret = virtio_pstore_do_erase(s, &req);
            break;
        case VIRTIO_PSTORE_CMD_READ:
            ret = virtio_pstore_do_read(s, elem);
            if (ret == 1) {
                /* async channel io */
                continue;
            }
            break;
        case VIRTIO_PSTORE_CMD_WRITE:
            ret = virtio_pstore_do_write(s, elem, &req);
            if (ret == 1) {
                /* async channel io */
                continue;
            }
            break;
        default:
            ret = -1;
            break;
        }

        res.ret = ret;

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

    if (!s->bufsize)
        s->bufsize = PSTORE_DEFAULT_BUFSIZE;
    if (!s->file_max)
        s->file_max = PSTORE_DEFAULT_FILE_MAX;

    s->rvq = virtio_add_queue(vdev, 128, virtio_pstore_handle_io);
    s->wvq = virtio_add_queue(vdev, 128, virtio_pstore_handle_io);
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
        error_setg(&error, "Warning: too small buffer size: %"PRIu64, value);
        error_propagate(errp, error);
        return;
    }

    s->bufsize = value;
}

static void pstore_get_file_max(Object *obj, Visitor *v,
                                const char *name, void *opaque,
                                Error **errp)
{
    VirtIOPstore *s = opaque;
    int64_t value = s->file_max;

    visit_type_int(v, name, &value, errp);
}

static void pstore_set_file_max(Object *obj, Visitor *v,
                                const char *name, void *opaque,
                                Error **errp)
{
    VirtIOPstore *s = opaque;
    Error *error = NULL;
    int64_t value;

    visit_type_int(v, name, &value, &error);
    if (error) {
        error_propagate(errp, error);
        return;
    }

    s->file_max = value;
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
    object_property_add(obj, "file-max", "int",
                        pstore_get_file_max, pstore_set_file_max, NULL, s, NULL);
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
