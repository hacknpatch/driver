
#include <linux/kernel.h>
#include <linux/fs.h>

#include "vencrypt-buffers.h"

struct venc_buffers *venc_alloc_buffers(int num_buffers)
{
	struct venc_buffers *bufs;
	struct venc_buffer *buf;
	int i;

	bufs = kmalloc(sizeof(struct venc_buffers), GFP_KERNEL);
	if (!bufs) {
		return NULL;
	}

	bufs->bufs =
		kmalloc(num_buffers * sizeof(struct venc_buffer), GFP_KERNEL);
	if (!bufs->bufs) {
		kfree(bufs);
		return NULL;
	}

	bufs->num_buffers = num_buffers;

	INIT_LIST_HEAD(&bufs->free);
	INIT_LIST_HEAD(&bufs->used);

	bufs->used_count = 0;
	bufs->drain = false;

	spin_lock_init(&bufs->lock);
	init_waitqueue_head(&bufs->wait);

	for (i = 0; i < num_buffers; i++) {
		buf = &bufs->bufs[i];
		list_add_tail(&buf->list, &bufs->free);
	}

	return bufs;
}

void venc_free_buffers(struct venc_buffers *bufs)
{
	kfree(bufs->bufs);
	kfree(bufs);
}

void venc_move_to_used(struct venc_buffers *bufs, struct venc_buffer *buf)
{
	spin_lock(&bufs->lock);
	list_del(&buf->list);
	list_add_tail(&buf->list, &bufs->used);
	bufs->used_count++;
	spin_unlock(&bufs->lock);
	wake_up_interruptible(&bufs->wait);
}

void venc_move_to_free(struct venc_buffers *bufs, struct venc_buffer *buf)
{
	spin_lock(&bufs->lock);
	bufs->used_count--;
	list_del(&buf->list);
	list_add_tail(&buf->list, &bufs->free);
	spin_unlock(&bufs->lock);
	wake_up_interruptible(&bufs->wait);
}

struct venc_buffer *venc_first_free_or_null(struct venc_buffers *bufs)
{
	return list_first_entry_or_null(&bufs->free, struct venc_buffer, list);
}

int venc_wait_for_free(struct venc_buffers *bufs, struct venc_buffer **buf)
{
	return wait_event_interruptible(
		bufs->wait, (*buf = venc_first_free_or_null(bufs)) != NULL);
}

struct venc_buffer *venc_first_used_or_null(struct venc_buffers *bufs)
{
	return list_first_entry_or_null(&bufs->used, struct venc_buffer, list);
}

struct venc_buffer *venc_last_used_or_null(struct venc_buffers *bufs)
{
	if (list_empty(&bufs->used))
		return NULL;
	return list_last_entry(&bufs->used, struct venc_buffer, list);
}

static bool venc_used_available(struct venc_buffers *bufs, bool *drain)
{
	bool available;
	spin_lock(&bufs->lock);
	available = bufs->used_count > 1 || bufs->drain;
	*drain = bufs->drain;
	spin_unlock(&bufs->lock);
	return available;
}

int venc_wait_for_used(struct venc_buffers *bufs, struct venc_buffer **buf,
		       bool *drain)
{
	int err = wait_event_interruptible(bufs->wait,
					   (venc_used_available(bufs, drain)));

	if (err)
		return err;

	*buf = venc_first_used_or_null(bufs);
	return 0;
}

void venc_set_drain(struct venc_buffers *bufs, bool drain)
{
	spin_lock(&bufs->lock);
	bufs->drain = drain;
	spin_unlock(&bufs->lock);
	wake_up_interruptible(&bufs->wait);
}

int venc_drain(struct venc_buffers *bufs)
{
	bool drain;
	spin_lock(&bufs->lock);
	drain = bufs->drain;
	spin_unlock(&bufs->lock);
	return drain;
}

int venc_wait_for_drain(struct venc_buffers *bufs, bool drain)
{
	return wait_event_interruptible(bufs->wait,
					(venc_drain(bufs) == drain));
}