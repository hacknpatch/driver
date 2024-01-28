
#include <linux/kernel.h>
#include <linux/fs.h>

#include "vencrypt-buffers.h"

void venc_init_buffers(struct venc_buffers *bufs)
{
	int i;
	struct venc_buffer *buf;

	INIT_LIST_HEAD(&bufs->free);
	INIT_LIST_HEAD(&bufs->used);

	spin_lock_init(&bufs->lock);
	init_waitqueue_head(&bufs->wait);

	for (i = 0; i < sizeof(bufs->bufs) / sizeof(struct venc_buffer); i++) {		
		buf = &bufs->bufs[i];		
		list_add_tail(&buf->list, &bufs->free);
	}
}

void venc_move_to_used(struct venc_buffers *bufs, struct venc_buffer *buf)
{
	spin_lock(&bufs->lock);
	list_del(&buf->list);
	list_add_tail(&buf->list, &bufs->used);
	spin_unlock(&bufs->lock);
	wake_up_interruptible(&bufs->wait);
}

void venc_move_to_free(struct venc_buffers *bufs, struct venc_buffer *buf)
{
	spin_lock(&bufs->lock);
	list_del(&buf->list);
	list_add_tail(&buf->list, &bufs->free);
	spin_unlock(&bufs->lock);
	wake_up_interruptible(&bufs->wait);
}

struct venc_buffer * venc_first_free_or_null(struct venc_buffers *bufs)
{
	return list_first_entry_or_null(&bufs->free, struct venc_buffer, list);
}

int venc_wait_for_free(struct venc_buffers *bufs, struct venc_buffer **buf)
{
	return wait_event_interruptible(bufs->wait,
		(*buf = venc_first_free_or_null(bufs)) != NULL);
}

struct venc_buffer * venc_first_used_or_null(struct venc_buffers *bufs)
{
	return list_first_entry_or_null(&bufs->used, struct venc_buffer, list);
}

int venc_wait_for_used(struct venc_buffers *bufs, struct venc_buffer **buf)
{
	return wait_event_interruptible(bufs->wait,
		((*buf = venc_first_used_or_null(bufs)) != NULL || READ_ONCE(bufs->drain))
		);
}

void venc_drain(struct venc_buffers *bufs)
{
	WRITE_ONCE(bufs->drain, true);	
	wake_up_interruptible(&bufs->wait);
}

void venc_clear_drain(struct venc_buffers *bufs)
{
	WRITE_ONCE(bufs->drain, false);	
	wake_up_interruptible(&bufs->wait);
}