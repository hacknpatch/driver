#ifndef __VENCRYPT_BUFFERS_H
#define __VENCRYPT_BUFFERS_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/types.h>

#include "vencrypt-crypto.h"

struct venc_buffer {
	struct list_head list; /* the list the buffer belongs to free or used.*/
	size_t size; /* the number of bytes in data */
	u8 data[AES_BLOCK_SIZE]; /* the data being encrypted or decrypted*/
};

struct venc_buffers {
	struct list_head free;
	struct list_head used;
	int used_count;
	bool drain;

	spinlock_t lock;
	wait_queue_head_t wait; /* used for signaling queue changes */
	int num_buffers;
	struct venc_buffer *bufs;
};

struct venc_buffers *venc_alloc_buffers(int num_buffers);
void venc_free_buffers(struct venc_buffers *bufs);

void venc_move_to_used(struct venc_buffers *bufs, struct venc_buffer *buf);
void venc_move_to_free(struct venc_buffers *bufs, struct venc_buffer *buf);

struct venc_buffer *venc_first_free_or_null(struct venc_buffers *bufs);
struct venc_buffer *venc_first_used_or_null(struct venc_buffers *bufs);
struct venc_buffer *venc_last_used_or_null(struct venc_buffers *bufs);

int venc_wait_for_free(struct venc_buffers *bufs, struct venc_buffer **buf);
int venc_wait_for_used(struct venc_buffers *bufs, struct venc_buffer **buf,
		       bool *drain);

void venc_set_drain(struct venc_buffers *bufs, bool drain);
int venc_wait_for_drain(struct venc_buffers *bufs, bool drain);

#endif /* __VENCRYPT_BUFFERS_H */
