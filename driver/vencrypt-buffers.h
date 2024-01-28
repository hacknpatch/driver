#ifndef __VENCYPTO_BUFFERS_H
#define __VENCYPTO_BUFFERS_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/types.h>


struct venc_buffer {
	struct list_head list; /* the list the buffer belongs to free or used.*/
	size_t size; /* the number of bytes in data */
	u8 data[16]; /* the data being encrypted or decrypted*/		
};

struct venc_buffers {
	struct list_head free;
	struct list_head used;	
	bool drain;
	spinlock_t lock;            
	wait_queue_head_t wait;     /* used for signaling queue changes */
	struct venc_buffer bufs[100];
};

void venc_init_buffers(struct venc_buffers *bufs);
void venc_move_to_used(struct venc_buffers *bufs, struct venc_buffer *buf);
void venc_move_to_free(struct venc_buffers *bufs, struct venc_buffer *buf);
struct venc_buffer * venc_first_free_or_null(struct venc_buffers *bufs);
struct venc_buffer * venc_first_used_or_null(struct venc_buffers *bufs);
int venc_wait_for_free(struct venc_buffers *bufs, struct venc_buffer **buf);
int venc_wait_for_used(struct venc_buffers *bufs, struct venc_buffer **buf);
void venc_drain(struct venc_buffers *bufs);
void venc_clear_drain(struct venc_buffers *bufs);

#endif /* __VENCYPTO_BUFFERS_H */
