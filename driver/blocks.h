// SPDX-License-Identifier: GPL-2.0-only

#ifndef __VENCRYPT_BLOCKS_H
#define __VENCRYPT_BLOCKS_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/types.h>

#include "crypto.h"

struct venc_block {
	/* 
	 * the list the buffer belongs to free or used.
	 */
	struct list_head list;
	/*
	 * the number of bytes allocated in data
	 */
	size_t size;

	/*
	 * the data being encrypted or decrypted
	 */
	u8 data[AES_BLOCK_SIZE];
};

/* 
 * The struct venc_blocks implements a pool of blocks/buffers. It also manages  
 * synchronization using a spin_lock and a wait_queue. The wait queue is 
 * utilized to notify the `reader`, `writer`, `release`, and  `open` functions 
 * when a new block has been added or freed, or when a final padding block is 
 * completed.
 */
struct venc_blocks {
	struct list_head free;
	struct list_head used;
	/*
	 * a count of the number of buffers in the used list.
	 */
	int used_count;
	/*
	 * used for draining used buffers, new writer opens are blocked until 
	 * this flag is cleared
	 */
	bool drain;

	spinlock_t lock;
	/* 
	 * used for signaling queue changes
	 */
	wait_queue_head_t wait;

	/*
	 * the number of blocks dynamically allocated.
	 */
	int num_blocks;

	/* 
	  * the blocks / buffers containing the data.
	  */
	struct venc_block *blocks;
};

struct venc_blocks *venc_alloc_blocks(int num_buffers);
void venc_free_blocks(struct venc_blocks *blocks);

void venc_move_to_used(struct venc_blocks *blocks, struct venc_block *block);
void venc_move_to_free(struct venc_blocks *blocks, struct venc_block *buf);

struct venc_block *venc_first_free_or_null(struct venc_blocks *blocks);
struct venc_block *venc_first_used_or_null(struct venc_blocks *blocks);
struct venc_block *venc_last_used_or_null(struct venc_blocks *blocks);

int venc_wait_for_free(struct venc_blocks *blocks, struct venc_block **block);
int venc_wait_for_used(struct venc_blocks *blocks, struct venc_block **block,
		       bool *drain);

void venc_set_drain(struct venc_blocks *blocks, bool drain);
int venc_wait_for_drain(struct venc_blocks *blocks, bool drain);

#endif /* __VENCRYPT_BLOCKS_H */
