
#include <linux/kernel.h>
#include <linux/fs.h>

#include "blocks.h"

struct venc_blocks *venc_alloc_blocks(int num_blocks)
{
	struct venc_blocks *blocks;
	struct venc_block *block;
	int i;

	blocks = kmalloc(sizeof(struct venc_blocks), GFP_KERNEL);
	if (!blocks) {
		return NULL;
	}

	blocks->blocks =
		kmalloc(num_blocks * sizeof(struct venc_block), GFP_KERNEL);
	if (!blocks->blocks) {
		kfree(blocks);
		return NULL;
	}

	blocks->num_blocks = num_blocks;

	INIT_LIST_HEAD(&blocks->free);
	INIT_LIST_HEAD(&blocks->used);

	blocks->used_count = 0;
	blocks->drain = false;

	spin_lock_init(&blocks->lock);
	init_waitqueue_head(&blocks->wait);

	for (i = 0; i < num_blocks; i++) {
		block = &blocks->blocks[i];
		list_add_tail(&block->list, &blocks->free);
	}

	return blocks;
}

void venc_free_blocks(struct venc_blocks *blocks)
{
	kfree(blocks->blocks);
	kfree(blocks);
}

void venc_move_to_used(struct venc_blocks *blocks, struct venc_block *block)
{
	spin_lock(&blocks->lock);
	list_del(&block->list);
	list_add_tail(&block->list, &blocks->used);
	blocks->used_count++;
	spin_unlock(&blocks->lock);
	wake_up_interruptible(&blocks->wait);
}

void venc_move_to_free(struct venc_blocks *blocks, struct venc_block *block)
{
	spin_lock(&blocks->lock);
	blocks->used_count--;
	list_del(&block->list);
	list_add_tail(&block->list, &blocks->free);
	spin_unlock(&blocks->lock);
	wake_up_interruptible(&blocks->wait);
}

struct venc_block *venc_first_free_or_null(struct venc_blocks *blocks)
{
	return list_first_entry_or_null(&blocks->free, struct venc_block, list);
}

int venc_wait_for_free(struct venc_blocks *blocks, struct venc_block **block)
{
	return wait_event_interruptible(
		blocks->wait,
		(*block = venc_first_free_or_null(blocks)) != NULL);
}

struct venc_block *venc_first_used_or_null(struct venc_blocks *blocks)
{
	return list_first_entry_or_null(&blocks->used, struct venc_block, list);
}

struct venc_block *venc_last_used_or_null(struct venc_blocks *blocks)
{
	if (list_empty(&blocks->used))
		return NULL;
	return list_last_entry(&blocks->used, struct venc_block, list);
}

static bool venc_used_available(struct venc_blocks *blocks, bool *drain)
{
	bool available;
	spin_lock(&blocks->lock);
	available = blocks->used_count > 1 || blocks->drain;
	*drain = blocks->drain;
	spin_unlock(&blocks->lock);
	return available;
}

int venc_wait_for_used(struct venc_blocks *blocks, struct venc_block **block,
		       bool *drain)
{
	int err = wait_event_interruptible(
		blocks->wait, (venc_used_available(blocks, drain)));

	if (err)
		return err;

	*block = venc_first_used_or_null(blocks);
	return 0;
}

void venc_set_drain(struct venc_blocks *blocks, bool drain)
{
	spin_lock(&blocks->lock);
	blocks->drain = drain;
	spin_unlock(&blocks->lock);
	wake_up_interruptible(&blocks->wait);
}

int venc_drain(struct venc_blocks *blocks)
{
	bool drain;
	spin_lock(&blocks->lock);
	drain = blocks->drain;
	spin_unlock(&blocks->lock);
	return drain;
}

int venc_wait_for_drain(struct venc_blocks *blocks, bool drain)
{
	return wait_event_interruptible(blocks->wait,
					(venc_drain(blocks) == drain));
}