#include <linux/module.h>
#include <linux/cdev.h>

#include "vencrypt-strings.h"
#include "vencrypt-blocks.h"
#include "vencrypt-crypto.h"

#define DRIVER_NAME "vencrypt"
#define READ_MINOR 0
#define WRITE_MINOR 1
#define CHAR_DEVICES 2

static int mod_param_encrypt = 1;
module_param_named(encrypt, mod_param_encrypt, int, S_IRUGO);

static char *mod_param_key;
module_param_named(key, mod_param_key, charp, S_IRUGO);

static int mod_param_num_blocks = 10;
module_param_named(blocks, mod_param_num_blocks, int, S_IRUGO);

struct vencrypt_ctx {
	struct cdev cdev;
	struct venc_cipher cipher;
	struct venc_blocks *blocks;
	unsigned long open_flags;
};

static int encode_block(struct venc_cipher *cipher, struct venc_block *block)
{
	int err;

	if (block->size == 0)
		return 0;

	if (mod_param_encrypt)
		err = venc_encrypt(cipher, block->data, block->size);
	else
		err = venc_decrypt(cipher, block->data, block->size);

	if (err)
		pr_err("%s: encode_block failed: %d\n", DRIVER_NAME, err);

	return err;
}

static int pad_last_block(struct vencrypt_ctx *ctx)
{
	struct venc_block *block;
	int err;
	/*
	 * check to see if we have an uncomplete buffer from _write, if 
	 * so pad and encrypt it.
	 */
	block = venc_first_free_or_null(ctx->blocks);
	if (block == NULL || block->size == AES_BLOCK_SIZE) {
		err = venc_wait_for_free(ctx->blocks, &block);
		if (err) {
			pr_err("%s: wait for free block failed with %d\n",
			       DRIVER_NAME, err);
			return err;
		}
		memset(block->data, 0, AES_BLOCK_SIZE);
		block->size = 0;
	}

	pkcs7_pad_block(block->data, block->size, AES_BLOCK_SIZE);
	block->size = AES_BLOCK_SIZE;

	venc_encrypt(&ctx->cipher, block->data, block->size);
	venc_move_to_used(ctx->blocks, block);
	return 0;
}

static void unpad_last_block(struct vencrypt_ctx *ctx)
{
	struct venc_block *block;
	/* 
	 * we keep the last block in the used list, so we can
	 * workout its padding length. Then allow it to be sent with actual len.
	 */
	block = venc_last_used_or_null(ctx->blocks);
	if (block != NULL)
		block->size = pkcs7_block_len(block->data, block->size);
	else
		pr_err("%s: no last block for pkcs7 size out maybe be wrong!\n",
		       DRIVER_NAME);
}

static int venc_open(struct inode *inode, struct file *file)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	int err;

	minor = iminor(inode);

	if (minor == READ_MINOR && file->f_mode & FMODE_WRITE)
		return -EPERM;

	if (minor == WRITE_MINOR && (file->f_mode & FMODE_WRITE) == 0)
		return -EPERM;

	ctx = container_of(inode->i_cdev, struct vencrypt_ctx, cdev);

	if (test_and_set_bit_lock(minor, &ctx->open_flags))
		return -EBUSY;

	file->private_data = ctx;

	err = 0;

	if (minor == WRITE_MINOR) {
		/*
		 * if drain is set, it means a reader is still reading, so we
		 * need to wait for it to finish.
		 */
		err = venc_wait_for_drain(ctx->blocks, false);
		/* 
		 * writer does encryption, so this is safe to clear IV. The 
		 * unread blocks in used queue will be in the drian state until the
		 * reader closes.
		 */
		if (!err)
			venc_zero_cipher_iv(&ctx->cipher);
	}

	return 0;
}

static int venc_release(struct inode *inode, struct file *file)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;

	int err;

	minor = iminor(inode);
	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	err = 0;
	if (minor == WRITE_MINOR) {
		if (mod_param_encrypt)
			err = pad_last_block(ctx);
		else
			unpad_last_block(ctx);

		/* 
		 * drain the out buffers, then fops read will return 0 until 
		 * next reader closes / releases.
		 */
		venc_set_drain(ctx->blocks, true);

	} else if (minor == READ_MINOR) {
		/*
		 * TODO: consider what to do if read exists but there is still
		 * data in the used list? trash it maybe?
		 */
		venc_set_drain(ctx->blocks, false);
	}

	smp_mb__before_atomic();
	clear_bit_unlock(minor, &ctx->open_flags);
	return err;
}

static ssize_t venc_read(struct file *file, char __user *user_buf, size_t count,
			 loff_t *offset)
{
	int err;
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	struct venc_block *block;
	size_t to_copy;
	bool drain;

	minor = iminor(file_inode(file));

	if (minor != READ_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	err = venc_wait_for_used(ctx->blocks, &block, &drain);
	if (err)
		return err;

	if (block == NULL)
		return drain ? 0 : -EIO;

	if (block->size == 0)
		return 0;

	to_copy = min(block->size, count);

	if (copy_to_user(user_buf, block->data, to_copy))
		return -EFAULT;

	block->size -= to_copy;

	if (block->size == 0)
		venc_move_to_free(ctx->blocks, block);

	return to_copy;
}

static ssize_t venc_write(struct file *file, const char __user *user_buf,
			  size_t count, loff_t *offset)
{
	int err;
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	struct venc_block *block;
	size_t free, copied;

	minor = iminor(file_inode(file));

	if (minor != WRITE_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	err = venc_wait_for_free(ctx->blocks, &block);
	if (err)
		return err;

	copied = min(AES_BLOCK_SIZE - block->size, count);

	if (copy_from_user(&block->data[block->size], user_buf, copied))
		return -EFAULT;

	block->size += copied;

	free = AES_BLOCK_SIZE - block->size;
	if (free == 0) {
		encode_block(&ctx->cipher, block);
		venc_move_to_used(ctx->blocks, block);
	}

	return copied;
}

static const struct file_operations vencrypt_fops = {
	.owner = THIS_MODULE,
	.open = venc_open,
	.read = venc_read,
	.write = venc_write,
	.release = venc_release,
};

static int driver_major;
static struct class *driver_device_class;
static dev_t driver_dev;
static struct vencrypt_ctx *driver_ctx;

static int __init venc_init(void)
{
	int err;
	struct device *dev;
	u8 key[32] = { 0 };
	int key_len;

	/*
	 * this should work with a single buffer, but I haven't tested it.	 
	 */
	if (mod_param_num_blocks < 3 || mod_param_num_blocks > 1000) {
		pr_err("%s: Module param invalid blocks=%d choices: 3-1000\n",
		       DRIVER_NAME, mod_param_num_blocks);
		return -EINVAL;
	}

	if (mod_param_encrypt < 0 || mod_param_encrypt > 1) {
		pr_err("%s: Module param invalid encrypt=%d choices: 0=decrypt, 1=encrypt\n",
		       DRIVER_NAME, mod_param_encrypt);
		return -EINVAL;
	}

	key_len = strlen(mod_param_key) / 2;
	if (key_len < AES_MIN_KEY_SIZE || key_len > AES_MAX_KEY_SIZE) {
		pr_err("%s: Module param key length %d it must between %d and %d\n",
		       DRIVER_NAME, key_len, AES_MIN_KEY_SIZE,
		       AES_MAX_KEY_SIZE);
		return -EINVAL;
	}

	err = alloc_chrdev_region(&driver_dev, 0, CHAR_DEVICES, DRIVER_NAME);
	if (err)
		return -ENOMEM;

	driver_major = MAJOR(driver_dev);

	driver_device_class = class_create(DRIVER_NAME);
	if (IS_ERR(driver_device_class)) {
		err = PTR_ERR(driver_device_class);
		goto err_unregister_chrdev;
	}

	driver_ctx = kzalloc(sizeof(struct vencrypt_ctx), GFP_KERNEL);
	if (!driver_ctx) {
		err = -ENOMEM;
		goto err_destroy_class;
	}

	err = hex_to_bytes(key, mod_param_key, key_len);
	if (err) {
		pr_err("%s: Module param key invalid hex\n", DRIVER_NAME);
		goto err_free_data;
	}

	err = venc_init_cipher(&driver_ctx->cipher, key, AES_MAX_KEY_SIZE);
	if (err) {
		pr_err("%s: Crypter setup failed err %d\n", DRIVER_NAME, err);
		goto err_free_data;
	}

	driver_ctx->blocks = venc_alloc_blocks(mod_param_num_blocks);
	if (!driver_ctx->blocks) {
		err = -ENOMEM;
		goto err_free_cipher;
	}

	cdev_init(&driver_ctx->cdev, &vencrypt_fops);
	driver_ctx->cdev.owner = THIS_MODULE;

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, READ_MINOR), driver_ctx,
			    "%s_%s", DRIVER_NAME,
			    mod_param_encrypt == 0 ? "pt" : "ct");
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto err_free_blocks;
	}

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, WRITE_MINOR), driver_ctx,
			    "%s_%s", DRIVER_NAME,
			    mod_param_encrypt == 0 ? "ct" : "pt");
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		device_destroy(driver_device_class,
			       MKDEV(driver_major, READ_MINOR));
		goto err_free_blocks;
	}

	err = cdev_add(&driver_ctx->cdev, driver_dev, CHAR_DEVICES);
	if (err)
		goto err_free_blocks;

	pr_info("%s: Initialized\n", DRIVER_NAME);
	return 0;

err_free_blocks:
	venc_free_blocks(driver_ctx->blocks);

err_free_cipher:
	venc_free_cipher(&driver_ctx->cipher);

err_free_data:
	kfree(driver_ctx);

err_destroy_class:
	class_destroy(driver_device_class);

err_unregister_chrdev:
	unregister_chrdev_region(driver_dev, CHAR_DEVICES);
	return err;
}

static void __exit venc_exit(void)
{
	cdev_del(&driver_ctx->cdev);
	device_destroy(driver_device_class, MKDEV(driver_major, READ_MINOR));
	device_destroy(driver_device_class, MKDEV(driver_major, WRITE_MINOR));
	class_destroy(driver_device_class);
	unregister_chrdev_region(driver_dev, CHAR_DEVICES);
	venc_free_cipher(&driver_ctx->cipher);
	venc_free_blocks(driver_ctx->blocks);
	kfree(driver_ctx);
	pr_info("%s: Exited\n", DRIVER_NAME);
}

module_init(venc_init);
module_exit(venc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Chalmers");
