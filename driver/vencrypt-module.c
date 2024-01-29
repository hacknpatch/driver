#include <linux/module.h>
#include <linux/cdev.h>

#include "vencrypt-strings.h"
#include "vencrypt-buffers.h"
#include "vencrypt-crypto.h"

#define DRIVER_NAME "vencrypt"
#define READ_MINOR 0
#define WRITE_MINOR 1
#define CHAR_DEVICES 2

static int mod_param_encrypt = 1;
module_param_named(encrypt, mod_param_encrypt, int, S_IRUGO);

static char *mod_param_key;
module_param_named(key, mod_param_key, charp, S_IRUGO);

struct vencrypt_ctx {
	struct cdev cdev;
	struct venc_cipher cipher;
	struct venc_buffers bufs;
	unsigned long open_flags;
};

static int encode_buf(struct venc_cipher *cipher, struct venc_buffer *buf)
{
	int err;

	if (buf->size == 0)
		return 0;
	/*
	 * used for testing, i.e. 2 = don't encrypt
	 */
	if (mod_param_encrypt == 2)
		return 0;

	if (mod_param_encrypt)
		err = venc_encrypt(cipher, buf->data, buf->size);
	else
		err = venc_decrypt(cipher, buf->data, buf->size);

	if (err)
		pr_err("%s: encode_buf failed: %d\n", DRIVER_NAME, err);

	return err;
}

static int vencrypt_open(struct inode *inode, struct file *file)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;

	minor = iminor(inode);

	if (minor == READ_MINOR && file->f_mode & FMODE_WRITE)
		return -EPERM;

	if (minor == WRITE_MINOR && (file->f_mode & FMODE_WRITE) == 0)
		return -EPERM;

	ctx = container_of(inode->i_cdev, struct vencrypt_ctx, cdev);

	if (test_and_set_bit_lock(minor, &ctx->open_flags))
		return -EBUSY;

	file->private_data = ctx;

	/* 
	* Writer does encryption, so this is safe to clear IV. The unread bufs
	* in used queue will be in the drian state until the reader closes.
	*/
	if (minor == WRITE_MINOR)
		venc_zero_cipher_iv(&ctx->cipher);

	return 0;
}

static int last_block_encrypt_pkcs7(struct vencrypt_ctx *ctx) 
{
	struct venc_buffer *buf;
	int err;
	/*
	 * check to see if we have an uncomplete buffer from _write, if 
	 * so pad and encrypt it.
	 */
	buf = venc_first_free_or_null(&ctx->bufs);
	if (buf == NULL || buf->size == AES_BLOCK_SIZE) {
		pr_info("%s: padding getting out buff\n", DRIVER_NAME);
		err = venc_wait_for_free(&ctx->bufs, &buf);
		if (err) {
			pr_err("%s: wait for free buf failed with %d\n",
			DRIVER_NAME, err);
			return err;
		}
		memset(buf->data, 0, sizeof(buf->data));
		buf->size = 0;
		pr_info("%s: padding last block\n", DRIVER_NAME);
	}
	
	pkcs7_pad_block(buf->data, buf->size, sizeof(buf->data));
	buf->size = AES_BLOCK_SIZE;
	venc_encrypt(&ctx->cipher, buf->data, buf->size);
	venc_move_to_used(&ctx->bufs, buf);
	return 0;
}

static void last_block_decrypt_pkcs7(struct vencrypt_ctx *ctx) 
{
	struct venc_buffer *buf;
	/* 
	 * we keep the last block in the used list, so we can
	 * workout its padding length. Then allow it to be sent.
	 */
	buf = venc_last_used_or_null(&ctx->bufs);
	if (buf != NULL) {				
		buf->size = pkcs7_block_len(buf->data, buf->size);
		pr_info("%s: decrypted size %zu\n", DRIVER_NAME, buf->size);
	} else {
		pr_err("%s: no last block\n", DRIVER_NAME);
	}
}

static int vencrypt_release(struct inode *inode, struct file *file)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	
	int err;

	minor = iminor(inode);
	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	err = 0;
	if (minor == WRITE_MINOR) {

		if (mod_param_encrypt) 
			err = last_block_encrypt_pkcs7(ctx);
		else
			last_block_decrypt_pkcs7(ctx);
		
		/* 
		 * drain the out buffers, then fops read will return 0 until 
		 * next reader closes / releases.
		 */
		venc_drain(&ctx->bufs);

	} else if (minor == READ_MINOR) {
		/*
		 * TODO: consider what to do if read exists but there is still
		 * data in the used list?
		 */
		venc_clear_drain(&ctx->bufs);
	}

	smp_mb__before_atomic();
	clear_bit_unlock(minor, &ctx->open_flags);
	return err;
}

static ssize_t vencrypt_read(struct file *file, char __user *user_buf,
			     size_t count, loff_t *offset)
{
	int err;
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	struct venc_buffer *buf;
	size_t to_copy;

	minor = iminor(file_inode(file));

	if (minor != READ_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	err = venc_wait_for_used(&ctx->bufs, &buf);
	if (err)
		return err;

	if (buf == NULL) {
		if (ctx->bufs.drain)
			return 0;
		else
			return -EIO;
	}

	if (buf->size == 0)
		return 0;

	to_copy = min(buf->size, count);

	if (copy_to_user(user_buf, buf->data, to_copy))
		return -EFAULT;

	buf->size -= to_copy;

	if (buf->size == 0)
		venc_move_to_free(&ctx->bufs, buf);

	return to_copy;
}

static ssize_t vencrypt_write(struct file *file, const char __user *user_buf,
			      size_t count, loff_t *offset)
{
	int err;
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	struct venc_buffer *buf;
	size_t free, copied;

	minor = iminor(file_inode(file));

	if (minor != WRITE_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	err = venc_wait_for_free(&ctx->bufs, &buf);
	if (err)
		return err;

	copied = min(sizeof(buf->data) - buf->size, count);

	if (copy_from_user(&buf->data[buf->size], user_buf, copied))
		return -EFAULT;

	buf->size += copied;

	free = sizeof(buf->data) - buf->size;
	if (free == 0) {
		encode_buf(&ctx->cipher, buf);
		venc_move_to_used(&ctx->bufs, buf);
	}

	return copied;
}

static const char *get_dev_read_prefix(void)
{
	switch (mod_param_encrypt) {
	case 0:
		return "pt";
	case 1:
		return "ct";
	case 2:
		return "read";
	}
	return "invalid_r";
}

static const char *get_dev_write_prefix(void)
{
	switch (mod_param_encrypt) {
	case 0:
		return "ct";
	case 1:
		return "pt";
	case 2:
		return "write";
	}
	return "invalid_w";
}

static const struct file_operations vencrypt_fops = {
	.owner = THIS_MODULE,
	.open = vencrypt_open,
	.read = vencrypt_read,
	.write = vencrypt_write,
	.release = vencrypt_release,
};

static int driver_major;
static struct class *driver_device_class;
static dev_t driver_dev;
static struct vencrypt_ctx *driver_ctx;

static int __init vencrypt_init(void)
{
	int err;
	struct device *dev;
	u8 key[32] = { 0 };
	int key_len;

	if (mod_param_encrypt < 0 || mod_param_encrypt > 2) {
		pr_err("%s: Invalid crypter encrypt=%d choices: 0=decrypt, 1=encrypt, 2=no-encryption\n",
		       DRIVER_NAME, mod_param_encrypt);
		return -EINVAL;
	}

	key_len = strlen(mod_param_key) / 2;
	if (key_len < CBC_AES_MIN_KEY_SIZE || key_len > CBC_AES_MAX_KEY_SIZE) {
		pr_err("%s: Invalid crypter key length %d it must between %d and %d\n",
		       DRIVER_NAME, key_len, CBC_AES_MIN_KEY_SIZE,
		       CBC_AES_MAX_KEY_SIZE);
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
		pr_err("%s: Crypter key is invalid hex\n", DRIVER_NAME);
		goto err_free_data;
	}

	err = venc_init_cipher(&driver_ctx->cipher, key, sizeof(key));
	if (err) {
		pr_err("%s: Crypter setup failed err %d\n", DRIVER_NAME, err);
		goto err_free_data;
	}

	venc_init_buffers(&driver_ctx->bufs);

	cdev_init(&driver_ctx->cdev, &vencrypt_fops);
	driver_ctx->cdev.owner = THIS_MODULE;

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, READ_MINOR), driver_ctx,
			    "%s_%s", DRIVER_NAME, get_dev_read_prefix());
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto err_free_cipher;
	}

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, WRITE_MINOR), driver_ctx,
			    "%s_%s", DRIVER_NAME, get_dev_write_prefix());
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		device_destroy(driver_device_class,
			       MKDEV(driver_major, READ_MINOR));
		goto err_free_cipher;
	}

	err = cdev_add(&driver_ctx->cdev, driver_dev, 2);
	if (err)
		goto err_free_cipher;

	pr_info("%s: Initialized\n", DRIVER_NAME);
	return 0;

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

static void __exit vencrypt_exit(void)
{
	cdev_del(&driver_ctx->cdev);
	device_destroy(driver_device_class, MKDEV(driver_major, READ_MINOR));
	device_destroy(driver_device_class, MKDEV(driver_major, WRITE_MINOR));
	class_destroy(driver_device_class);
	unregister_chrdev_region(driver_dev, CHAR_DEVICES);
	venc_free_cipher(&driver_ctx->cipher);
	kfree(driver_ctx);
	pr_info("%s: Exited\n", DRIVER_NAME);
}

module_init(vencrypt_init);
module_exit(vencrypt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Chalmers");
