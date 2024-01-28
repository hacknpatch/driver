#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
// #include <linux/mutex.h>
#include <linux/slab.h>
#include <crypto/skcipher.h>

#include "vencrypt-crypto.h"

#define DRIVER_NAME "vencrypt"
#define READ_MINOR 0
#define WRITE_MINOR 1
#define CHAR_DEVICES 2

#define CBC_AES_MIN_KEY_SIZE 16
#define CBC_AES_MAX_KEY_SIZE 32

#define CYPHER_KEY_SIZE CBC_AES_MAX_KEY_SIZE
#define CYPHER_IV_SIZE 16 /* AES-256 bit */
#define CYPHER_BLOCK_SIZE 16

#define BUFFER_SIZE CYPHER_BLOCK_SIZE

/*
 * 
 * name         : cbc(aes)
 * driver       : cbc-aes-aesni
 * module       : aesni_intel
 * priority     : 400
 * refcnt       : 1
 * selftest     : passed
 * internal     : no
 *  type         : skcipher
 * async        : yes
 * blocksize    : 16
 * min keysize  : 16
 * max keysize  : 32
 * ivsize       : 16
 * chunksize    : 16
 * walksize     : 16
 */

static int cypher_encrypt = 1;
module_param_named(encrypt, cypher_encrypt, int, S_IRUGO);

static char *cypher_key;
module_param_named(key, cypher_key, charp, S_IRUGO);

enum state {
	ST_REVC = 0,
	ST_SEND,
	ST_CLOSING,
};

struct vencrypt_ctx {
	struct cdev cdev;

	struct cipher_ctx cipher;

	char buff[BUFFER_SIZE];
	size_t buff_size;

	enum state state;
	wait_queue_head_t state_q;

	unsigned long open_flags;
};

static int driver_major;
static struct class *driver_device_class;
static dev_t driver_dev;
static struct vencrypt_ctx *driver_ctx;


static int encode_buffer(struct vencrypt_ctx *ctx)
{
	int err;
	if (ctx->buff_size == 0)
		return 0;
	
	if (cypher_encrypt) {
		if (ctx->buff_size != BUFFER_SIZE)
			pad_block_pkcs7(ctx->buff, ctx->buff_size, BUFFER_SIZE);
		err = encrypt_block(&ctx->cipher, ctx->buff, BUFFER_SIZE);
		ctx->buff_size = BUFFER_SIZE;	
	} else {
		err = decrypt_block(&ctx->cipher, ctx->buff, BUFFER_SIZE);
		ctx->buff_size = block_len_pkcs7(ctx->buff, BUFFER_SIZE);
	}
	smp_wmb();
	return err;
}

static void set_state(struct vencrypt_ctx *ctx, enum state state)
{
	if (ctx->state != state) {
		if (state == ST_SEND || state == ST_CLOSING)
			encode_buffer(ctx);
		ctx->state = state;
	}
	wake_up_interruptible(&ctx->state_q);
}

static int vencrypt_open(struct inode *inode, struct file *file)
{
	int err;
	uint8_t minor;
	struct vencrypt_ctx *ctx;

	err = 0;
	minor = iminor(inode);

	if (minor == READ_MINOR && file->f_mode & FMODE_WRITE)
		return -EPERM;

	if (minor == WRITE_MINOR && (file->f_mode & FMODE_WRITE) == 0)
		return -EPERM;

	ctx = container_of(inode->i_cdev, struct vencrypt_ctx, cdev);

	if (test_and_set_bit_lock(minor, &ctx->open_flags))
		return -EBUSY;

	file->private_data = ctx;

	if (minor == WRITE_MINOR) {
		err = wait_event_interruptible(ctx->state_q,
					       ctx->state == ST_REVC);
		if (!err) {
			zero_cipher_iv(&ctx->cipher);			
			ctx->buff_size = 0;
		}

	} else if (minor == READ_MINOR && ctx->buff_size > 0) {
		err = wait_event_interruptible(ctx->state_q,
					       ctx->state != ST_REVC);
	}

	if (err)
		clear_bit_unlock(minor, &ctx->open_flags);

	return err;
}

static int vencrypt_release(struct inode *inode, struct file *file)
{
	int err;
	uint8_t minor;
	struct vencrypt_ctx *ctx;

	err = 0;
	minor = iminor(inode);
	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	if (minor == WRITE_MINOR) {
		err = wait_event_interruptible(ctx->state_q,
					       ctx->state == ST_REVC);
		if (!err)			
			set_state(ctx, ST_CLOSING);

	} else if (minor == READ_MINOR && ctx->buff_size == 0 &&
		   ctx->state == ST_CLOSING) {
		set_state(ctx, ST_REVC);
	}

	clear_bit_unlock(minor, &ctx->open_flags);
	return err;
}

static ssize_t vencrypt_read(struct file *file, char __user *buf, size_t count,
			     loff_t *offset)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	size_t to_copy;

	minor = iminor(file_inode(file));

	if (minor != READ_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	if (wait_event_interruptible(ctx->state_q,
				     (ctx->state == ST_SEND ||
				      ctx->state == ST_CLOSING)))
		return -ERESTARTSYS;

	 ctx->state, ctx->buff_size, BUFFER_SIZE, ctx->buff);

	if (ctx->buff_size == 0) {
		if (ctx->state != ST_CLOSING)
			set_state(ctx, ST_REVC);			
		return 0;
	}

	to_copy = min(ctx->buff_size, count);

	if (copy_to_user(buf, ctx->buff, to_copy))
		return -EFAULT;

	ctx->buff_size -= to_copy;

	if (ctx->buff_size == 0 && ctx->state != ST_CLOSING)
		set_state(ctx, ST_REVC);

	return (ssize_t)to_copy;
}

static ssize_t vencrypt_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	size_t to_copy;
	size_t remaining;

	minor = iminor(file_inode(file));

	if (minor != WRITE_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	remaining = BUFFER_SIZE - ctx->buff_size;
	if (remaining == 0) {
		set_state(ctx, ST_SEND);
		if (wait_event_interruptible(ctx->state_q,
					     ctx->state == ST_REVC))
			return -ERESTARTSYS;
		remaining = BUFFER_SIZE - ctx->buff_size;
	}
	to_copy = min(remaining, count);

	if (copy_from_user(&ctx->buff[ctx->buff_size], buf, to_copy))
		return -EFAULT;

	ctx->buff_size += to_copy;

	remaining = BUFFER_SIZE - ctx->buff_size;
	if (remaining == 0)		
		set_state(ctx, ST_SEND);

	return to_copy;
}

int init_skcipher(struct vencrypt_ctx *ctx)
{
	return 0;
}

int char_to_nibble(char c)
{
	if ('0' <= c && c <= '9')
		return (unsigned char)(c - '0');
	if ('A' <= c && c <= 'F')
		return (unsigned char)(c - 'A' + 10);
	if ('a' <= c && c <= 'f')
		return (unsigned char)(c - 'a' + 10);
	return -EINVAL;
}

int hex_to_bytes(unsigned char *dst, const char *src, unsigned int dst_size)
{
	size_t i, l;
	int ms, ls;

	l = strlen(src);
	if (src[0] == '\0' || l % 2)
		return -EINVAL;
	if (l > dst_size * 2)
		return -EINVAL;
	memset(dst, 0, dst_size);

	for (i = 0; i < l; i += 2) {
		ms = char_to_nibble(src[i]);
		if (ms < 0)
			return -EINVAL;
		ls = char_to_nibble(src[i + 1]);
		if (ls < 0)
			return -EINVAL;
		dst[i / 2] = (ms << 4) | ls;
	}
	return 0;
}

static const struct file_operations vencrypt_fops = {
	.owner		= THIS_MODULE,
	.open		= vencrypt_open,
	.read		= vencrypt_read,
	.write		= vencrypt_write,
	.release	= vencrypt_release,
};

static int __init vencrypt_init(void)
{
	int err;
	struct device *dev;
	u8 key[32] = {0};
	int key_len;

	key_len = strlen(cypher_key) / 2;
	if (key_len < 16 || key_len > 32) {
		pr_err("%s: Invalid crypter key length %d it must between 16 and 32\n", 
		       DRIVER_NAME, key_len);
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

	err = hex_to_bytes(key, cypher_key, key_len);
	if (err) {		
		pr_err("%s: Crypter key is invalid hex\n", DRIVER_NAME);
		goto err_free_data;
	}

	err = setup_cipher_context(&driver_ctx->cipher, key, sizeof(key));
	if (err) {
		pr_err("%s: Crypter setup failed err %d\n", DRIVER_NAME, err);
		goto err_free_data;
	}
	
	cdev_init(&driver_ctx->cdev, &vencrypt_fops);
	driver_ctx->cdev.owner = THIS_MODULE;

	err = cdev_add(&driver_ctx->cdev, driver_dev, 2);
	if (err)
		goto err_free_cipher;

	driver_ctx->buff_size = 0;
	driver_ctx->state = ST_REVC;
	init_waitqueue_head(&driver_ctx->state_q);

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, READ_MINOR), driver_ctx,
			    "vencrypt_read");
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto err_free_cipher;
	}

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, WRITE_MINOR), driver_ctx,
			    "vencrypt_write");
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		device_destroy(driver_device_class,
			       MKDEV(driver_major, READ_MINOR));
		goto err_free_cipher;
	}

	err = init_skcipher(driver_ctx);
	if (err)
		goto err_free_devices;

	pr_info("%s: Initialized\n", DRIVER_NAME);
	return 0;

err_free_devices:
	device_destroy(driver_device_class, MKDEV(driver_major, READ_MINOR));
	device_destroy(driver_device_class, MKDEV(driver_major, WRITE_MINOR));

err_free_cipher:
	free_cipher_context(&driver_ctx->cipher);

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
	free_cipher_context(&driver_ctx->cipher);
	kfree(driver_ctx);
	pr_info("%s: Exited\n", DRIVER_NAME);
}

module_init(vencrypt_init);
module_exit(vencrypt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Chalmers");
