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

static int mod_param_encrypt = 1;
module_param_named(encrypt, mod_param_encrypt, int, S_IRUGO);

static char *mod_param_key;
module_param_named(key, mod_param_key, charp, S_IRUGO);


#define BUFFER_QUEUE_NUM 10

struct buffer {
	unsigned char data[AES_BLOCK_SIZE]; /* the data being encrypted or decrypted*/
	size_t size; /* the number of bytes in data */
	struct list_head list; /* the list the buffer belongs to free or used.*/
};

struct buffer_queue {
	struct buffer buffers[BUFFER_QUEUE_NUM];
	struct list_head free_list; /* list of buffers not in use */
	struct list_head used_list; /* list of buffers in use */
	spinlock_t lock;            /* spinlock around list operations */
	wait_queue_head_t wait;     /* used for signaling queue changes */
};

struct vencrypt_ctx {
	struct cdev cdev;
	struct vencrypt_cipher cipher;
	struct buffer_queue buffer_queue;
	unsigned long open_flags;
};

static int driver_major;
static struct class *driver_device_class;
static dev_t driver_dev;
static struct vencrypt_ctx *driver_ctx;

void init_buffer_queue(struct buffer_queue *q)
{
	INIT_LIST_HEAD(&q->free_list);
	INIT_LIST_HEAD(&q->used_list);
	spin_lock_init(&q->lock);
	init_waitqueue_head(&q->wait);

	for (int i = 0; i < MAX_BUFFERS; i++) {
		q->buffers[i].size = 0;
		list_add(&q->buffers[i].list, &q->free_list);
	}
}

struct buffer * get_out_buffer(struct buffer_queue *q)
{
	struct buffer *buf;
	buf = NULL;
	spin_lock(&q->lock);
	if (!list_empty(&q->used_list))
		buf = list_first_entry(&q->used_list, struct buffer, list);	
	spin_unlock(&q->lock);
	return buf;
}

int wait_out_buffer(struct vencrypt_ctx *ctx, struct buffer **buf)
{
	return wait_event_interruptible(ctx->buffer_queue.wait,
		(*buf = get_out_buffer(&ctx->buffer_queue)) != NULL);
}

void release_read_buffer(struct buffer_queue *q, struct buffer *buf)
{	
	buf->size = 0;
	spin_lock(&q->lock);
	list_del(&buf->list);
	list_add(&buf->list, &q->free_list);
	spin_unlock(&q->lock);
	wake_up_interruptible(&q->wait);
}

struct buffer * get_in_buffer(struct buffer_queue *q)
{
	struct buffer *buf;
	buf = NULL;
	spin_lock(&q->lock);
	if (!list_empty(&q->free_list))
		buf = list_first_entry(&q->free_list, struct buffer, list);	
	spin_unlock(&q->lock);
	return buf;
}

int wait_in_buffer(struct vencrypt_ctx *ctx, struct buffer **buf)
{
	return wait_event_interruptible(ctx->buffer_queue.wait,
		(*buf = get_in_buffer(&ctx->buffer_queue)) != NULL);
}

static int encode_buffer(struct vencrypt_cipher *cipher, struct buffer *buf)
{
	int err;
	if (buf->size == 0)
		return 0;
	/*
	 * used for tests, i.e. we don't encrypt
	 */
	if (mod_param_encrypt == 2)
		return 0;
	
	if (mod_param_encrypt) {
		if (buf->size != sizeof(buf->size)) {
			pad_block_pkcs7(buf->data, buf->size , sizeof(buf->size));
			buf->size = sizeof(buf->size);
		}
		err = encrypt_block(cipher, buf->data, sizeof(buf->size));
	} else {
		err = decrypt_block(cipher, buf->data, buf->size);
		buf->size = block_len_pkcs7(buf->data, buf->size);
	}

	// smp_wmb();
	return err;
}

void in_buffer_ready(struct vencrypt_cipher *c, 
			struct buffer_queue *q,
			struct buffer *buf)
{
	encode_buffer(c, buf);
	spin_lock(&q->lock);
	list_del(&buf->list); // Remove from free list
	list_add_tail(&buf->list, &q->used_list); // Add to used list
	spin_unlock(&q->lock);
	wake_up_interruptible(&q->wait);
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

	if (minor == WRITE_MINOR)
		// writer does encryption, so this is safe.
		zero_cipher_iv(&ctx->cipher);

	return 0;
}

static int vencrypt_release(struct inode *inode, struct file *file)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	struct buffer *buf;

	minor = iminor(inode);
	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	if (minor == WRITE_MINOR
	   && (buf = get_in_buffer(&ctx->buffer_queue)) != NULL
	   && buf->size > 0)
		in_buffer_ready(&ctx->cipher, &ctx->buffer_queue, buf);

	smp_mb__before_atomic();
	clear_bit_unlock(minor, &ctx->open_flags);
	return 0;
}

static ssize_t vencrypt_read(struct file *file, char __user *user_buf, size_t count,
			     loff_t *offset)
{
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	size_t to_copy;
	struct buffer *buf;
	int err;

	minor = iminor(file_inode(file));

	if (minor != READ_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);

	err = wait_out_buffer(ctx, &buf);
	if (err)
		return err;
	
	if (buf->size == 0)
		return 0;

	to_copy = min(buf->size, count);

	if (copy_to_user(user_buf, buf->data, to_copy))
		return -EFAULT;

	buf->size -= to_copy;

	if (buf->size == 0)
		release_read_buffer(&ctx->buffer_queue, buf);

	return (ssize_t)to_copy;
}

static ssize_t vencrypt_write(struct file *file, const char __user *user_buf,
			      size_t count, loff_t *offset)
{
	int err;
	uint8_t minor;
	struct vencrypt_ctx *ctx;
	struct buffer *buf;
	size_t available, copied;

	minor = iminor(file_inode(file));

	if (minor != WRITE_MINOR)
		return -EPERM;

	ctx = container_of(file->private_data, struct vencrypt_ctx, cdev);
	
	err = wait_in_buffer(ctx, &buf);
	if (err)
		return err;

	copied = min(sizeof(buf->data) - buf->size, count);
	
	if (copy_from_user(&buf->data[buf->size], user_buf, copied))
		return -EFAULT;
	
	buf->size += copied;

	available = sizeof(buf->data) - buf->size;
	pr_info("%s: write count: %zu offset: %lld buff_size: %zu available: %zu copied:%zu\n",
		DRIVER_NAME, count, *offset, buf->size, available, copied);
	if (available == 0)		
		in_buffer_ready(&ctx->cipher, &ctx->buffer_queue, buf);

	return copied;
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

const char* get_dev_read_prefix(void)
{
	switch (mod_param_encrypt)
	{
		case 0:
			return "pt";
		case 1:		
			return "ct";
		case 2:
			return "read";
	}
	return "invalid_r";
}

const char* get_dev_write_prefix(void)
{
	switch (mod_param_encrypt)
	{
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

	if (mod_param_encrypt < 0 || mod_param_encrypt > 2)
	{
		pr_err("%s: Invalid crypter encrypt=%d choices: 0=decrypt, 1=encrypt, 2=no-encryption\n", 
		       DRIVER_NAME, mod_param_encrypt);
		return -EINVAL;
	}

	key_len = strlen(mod_param_key) / 2;
	if (key_len < CBC_AES_MIN_KEY_SIZE || key_len > CBC_AES_MAX_KEY_SIZE) {
		pr_err("%s: Invalid crypter key length %d it must between %d and %d\n", 
		       DRIVER_NAME, key_len, CBC_AES_MIN_KEY_SIZE, CBC_AES_MAX_KEY_SIZE);
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

	err = init_cipher(&driver_ctx->cipher, key, sizeof(key));
	if (err) {
		pr_err("%s: Crypter setup failed err %d\n", DRIVER_NAME, err);
		goto err_free_data;
	}	
	
	init_buffer_queue(&driver_ctx->buffer_queue);

	cdev_init(&driver_ctx->cdev, &vencrypt_fops);
	driver_ctx->cdev.owner = THIS_MODULE;

	err = cdev_add(&driver_ctx->cdev, driver_dev, 2);
	if (err)
		goto err_free_cipher;

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

	pr_info("%s: Initialized\n", DRIVER_NAME);
	return 0;

err_free_cipher:
	free_cipher(&driver_ctx->cipher);

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
	free_cipher(&driver_ctx->cipher);
	kfree(driver_ctx);
	pr_info("%s: Exited\n", DRIVER_NAME);
}

module_init(vencrypt_init);
module_exit(vencrypt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Chalmers");
