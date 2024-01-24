#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
// #include <linux/mutex.h>
#include <linux/slab.h>

#define DRIVER_NAME "vencrypt"
#define READ_MINOR 0
#define WRITE_MINOR 1
#define CHAR_DEVICES 2

#define CYPHER_KEY_SIZE 16
#define CYPHER_IV_SIZE 16
#define CYPHER_BLOCK_SIZE 16
#define BUFFER_SIZE CYPHER_BLOCK_SIZE

static int cypher_encrypt = 1;
module_param_named(encrypt, cypher_encrypt, int, S_IRUGO);

static char *cypher_key;
module_param_named(key, cypher_key, charp, S_IRUGO);

enum buffer_state {
	AVAILABLE = 0,
	SENDING,
	SENDING_LEN,
};

struct vencrypt_data {
	struct cdev cdev;
	wait_queue_head_t write_queue, read_queue;

	char key[CYPHER_KEY_SIZE];
	char iv[CYPHER_IV_SIZE];

	char buff[BUFFER_SIZE];
	size_t buff_size;
	enum buffer_state buff_state;

	bool writer_finshed;

	// the total size of the enctypted packet.
	// we add it to the end of the data unecrypted.
	uint64_t compelete_size;
	unsigned long flags;
};

static int driver_major;
static struct class *driver_device_class;
static dev_t driver_dev;
static struct vencrypt_data *driver_data;

static int vencrypt_open(struct inode *inode, struct file *file)
{
	uint8_t minor;
	struct vencrypt_data *data;

	minor = iminor(inode);

	// just incase the permissions are not set correctly on the device file

	if (minor == READ_MINOR && file->f_mode & FMODE_WRITE)
		return -EPERM;

	if (minor == WRITE_MINOR && (file->f_mode & FMODE_WRITE) == 0)
		return -EPERM;

	data = container_of(inode->i_cdev, struct vencrypt_data, cdev);

	// check to see if another reader or write is open.
	if (test_and_set_bit_lock(minor, &data->flags))
		return -EBUSY;

	file->private_data = data;

	/* reset the state of the device.
	 * TODO: i should think about what to do when a previous write has not
	 * been completely read and a new write is opened.
	 * Should I flag the next read is invalid?
	 */
	if (minor == WRITE_MINOR) {
		memset(data->iv, 0, sizeof(data->iv));
		data->writer_finshed = false;
		data->compelete_size = 0;
		data->buff_size = 0;
		data->buff_state = AVAILABLE;
	}

	pr_info("%s: %s open %d:%d\n", DRIVER_NAME,
		minor == READ_MINOR ? "read" : "write", driver_major, minor);
	return 0;
}

static void buffer_available(struct vencrypt_data *data)
{
	data->buff_state = AVAILABLE;
	wake_up_interruptible(&data->write_queue);
}

static void encode_buffer(struct vencrypt_data *data)
{
	pr_info("%s: encode_buffer cypher_encrypt: %d\n", DRIVER_NAME,
		cypher_encrypt);
}

static void buffer_send(struct vencrypt_data *data)
{
	encode_buffer(data);
	data->buff_state = SENDING;
	wake_up_interruptible(&data->read_queue);
}

static int buffer_send_and_wait(struct vencrypt_data *data)
{
	buffer_send(data);
	if (wait_event_interruptible(data->write_queue,
				     data->buff_state == AVAILABLE))
		return -ERESTARTSYS;

	return 0;
}

static int vencrypt_release(struct inode *inode, struct file *file)
{
	uint8_t minor;
	struct vencrypt_data *data;

	minor = iminor(inode);
	data = container_of(file->private_data, struct vencrypt_data, cdev);

	if (minor == WRITE_MINOR) {
		data->writer_finshed = true;
		if (data->buff_size >= 0) {
			buffer_send(data);
		} else {
			data->buff_state = SENDING_LEN;
			wake_up_interruptible(&data->read_queue);
		}

	} else if (minor == READ_MINOR) {
		if (data->buff_size == 0) {
			buffer_available(data);
			data->writer_finshed = false;
		}
	}

	pr_info("%s: %s release %d:%d\n", DRIVER_NAME,
		minor == READ_MINOR ? "read" : "write", driver_major, minor);
	clear_bit_unlock(minor, &data->flags);
	return 0;
}

static ssize_t vencrypt_read(struct file *file, char __user *buf, size_t count,
			     loff_t *offset)
{
	uint8_t minor;
	struct vencrypt_data *data;
	size_t to_copy;

	minor = iminor(file_inode(file));

	if (minor != READ_MINOR)
		return -EPERM;

	data = container_of(file->private_data, struct vencrypt_data, cdev);

	pr_info("%s: read off:%lld\n", DRIVER_NAME, *offset);

	if (wait_event_interruptible(data->read_queue,
				     data->buff_state == SENDING ||
					     data->buff_state == SENDING_LEN))
		return -ERESTARTSYS;

	pr_info("%s: read buff_size:%zu buff_state:%d\n", DRIVER_NAME,
		data->buff_size, data->buff_state);

	if (data->buff_size == 0) {
		if (data->buff_state == SENDING) {
			if (copy_to_user(buf, &data->compelete_size,
					 sizeof(data->compelete_size)))
				return -EFAULT;
			data->compelete_size = 0;
			data->buff_state = SENDING_LEN;
			return sizeof(data->compelete_size);
		}
		if (data->buff_state == SENDING_LEN)
			return 0;
		/*
		 * should never get here.
		 */
		pr_err("%s: read ERROR buff_size:%zu buff_state:%d\n",
		       DRIVER_NAME, data->buff_size, data->buff_state);
		return -EINVAL;
	}

	to_copy = min(data->buff_size, count);
	pr_info("%s: read to_copy:%zu\n", DRIVER_NAME, to_copy);

	if (copy_to_user(buf, data->buff, to_copy))
		return -EFAULT;

	data->buff_size -= to_copy;
	data->compelete_size += to_copy;

	pr_info("%s: read buff_size:%zu\n", DRIVER_NAME, data->buff_size);

	if (data->buff_size == 0) {
		if (data->writer_finshed)
			data->buff_state = SENDING_LEN;
		else
			buffer_available(data);
	}
	return (ssize_t)to_copy;
}

static ssize_t vencrypt_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	uint8_t minor;
	struct vencrypt_data *data;
	size_t to_copy;
	size_t remaining;

	minor = iminor(file_inode(file));

	if (minor != WRITE_MINOR)
		return -EPERM;

	data = container_of(file->private_data, struct vencrypt_data, cdev);

	remaining = BUFFER_SIZE - data->buff_size;
	if (remaining == 0) {
		if (buffer_send_and_wait(data))
			return -ERESTARTSYS;
		remaining = BUFFER_SIZE - data->buff_size;
	}
	to_copy = min(remaining, count);

	pr_info("%s: write remaining:%zu count:%zu\n", DRIVER_NAME, remaining,
		count);

	if (copy_from_user(&data->buff[data->buff_size], buf, to_copy))
		return -EFAULT;

	data->buff_size += to_copy;

	remaining = BUFFER_SIZE - data->buff_size;
	if (remaining == 0)
		buffer_send(data);

	return to_copy;
}

static const struct file_operations vencrypt_fops = {
	.owner          = THIS_MODULE,
	.open           = vencrypt_open,
	.read           = vencrypt_read,
	.write          = vencrypt_write,
	.release        = vencrypt_release,
};

int char_to_nibble(char c)
{
	if ('0' <= c && c <= '9')
		return (unsigned char)(c - '0');
	if ('A' <= c && c <= 'F')
		return (unsigned char)(c - 'A' + 10);
	if ('a' <= c && c <= 'f')
		return (unsigned char)(c - 'a' + 10);
	return 0xFF;
}

int hex_to_bytes(unsigned char *dst, const char *src, unsigned int dst_size)
{
	size_t i, l;
	int ms, ls;

	l = strlen(src);

	memset(dst, 0, dst_size);

	if (src[0] == '\0' || l % 2)
		return -1;

	if (l > dst_size * 2)
		return -1;

	for (i = 0; i < l; i += 2) {
		ms = char_to_nibble(src[i]);
		if (ms < 0 || ms > 0xff)
			return -1;
		ls = char_to_nibble(src[i + 1]);
		if (ls < 0 || ls > 0xff)
			return -1;
		dst[i / 2] = (ms << 4) + ls;
	}
	return 0;
}

static int __init vencrypt_init(void)
{
	int err;
	struct device *dev;

	err = alloc_chrdev_region(&driver_dev, 0, CHAR_DEVICES, DRIVER_NAME);
	if (err)
		return -ENOMEM;

	driver_major = MAJOR(driver_dev);

	driver_device_class = class_create(DRIVER_NAME);
	if (IS_ERR(driver_device_class)) {
		err = PTR_ERR(driver_device_class);
		goto err_unregister_chrdev;
	}

	driver_data = kzalloc(sizeof(struct vencrypt_data), GFP_KERNEL);
	if (!driver_data) {
		err = -ENOMEM;
		goto err_destroy_class;
	}

	err = hex_to_bytes(driver_data->key, cypher_key, CYPHER_KEY_SIZE);
	if (err)
		goto err_free_data;

	cdev_init(&driver_data->cdev, &vencrypt_fops);
	driver_data->cdev.owner = THIS_MODULE;

	err = cdev_add(&driver_data->cdev, driver_dev, 2);
	if (err)
		goto err_free_data;

	init_waitqueue_head(&driver_data->write_queue);
	init_waitqueue_head(&driver_data->read_queue);

	driver_data->buff_size = 0;
	driver_data->buff_state = AVAILABLE;

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, READ_MINOR), driver_data,
			    "vencrypt_read");
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto err_free_data;
	}

	dev = device_create(driver_device_class, NULL,
			    MKDEV(driver_major, WRITE_MINOR), driver_data,
			    "vencrypt_write");
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		device_destroy(driver_device_class,
			       MKDEV(driver_major, READ_MINOR));
		goto err_free_data;
	}

	return 0;

err_free_data:
	kfree(driver_data);

err_destroy_class:
	class_destroy(driver_device_class);

err_unregister_chrdev:
	unregister_chrdev_region(driver_dev, CHAR_DEVICES);
	return err;
}

static void __exit vencrypt_exit(void)
{
	cdev_del(&driver_data->cdev);
	device_destroy(driver_device_class, MKDEV(driver_major, READ_MINOR));
	device_destroy(driver_device_class, MKDEV(driver_major, WRITE_MINOR));
	class_destroy(driver_device_class);
	unregister_chrdev_region(driver_dev, CHAR_DEVICES);
	kfree(driver_data);

	pr_info("%s: Exited\n", DRIVER_NAME);
}

MODULE_LICENSE("GPL");
module_init(vencrypt_init);
module_exit(vencrypt_exit);
