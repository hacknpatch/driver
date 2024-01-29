#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/printk.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/string.h>

#include "crypto.h"
#include "blocks.h"
#include "strings.h"

#define AES_BLOCK_SIZE 16
#define MODULE_NAME "tests"
#define TEST_KEY "C0FFEE0C0DE0C0FFEE0C0DE00FEED0BEEF0BED"

void test_cipher_with_two_blocks(void)
{
	struct venc_cipher ctx;
	int ret;
	u8 key[32] = { 0 }; // Define a test key (zero-filled for simplicity)
	unsigned int keylen = 32; // Set key length (e.g., 32 bytes for AES-256)
	u8 original_data1[16] = "TestDataBlock01!";
	u8 original_data2[16] = "TestDataBlock02!";
	u8 encrypted_data1[16], encrypted_data2[16];
	u8 decrypted_data1[16], decrypted_data2[16];
	u8 original_iv[16];

	if (hex_to_bytes(key, TEST_KEY, 32)) {
		pr_err("Failed to convert key to bytes\n");
		return;
	}

	// Initialize context for encryption with key
	ret = venc_init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("Failed to initialize encryption context\n");
		return;
	}
	// venc_zero_cipher_iv(&ctx);
	venc_random_cipher_iv(&ctx);

	memcpy(original_iv, ctx.iv, sizeof(ctx.iv));

	// Copy and Encrypt the first block of data
	memcpy(encrypted_data1, original_data1, sizeof(original_data1));
	ret = venc_encrypt(&ctx, encrypted_data1, sizeof(encrypted_data1));
	if (ret) {
		pr_err("Encryption of block 1 failed\n");
		venc_free_cipher(&ctx);
		return;
	}

	// Copy and Encrypt the second block of data
	memcpy(encrypted_data2, original_data2, sizeof(original_data2));
	ret = venc_encrypt(&ctx, encrypted_data2, sizeof(encrypted_data2));
	if (ret) {
		pr_err("Encryption of block 2 failed\n");
		venc_free_cipher(&ctx);
		return;
	}

	venc_free_cipher(&ctx);
	ret = venc_init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("Failed to initialize decryption context\n");
		return;
	}

	// Restore the original IV for decryption of the first block
	memcpy(ctx.iv, original_iv, sizeof(ctx.iv));

	memcpy(decrypted_data1, encrypted_data1, sizeof(encrypted_data1));
	ret = venc_decrypt(&ctx, decrypted_data1, sizeof(decrypted_data1));
	if (ret) {
		pr_err("Decryption of block 1 failed\n");
		venc_free_cipher(&ctx);
		return;
	}

	// Decrypt the second block using the IV of the first encrypted block
	memcpy(decrypted_data2, encrypted_data2, sizeof(encrypted_data2));
	ret = venc_decrypt(&ctx, decrypted_data2, sizeof(decrypted_data2));
	if (ret) {
		pr_err("Decryption of block 2 failed\n");
		venc_free_cipher(&ctx);
		return;
	}

	if (memcmp(original_data1, decrypted_data1, sizeof(original_data1)) !=
	    0)
		pr_err("Test failed: Decrypted data does not match original data for block 1\n");
	else
		pr_info("Test passed: Decrypted data matches original data for block 1\n");

	if (memcmp(original_data2, decrypted_data2, sizeof(original_data2)) !=
	    0)
		pr_err("Test failed: Decrypted data does not match original data for block 2\n");
	else
		pr_info("Test passed: Decrypted data matches original data for block 2\n");

	venc_free_cipher(&ctx);
	pr_info("Test completed\n");
}

void test_pkcs7_padding(void)
{
	u8 test_block[AES_BLOCK_SIZE];
	unsigned int original_lengths[] = { 0, 5, 10, 15, 16 };
	unsigned int num_tests =
		sizeof(original_lengths) / sizeof(original_lengths[0]);
	unsigned int i, j;

	for (i = 0; i < num_tests; i++) {
		unsigned int len = original_lengths[i];
		
		memset(test_block, 0x55, len); 

		pkcs7_pad_block(test_block, len, AES_BLOCK_SIZE);

		unsigned int padded_len = AES_BLOCK_SIZE - len;
		for (j = len; j < AES_BLOCK_SIZE; j++) {
			if (test_block[j] != padded_len) {
				printk(KERN_ERR
				       "Padding failed for length %u\n",
				       len);
				return;
			}
		}

		// Check effective length after padding
		unsigned int effective_len =
			pkcs7_block_len(test_block, AES_BLOCK_SIZE);
		if (effective_len != len) {
			printk(KERN_ERR
			       "Effective length check failed for length %u\n",
			       len);
			return;
		}
	}

	printk(KERN_INFO "All PKCS#7 padding tests passed successfully\n");
}

void test_cipher_hello(void)
{
	struct venc_cipher ctx;
	int ret;
	u8 key[32] = { 0 };
	unsigned int keylen = AES_MAX_KEY_SIZE;
	u8 original_data1[16] = "hello";
	u8 encrypted_data1[16];
	u8 decrypted_data1[16];
	u8 original_iv[16];

	if (hex_to_bytes(key, TEST_KEY, 32)) {
		pr_err("%s Failed to convert key to bytes\n", __func__);
		return;
	}

	ret = venc_init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("%s Failed to initialize encryption context\n",__func__);
		return;
	}

	venc_zero_cipher_iv(&ctx);
	memcpy(original_iv, ctx.iv, sizeof(ctx.iv));
	
	memcpy(encrypted_data1, original_data1, sizeof(original_data1));
	ret = venc_encrypt(&ctx, encrypted_data1, sizeof(encrypted_data1));
	if (ret) {
		pr_err("%s Encryption of block 1 failed\n", __func__);
		venc_free_cipher(&ctx);
		return;
	}
	
	venc_free_cipher(&ctx);
	ret = venc_init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("%s Failed to initialize decryption context\n", __func__);
		return;
	}

	memcpy(ctx.iv, original_iv, sizeof(ctx.iv));

	memcpy(decrypted_data1, encrypted_data1, sizeof(encrypted_data1));
	ret = venc_decrypt(&ctx, decrypted_data1, sizeof(decrypted_data1));
	if (ret) {
		pr_err("%s Decryption of block 1 failed\n", __func__);
		venc_free_cipher(&ctx);
		return;
	}

	if (memcmp(original_data1, decrypted_data1, sizeof(original_data1)) !=
	    0)
		pr_err("%s Test failed: Decrypted data does not match original data for block 1\n", __func__);
	else
		pr_info("%s Test passed: Decrypted data matches original data for block 1\n", __func__);

	venc_free_cipher(&ctx);

	pr_info("Test completed\n");
}

void test_buffers(void) 
{
	struct venc_block *buf;
	struct venc_blocks* blocks;
	blocks = venc_alloc_blocks(2);
	if (!blocks) {
		pr_err("Failed to allocate buffers\n");
		return;
	}
	
	buf = venc_first_free_or_null(blocks);
	venc_move_to_used(blocks, buf);
	buf = venc_first_free_or_null(blocks);
	buf = venc_first_used_or_null(blocks);
	venc_move_to_free(blocks, buf);
	buf = venc_first_free_or_null(blocks);
	buf = venc_first_used_or_null(blocks);	
	venc_free_blocks(blocks);
	pr_info("%s Test completed\n", __func__);

}

static int __init my_module_init(void)
{
	test_buffers();
	test_cipher_hello();
	test_cipher_with_two_blocks();
	test_pkcs7_padding();
	return 0;
}

static void __exit my_module_exit(void)
{
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_AUTHOR("n/a");
MODULE_DESCRIPTION("n/a");
MODULE_LICENSE("GPL");
