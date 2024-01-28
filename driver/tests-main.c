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

#include "vencrypt-crypto.h"

#define AES_BLOCK_SIZE 16

void test_cipher_with_two_blocks(void)
{
	struct vencrypt_cipher ctx;
	int ret;
	u8 key[32] = { 0 }; // Define a test key (zero-filled for simplicity)
	unsigned int keylen = 32; // Set key length (e.g., 32 bytes for AES-256)
	u8 original_data1[16] = "TestDataBlock01!";
	u8 original_data2[16] = "TestDataBlock02!";
	u8 encrypted_data1[16], encrypted_data2[16];
	u8 decrypted_data1[16], decrypted_data2[16];
	u8 original_iv[16];

	// Initialize context for encryption with key
	ret = init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("Failed to initialize encryption context\n");
		return;
	}
	// zero_cipher_iv(&ctx);
	random_cipher_iv(&ctx);

	memcpy(original_iv, ctx.iv, sizeof(ctx.iv));

	// Copy and Encrypt the first block of data
	memcpy(encrypted_data1, original_data1, sizeof(original_data1));
	ret = encrypt_block(&ctx, encrypted_data1, sizeof(encrypted_data1));
	if (ret) {
		pr_err("Encryption of block 1 failed\n");
		free_cipher(&ctx);
		return;
	}

	// Copy and Encrypt the second block of data
	memcpy(encrypted_data2, original_data2, sizeof(original_data2));
	ret = encrypt_block(&ctx, encrypted_data2, sizeof(encrypted_data2));
	if (ret) {
		pr_err("Encryption of block 2 failed\n");
		free_cipher(&ctx);
		return;
	}

	free_cipher(&ctx);
	ret = init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("Failed to initialize decryption context\n");
		return;
	}

	// Restore the original IV for decryption of the first block
	memcpy(ctx.iv, original_iv, sizeof(ctx.iv));

	memcpy(decrypted_data1, encrypted_data1, sizeof(encrypted_data1));
	ret = decrypt_block(&ctx, decrypted_data1, sizeof(decrypted_data1));
	if (ret) {
		pr_err("Decryption of block 1 failed\n");
		free_cipher(&ctx);
		return;
	}

	// Decrypt the second block using the IV of the first encrypted block
	memcpy(decrypted_data2, encrypted_data2, sizeof(encrypted_data2));
	ret = decrypt_block(&ctx, decrypted_data2, sizeof(decrypted_data2));
	if (ret) {
		pr_err("Decryption of block 2 failed\n");
		free_cipher(&ctx);
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

	free_cipher(&ctx);
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

		// 0x55 is arbitrary test data
		memset(test_block, 0x55, len); 

		// Apply PKCS#7 padding
		pad_block_pkcs7(test_block, len, AES_BLOCK_SIZE);

		// Check if padding is correct
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
			block_len_pkcs7(test_block, AES_BLOCK_SIZE);
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
	struct vencrypt_cipher ctx;
	int ret;
	u8 key[32] = { 0 }; // Define a test key (zero-filled for simplicity)
	unsigned int keylen = 32; // Set key length (e.g., 32 bytes for AES-256)
	u8 original_data1[16] = "hello";
	u8 encrypted_data1[16];
	u8 decrypted_data1[16];
	u8 original_iv[16];

	// Initialize context for encryption with key
	ret = init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("Failed to initialize encryption context\n");
		return;
	}

	zero_cipher_iv(&ctx);
	memcpy(original_iv, ctx.iv, sizeof(ctx.iv));
	// pad_block_pkcs7(original_data1, strlen(original_data1), AES_BLOCK_SIZE);

	// Copy and Encrypt the first block of data
	memcpy(encrypted_data1, original_data1, sizeof(original_data1));
	ret = encrypt_block(&ctx, encrypted_data1, sizeof(encrypted_data1));
	if (ret) {
		pr_err("Encryption of block 1 failed\n");
		free_cipher(&ctx);
		return;
	}
	
	free_cipher(&ctx);
	ret = init_cipher(&ctx, key, keylen);
	if (ret) {
		pr_err("Failed to initialize decryption context\n");
		return;
	}

	// Restore the original IV for decryption of the first block
	memcpy(ctx.iv, original_iv, sizeof(ctx.iv));

	memcpy(decrypted_data1, encrypted_data1, sizeof(encrypted_data1));
	ret = decrypt_block(&ctx, decrypted_data1, sizeof(decrypted_data1));
	if (ret) {
		pr_err("Decryption of block 1 failed\n");
		free_cipher(&ctx);
		return;
	}

	if (memcmp(original_data1, decrypted_data1, sizeof(original_data1)) !=
	    0)
		pr_err("Test failed: Decrypted data does not match original data for block 1\n");
	else
		pr_info("Test passed: Decrypted data matches original data for block 1\n");		

	free_cipher(&ctx);

	pr_info("Test original: %*ph\n", 16, original_data1);
	pr_info("Test encrypted: %*ph\n", 16, encrypted_data1);
	pr_info("Test encrypted: %*ph\n", 16, decrypted_data1);
	pr_info("Test completed\n");
}

static int __init my_module_init(void)
{
	test_cipher_hello();
	// test_cipher_with_two_blocks();
	// test_pkcs7_padding();
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
