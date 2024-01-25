#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/printk.h>

#define AES_BLOCK_SIZE 16


struct cipher_ctx {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct scatterlist sg;
	struct crypto_wait wait;
	bool encrypt;
	u8 iv[16];
	u8 key[32]; // AES key (up to 256 bits)
};

void free_cipher_context(struct cipher_ctx *ctx)
{
	if (ctx->req)
		skcipher_request_free(ctx->req);
	if (ctx->tfm)
		crypto_free_skcipher(ctx->tfm);
}

int setup_cipher_context(struct cipher_ctx *ctx, bool encryption_mode,
			 const u8 *key, unsigned int keylen)
{
	int ret;

	ctx->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(ctx->tfm)) {
		pr_err("Error allocating cipher handle: %ld\n",
		       PTR_ERR(ctx->tfm));
		return PTR_ERR(ctx->tfm);
	}

	ctx->req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!ctx->req) {
		pr_err("Failed to allocate skcipher request\n");
		crypto_free_skcipher(ctx->tfm);
		return -ENOMEM;
	}

	ctx->encrypt = encryption_mode;

	/*
	 * it was reuquest to always use a zero IV :S I might not help me self
	 * and put the random IV at the start of the encrypted data!	
	 */
	get_random_bytes(ctx->iv, sizeof(ctx->iv));
	/* memset(ctx->iv, 0, sizeof(ctx->iv)); */

	init_completion(&ctx->wait.completion);

	memcpy(ctx->key, key, keylen);
	ret = crypto_skcipher_setkey(ctx->tfm, ctx->key, keylen);
	if (ret) {
		pr_err("crypto_skcipher_setkey: %d\n", ret);
		free_cipher_context(ctx);
		return ret;
	}

	return 0;
}

int encrypt_block(struct cipher_ctx *ctx, u8 *block, const size_t block_length)
{
	int ret;

	sg_init_one(&ctx->sg, block, block_length);

	skcipher_request_set_callback(
		ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &ctx->wait);

	skcipher_request_set_crypt(ctx->req, &ctx->sg, &ctx->sg, block_length,
				   ctx->iv);

	ret = crypto_wait_req(crypto_skcipher_encrypt(ctx->req), &ctx->wait);
	if (ret) {
		pr_err("encrypt_block/crypto_wait_req failed: %d\n", ret);
		return ret;
	}

	/* 
	 * CBC / IV
	 */
	memcpy(ctx->iv, block + block_length - 16, 16);
	return 0;
}

int decrypt_block(struct cipher_ctx *ctx, u8 *block, const size_t block_length)
{
	int ret;
	u8 next_iv[16];

	sg_init_one(&ctx->sg, block, block_length);

	skcipher_request_set_callback(
		ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &ctx->wait);

	skcipher_request_set_crypt(ctx->req, &ctx->sg, &ctx->sg, block_length,
				   ctx->iv);

	memcpy(next_iv, block, 16);
	/*
	 * TODO: consider if I need to handle -EINPROGRESS, -EBUSY, -EAGAIN
	 */
	ret = crypto_wait_req(crypto_skcipher_decrypt(ctx->req), &ctx->wait);
	if (ret) {
		pr_err("decrypt_block/crypto_wait_req failed: %d\n", ret);
		return ret;
	}

	/* 
	 * CBC / IV
	 */
	memcpy(ctx->iv, next_iv, 16);
	return 0;
}

void test_cipher_with_two_blocks(void)
{
	struct cipher_ctx ctx;
	int ret;
	u8 key[32] = { 0 }; // Define a test key (zero-filled for simplicity)
	unsigned int keylen = 32; // Set key length (e.g., 32 bytes for AES-256)
	u8 original_data1[16] = "TestDataBlock01!";
	u8 original_data2[16] = "TestDataBlock02!";
	u8 encrypted_data1[16], encrypted_data2[16];
	u8 decrypted_data1[16], decrypted_data2[16];
	u8 original_iv[16];

	// Initialize context for encryption with key
	ret = setup_cipher_context(&ctx, true, key, keylen);
	if (ret) {
		pr_err("Failed to initialize encryption context\n");
		return;
	}
	memcpy(original_iv, ctx.iv, sizeof(ctx.iv));

	// Copy and Encrypt the first block of data
	memcpy(encrypted_data1, original_data1, sizeof(original_data1));
	ret = encrypt_block(&ctx, encrypted_data1, sizeof(encrypted_data1));
	if (ret) {
		pr_err("Encryption of block 1 failed\n");
		free_cipher_context(&ctx);
		return;
	}

	// Copy and Encrypt the second block of data
	memcpy(encrypted_data2, original_data2, sizeof(original_data2));
	ret = encrypt_block(&ctx, encrypted_data2, sizeof(encrypted_data2));
	if (ret) {
		pr_err("Encryption of block 2 failed\n");
		free_cipher_context(&ctx);
		return;
	}

	free_cipher_context(&ctx);
	ret = setup_cipher_context(&ctx, false, key, keylen);
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
		free_cipher_context(&ctx);
		return;
	}

	// Decrypt the second block using the IV of the first encrypted block
	memcpy(decrypted_data2, encrypted_data2, sizeof(encrypted_data2));
	ret = decrypt_block(&ctx, decrypted_data2, sizeof(decrypted_data2));
	if (ret) {
		pr_err("Decryption of block 2 failed\n");
		free_cipher_context(&ctx);
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

	free_cipher_context(&ctx);
	pr_info("Test completed\n");
}

void pad_block_pkcs7(u8 *block, unsigned int current_length,
		     unsigned int block_size)
{
	if (current_length >= block_size)
		return;

	u8 pad_value = block_size - current_length;
	memset(block + current_length, pad_value, pad_value);
}

unsigned int block_len_pkcs7(u8 *block, unsigned int block_size)
{
	u8 last_byte = block[block_size - 1];

	if (last_byte == 0 || last_byte > block_size)
		return block_size;

	for (unsigned int i = block_size - last_byte; i < block_size; i++)
		if (block[i] != last_byte)
			return block_size;

	return block_size - last_byte;
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

static int __init my_module_init(void)
{
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
