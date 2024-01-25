#include <linux/module.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/string.h>
#include <linux/printk.h>

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

	// Allocate a cipher transformation object
	ctx->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(ctx->tfm)) {
		pr_err("Error allocating cipher handle: %ld\n",
		       PTR_ERR(ctx->tfm));
		return PTR_ERR(ctx->tfm);
	}

	// Allocate a request object
	ctx->req = skcipher_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!ctx->req) {
		pr_err("Failed to allocate skcipher request\n");
		crypto_free_skcipher(ctx->tfm);
		return -ENOMEM;
	}

	ctx->encrypt = encryption_mode;

	// Initialize the IV to a random value
	get_random_bytes(ctx->iv, sizeof(ctx->iv));

	// Initialize the wait completion
	init_completion(&ctx->wait.completion);

	// Set the key
	memcpy(ctx->key, key, keylen);
	ret = crypto_skcipher_setkey(ctx->tfm, ctx->key, keylen);
	if (ret) {
		pr_err("Key could not be set: %d\n", ret);
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
		pr_err("Encryption failed: %d\n", ret);
		return ret;
	}

	// For CBC encryption, update IV with the ciphertext of this block
	memcpy(ctx->iv, block + block_length - 16, 16);

	return 0;
}

int decrypt_block(struct cipher_ctx *ctx, u8 *block, const size_t block_length)
{
	int ret;
	u8 next_iv[16]; // Temporary buffer to store the next IV

	sg_init_one(&ctx->sg, block, block_length);
	skcipher_request_set_callback(
		ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &ctx->wait);
	skcipher_request_set_crypt(ctx->req, &ctx->sg, &ctx->sg, block_length,
				   ctx->iv);

	// Save the current ciphertext to be used as the next IV
	memcpy(next_iv, block, 16);
	ret = crypto_wait_req(crypto_skcipher_decrypt(ctx->req), &ctx->wait);
	if (ret) {
		pr_err("Decryption failed: %d\n", ret);
		return ret;
	}

	memcpy(ctx->iv, next_iv, 16);

	return 0;
}


void print_hex(u8 *data, size_t len) {
    char hex_string[len * 2 + 1];
    int i;

    for (i = 0; i < len; i++) {
        sprintf(hex_string + i * 2, "%02x", data[i]);
    }

    hex_string[len * 2] = '\0'; // Null-terminate the string
    printk(KERN_INFO "%s\n", hex_string);
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

	if (memcmp(original_data1, decrypted_data1, sizeof(original_data1)) != 0)
		pr_err("Test failed: Decrypted data does not match original data for block 1\n");
	else
		pr_info("Test passed: Decrypted data matches original data for block 1\n");
	
	if (memcmp(original_data2, decrypted_data2, sizeof(original_data2)) != 0) 
		pr_err("Test failed: Decrypted data does not match original data for block 2\n");
	else
		pr_info("Test passed: Decrypted data matches original data for block 2\n");
	
	free_cipher_context(&ctx);
	pr_info("Test completed\n");
}

static int __init my_module_init(void)
{
	test_cipher_with_two_blocks();
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
