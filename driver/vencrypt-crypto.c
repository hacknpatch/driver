#include <linux/random.h>
#include <linux/string.h>

#include "vencrypt-crypto.h"


void free_cipher_context(struct cipher_ctx *ctx)
{
	if (ctx->req)
		skcipher_request_free(ctx->req);
	if (ctx->tfm)
		crypto_free_skcipher(ctx->tfm);
}

int setup_cipher_context(struct cipher_ctx *ctx,
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

	memset(ctx->iv, 0, sizeof(ctx->iv));

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

void zero_cipher_iv(struct cipher_ctx *ctx)
{
	memset(ctx->iv, 0, sizeof(ctx->iv));
}

void random_cipher_iv(struct cipher_ctx *ctx)
{
	get_random_bytes(ctx->iv, sizeof(ctx->iv)); 
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

void pad_block_pkcs7(u8 *block, unsigned int current_length,
		     unsigned int block_size)
{
	if (current_length >= block_size)
		return;

	u8 pad_value = block_size - current_length;
	pr_info("Padding block with %d \n", pad_value);
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
