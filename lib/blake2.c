/*
 *	BIRD Library -- Blake2 hash function wrappers
 *
 *	(c) 2018 Toke Høiland-Jørgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include "blake2-ref.h"

void blake2s_bird_init(struct mac_context *mac, const byte *key, uint keylen)
{
  struct blake2s_context *ctx = (void *) mac;
  blake2s_init_key(&ctx->state, BLAKE2S_SIZE, key, keylen);
}

void blake2s_bird_update(struct mac_context *mac, const byte *buf, uint len)
{
  struct blake2s_context *ctx = (void *) mac;
  blake2s_update(&ctx->state, buf, len);
}

byte *blake2s_bird_final(struct mac_context *mac)
{
  struct blake2s_context *ctx = (void *) mac;
  blake2s_final(&ctx->state, ctx->buf, BLAKE2S_SIZE);
  return ctx->buf;
}

void blake2b_bird_init(struct mac_context *mac, const byte *key, uint keylen)
{
  struct blake2b_context *ctx = (void *) mac;
  blake2b_init_key(&ctx->state, BLAKE2B_SIZE, key, keylen);
}
void blake2b_bird_update(struct mac_context *mac, const byte *buf, uint len)
{
  struct blake2b_context *ctx = (void *) mac;
  blake2b_update(&ctx->state, buf, len);
}
byte *blake2b_bird_final(struct mac_context *mac)
{
  struct blake2b_context *ctx = (void *) mac;
  blake2b_final(&ctx->state, ctx->buf, BLAKE2B_SIZE);
  return ctx->buf;
}
