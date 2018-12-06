/*
 *	BIRD Library -- Blake2 hash function wrappers
 *
 *	(c) 2018 Toke Høiland-Jørgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BLAKE2_H_
#define _BIRD_BLAKE2_H_

#include "nest/bird.h"
struct mac_context;

#define BLAKE2S_SIZE		32  // BLAKE2S_KEYBYTES
#define BLAKE2S_HEX_SIZE	65
#define BLAKE2S_BLOCK_SIZE	64  // BLAKE2S_BLOCKBYTES

#define BLAKE2B_SIZE		64  // BLAKE2B_KEYBYTES
#define BLAKE2B_HEX_SIZE	129
#define BLAKE2B_BLOCK_SIZE	128 // BLAKE2B_BLOCKBYTEs

typedef struct blake2s_state__
{
  uint32_t h[8];
  uint32_t t[2];
  uint32_t f[2];
  uint8_t  buf[BLAKE2S_BLOCK_SIZE];
  size_t   buflen;
  size_t   outlen;
  uint8_t  last_node;
} blake2s_state;

typedef struct blake2b_state__
{
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t  buf[BLAKE2B_BLOCK_SIZE];
  size_t   buflen;
  size_t   outlen;
  uint8_t  last_node;
} blake2b_state;

struct hash_context;

struct blake2s_context {
  const struct mac_desc *type;
  blake2s_state state;
  byte buf[BLAKE2B_SIZE];
};
struct blake2b_context {
  const struct mac_desc *type;
  blake2b_state state;
  byte buf[BLAKE2B_SIZE];
};

void blake2s_bird_init(struct mac_context *ctx, const byte *key, uint keylen);
void blake2s_bird_update(struct mac_context *ctx, const byte *buf, uint len);
byte *blake2s_bird_final(struct mac_context *ctx);

void blake2b_bird_init(struct mac_context *ctx, const byte *key, uint keylen);
void blake2b_bird_update(struct mac_context *ctx, const byte *buf, uint len);
byte *blake2b_bird_final(struct mac_context *ctx);


#endif /* _BIRD_BLAKE2_H_ */
