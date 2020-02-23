/*
 *	BIRD -- The Babel protocol
 *
 *	Copyright (c) 2020 Toke Hoiland-Jorgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains packet parsing-related data structures for the Babel protocol
 */

#ifndef _BIRD_BABEL_PACKETS_H_
#define _BIRD_BABEL_PACKETS_H_

#include "nest/bird.h"

struct babel_pkt_header {
  u8 magic;
  u8 version;
  u16 length;
} PACKED;

struct babel_tlv {
  u8 type;
  u8 length;
  u8 value[0];
} PACKED;

enum parse_result {
  PARSE_SUCCESS,
  PARSE_ERROR,
  PARSE_IGNORE,
};

#define FIRST_TLV(p) ((struct babel_tlv *) (((struct babel_pkt_header *) p) + 1))
#define NEXT_TLV(t) ((struct babel_tlv *) (((byte *) t) + TLV_LENGTH(t)))
#define TLV_LENGTH(t) (t->type == BABEL_TLV_PAD1 ? 1 : t->length + sizeof(struct babel_tlv))
#define TLV_OPT_LENGTH(t) (t->length + sizeof(struct babel_tlv) - sizeof(*t))
#define TLV_HDR(tlv,t,l) ({ tlv->type = t; tlv->length = l - sizeof(struct babel_tlv); })
#define TLV_HDR0(tlv,t) TLV_HDR(tlv, t, tlv_data[t].min_length)

#define NET_SIZE(n) BYTES(net_pxlen(n))

#define LOG_PKT(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_REMOTE "%s: " msg, p->p.name, args)
#define LOG_WARN(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_WARN "%s: " msg, p->p.name, args)

/* Helper macros to loop over a series of TLVs.
 * @start pointer to first TLV
 * @end   byte * pointer to TLV stream end
 * @tlv   struct babel_tlv pointer used as iterator
 */
#define WALK_TLVS(start, end, tlv, saddr, ifname)                       \
  for (tlv = (void *)start;						\
       (byte *)tlv < end;						\
       tlv = NEXT_TLV(tlv))						\
  {									\
    byte *loop_pos;							\
    /* Ugly special case */						\
    if (tlv->type == BABEL_TLV_PAD1)					\
      continue;                                                         \
									\
    /* The end of the common TLV header */				\
    loop_pos = (byte *)tlv + sizeof(struct babel_tlv);			\
    if ((loop_pos > end) || (loop_pos + tlv->length > end))             \
    {                                                                   \
      LOG_PKT("Bad TLV from %I via %s type %d pos %d - framing error",  \
	      saddr, ifname, tlv->type, (byte *)tlv - (byte *)start);   \
      goto frame_err;							\
    }

#define WALK_TLVS_END }

struct babel_read_state;
struct babel_write_state;

struct babel_tlv_data {
  u8 min_length;
  int (*read_tlv)(struct babel_tlv *hdr, union babel_msg *m, struct babel_read_state *state);
  uint (*write_tlv)(struct babel_tlv *hdr, union babel_msg *m, struct babel_write_state *state, uint max_len);
  void (*handle_tlv)(union babel_msg *m, struct babel_iface *ifa);
};

struct babel_read_state {
  const struct babel_tlv_data* (*get_tlv_data)(u8 type);
  const struct babel_tlv_data* (*get_subtlv_data)(u8 type);
  struct babel_proto *proto;
  struct babel_iface *ifa;
  ip_addr saddr;
  u8 current_tlv_endpos;	/* End of self-terminating TLVs (offset from start) */
};

int babel_read_tlv(struct babel_tlv *hdr,
                   union babel_msg *msg,
                   struct babel_read_state *state);
#endif
