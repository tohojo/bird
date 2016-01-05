/**  -*- c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 *	The Babel protocol
 *
 *	Copyright (c) 2015 Toke Høiland-Jørgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This files contains the packet and TLV handling routines for the protocol.
 */

#undef LOCAL_DEBUG
#define LOCAL_DEBUG 1

#include "babel.h"
#include "packet.h"

#define BAD(x) { log(L_REMOTE "%s: " x, p->p.name); return 1; }
#define FIRST_TLV(p) ((struct babel_pkt_tlv_header *)(((struct babel_pkt_header *) p) + 1))
#define NEXT_TLV(t) (t = (void *)((byte *)t) + TLV_SIZE(t))
#define TLV_SIZE(t) (t->type == BABEL_TLV_PAD0 ? 1 : t->length + sizeof(struct babel_pkt_tlv_header))


static inline ip_addr
get_ip6_ll(void *p)
{
  return ipa_build6(0xfe800000,0,get_u32(p),get_u32(p+sizeof(u32)));
}

static inline void
put_ip6_ll(void *p, ip_addr addr)
{
  put_u32(p, _I2(addr));
  put_u32(p+sizeof(u32), _I3(addr));
}


static enum parse_result
babel_read_ack_req(struct babel_pkt_tlv_header *hdr,
                   union babel_tlv *tlv,
                   struct babel_parse_state *state);
static enum parse_result
babel_read_hello(struct babel_pkt_tlv_header *hdr,
                 union babel_tlv *tlv,
                 struct babel_parse_state *state);
static enum parse_result
babel_read_ihu(struct babel_pkt_tlv_header *hdr,
               union babel_tlv *tlv,
               struct babel_parse_state *state);
static enum parse_result
babel_read_router_id(struct babel_pkt_tlv_header *hdr,
                     union babel_tlv *tlv,
                     struct babel_parse_state *state);
static enum parse_result
babel_read_next_hop(struct babel_pkt_tlv_header *hdr,
                    union babel_tlv *tlv,
                    struct babel_parse_state *state);
static enum parse_result
babel_read_update(struct babel_pkt_tlv_header *hdr,
                  union babel_tlv *tlv,
                  struct babel_parse_state *state);
static enum parse_result
babel_read_route_request(struct babel_pkt_tlv_header *hdr,
                         union babel_tlv *tlv,
                         struct babel_parse_state *state);
static enum parse_result
babel_read_seqno_request(struct babel_pkt_tlv_header *hdr,
                         union babel_tlv *tlv,
                         struct babel_parse_state *state);


static int
babel_write_ack(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                struct babel_write_state *state, int max_len);
static int
babel_write_hello(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                  struct babel_write_state *state, int max_len);
static int
babel_write_ihu(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                struct babel_write_state *state, int max_len);
static int
babel_write_update(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                   struct babel_write_state *state, int max_len);
static int
babel_write_route_request(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                          struct babel_write_state *state, int max_len);
static int
babel_write_seqno_request(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                          struct babel_write_state *state, int max_len);

struct babel_pkt_tlv_data {
  u8 min_size;
  enum parse_result (*read_tlv)(struct babel_pkt_tlv_header *hdr,
                                union babel_tlv *tlv, struct babel_parse_state *state);
  int (*write_tlv)(struct babel_pkt_tlv_header *hdr,
                   union babel_tlv *tlv, struct babel_write_state *state, int max_len);
  void (*handle_tlv)(union babel_tlv *tlv, struct babel_iface *ifa);
};

const static struct babel_pkt_tlv_data tlv_data[BABEL_TLV_MAX] = {
  [BABEL_TLV_PAD0] = {0, NULL,NULL,NULL},
  [BABEL_TLV_PADN] = {0, NULL,NULL,NULL},
  [BABEL_TLV_ACK_REQ] = {sizeof(struct babel_pkt_tlv_ack_req),
                          babel_read_ack_req,
                          NULL,
                          babel_handle_ack_req},
  [BABEL_TLV_ACK] = {0, NULL,
                      babel_write_ack,
                      NULL},
  [BABEL_TLV_HELLO] = {sizeof(struct babel_pkt_tlv_hello),
                        babel_read_hello,
                        babel_write_hello,
                        babel_handle_hello},
  [BABEL_TLV_IHU] = {sizeof(struct babel_pkt_tlv_ihu),
                      babel_read_ihu,
                      babel_write_ihu,
                      babel_handle_ihu},
  [BABEL_TLV_ROUTER_ID] = {sizeof(struct babel_pkt_tlv_router_id),
                            babel_read_router_id,
                            NULL,
                            NULL},
  [BABEL_TLV_NEXT_HOP] = {sizeof(struct babel_pkt_tlv_next_hop),
                           babel_read_next_hop,
                           NULL,
                           NULL},
  [BABEL_TLV_UPDATE] = {sizeof(struct babel_pkt_tlv_update),
                         babel_read_update,
                         babel_write_update,
                         babel_handle_update},
  [BABEL_TLV_ROUTE_REQUEST] = {sizeof(struct babel_pkt_tlv_route_request),
                                babel_read_route_request,
                                babel_write_route_request,
                                babel_handle_route_request},
  [BABEL_TLV_SEQNO_REQUEST] = {sizeof(struct babel_pkt_tlv_seqno_request),
                                babel_read_seqno_request,
                                babel_write_seqno_request,
                                babel_handle_seqno_request},
};

static inline int
read_tlv(struct babel_pkt_tlv_header *hdr,
         union babel_tlv *tlv,
         struct babel_parse_state *state)
{
  if (hdr->type <= BABEL_TLV_PADN ||
     hdr->type >= BABEL_TLV_MAX ||
     tlv_data[hdr->type].read_tlv == NULL)
    return PARSE_IGNORE;

  if (TLV_SIZE(hdr) < tlv_data[hdr->type].min_size)
    return PARSE_ERROR;

  return tlv_data[hdr->type].read_tlv(hdr, tlv, state);
}

static enum parse_result
babel_read_ack_req(struct babel_pkt_tlv_header *hdr,
                   union babel_tlv *tlv,
                   struct babel_parse_state *state)
{
  struct babel_pkt_tlv_ack_req * pkt_tlv = (struct babel_pkt_tlv_ack_req *) hdr;
  tlv->ack_req.nonce = get_u16(&pkt_tlv->nonce);
  tlv->ack_req.interval = get_u16(&pkt_tlv->interval);
  tlv->ack_req.sender = state->saddr;
  return PARSE_SUCCESS;
}


static enum parse_result
babel_read_hello(struct babel_pkt_tlv_header *hdr,
                 union babel_tlv *tlv,
                 struct babel_parse_state *state)
{
  struct babel_pkt_tlv_hello * pkt_tlv = (struct babel_pkt_tlv_hello *) hdr;
  tlv->hello.seqno = get_u16(&pkt_tlv->seqno);
  tlv->hello.interval = get_u16(&pkt_tlv->interval);
  tlv->hello.sender = state->saddr;
  return PARSE_SUCCESS;
}


static enum parse_result
babel_read_ihu(struct babel_pkt_tlv_header *hdr,
               union babel_tlv *tlv,
               struct babel_parse_state *state)
{
  struct babel_pkt_tlv_ihu * pkt_tlv = (struct babel_pkt_tlv_ihu *) hdr;
  tlv->ihu.ae = pkt_tlv->ae;
  tlv->ihu.rxcost = get_u16(&pkt_tlv->rxcost);
  tlv->ihu.interval = get_u16(&pkt_tlv->interval);

  if (tlv->ihu.ae >= BABEL_AE_MAX)
    return PARSE_IGNORE;

  // We handle link-local IPs. In every other case, the addr field will be 0 but
  // validation will succeed. The handler takes care of these cases.
  if (tlv->ihu.ae == BABEL_AE_IP6_LL)
  {
    if (TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_ihu)+8) return PARSE_ERROR;
    tlv->ihu.addr = get_ip6_ll(&pkt_tlv->addr);
  }
  tlv->ihu.sender = state->saddr;
  return PARSE_SUCCESS;
}


static enum parse_result
babel_read_router_id(struct babel_pkt_tlv_header *hdr,
                     union babel_tlv *tlv,
                     struct babel_parse_state *state)
{
  struct babel_pkt_tlv_router_id * pkt_tlv = (struct babel_pkt_tlv_router_id *) hdr;
  state->router_id = pkt_tlv->router_id;
  state->router_id_seen = 1;
  return PARSE_SUCCESS;
}

static enum parse_result
babel_read_next_hop(struct babel_pkt_tlv_header *hdr,
                    union babel_tlv *tlv,
                    struct babel_parse_state *state)
{
  struct babel_pkt_tlv_next_hop * pkt_tlv = (struct babel_pkt_tlv_next_hop *) hdr;

  if (pkt_tlv->ae >= BABEL_AE_MAX)
    return PARSE_IGNORE;

  if (pkt_tlv->ae == BABEL_AE_IP6_LL)
  {
    if (TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_next_hop)+8) return PARSE_ERROR;
    state->next_hop = get_ip6_ll(&pkt_tlv->addr);
  }
  return PARSE_SUCCESS;
}

static enum parse_result
babel_read_update(struct babel_pkt_tlv_header *hdr,
                  union babel_tlv *tlv,
                  struct babel_parse_state *state)
{
  struct babel_pkt_tlv_update * pkt_tlv = (struct babel_pkt_tlv_update *) hdr;
  char buf[16] = {};
  u8 len = (pkt_tlv->plen + 7)/8;
  tlv->update.ae = pkt_tlv->ae;
  tlv->update.plen = pkt_tlv->plen;
  tlv->update.interval = get_u16(&pkt_tlv->interval);
  tlv->update.seqno = get_u16(&pkt_tlv->seqno);
  tlv->update.metric = get_u16(&pkt_tlv->metric);

  if (tlv->update.plen > MAX_PREFIX_LENGTH)
    return PARSE_ERROR;

  if (tlv->update.ae >= BABEL_AE_MAX)
    return PARSE_IGNORE;
  /* Can only omit bits if a previous update defined a prefix to take them from */
  if (pkt_tlv->omitted && ipa_equal(state->prefix, IPA_NONE))
    return PARSE_ERROR;

  /* TLV should be large enough to hold the entire prefix */
  if (TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_update) + len - pkt_tlv->omitted)
    return PARSE_ERROR;

  /* IP address decoding */
  if (tlv->update.ae == BABEL_AE_WILDCARD || tlv->update.ae == BABEL_AE_IP4)
  {
    tlv->update.prefix = IPA_NONE;
  }
  else if (tlv->update.ae == BABEL_AE_IP6_LL)
  {
    tlv->update.prefix = get_ip6_ll(&pkt_tlv->addr);
  }
  else
  {
    /* if we have omitted bytes, get them from previous prefix */
    if (pkt_tlv->omitted) put_ipa(buf, state->prefix);
    /* if the prefix is longer than the omitted octets, copy the rest */
    if (pkt_tlv->omitted < len) memcpy(buf+pkt_tlv->omitted,
                                      &pkt_tlv->addr,
                                      len - pkt_tlv->omitted);
    /* make sure the tail is zeroed */
    if (len < 16) memset(buf+len, 0, 16-len);
    tlv->update.prefix = get_ipa(buf);
  }
  if (pkt_tlv->flags & BABEL_FLAG_DEF_PREFIX)
  {
    state->prefix = tlv->update.prefix;
  }
  if (pkt_tlv->flags & BABEL_FLAG_ROUTER_ID)
  {
    if (pkt_tlv->ae == BABEL_AE_IP4) return PARSE_ERROR;
    state->router_id = ((u64) _I2(tlv->update.prefix)) << 32 | _I3(tlv->update.prefix);
    state->router_id_seen = 1;
  }
  if (!state->router_id_seen) return PARSE_ERROR;

  tlv->update.router_id = state->router_id;
  tlv->update.next_hop = state->next_hop;
  tlv->update.sender = state->saddr;
  return PARSE_SUCCESS;
}


static enum parse_result
babel_read_route_request(struct babel_pkt_tlv_header *hdr,
                         union babel_tlv *tlv,
                         struct babel_parse_state *state)
{
  struct babel_pkt_tlv_route_request * pkt_tlv = (struct babel_pkt_tlv_route_request *) hdr;
  u8 len = (pkt_tlv->plen + 7)/8;
  char buf[16] = {};
  tlv->route_request.ae = pkt_tlv->ae;
  tlv->route_request.plen = pkt_tlv->plen;

  if (tlv->route_request.plen > MAX_PREFIX_LENGTH)
    return PARSE_ERROR;

  /* Prefixes cannot be link-local addresses. */
  if (tlv->route_request.ae >= BABEL_AE_IP6_LL)
    return PARSE_ERROR;

  /* enough space to hold the prefix */
  if (TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_route_request) + len)
    return PARSE_ERROR;

  /* wildcard requests must have plen 0, others must not */
  if ((tlv->route_request.ae == BABEL_AE_WILDCARD && tlv->route_request.plen > 0) ||
     (tlv->route_request.ae != BABEL_AE_WILDCARD && tlv->route_request.plen == 0))
    return PARSE_ERROR;

  /* IP address decoding */
  if (tlv->route_request.ae == BABEL_AE_WILDCARD || tlv->route_request.ae == BABEL_AE_IP4)
  {
    tlv->route_request.prefix = IPA_NONE;
  }
  else
  {
    memcpy(buf, &pkt_tlv->addr, len);
    tlv->route_request.prefix = get_ipa(buf);
  }

  return PARSE_SUCCESS;
}

static enum parse_result
babel_read_seqno_request(struct babel_pkt_tlv_header *hdr,
                         union babel_tlv *tlv,
                         struct babel_parse_state *state)
{
  struct babel_pkt_tlv_seqno_request * pkt_tlv = (struct babel_pkt_tlv_seqno_request *) hdr;
  u8 len = (pkt_tlv->plen + 7)/8;
  char buf[16] = {};
  tlv->seqno_request.ae = pkt_tlv->ae;
  tlv->seqno_request.plen = pkt_tlv->plen;
  tlv->seqno_request.seqno = get_u16(&pkt_tlv->seqno);
  tlv->seqno_request.hop_count = pkt_tlv->hop_count;
  tlv->seqno_request.router_id = get_u64(&pkt_tlv->router_id);

  if (tlv->seqno_request.plen > MAX_PREFIX_LENGTH) {
    DBG("Babel: Prefix len too long\n");
    return PARSE_ERROR;
  }

  /* Prefixes cannot be link-local addresses. */
  if (tlv->seqno_request.ae >= BABEL_AE_IP6_LL) {
    DBG("Babel: Invalid AE\n");
    return PARSE_ERROR;
  }

  /* enough space to hold the prefix */
  if (TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_seqno_request) + len) {
    DBG("Babel: TLV size too small\n");
    return PARSE_ERROR;
  }

  /* wildcard requests not allowed */
  if (tlv->seqno_request.ae == BABEL_AE_WILDCARD) {
    DBG("Babel: Wildcard request disallowed\n");
    return PARSE_ERROR;
  }

  /* IP address decoding */
  if (tlv->seqno_request.plen == 0 || tlv->seqno_request.ae == BABEL_AE_IP4)
  {
    tlv->seqno_request.prefix = IPA_NONE;
  }
  else
  {
    memcpy(buf, &pkt_tlv->addr, len);
    tlv->seqno_request.prefix = get_ipa(buf);
  }

  tlv->seqno_request.sender = state->saddr;
  return PARSE_SUCCESS;

}

static int
write_tlv(struct babel_pkt_tlv_header *hdr,
          union babel_tlv *tlv,
          struct babel_write_state *state,
          int max_len)
{
  if (tlv->type <= BABEL_TLV_PADN ||
     tlv->type >= BABEL_TLV_MAX ||
     tlv_data[tlv->type].write_tlv == NULL)
    return 0;

  if (max_len < tlv_data[tlv->type].min_size)
    return 0;

  memset(hdr, 0, tlv_data[tlv->type].min_size);
  return tlv_data[tlv->type].write_tlv(hdr, tlv, state, max_len);
}


static int
babel_write_ack(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                struct babel_write_state *state, int max_len)
{
  struct babel_pkt_tlv_ack * pkt_tlv = (struct babel_pkt_tlv_ack *) hdr;
  hdr->type = BABEL_TLV_ACK;
  hdr->length = sizeof(struct babel_pkt_tlv_ack) - sizeof(struct babel_pkt_tlv_header);
  put_u16(&pkt_tlv->nonce, tlv->ack.nonce);
  return sizeof(struct babel_pkt_tlv_ack);
}

static int
babel_write_hello(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                  struct babel_write_state *state, int max_len)
{
  struct babel_pkt_tlv_hello * pkt_tlv = (struct babel_pkt_tlv_hello *) hdr;
  hdr->type = BABEL_TLV_HELLO;
  hdr->length = sizeof(struct babel_pkt_tlv_hello) - sizeof(struct babel_pkt_tlv_header);
  put_u16(&pkt_tlv->seqno, tlv->hello.seqno);
  put_u16(&pkt_tlv->interval, tlv->hello.interval);
  return sizeof(struct babel_pkt_tlv_hello);
}

static int
babel_write_ihu(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                struct babel_write_state *state, int max_len)
{

  struct babel_pkt_tlv_ihu * pkt_tlv = (struct babel_pkt_tlv_ihu *) hdr;

  if (ipa_is_link_local(tlv->ihu.addr) && max_len < sizeof(struct babel_pkt_tlv_ihu) + 8)
    return 0;

  hdr->type = BABEL_TLV_IHU;
  hdr->length = sizeof(struct babel_pkt_tlv_ihu) - sizeof(struct babel_pkt_tlv_header);
  put_u16(&pkt_tlv->rxcost, tlv->ihu.rxcost);
  put_u16(&pkt_tlv->interval, tlv->ihu.interval);
  if (!ipa_is_link_local(tlv->ihu.addr))
  {
    pkt_tlv->ae = BABEL_AE_WILDCARD;
    return sizeof(struct babel_pkt_tlv_ihu);
  }
  put_ip6_ll(&pkt_tlv->addr, tlv->ihu.addr);
  pkt_tlv->ae = BABEL_AE_IP6_LL;
  hdr->length += 8;
  return sizeof(struct babel_pkt_tlv_ihu) + 8;
}

static int
babel_write_update(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                   struct babel_write_state *state, int max_len)
{

  struct babel_pkt_tlv_update * pkt_tlv = (struct babel_pkt_tlv_update *) hdr;
  struct babel_pkt_tlv_router_id * router_id;
  char buf[16] = {};
  u8 size, len = (tlv->update.plen + 7)/8;
  size = sizeof(struct babel_pkt_tlv_update) + len;

  /* If we haven't added the right router ID previous to this update, we really
     add two TLVs to the packet buffer. Check that we have space for this (if
     relevant), and also if we have space for the update TLV itself.. */
  if (max_len < size || ((!state->router_id_seen ||
                         state->router_id != tlv->update.router_id) &&
                        max_len < size + sizeof(struct babel_pkt_tlv_router_id)))
    return 0;
  put_ipa(buf, tlv->update.prefix);

  if (!state->router_id_seen || state->router_id != tlv->update.router_id) {
    hdr->type = BABEL_TLV_ROUTER_ID;
    hdr->length = sizeof(struct babel_pkt_tlv_router_id) - sizeof(struct babel_pkt_tlv_header);
    router_id = (struct babel_pkt_tlv_router_id *)hdr;
    put_u64(&router_id->router_id, tlv->update.router_id);
    NEXT_TLV(hdr);
    pkt_tlv = (struct babel_pkt_tlv_update *) hdr;
    memset(hdr, 0, size);
    size += sizeof(struct babel_pkt_tlv_router_id);
    state->router_id = tlv->update.router_id;
    state->router_id_seen = 1;
  }

  hdr->type = BABEL_TLV_UPDATE;
  hdr->length = sizeof(struct babel_pkt_tlv_update) - sizeof(struct babel_pkt_tlv_header) + len;
  pkt_tlv->ae = BABEL_AE_IP6;
  pkt_tlv->plen = tlv->update.plen;
  put_u16(&pkt_tlv->interval, tlv->update.interval);
  put_u16(&pkt_tlv->seqno, tlv->update.seqno);
  put_u16(&pkt_tlv->metric, tlv->update.metric);
  memcpy(pkt_tlv->addr, buf, len);

  return size;
}

static int
babel_write_route_request(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                   struct babel_write_state *state, int max_len)
{

  struct babel_pkt_tlv_route_request * pkt_tlv = (struct babel_pkt_tlv_route_request *) hdr;
  char buf[16] = {};
  u8 size, len = (tlv->route_request.plen + 7)/8;
  size = sizeof(struct babel_pkt_tlv_route_request) + len;
  if (max_len < size)
    return 0;
  put_ipa(buf, tlv->route_request.prefix);

  hdr->type = BABEL_TLV_ROUTE_REQUEST;
  hdr->length = size - sizeof(struct babel_pkt_tlv_header);
  pkt_tlv->ae = BABEL_AE_IP6;
  pkt_tlv->plen = tlv->route_request.plen;
  memcpy(pkt_tlv->addr, buf, len);
  return size;
}

static int
babel_write_seqno_request(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv,
                   struct babel_write_state *state, int max_len)
{

  struct babel_pkt_tlv_seqno_request * pkt_tlv = (struct babel_pkt_tlv_seqno_request *) hdr;
  char buf[16] = {};
  u8 size, len = (tlv->seqno_request.plen + 7)/8;
  size = sizeof(struct babel_pkt_tlv_seqno_request) + len;
  if (max_len < size)
    return 0;
  put_ipa(buf, tlv->seqno_request.prefix);

  hdr->type = BABEL_TLV_SEQNO_REQUEST;
  hdr->length = size - sizeof(struct babel_pkt_tlv_header);
  pkt_tlv->ae = BABEL_AE_IP6;
  pkt_tlv->plen = tlv->seqno_request.plen;
  put_u16(&pkt_tlv->seqno, tlv->seqno_request.seqno);
  pkt_tlv->hop_count = tlv->seqno_request.hop_count;
  put_u64(&pkt_tlv->router_id, tlv->seqno_request.router_id);
  memcpy(pkt_tlv->addr, buf, len);
  return size;
}


void
babel_init_packet(void *buf)
{
  struct babel_pkt_header *hdr = buf;
  memset(hdr, 0, sizeof(struct babel_pkt_header));
  hdr->magic = BABEL_MAGIC;
  hdr->version = BABEL_VERSION;
}

static int
babel_send_to(struct babel_iface *ifa, ip_addr dest)
{
  sock *sk = ifa->sock;
  struct babel_pkt_header *hdr = (void *) sk->tbuf;
  int len = get_u16(&hdr->length)+sizeof(struct babel_pkt_header);

  DBG("Babel: Sending %d bytes to %I\n", len, dest);
  return sk_send_to(sk, len, dest, 0);
}

static int babel_write_queue(struct babel_iface *ifa, list queue)
{
  struct babel_proto *p = ifa->proto;
  struct babel_pkt_header *dst = (void *)ifa->sock->tbuf;
  struct babel_pkt_tlv_header *hdr;
  struct babel_tlv_node *cur;
  struct babel_write_state state = {};
  u16 written, len = 0;

  if (EMPTY_LIST(queue))
    return 0;

  babel_init_packet(dst);
  hdr = FIRST_TLV(dst);
  WALK_LIST_FIRST(cur, ifa->tlv_queue) {
    if ((written = write_tlv(hdr, &cur->tlv, &state,
                            ifa->max_pkt_len - ((byte *)hdr-(byte *)dst))) == 0)
      break;
    len += written;
    hdr = (void *)((byte *) hdr + written);
    rem_node(NODE cur);
    sl_free(p->tlv_slab, cur);
  }
  put_u16(&dst->length, len);
  return len;
}

void
babel_send_queue(void *arg)
{
  struct babel_iface *ifa = arg;
  while (babel_write_queue(ifa, ifa->tlv_queue) > 0 &&
         babel_send_to(ifa, IP6_BABEL_ROUTERS) > 0) ;
}

void
babel_send_unicast(union babel_tlv *tlv, struct babel_iface *ifa, ip_addr dest)
{
  list queue;
  struct babel_proto *p = ifa->proto;
  struct babel_tlv_node *tlvn = sl_alloc(p->tlv_slab);
  init_list(&queue);

  tlvn->tlv = *tlv;
  add_tail(&queue, NODE tlvn);
  babel_write_queue(ifa, queue);
  babel_send_to(ifa, dest);
}


void
babel_enqueue(union babel_tlv *tlv, struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  struct babel_tlv_node *tlvn = sl_alloc(p->tlv_slab);
  tlvn->tlv = *tlv;
  add_tail(&ifa->tlv_queue, NODE tlvn);
  ev_schedule(ifa->send_event);
}



void
babel_process_packet(struct babel_pkt_header *pkt, int size,
                     ip_addr saddr, int port, struct babel_iface *ifa)
{
  struct babel_pkt_tlv_header *tlv = FIRST_TLV(pkt);
  struct babel_proto *proto = ifa->proto;
  struct babel_parse_state state = {
    .proto	  = proto,
    .ifa	  = ifa,
    .saddr	  = saddr,
    .next_hop	  = saddr,
  };
  byte *ptr = (byte *)tlv;
  u16 len = get_u16(&pkt->length);
  struct babel_tlv_node *cur;
  enum parse_result res;
  list tlvs;
  init_list(&tlvs);

  if (pkt->magic != BABEL_MAGIC
     || pkt->version != BABEL_VERSION
     || len + sizeof(struct babel_pkt_header) > size)
  {
    log(L_ERR "Babel: Invalid packet: magic %d version %d length %d size %d\n",
	pkt->magic, pkt->version, pkt->length, size);
    return;
  }


  /* First pass through the packet TLV by TLV, parsing each into internal data
     structures. */
  for (cur = sl_alloc(proto->tlv_slab);
       (byte *)tlv < ptr + len;
       NEXT_TLV(tlv))
  {
    if ((byte *)tlv + tlv->length > ptr + len) {
      log(L_ERR "Babel: Framing error: TLV type %d length %d exceeds end of packet\n",
          tlv->type, tlv->length);
      sl_free(proto->tlv_slab, cur);
      break;
    }

    if ((res = read_tlv(tlv, &cur->tlv, &state)) == PARSE_SUCCESS)
    {
      cur->tlv.type = tlv->type;
      add_tail(&tlvs, NODE cur);
      cur = sl_alloc(proto->tlv_slab);
    }
    else if (res == PARSE_IGNORE)
    {
      DBG("Ignoring TLV of type %d\n",tlv->type);
    }
    else
    {
      DBG("TLV read error for type %d\n",tlv->type);
      sl_free(proto->tlv_slab, cur);
      break;
    }
  }

  /* Parsing done, handle all parsed TLVs */
  WALK_LIST_FIRST(cur, tlvs) {
    if (tlv_data[cur->tlv.type].handle_tlv != NULL)
      tlv_data[cur->tlv.type].handle_tlv(&cur->tlv, ifa);
    rem_node(NODE cur);
    sl_free(proto->tlv_slab, cur);
  }
}

static void
babel_err_hook(sock *sk, int err)
{
  struct babel_iface *ifa = sk->data;
  struct babel_proto *p = ifa->proto;

  log(L_ERR "%s: Socket error on %s: %M", p->p.name, ifa->iface->name, err);
  /* FIXME: Drop queued TLVs here? */
}


static void
babel_tx_hook(sock *sk)
{
  struct babel_iface *ifa = sk->data;

  DBG("Babel: TX hook called (iface %s, src %I, dst %I)\n",
      sk->iface->name, sk->saddr, sk->daddr);

  babel_send_queue(ifa);
}


static int
babel_rx_hook(sock *sk, int size)
{
  struct babel_iface *ifa = sk->data;
  struct babel_proto *p = ifa->proto;
  if (!ifa->iface || sk->lifindex != ifa->iface->index)
    return 1;

  TRACE(D_PACKETS, "Incoming packet: %d bytes from %I via %s", size, sk->faddr, ifa->iface->name);
  if (size < sizeof(struct babel_pkt_header)) BAD("Too small packet");

  if (ipa_equal(ifa->iface->addr->ip, sk->faddr))
  {
    DBG("My own packet\n");
    return 1;
  }

  if (!ipa_is_link_local(sk->faddr)) { BAD("Non-link local sender"); }

  babel_process_packet((struct babel_pkt_header *) sk->rbuf, size, sk->faddr, sk->fport, ifa);
  return 1;
}

int
babel_open_socket(struct babel_iface *ifa)
{
  struct babel_proto *p = ifa->proto;
  sock *sk;
  sk = sk_new(ifa->pool);
  sk->type = SK_UDP;
  sk->sport = ifa->cf->port;
  sk->rx_hook = babel_rx_hook;
  sk->tx_hook = babel_tx_hook;
  sk->data = ifa;
  sk->rbsize = MAX(512, ifa->iface->mtu);
  sk->tbsize = sk->rbsize;
  sk->iface = ifa->iface;
  sk->err_hook = babel_err_hook;
  sk->dport = ifa->cf->port;
  sk->daddr = IP6_BABEL_ROUTERS;

  sk->tos = ifa->cf->tx_tos;
  sk->priority = ifa->cf->tx_priority;
  sk->flags = SKF_LADDR_RX;
  if (sk_open(sk) < 0)
    goto err;
  if (sk_setup_multicast(sk) < 0)
    goto err;
  if (sk_join_group(sk, sk->daddr) < 0)
    goto err;
  TRACE(D_EVENTS, "Listening on %s, port %d, mode multicast (%I)",
        ifa->iface->name, ifa->cf->port, sk->daddr);

  ifa->sock = sk;

  babel_iface_start(ifa);

  return 1;

 err:
  sk_log_error(sk, p->p.name);
  rfree(sk);
  return 0;

}
