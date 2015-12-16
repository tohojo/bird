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

#define BAD( x ) { log( L_REMOTE "%s: " x, p->p.name ); return 1; }
#define FIRST_TLV(p) ((struct babel_pkt_tlv_header *)(((struct babel_pkt_header *) p) + 1))
#define NEXT_TLV(t) (t = (void *)((char *)t) + TLV_SIZE(t))
#define TLV_SIZE(t) (t->type == BABEL_TYPE_PAD0 ? 1 : t->length + sizeof(struct babel_pkt_tlv_header))

static enum parse_result {
  PARSE_SUCCESS,
  PARSE_ERROR,
  PARSE_IGNORE,
};

static void babel_send_to(struct babel_iface *bif, ip_addr dest);

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


static enum parse_result babel_read_ack_req(struct babel_pkt_tlv_header *hdr,
                              union babel_tlv *tlv,
                              struct babel_parse_state *state);
static enum parse_result babel_read_hello(struct babel_pkt_tlv_header *hdr,
                            union babel_tlv *tlv,
                            struct babel_parse_state *state);
static enum parse_result babel_read_ihu(struct babel_pkt_tlv_header *hdr,
                          union babel_tlv *tlv,
                          struct babel_parse_state *state);
static enum parse_result babel_read_router_id(struct babel_pkt_tlv_header *hdr,
                                union babel_tlv *tlv,
                                struct babel_parse_state *state);
static enum parse_result babel_read_next_hop(struct babel_pkt_tlv_header *hdr,
                               union babel_tlv *tlv,
                               struct babel_parse_state *state);
static enum parse_result babel_read_update(struct babel_pkt_tlv_header *hdr,
                             union babel_tlv *tlv,
                             struct babel_parse_state *state);
static enum parse_result babel_read_route_request(struct babel_pkt_tlv_header *hdr,
                                    union babel_tlv *tlv,
                                    struct babel_parse_state *state);
static enum parse_result babel_read_seqno_request(struct babel_pkt_tlv_header *hdr,
                                    union babel_tlv *tlv,
                                    struct babel_parse_state *state);



struct babel_pkt_tlv_data {
  u8 min_size;
  enum parse_result (*read_tlv)(struct babel_pkt_tlv_header *hdr,
                                union babel_tlv *tlv, struct babel_parse_state *state);
  void (*write_tlv)(struct babel_pkt_tlv_header *hdr,
                    union babel_tlv *tlv);
  int (*handle_tlv)(union babel_tlv *tlv, struct babel_iface *bif);
};

const static struct babel_pkt_tlv_data tlv_data[BABEL_TYPE_MAX] = {
  [BABEL_TYPE_PAD0] = {0, NULL,NULL,NULL},
  [BABEL_TYPE_PADN] = {0, NULL,NULL,NULL},
  [BABEL_TYPE_ACK_REQ] = {sizeof(struct babel_pkt_tlv_ack_req),
                          babel_read_ack_req,
                          babel_write_ack_req,
                          babel_handle_ack_req},
  [BABEL_TYPE_ACK] = {0, NULL,
                      babel_write_ack,
                      babel_handle_ack},
  [BABEL_TYPE_HELLO] = {sizeof(struct babel_pkt_tlv_hello),
                        babel_read_hello,
                        babel_write_hello,
                        babel_handle_hello},
  [BABEL_TYPE_IHU] = {sizeof(struct babel_pkt_tlv_ihu),
                      babel_read_ihu,
                      babel_write_ihu,
                      babel_handle_ihu},
  [BABEL_TYPE_ROUTER_ID] = {sizeof(struct babel_pkt_tlv_router_id),
                            babel_read_router_id,
                            babel_write_router_id,
                            babel_handle_router_id},
  [BABEL_TYPE_NEXT_HOP] = {sizeof(struct babel_pkt_tlv_next_hop),
                           babel_read_next_hop,
                           NULL,
                           babel_handle_next_hop},
  [BABEL_TYPE_UPDATE] = {sizeof(struct babel_pkt_tlv_update),
                         babel_read_update,
                         babel_write_update,
                         babel_handle_update},
  [BABEL_TYPE_ROUTE_REQUEST] = {sizeof(struct babel_pkt_tlv_route_request),
                                babel_read_route_request,
                                babel_write_route_request,
                                babel_handle_route_request},
  [BABEL_TYPE_SEQNO_REQUEST] = {sizeof(struct babel_pkt_tlv_seqno_request),
                                babel_read_seqno_request,
                                babel_write_seqno_request,
                                babel_handle_seqno_request},
};

static inline int
read_tlv(struct babel_pkt_tlv_header *hdr,
         union babel_tlv *tlv,
         struct babel_parse_state *state)
{
  if(hdr->type <= BABEL_TYPE_PADN ||
     tlv->type >= BABEL_TYPE_MAX ||
     tlv_data[hdr->type].read_tlv == NULL)
    return PARSE_IGNORE;

  if(TLV_SIZE(hdr) < tlv_data[hdr->type].min_size)
    return PARSE_ERROR;

  memset(tlv, 0, sizeof(*tlv));
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

void
babel_write_ack_req(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv)
{
  struct babel_pkt_tlv_ack_req * pkt_tlv = (struct babel_pkt_tlv_ack_req *) hdr;
  put_u16(&pkt_tlv->nonce, tlv->ack_req.nonce);
  put_u16(&pkt_tlv->interval, tlv->ack_req.interval);
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

void
babel_write_hello(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv)
{
  struct babel_pkt_tlv_hello * pkt_tlv = (struct babel_pkt_tlv_hello *) hdr;
  put_u16(&pkt_tlv->seqno, tlv->hello.seqno);
  put_u16(&pkt_tlv->interval, tlv->hello.interval);
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

  if(tlv->ihu.ae >= BABEL_AE_MAX)
    return PARSE_IGNORE;

  // We handle link-local IPs. In every other case, the addr field will be 0 but
  // validation will succeed. The handler takes care of these cases.
  if(tlv->ihu.ae == BABEL_AE_IP6_LL)
  {
    if(TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_ihu)+8) return PARSE_ERROR;
    tlv->ihu.addr = get_ip6_ll(&pkt_tlv->addr);
  }
  tlv->ihu.sender = state->saddr;
  return PARSE_SUCCESS;
}

void
babel_write_ihu(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv)
{

  struct babel_pkt_tlv_ihu * pkt_tlv = (struct babel_pkt_tlv_ihu *) hdr;
  put_u16(&pkt_tlv->rxcost, tlv->ihu.rxcost);
  put_u16(&pkt_tlv->interval, tlv->ihu.interval);
  if(!ipa_is_link_local(tlv->ihu.addr))
  {
    pkt_tlv->ae = BABEL_AE_WILDCARD;
    return;
  }
  put_ip6_ll(&pkt_tlv->addr, tlv->ihu.addr);
}


static enum parse_result
babel_read_router_id(struct babel_pkt_tlv_header *hdr,
                     union babel_tlv *tlv,
                     struct babel_parse_state *state)
{
  struct babel_pkt_tlv_router_id * pkt_tlv = (struct babel_pkt_tlv_router_id *) hdr;
  state->router_id = tlv->router_id.router_id;
  state->router_id_seen = 1;
  return PARSE_SUCCESS;
}

void
babel_write_router_id(struct babel_pkt_tlv_header *hdr, union babel_tlv *tlv)
{
  struct babel_pkt_tlv_router_id * pkt_tlv = (struct babel_pkt_tlv_router_id *) hdr;
  put_u64(&pkt_tlv->router_id, tlv->router_id.router_id);
}

static enum parse_result
babel_read_next_hop(struct babel_pkt_tlv_header *hdr,
                    union babel_tlv *tlv,
                    struct babel_parse_state *state)
{
  struct babel_pkt_tlv_next_hop * pkt_tlv = (struct babel_pkt_tlv_next_hop *) hdr;
  tlv->next_hop.ae = pkt_tlv->ae;

  if(tlv->ihu.ae >= BABEL_AE_MAX)
    return PARSE_IGNORE;

  if(tlv->next_hop.ae == BABEL_AE_IP6_LL)
  {
    if(TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_next_hop)+8) return PARSE_ERROR;
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
  u8 len; char buf[16] = {0};
  tlv->update.ae = pkt_tlv->ae;
  tlv->update.plen = pkt_tlv->plen;
  tlv->update.interval = get_u16(&pkt_tlv->interval);
  tlv->update.seqno = get_u16(&pkt_tlv->seqno);
  tlv->update.metric = get_u16(&pkt_tlv->metric);

  len = tlv->update.plen/8;
  if(tlv->update.plen % 8) len++;

  if(tlv->update.plen > MAX_PREFIX_LENGTH)
    return PARSE_ERROR;

  if(tlv->update.ae >= BABEL_AE_MAX)
    return PARSE_IGNORE;
  /* Can only omit bits if a previous update defined a prefix to take them from */
  if(pkt_tlv->omitted && ipa_equal(state->prefix, IPA_NONE))
    return PARSE_ERROR;

  /* TLV should be large enough to hold the entire prefix */
  if(TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_update) + len - pkt_tlv->omitted)
    return PARSE_ERROR;

  /* IP address decoding */
  if(tlv->update.ae == BABEL_AE_WILDCARD || tlv->update.ae == BABEL_AE_IP4)
  {
    tlv->update.addr = IPA_NONE;
  }
  else if(tlv->update.ae == BABEL_AE_IP6_LL)
  {
    tlv->update.addr = get_ip6_ll(&pkt_tlv->addr);
  }
  else
  {
    /* if we have omitted bytes, get them from previous prefix */
    if(pkt_tlv->omitted) put_ipa(buf, state->prefix);
    /* if the prefix is longer than the omitted octets, copy the rest */
    if(pkt_tlv->omitted < len) memcpy(buf+pkt_tlv->omitted,
                                      &pkt_tlv->addr,
                                      len - pkt_tlv->omitted);
    /* make sure the tail is zeroed */
    if(len < 16) memset(buf+len, 0, 16-len);
    tlv->update.addr = get_ipa(buf);
  }
  if (pkt_tlv->flags & BABEL_FLAG_DEF_PREFIX)
  {
    state->prefix = tlv->update.addr;
  }
  if (pkt_tlv->flags & BABEL_FLAG_ROUTER_ID)
  {
    state->router_id = ((u64) _I2(tlv->update.addr)) << 32 | _I3(tlv->update.addr);
    state->router_id_seen = 1;
  }
  if(!state->router_id_seen) return PARSE_ERROR;

  tlv->update.router_id = state->router_id;
  tlv->update.sender = state->saddr;
  return PARSE_SUCCESS;
}


static enum parse_result
babel_read_route_request(struct babel_pkt_tlv_header *hdr,
                         union babel_tlv *tlv,
                         struct babel_parse_state *state)
{
  struct babel_pkt_tlv_route_request * pkt_tlv = (struct babel_pkt_tlv_route_request *) hdr;
  u8 len; char buf[16] = {0};
  tlv->route_request.ae = pkt_tlv->ae;
  tlv->route_request.plen = pkt_tlv->plen;
  len = tlv->route_request.plen/8;
  if(tlv->route_request.plen % 8) len++;

  if(tlv->route_request.plen > MAX_PREFIX_LENGTH)
    return PARSE_ERROR;

  /* Prefixes cannot be link-local addresses. */
  if(tlv->route_request.ae >= BABEL_AE_IP6_LL)
    return PARSE_ERROR;

  /* enough space to hold the prefix */
  if(TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_route_request) + len)
    return PARSE_ERROR;

  /* wildcard requests must have plen 0, others must not */
  if((tlv->route_request.ae == BABEL_AE_WILDCARD && tlv->route_request.plen > 0) ||
     (tlv->route_request.ae != BABEL_AE_WILDCARD && tlv->route_request.plen == 0))
    return PARSE_ERROR;

  /* IP address decoding */
  if(tlv->route_request.ae == BABEL_AE_WILDCARD || tlv->route_request.ae == BABEL_AE_IP4)
  {
    tlv->route_request.addr = IPA_NONE;
  }
  else
  {
    memcpy(buf, &pkt_tlv->addr, len);
    tlv->route_request.addr = get_ipa(buf);
  }

  return PARSE_SUCCESS;
}

static enum parse_result
babel_read_seqno_request(struct babel_pkt_tlv_header *hdr,
                         union babel_tlv *tlv,
                         struct babel_parse_state *state)
{
  struct babel_pkt_tlv_seqno_request * pkt_tlv = (struct babel_pkt_tlv_seqno_request *) hdr;
  u8 len; char buf[16] = {0};
  tlv->seqno_request.ae = pkt_tlv->ae;
  tlv->seqno_request.plen = pkt_tlv->plen;
  tlv->seqno_request.seqno = get_u16(&pkt_tlv->seqno);
  tlv->seqno_request.hop_count = pkt_tlv->hop_count;
  tlv->seqno_request.router_id = get_u64(&pkt_tlv->router_id);
  len = tlv->seqno_request.plen/8;
  if(tlv->seqno_request.plen % 8) len++;

  if(tlv->seqno_request.plen > MAX_PREFIX_LENGTH)
    return PARSE_ERROR;

  /* Prefixes cannot be link-local addresses. */
  if(tlv->seqno_request.ae >= BABEL_AE_IP6_LL)
    return PARSE_ERROR;

  /* enough space to hold the prefix */
  if(TLV_SIZE(hdr) < sizeof(struct babel_pkt_tlv_seqno_request) + len)
    return PARSE_ERROR;

  /* wildcard requests must have plen 0, others must not */
  if((tlv->seqno_request.ae == BABEL_AE_WILDCARD && tlv->seqno_request.plen > 0) ||
     (tlv->seqno_request.ae != BABEL_AE_WILDCARD && tlv->seqno_request.plen == 0))
    return PARSE_ERROR;

  /* IP address decoding */
  if(tlv->seqno_request.ae == BABEL_AE_WILDCARD || tlv->seqno_request.ae == BABEL_AE_IP4)
  {
    tlv->seqno_request.addr = IPA_NONE;
  }
  else
  {
    memcpy(buf, &pkt_tlv->addr, len);
    tlv->seqno_request.addr = get_ipa(buf);
  }

  tlv->seqno_request.sender = state->saddr;
  return PARSE_SUCCESS;
}




void
babel_init_packet(void *buf)
{
  struct babel_pkt_header *hdr = buf;
  memset(hdr, 0, sizeof(struct babel_pkt_header));
  hdr->magic = BABEL_MAGIC;
  hdr->version = BABEL_VERSION;
}

void
babel_new_unicast(struct babel_iface *bif)
{
  babel_init_packet(bif->sock->tbuf);
  bif->current_buf = bif->sock->tbuf;
}

void
babel_send_unicast(struct babel_iface *bif, ip_addr dest)
{
  babel_send_to(bif, dest);
  bif->current_buf = bif->tlv_buf;
}


struct babel_pkt_tlv_header *
babel_add_tlv_size(struct babel_iface *bif, u16 type, int len)
{
  struct babel_pkt_header *hdr = bif->current_buf;
  struct babel_pkt_tlv_header *tlv;
  int pktlen = sizeof(struct babel_pkt_header)+hdr->length;
  if(pktlen+len > bif->max_pkt_len)
  {
    babel_send_queue(bif);
    pktlen = sizeof(struct babel_pkt_header)+hdr->length;
  }
  hdr->length+=len;
  tlv = (struct babel_pkt_tlv_header *)((char*)hdr+pktlen);
  memset(tlv, 0, len);
  tlv->type = type;
  tlv->length = TLV_LENGTH(type);
  return tlv;
}

struct babel_pkt_tlv_header *
babel_add_tlv(struct babel_iface *bif, u16 type)
{
  return babel_add_tlv_size(bif, type, tlv_data[type].struct_length);
}


static int
babel_copy_tlv(void *buf, struct babel_pkt_tlv_header *src, int max_len)
{
  struct babel_pkt_header *dst = buf;
  int pktlen = sizeof(struct babel_pkt_header)+dst->length;
  int len = tlv_data[src->type].struct_length;
  if(pktlen+len > max_len)
    return PARSE_ERROR;

  memcpy((char *)dst + pktlen, src, len);
  dst->length += len;
  return PARSE_SUCCESS;
}


static void
babel_send_to(struct babel_iface *bif, ip_addr dest)
{
  sock *s = bif->sock;
  struct babel_pkt_header *hdr = (void *) s->tbuf;
  int len = hdr->length+sizeof(struct babel_pkt_header);
  int done;

  babel_packet_hton(hdr);

  DBG( "Sending %d bytes to %I\n", len, dest);
  done = sk_send_to(s, len, dest, 0);
  if(!done)
    log(L_WARN "Babel: TX queue full on %s", bif->ifname);
}

static void
babel_send(struct babel_iface *bif)
{
  babel_send_to(bif, IP6_BABEL_ROUTERS);
}

void
babel_send_queue(void *arg)
{
  struct babel_iface *bif = arg;
  struct babel_pkt_header *dst = (void *)bif->sock->tbuf;
  struct babel_pkt_header *src = (void *)bif->tlv_buf;
  struct babel_pkt_tlv_header *hdr;
  char *p;
  int moved;
  if(!src->length) return;

  babel_init_packet(dst);
  hdr = FIRST_TLV(bif->tlv_buf);
  p = (char *) hdr;
  while((char *)hdr < p + src->length && babel_copy_tlv(dst, hdr, bif->max_pkt_len))
  {
    NEXT_TLV(hdr);
  }
  moved = (char *)hdr - p;
  if(moved && moved < src->length)
  {
    memmove(p, hdr, src->length - moved);
  }
  src->length -= moved;
  babel_send(bif);

  /* re-schedule if we still have data to send */
  if(src->length)
    ev_schedule(bif->send_event);
}


void
babel_process_packet(struct babel_pkt_header *pkt, int size,
                     ip_addr saddr, int port, struct babel_iface *bif)
{
  struct babel_pkt_tlv_header *tlv = FIRST_TLV(pkt);
  struct babel_proto *proto = bif->proto;
  struct babel_parse_state state = {
    .proto	  = proto,
    .bif	  = bif,
    .saddr	  = saddr,
    .prefix	  = IPA_NONE,
    .next_hop	  = saddr,
  };
  list tlvs;
  struct babel_tlv_node *cur;
  init_list(&tlvs);
  char *p = (char *)pkt;
  enum parse_result res;

  pkt->length = ntohs(pkt->length);
  if(pkt->magic != BABEL_MAGIC
     || pkt->version != BABEL_VERSION
     || pkt->length > size - sizeof(struct babel_pkt_header))
  {
    DBG("Invalid packet: magic %d version %d length %d size %d\n",
	pkt->magic, pkt->version, pkt->length, size);
    return;
  }

  cur = sl_alloc(proto->tlv_slab);
  while((char *)tlv < p+size)
  {
    if((res = read_tlv(tlv, &cur->tlv, &state)) == PARSE_SUCCESS)
    {
      cur->tlv.type = tlv->type;
      add_tail(&tlvs, NODE cur);
      NEXT_TLV(tlv);
      cur = sl_alloc(proto->tlv_slab);
  }
    else if(res == PARSE_IGNORE)
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
  WALK_LIST_FIRST(cur, tlvs) {
    tlv_data[cur->tlv.type].handle_tlv(&cur->tlv, bif);
    rem_node(NODE cur);
    sl_free(proto->tlv_slab, cur);
  }
  if(state.needs_update)
    bif->update_triggered = 1;
}

static void
babel_tx_err( sock *s, int err )
{
  log( L_ERR ": Unexpected error at Babel transmit: %M", err );
}


static int
babel_rx(sock *s, int size)
{
  struct babel_iface *bif = s->data;
  struct babel_proto *p = bif->proto;
  if (! bif->iface || s->lifindex != bif->iface->index)
    return 1;

  DBG("Babel: incoming packet: %d bytes from %I via %s\n", size, s->faddr, bif->iface->name);
  if (size < sizeof(struct babel_pkt_header)) BAD( "Too small packet" );

  if (ipa_equal(bif->iface->addr->ip, s->faddr))
  {
    DBG("My own packet\n");
    return 1;
  }

  if (!ipa_is_link_local(s->faddr)) { BAD("Non-link local sender"); }

  babel_process_packet((struct babel_pkt_header *) s->rbuf, size, s->faddr, s->fport, bif );
  return 1;
}

int
babel_open_socket(struct babel_iface *bif)
{
  struct babel_proto *p = bif->proto;
  struct babel_config *cf = (struct babel_config *) p->p.cf;
  bif->sock = sk_new( bif->pool );
  bif->sock->type = SK_UDP;
  bif->sock->sport = cf->port;
  bif->sock->rx_hook = babel_rx;
  bif->sock->data =  bif;
  bif->sock->rbsize = 10240;
  bif->sock->iface = bif->iface;
  bif->sock->tbuf = mb_alloc( bif->pool, bif->iface->mtu);
  bif->sock->err_hook = babel_tx_err;
  bif->sock->dport = cf->port;
  bif->sock->daddr = IP6_BABEL_ROUTERS;

  bif->sock->tos = bif->cf->tx_tos;
  bif->sock->priority = bif->cf->tx_priority;
  bif->sock->flags = SKF_LADDR_RX;
  if (sk_open( bif->sock) < 0)
    goto err;
  if (sk_setup_multicast( bif->sock) < 0)
    goto err;
  if (sk_join_group( bif->sock,  bif->sock->daddr) < 0)
    goto err;
  TRACE(D_EVENTS, "Listening on %s, port %d, mode multicast (%I)",  bif->iface->name, cf->port,  bif->sock->daddr );

  tm_start(bif->hello_timer, bif->cf->hello_interval);
  tm_start(bif->update_timer, bif->cf->update_interval);
  tm_start(bif->packet_timer, 1);

  babel_send_hello(bif,0);
  babel_send_queue(bif);

  return 1;

 err:
  sk_log_error(bif->sock, p->p.name);
  log(L_ERR "%s: Cannot open socket for %s", p->p.name,  bif->iface->name);
  rfree(bif->sock);
  return 0;

}
