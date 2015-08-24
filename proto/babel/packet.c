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


#define FIRST_TLV(p) ((struct babel_tlv_header *)(((struct babel_header *) p) + 1))
#define NEXT_TLV(t) (t = (void *)((char *)t) + TLV_SIZE(t))
#define TLV_SIZE(t) (t->type == BABEL_TYPE_PAD0 ? 1 : t->length + sizeof(struct babel_tlv_header))
#define TLV_LENGTH(t) (tlv_data[t].struct_length-sizeof(struct babel_tlv_header))



static ip_addr get_ip6_ll(u32 *addr)
{
    return ip6_or(ipa_build6(0xfe800000,0,0,0),
		  ipa_build6(0,0,ntohl(addr[0]),ntohl(addr[1])));
}


struct babel_tlv_data {
  int struct_length;
  int (*handle)(struct babel_tlv_header *tlv,
		struct babel_parse_state *state);
  int (*validate)(struct babel_tlv_header *tlv,
		  struct babel_parse_state *state);
  void (*hton)(struct babel_tlv_header *tlv);
  void (*ntoh)(struct babel_tlv_header *tlv);
  ip_addr (*get_addr)(struct babel_tlv_header *tlv,
		      struct babel_parse_state *state);
  void (*put_addr)(struct babel_tlv_header *tlv, ip_addr addr);
};

static struct babel_tlv_data tlv_data[BABEL_TYPE_MAX] = {
  {1, NULL,NULL,NULL,NULL,NULL},
  {3, NULL,NULL,NULL,NULL,NULL},
  {sizeof(struct babel_tlv_ack_req),
   babel_handle_ack_req, babel_validate_length,
   babel_hton_ack_req, babel_ntoh_ack_req,
   NULL,NULL},
  {sizeof(struct babel_tlv_ack),
   babel_handle_ack, babel_validate_length,
   NULL, NULL,
   NULL, NULL},
  {sizeof(struct babel_tlv_hello),
   babel_handle_hello, babel_validate_length,
   babel_hton_hello, babel_ntoh_hello,
   NULL, NULL},
  {sizeof(struct babel_tlv_ihu),
   babel_handle_ihu, babel_validate_ihu,
   babel_hton_ihu, babel_ntoh_ihu,
   babel_get_addr_ihu, babel_put_addr_ihu},
  {sizeof(struct babel_tlv_router_id),
   babel_handle_router_id, babel_validate_length,
   babel_hton_router_id, babel_ntoh_router_id,
   NULL, NULL},
  {sizeof(struct babel_tlv_next_hop),
   babel_handle_next_hop, babel_validate_next_hop,
   NULL, NULL,
   babel_get_addr_next_hop, babel_put_addr_next_hop},
  {sizeof(struct babel_tlv_update),
   babel_handle_update, babel_validate_update,
   babel_hton_update, babel_ntoh_update,
   babel_get_addr_update, babel_put_addr_update},
  {sizeof(struct babel_tlv_route_request),
   babel_handle_route_request, babel_validate_request,
   NULL, NULL,
   babel_get_addr_request, babel_put_addr_request},
  {sizeof(struct babel_tlv_seqno_request),
   babel_handle_seqno_request, babel_validate_request,
   babel_hton_seqno_request, babel_ntoh_seqno_request,
   babel_get_addr_request, babel_put_addr_request},
};

static inline int validate_tlv(struct babel_tlv_header *tlv, struct babel_parse_state *state)
{
  return (tlv_data[tlv->type].validate != NULL && tlv_data[tlv->type].validate(tlv, state));
}

void babel_hton_ack_req(struct babel_tlv_header *hdr)
{
  struct babel_tlv_ack_req *tlv = (struct babel_tlv_ack_req *)hdr;
  tlv->interval = htons(tlv->interval);
}
void babel_ntoh_ack_req(struct babel_tlv_header *hdr)
{
  struct babel_tlv_ack_req *tlv = (struct babel_tlv_ack_req *)hdr;
  tlv->interval = ntohs(tlv->interval);
}
void babel_hton_hello(struct babel_tlv_header *hdr)
{
  struct babel_tlv_hello *tlv = (struct babel_tlv_hello *)hdr;
  tlv->seqno = htons(tlv->seqno);
  tlv->interval = htons(tlv->interval);
}
void babel_ntoh_hello(struct babel_tlv_header *hdr)
{
  struct babel_tlv_hello *tlv = (struct babel_tlv_hello *)hdr;
  tlv->seqno = ntohs(tlv->seqno);
  tlv->interval = ntohs(tlv->interval);
}
int babel_validate_ihu(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ihu *tlv = (struct babel_tlv_ihu *)hdr;
  if(hdr->length < TLV_LENGTH(BABEL_TYPE_IHU)-sizeof(tlv->addr)) return 0;
  return (tlv->ae == BABEL_AE_WILDCARD
	  || (tlv->ae == BABEL_AE_IP6_LL && hdr->length >= TLV_LENGTH(BABEL_TYPE_IHU)));
}
void babel_hton_ihu(struct babel_tlv_header *hdr)
{
  struct babel_tlv_ihu *tlv = (struct babel_tlv_ihu *)hdr;
  tlv->rxcost = htons(tlv->rxcost);
  tlv->interval = htons(tlv->interval);
}
void babel_ntoh_ihu(struct babel_tlv_header *hdr)
{
  struct babel_tlv_ihu *tlv = (struct babel_tlv_ihu *)hdr;
  tlv->rxcost = ntohs(tlv->rxcost);
  tlv->interval = ntohs(tlv->interval);
}
ip_addr babel_get_addr_ihu(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ihu *tlv = (struct babel_tlv_ihu *)hdr;
  struct babel_interface *bif = state->bif;
  if(tlv->ae == BABEL_AE_WILDCARD) {
    return bif->iface->addr->ip; /* FIXME: Correct? */
  } else if(tlv->ae == BABEL_AE_IP6_LL) {
    return get_ip6_ll(tlv->addr);
  }
  return IPA_NONE;
}
void babel_put_addr_ihu(struct babel_tlv_header *hdr, ip_addr addr)
{
  char buf[16];
  struct babel_tlv_ihu *tlv = (struct babel_tlv_ihu *)hdr;
  if(!ipa_is_link_local(addr)) {
    tlv->ae = BABEL_AE_WILDCARD;
    return;
  }
  put_ip6(buf,addr);
  memcpy(tlv->addr, buf+8, 8);
  tlv->ae = BABEL_AE_IP6_LL;
}
void babel_hton_router_id(struct babel_tlv_header *hdr)
{
  struct babel_tlv_router_id *tlv = (struct babel_tlv_router_id *)hdr;
  tlv->router_id = htobe64(tlv->router_id);
}
void babel_ntoh_router_id(struct babel_tlv_header *hdr)
{
  struct babel_tlv_router_id *tlv = (struct babel_tlv_router_id *)hdr;
  tlv->router_id = be64toh(tlv->router_id);
}
int babel_validate_next_hop(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_next_hop *tlv = (struct babel_tlv_next_hop *)hdr;
  /* We don't speak IPv4, so only recognise IP6 LL next hops */
  if(tlv->ae != BABEL_AE_IP6_LL) return 0;
  return babel_validate_length(hdr, state);
}
ip_addr babel_get_addr_next_hop(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_next_hop *tlv = (struct babel_tlv_next_hop *)hdr;
  return get_ip6_ll(tlv->addr);
}
void babel_put_addr_next_hop(struct babel_tlv_header *hdr, ip_addr addr)
{
}
int babel_validate_update(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_update *tlv = (struct babel_tlv_update *)hdr;
  int min_length = TLV_LENGTH(BABEL_TYPE_UPDATE)-sizeof(tlv->addr);
  u8 len = tlv->plen/8;
  if(tlv->plen % 8) len++;

  if(tlv->plen > MAX_PREFIX_LENGTH)
    return 0;

  if(hdr->length < min_length) return 0;
  if(tlv->ae == BABEL_AE_IP4   /* we don't speak IPv4 */
     || tlv->ae >= BABEL_AE_MAX) /* invalid */
     return 0;
  /* Can only omit bits if a previous update defined a prefix to take them from */
  if(tlv->omitted && ipa_equal(state->prefix, IPA_NONE))
    return 0;

  /* TLV should be large enough to old the entire prefix */
  if(hdr->length < min_length + len-tlv->omitted)
    return 0;

  return 1;
}
void babel_hton_update(struct babel_tlv_header *hdr)
{
  struct babel_tlv_update *tlv = (struct babel_tlv_update *)hdr;
  tlv->interval = htons(tlv->interval);
  tlv->seqno = htons(tlv->seqno);
  tlv->metric = htons(tlv->metric);
}
void babel_ntoh_update(struct babel_tlv_header *hdr)
{
  struct babel_tlv_update *tlv = (struct babel_tlv_update *)hdr;
  tlv->interval = ntohs(tlv->interval);
  tlv->seqno = ntohs(tlv->seqno);
  tlv->metric = ntohs(tlv->metric);
}
ip_addr babel_get_addr_update(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_update *tlv = (struct babel_tlv_update *)hdr;
  char buf[16] = {0};
  u8 len = tlv->plen/8;
  if(tlv->plen % 8) len++;

  /* fixed encodings */
  if(tlv->ae == BABEL_AE_WILDCARD) return IPA_NONE;
  if(tlv->ae == BABEL_AE_IP6_LL) return get_ip6_ll(tlv->addr);

  /* if we have omitted bytes, get them from previous prefix */
  if(tlv->omitted) put_ipa(buf, state->prefix);
  /* if the prefix is longer than the omitted octets, copy the rest */
  if(tlv->omitted < len) memcpy(buf+tlv->omitted, tlv->addr, len-tlv->omitted);
  /* make sure the tail is zeroed */
  if(len < 16) memset(buf+len, 0, 16-len);
  return get_ipa(buf);
}
void babel_put_addr_update(struct babel_tlv_header *hdr, ip_addr addr)
{
  struct babel_tlv_update *tlv = (struct babel_tlv_update *)hdr;
  tlv->ae = BABEL_AE_IP6;
  put_ipa(&tlv->addr, addr);
}
int babel_validate_request(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  /* Validates both seqno and route_request. Works because ae and plen fields
     are in the same place. */
  struct babel_tlv_route_request *tlv = (struct babel_tlv_route_request *)hdr;
  u8 len = tlv->plen/8;
  if(tlv->plen % 8) len++;

  if(tlv->plen > MAX_PREFIX_LENGTH)
    return 0;

  /* enough space to hold the prefix */
  if(hdr->length < TLV_LENGTH(hdr->type) - sizeof(tlv->addr) + len)
    return 0;
  /* wildcard requests must have plen 0 */
  if(tlv->ae == BABEL_AE_WILDCARD && tlv->plen > 0)
    return 0;

  /* We don't speak IPv4, and prefixes cannot be link-local addresses. */
  if(tlv->ae != BABEL_AE_IP6 && tlv->ae != BABEL_AE_WILDCARD)
    return 0;

  return 1;
}
ip_addr babel_get_addr_request(struct babel_tlv_header *hdr,
				     struct babel_parse_state *state)
{
  struct babel_tlv_route_request *tlv = (struct babel_tlv_route_request *)hdr;
  char buf[16] = {0};
  u8 len = tlv->plen/8;
  if(tlv->plen % 8) len++;

  /* fixed encoding */
  if(tlv->ae == BABEL_AE_WILDCARD) return IPA_NONE;
  if(hdr->type == BABEL_TYPE_SEQNO_REQUEST)
    memcpy(buf, ((struct babel_tlv_seqno_request *)tlv)->addr, len);
  else
    memcpy(buf, tlv->addr, len);
  return get_ipa(buf);
}
void babel_put_addr_request(struct babel_tlv_header *hdr, ip_addr addr)
{
  struct babel_tlv_route_request *tlv = (struct babel_tlv_route_request *)hdr;
  char buf[16] = {0};
  u8 len = tlv->plen/8;
  if(tlv->plen % 8) len++;
  put_ipa(buf, addr);
  memcpy(tlv->addr, buf, len);
}
void babel_hton_seqno_request(struct babel_tlv_header *hdr)
{
  struct babel_tlv_seqno_request *tlv = (struct babel_tlv_seqno_request *)hdr;
  tlv->seqno = htons(tlv->seqno);
  tlv->router_id = htobe64(tlv->router_id);
}
void babel_ntoh_seqno_request(struct babel_tlv_header *hdr)
{
  struct babel_tlv_seqno_request *tlv = (struct babel_tlv_seqno_request *)hdr;
  tlv->seqno = ntohs(tlv->seqno);
  tlv->router_id = be64toh(tlv->router_id);
}
static void babel_tlv_hton(struct babel_tlv_header *hdr)
{
  if(tlv_data[hdr->type].hton) {
    tlv_data[hdr->type].hton(hdr);
  }
}

static void babel_tlv_ntoh(struct babel_tlv_header *hdr)
{
  if(tlv_data[hdr->type].ntoh) {
    tlv_data[hdr->type].ntoh(hdr);
  }
}

static void babel_packet_hton(struct babel_header *hdr)
{
  struct babel_tlv_header *tlv = FIRST_TLV(hdr);
  int len = hdr->length+sizeof(struct babel_header);
  char *p = (char *)hdr;
  while((char *)tlv < p+len) {
    babel_tlv_hton(tlv);
    NEXT_TLV(tlv);
  }
  hdr->length = htons(hdr->length);
}

ip_addr babel_get_addr(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  if(tlv_data[hdr->type].get_addr) {
    return tlv_data[hdr->type].get_addr(hdr, state);
  }
  return IPA_NONE;
}
void babel_put_addr(struct babel_tlv_header *hdr, ip_addr addr)
{
  if(tlv_data[hdr->type].put_addr) {
    tlv_data[hdr->type].put_addr(hdr, addr);
  }
}

void babel_new_packet(struct babel_interface *bif)
{
  sock *s = bif->sock;
  struct babel_header *hdr = (void *) s->tbuf;
  memset(hdr, 0, sizeof(struct babel_header));
  hdr->magic = BABEL_MAGIC;
  hdr->version = BABEL_VERSION;
}

struct babel_tlv_header * babel_add_tlv(struct babel_interface *bif, u16 type)
{
  sock *s = bif->sock;
  struct babel_header *hdr = (void *) s->tbuf;
  struct babel_tlv_header *tlv;
  int len = tlv_data[type].struct_length;
  int pktlen = sizeof(struct babel_header)+hdr->length;
  if(pktlen+len > bif->max_pkt_len) {
    return NULL;
  }
  hdr->length+=len;
  tlv = (struct babel_tlv_header *)((char*)hdr+pktlen);
  memset(tlv, 0, len);
  tlv->type = type;
  tlv->length = TLV_LENGTH(type);
  return tlv;
}

void babel_send_to(struct babel_interface *bif, ip_addr dest)
{
  sock *s = bif->sock;
  struct babel_header *hdr = (void *) s->tbuf;
  int len = hdr->length+sizeof(struct babel_header);
  int done;

  babel_packet_hton(hdr);

  DBG( "Sending %d bytes to %I\n", len, dest);
  done = sk_send_to(s, len, dest, 0);
  if(!done)
    log(L_WARN "Babel: TX queue full on %s", bif->ifname);
}

void babel_send( struct babel_interface *bif )
{
  babel_send_to(bif, IP6_BABEL_ROUTERS);
}

int babel_process_packet(struct babel_header *pkt, int size,
			ip_addr saddr, int port, struct babel_interface *bif)
{
  struct babel_tlv_header *tlv = FIRST_TLV(pkt);
  struct proto *proto = bif->proto;
  struct babel_parse_state state = {
    .proto	  = proto,
    .bif	  = bif,
    .saddr	  = saddr,
    .prefix	  = IPA_NONE,
    .next_hop	  = saddr,
  };
  char *p = (char *)pkt;
  int res = 0;

  pkt->length = ntohs(pkt->length);
  if(pkt->magic != BABEL_MAGIC
     || pkt->version != BABEL_VERSION
     || pkt->length > size - sizeof(struct babel_header)) {
    DBG("Invalid packet: magic %d version %d length %d size %d\n",
	pkt->magic, pkt->version, pkt->length, size);
    return 1;
  }

  while((char *)tlv < p+size) {
    if(tlv->type > BABEL_TYPE_PADN
       && tlv->type < BABEL_TYPE_MAX
       && validate_tlv(tlv, &state)) {
      babel_tlv_ntoh(tlv);
      res &= tlv_data[tlv->type].handle(tlv, &state);
    } else {
      DBG("Unknown or invalid TLV of type %d\n",tlv->type);
    }
    NEXT_TLV(tlv);
  }
  if(state.needs_update)
    babel_send_update(bif);
  return res;
}

int babel_validate_length(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  /*DBG("Validate type: %d length: %d needed: %d\n", hdr->type, hdr->length,
    tlv_data[hdr->type].struct_length - sizeof(struct babel_tlv_header));*/
  return (hdr->length >= tlv_data[hdr->type].struct_length - sizeof(struct babel_tlv_header));
}
