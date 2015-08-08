/**
 * packet.c
 *
 * Toke Høiland-Jørgensen
 * 2015-08-07
 */

#include "babel.h"

#define FIRST_TLV(p) ((struct babel_tlv_header *)(((char *) p) + sizeof(struct babel_header)))
#define NEXT_TLV(t) (t = (void *)((char *)t) + (t->type == BABEL_TYPE_PAD0 ? 1 : t->length))
#define TLV_SIZE(t) (t->type == BABEL_TYPE_PAD0 ? 1 : t->length + sizeof(struct babel_tlv_header))


struct babel_tlv_data {
  int struct_length;
  int (*handle)(struct babel_tlv_header *tlv,
		      struct babel_parse_state *state);
  int (*validate)(struct babel_tlv_header *tlv);
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
   NULL, NULL,
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
   babel_handle_route_request, babel_validate_route_request,
   NULL, NULL,
   babel_get_addr_route_request, babel_put_addr_route_request},
  {sizeof(struct babel_tlv_seqno_request),
   babel_handle_seqno_request, babel_validate_seqno_request,
   babel_hton_seqno_request, babel_ntoh_seqno_request,
   babel_get_addr_seqno_request, babel_put_addr_seqno_request},
};

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
    return ip6_or(ipa_build6(0xfe800000,0,0,0),
		  ipa_build6(0,0,ntohl(tlv->addr[0]),ntohl(tlv->addr[1])));
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
ip_addr babel_get_addr_next_hop(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
}
void babel_put_addr_next_hop(struct babel_tlv_header *hdr, ip_addr addr)
{
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
}
void babel_put_addr_update(struct babel_tlv_header *hdr, ip_addr addr)
{
}
ip_addr babel_get_addr_route_request(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
}
void babel_put_addr_route_request(struct babel_tlv_header *hdr, ip_addr addr)
{
}
void babel_hton_seqno_request(struct babel_tlv_header *hdr)
{
  struct babel_tlv_seqno_request *tlv = (struct babel_tlv_seqno_request *)hdr;
  tlv->seqno = htons(tlv->seqno);
}
void babel_ntoh_seqno_request(struct babel_tlv_header *hdr)
{
  struct babel_tlv_seqno_request *tlv = (struct babel_tlv_seqno_request *)hdr;
  tlv->seqno = ntohs(tlv->seqno);
}
ip_addr babel_get_addr_seqno_request(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
}
void babel_put_addr_seqno_request(struct babel_tlv_header *hdr, ip_addr addr)
{
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

static void babel_packet_hton(struct babel_packet *pkt)
{
  struct babel_tlv_header *tlv = FIRST_TLV(pkt);
  int len = pkt->header.length+sizeof(struct babel_header);
  char *p = (char *)pkt;
  while((char *)tlv < p+len) {
    babel_tlv_hton(tlv);
    NEXT_TLV(tlv);
  }
  pkt->header.length = htons(pkt->header.length);
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


static void copy_tlv(struct babel_tlv_header *dest, struct babel_tlv_header *src)
{
  memcpy(dest, src, TLV_SIZE(src));
}


struct babel_tlv_header * babel_new_packet(struct babel_interface *bif, u16 len)
{
  sock *s = bif->sock;
  struct babel_header *hdr = (void *) s->tbuf;
  memset(hdr, 0, sizeof(struct babel_header)+len);
  hdr->magic = BABEL_MAGIC;
  hdr->version = BABEL_VERSION;
  hdr->length = len;
  return FIRST_TLV(hdr);
}

struct babel_tlv_header * babel_add_tlv(struct babel_interface *bif, u16 len)
{
  sock *s = bif->sock;
  struct babel_header *hdr = (void *) s->tbuf;
  struct babel_tlv_header *tlv;
  int pktlen = sizeof(struct babel_header)+hdr->length;
  if(pktlen+len > bif->max_pkt_len) {
    return NULL;
  }
  hdr->length+=len;
  tlv = (struct babel_tlv_header *)((char*)hdr+pktlen);
  memset(tlv, 0, len);
  return tlv;
}

struct babel_tlv_header * babel_add_tlv_send(struct babel_interface *bif, u16 len, ip_addr dest)
{
  struct babel_tlv_header *tlv = babel_add_tlv(bif, len);
  if(!tlv) {
    if(ipa_equal(dest, IPA_NONE)) {
      babel_send(bif);
    } else {
      babel_send_to(bif, dest);
    }
    tlv = babel_new_packet(bif, len);
  }
  return tlv;
}

void babel_send_to(struct babel_interface *bif, ip_addr dest)
{
  sock *s = bif->sock;
  struct babel_packet *pkt = (void *) s->tbuf;
  int len = pkt->header.length+sizeof(struct babel_header);
  int done;

  babel_packet_hton(pkt);

  DBG( "Sending %d bytes from %I to %I\n", len, s->saddr, dest);
  done = sk_send_to( s, len, dest, 0);
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
  struct babel_parse_state state = {
    .saddr = saddr,
    .bif = bif,
  };
  char *p = (char *)pkt;
  int res = 0;
  while((char *)tlv < p+size) {
    if(tlv->type > BABEL_TYPE_PADN
       && tlv->type < BABEL_TYPE_MAX
       && tlv_data[tlv->type].validate(tlv)) {
      babel_tlv_ntoh(tlv);
      res += tlv_data[tlv->type].handle(tlv, &state);
    }
    NEXT_TLV(tlv);
  }
  return res;
}

int babel_validate_length(struct babel_tlv_header *hdr)
{
  return (hdr->length >= tlv_data[hdr->type].struct_length);
}
