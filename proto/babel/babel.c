/*
 *	The Babel protocol
 *
 *	Copyright (c) 2015 Toke Høiland-Jørgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *	Partly based on the RIP protocol module.
 *
 *	FIXME: Requires IPv6
 */

/**
 * DOC: The Babel protocol
 *
 *  Babel (RFC6126) is a loop-avoiding distance-vector routing protocol that is
 *  robust and efficient both in ordinary wired networks and in wireless mesh
 *  networks.
 */

#undef LOCAL_DEBUG
#define LOCAL_DEBUG 1

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/socket.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/timer.h"
#include "lib/string.h"

#include "babel.h"

#define P ((struct babel_proto *) p)
#define P_CF ((struct babel_proto_config *)p->cf)
#define FIRST_TLV(p) ((void *)(((char *) p) + sizeof(struct babel_header)))
#define NEXT_TLV(t) (t = (void *)((char *)t) + (t->type == BABEL_TYPE_PAD0 ? 1 : t->length))
#define TLV_SIZE(t) (t->type == BABEL_TYPE_PAD0 ? 1 : t->length + sizeof(struct babel_tlv_header))

#undef TRACE
#define TRACE(level, msg, args...) do { if (p->debug & level) { log(L_TRACE "%s: " msg, p->name , ## args); } } while(0)
#define BAD( x ) { log( L_REMOTE "%s: " x, p->name ); return 1; }




static struct babel_interface *new_iface(struct proto *p, struct iface *new,
					 unsigned long flags, struct iface_patt *patt);
static void babel_tx( sock *s );
static void babel_sendto( sock *s, ip_addr dest );


static int babel_handle_ack_req(struct babel_tlv_header *tlv, struct babel_parse_state *state);
static int babel_handle_ack(struct babel_tlv_header *tlv, struct babel_parse_state *state);
static int babel_handle_hello(struct babel_tlv_header *tlv, struct babel_parse_state *state);
static int babel_handle_ihu(struct babel_tlv_header *tlv, struct babel_parse_state *state);
static int babel_handle_router_id(struct babel_tlv_header *tlv, struct babel_parse_state *state);
static int babel_handle_next_hop(struct babel_tlv_header *tlv, struct babel_parse_state *state);
static int babel_handle_update(struct babel_tlv_header *tlv, struct babel_parse_state *state);
static int babel_handle_route_request(struct babel_tlv_header *tlv,
				      struct babel_parse_state *state);
static int babel_handle_seqno_request(struct babel_tlv_header *tlv,
				      struct babel_parse_state *state);

struct babel_tlv_callback {
  int (*handle)(struct babel_tlv_header *tlv,
		      struct babel_parse_state *state);
  void (*hton)(struct babel_tlv_header *tlv);
  void (*ntoh)(struct babel_tlv_header *tlv);
};

static struct babel_tlv_callback babel_tlv_callbacks[BABEL_TYPE_MAX] = {
  {NULL,NULL,NULL},
  {NULL,NULL,NULL},
  {babel_handle_ack_req, babel_hton_ack_req, babel_ntoh_ack_req},
  {babel_handle_ack, NULL, NULL},
  {babel_handle_hello, babel_hton_hello, babel_ntoh_hello},
  {babel_handle_ihu, babel_hton_ihu, babel_ntoh_ihu},
  {babel_handle_router_id, NULL, NULL},
  {babel_handle_next_hop, NULL, NULL},
  {babel_handle_update, babel_hton_update, babel_ntoh_update},
  {babel_handle_route_request, NULL, NULL},
  {babel_handle_seqno_request, babel_hton_seqno_request, babel_ntoh_seqno_request},
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
static void babel_tlv_hton(struct babel_tlv_header *hdr)
{
  if(babel_tlv_callbacks[hdr->type].hton) {
    babel_tlv_callbacks[hdr->type].hton(hdr);
  }
}

static void babel_tlv_ntoh(struct babel_tlv_header *hdr)
{
  if(babel_tlv_callbacks[hdr->type].ntoh) {
    babel_tlv_callbacks[hdr->type].ntoh(hdr);
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

static void copy_tlv(struct babel_tlv_header *dest, struct babel_tlv_header *src)
{
  memcpy(dest, src, TLV_SIZE(src));
}


static void babel_new_packet(sock *s, u16 len)
{
  struct babel_packet *pkt = (void *) s->tbuf;
  pkt->header.magic = BABEL_MAGIC;
  pkt->header.version = BABEL_VERSION;
  pkt->header.length = len;
  memset(pkt+sizeof(struct babel_header), 0, len);
}

static void babel_send_ack(sock *s, ip_addr dest, u16 nonce)
{
  DBG("Babel: Sending ACK to %I with nonce %d\n", dest, nonce);
  struct babel_tlv_ack *tlv;
  babel_new_packet(s, sizeof(struct babel_tlv_hello));
  tlv = FIRST_TLV(s->tbuf);
  tlv->header.type = BABEL_TYPE_ACK;
  tlv->header.length = TLV_LENGTH(struct babel_tlv_ack);
  tlv->nonce = nonce;

  babel_sendto(s, dest);
}

static void babel_send_hello(sock *s)
{
  DBG("Babel: Sending hello\n");
  struct babel_interface *bif = s->data;
  struct proto *p = bif->proto;
  struct babel_tlv_hello *tlv;
  babel_new_packet(s, sizeof(struct babel_tlv_hello));
  tlv = FIRST_TLV(s->tbuf);
  tlv->header.type = BABEL_TYPE_HELLO;
  tlv->header.length = TLV_LENGTH(struct babel_tlv_hello);
  tlv->seqno = bif->hello_seqno++;
  tlv->interval = P_CF->hello_interval*110;
  bif->last_hello = now;

  babel_tx(s);
}





static int babel_handle_ack_req(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ack_req *tlv = (struct babel_tlv_ack_req *)hdr;
  if(tlv->interval) {
    babel_send_ack(state->bif->sock, state->whotoldme, tlv->nonce);
  }
}
static int babel_handle_ack(struct babel_tlv_header *tlv, struct babel_parse_state *state)
{
}
static int babel_handle_hello(struct babel_tlv_header *tlv, struct babel_parse_state *state)
{
}
static int babel_handle_ihu(struct babel_tlv_header *tlv, struct babel_parse_state *state)
{
}
static int babel_handle_router_id(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_router_id *tlv = (struct babel_tlv_router_id *)hdr;
  state->router_id = tlv->router_id;
  return 0;
}
static int babel_handle_next_hop(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
}
static int babel_handle_update(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
}
static int babel_handle_route_request(struct babel_tlv_header *hdr,
				      struct babel_parse_state *state)
{
}
static int babel_handle_seqno_request(struct babel_tlv_header *hdr,
				      struct babel_parse_state *state)
{
}


static int
babel_process_packet(struct babel_header *pkt, int size,
		     ip_addr whotoldme, int port, struct babel_interface *bif)
{
  struct babel_tlv_header *tlv = FIRST_TLV(pkt);
  struct babel_parse_state state = {
    .whotoldme = whotoldme,
    .bif = bif,
  };
  char *p = (char *)pkt;
  int res = 0;
  while((char *)tlv < p+size) {
    if(tlv->type > BABEL_TYPE_PADN && tlv->type < BABEL_TYPE_MAX) {
      babel_tlv_ntoh(tlv);
      res += babel_tlv_callbacks[tlv->type].handle(tlv, &state);
    }
    NEXT_TLV(tlv);
  }
  return res;
}


/*
 * Interface to BIRD core
 */

/*
 * babel_start - initialize instance of babel
 */

static void babel_dump(struct proto *p)
{
}

static void babel_tx_err( sock *s, int err )
{
  //  struct babel_connection *c = ((struct babel_interface *)(s->data))->busy;
  //struct proto *p = c->proto;
  log( L_ERR ": Unexpected error at Babel transmit: %M", /*p->name,*/ err );
}

static void babel_tx( sock *s )
{
  struct babel_packet *pkt = (void *) s->tbuf;
  int len = pkt->header.length+sizeof(struct babel_header);
  int i = 0;

  babel_packet_hton(pkt);

  DBG( "Sending %d bytes from %I to %I\n", len, s->saddr, s->daddr );
  i = sk_send( s, len);
  if(i<0) babel_tx_err(s,i);
  return;
}

static void babel_sendto(sock *s, ip_addr dest)
{
  struct babel_interface *bif = s->data;
  struct proto *p = bif->proto;
  struct babel_packet *pkt = (void *) s->tbuf;
  int len = pkt->header.length+sizeof(struct babel_header);
  int i = 0;

  babel_packet_hton(pkt);

  DBG( "Sending %d bytes from %I to %I\n", len, s->saddr, dest);
  i = sk_send_to( s, len, dest, P_CF->port);
  if(i<0) babel_tx_err(s,i);
  return;
}

static int
babel_rx(sock *s, int size)
{
  struct babel_interface *i = s->data;
  struct proto *p = i->proto;
  if (! i->iface || s->lifindex != i->iface->index)
    return 1;

  DBG( "Babel: incoming packet: %d bytes from %I via %s\n", size, s->faddr, i->iface ? i->iface->name : "(dummy)" );
  if (size < sizeof(struct babel_header)) BAD( "Too small packet" );

  if (ipa_equal(i->iface->addr->ip, s->faddr)) {
    DBG("My own packet\n");
    return 1;
  }

  if (!ipa_is_link_local(s->faddr)) { BAD("Non-link local sender\n"); }

  babel_process_packet((struct babel_header *) s->rbuf, size, s->faddr, s->fport, i );
  return 1;
}

static struct babel_interface*
find_interface(struct proto *p, struct iface *what)
{
  struct babel_interface *i;

  WALK_LIST (i, P->interfaces)
    if (i->iface == what)
      return i;
  return NULL;
}

static void
kill_iface(struct babel_interface *i)
{
  DBG( "Babel: Interface %s disappeared\n", i->iface->name);
  rfree(i->sock);
  mb_free(i);
}



static void
babel_add_if(struct object_lock *lock)
{
  struct iface *iface = lock->iface;
  struct proto *p = lock->data;
  struct babel_interface *bif;
  struct iface_patt *k = iface_patt_find(&P_CF->iface_list, iface, iface->addr);
  DBG("adding interface %s\n", iface->name );
  bif = new_iface(p, iface, iface->flags, k);
  if (bif) {
    add_head( &P->interfaces, NODE bif );
    DBG("Adding object lock of %p for %p\n", lock, bif);
    bif->lock = lock;
    babel_send_hello(bif->sock);
  } else { rfree(lock); }
}



static void
babel_if_notify(struct proto *p, unsigned c, struct iface *iface)
{
  DBG("Babel: if notify\n");
  if (iface->flags & IF_IGNORE)
    return;
  if (c & IF_CHANGE_DOWN) {
    struct babel_interface *i;
    i = find_interface(p, iface);
    if (i) {
      rem_node(NODE i);
      rfree(i->lock);
      kill_iface(i);
    }
  }
  if (c & IF_CHANGE_UP) {
    struct iface_patt *k = iface_patt_find(&P_CF->iface_list, iface, iface->addr);
    struct object_lock *lock;

    /* we only speak multicast */
    if(!(iface->flags & IF_MULTICAST)) return;

    if (!k) return; /* We are not interested in this interface */

    lock = olock_new( p->pool );
    lock->addr = IP6_BABEL_ROUTERS;
    lock->port = P_CF->port;
    lock->iface = iface;
    lock->hook = babel_add_if;
    lock->data = p;
    lock->type = OBJLOCK_UDP;
    olock_acquire(lock);
  }

}

static struct babel_interface *new_iface(struct proto *p, struct iface *new,
					 unsigned long flags, struct iface_patt *patt)
{
  struct babel_interface * bif;
  struct babel_patt *PATT = (struct babel_patt *) patt;

  if(!new) return NULL;

  bif = mb_allocz(p->pool, sizeof( struct babel_interface ));
  bif->iface = new;
  bif->proto = p;
  bif->busy = NULL;
  if (PATT) {
    bif->metric = PATT->metric;
  }
  init_list(&bif->tlv_queue);
  bif->hello_seqno = 1;
  bif->last_hello = 0;

  bif->sock = sk_new( p->pool );
  bif->sock->type = SK_UDP;
  bif->sock->sport = P_CF->port;
  bif->sock->rx_hook = babel_rx;
  bif->sock->data =  bif;
  bif->sock->rbsize = 10240;
  bif->sock->iface = new;
  bif->sock->tbuf = mb_alloc( p->pool, new->mtu);
  bif->sock->tx_hook = babel_tx;
  bif->sock->err_hook = babel_tx_err;
  bif->sock->dport = P_CF->port;
  bif->sock->daddr = IP6_BABEL_ROUTERS;
  if (sk_open( bif->sock) < 0)
    goto err;
  if (sk_setup_multicast( bif->sock) < 0)
    goto err;
  if (sk_join_group( bif->sock,  bif->sock->daddr) < 0)
    goto err;
  TRACE(D_EVENTS, "Listening on %s, port %d, mode multicast (%I)",  bif->iface ?  bif->iface->name : "(dummy)", P_CF->port,  bif->sock->daddr );
  return bif;
 err:
  sk_log_error(bif->sock, p->name);
  log(L_ERR "%s: Cannot open socket for %s", p->name,  bif->iface ?  bif->iface->name : "(dummy)" );
  if ( bif->iface) {
    rfree( bif->sock);
    mb_free( bif);
    return NULL;
  }

  return bif;
}


static struct ea_list *
babel_gen_attrs(struct linpool *pool, int metric)
{
  struct ea_list *l = lp_alloc(pool, sizeof(struct ea_list) + 1*sizeof(eattr));

  l->next = NULL;
  l->flags = EALF_SORTED;
  l->count = 1;
  l->attrs[0].id = EA_BABEL_METRIC;
  l->attrs[0].flags = 0;
  l->attrs[0].type = EAF_TYPE_INT | EAF_TEMP;
  l->attrs[0].u.data = metric;
  return l;
}

static void
babel_timer(timer *t)
{
  DBG("Babel: tick tock\n");
}


static int
babel_import_control(struct proto *p, struct rte **rt, struct ea_list **attrs, struct linpool *pool)
{
  if ((*rt)->attrs->src->proto == p)	/* My own must not be touched */
    return 1;

  if ((*rt)->attrs->source != RTS_BABEL) {
    struct ea_list *new = babel_gen_attrs(pool, 1);
    new->next = *attrs;
    *attrs = new;
  }
  return 0;
}

static struct ea_list *
babel_make_tmp_attrs(struct rte *rt, struct linpool *pool)
{
}

static void
babel_store_tmp_attrs(struct rte *rt, struct ea_list *attrs)
{
}

/*
 * babel_rt_notify - core tells us about new route (possibly our
 * own), so store it into our data structures.
 */
static void
babel_rt_notify(struct proto *p, struct rtable *table UNUSED, struct network *net,
		struct rte *new, struct rte *old UNUSED, struct ea_list *attrs)
{
}

static int
babel_rte_same(struct rte *new, struct rte *old)
{
}


static int
babel_rte_better(struct rte *new, struct rte *old)
{
}

/*
 * babel_rte_insert - we maintain linked list of "our" entries in main
 * routing table, so that we can timeout them correctly. babel_timer()
 * walks the list.
 */
static void
babel_rte_insert(net *net UNUSED, rte *rte)
{
}

/*
 * babel_rte_remove - link list maintenance
 */
static void
babel_rte_remove(net *net UNUSED, rte *rte)
{
}

static struct proto *
babel_init(struct proto_config *cfg)
{
  struct proto *p = proto_new(cfg, sizeof(struct babel_proto));

  p->accept_ra_types = RA_OPTIMAL;
  p->if_notify = babel_if_notify;
  p->rt_notify = babel_rt_notify;
  p->import_control = babel_import_control;
  p->make_tmp_attrs = babel_make_tmp_attrs;
  p->store_tmp_attrs = babel_store_tmp_attrs;
  p->rte_better = babel_rte_better;
  p->rte_same = babel_rte_same;
  p->rte_insert = babel_rte_insert;
  p->rte_remove = babel_rte_remove;

  return p;
}

void
babel_init_config(struct babel_proto_config *c)
{
  init_list(&c->iface_list);
  c->port	= BABEL_PORT;
  c->hello_interval	= BABEL_HELLO_INTERVAL;
  c->update_interval	= BABEL_UPDATE_INTERVAL;
  c->update_seqno	= 1;
}

static void
babel_get_route_info(rte *rte, byte *buf, ea_list *attrs)
{
}


static int
babel_get_attr(eattr *a, byte *buf, int buflen UNUSED)
{
  switch (a->id) {
  case EA_BABEL_METRIC: bsprintf( buf, "metric: %d", a->u.data ); return GA_FULL;
  default: return GA_UNKNOWN;
  }
}

static int
babel_reconfigure(struct proto *p, struct proto_config *c)
{
}

static void
babel_copy_config(struct proto_config *dest, struct proto_config *src)
{
  /* Shallow copy of everything */
  proto_copy_rest(dest, src, sizeof(struct babel_proto_config));

  /* We clean up iface_list, ifaces are non-sharable */
  init_list(&((struct babel_proto_config *) dest)->iface_list);

}

static int
babel_start(struct proto *p)
{
  DBG( "Babel: starting instance...\n" );
  fib_init( &P->rtable, p->pool, sizeof( struct babel_entry ), 0, NULL );
  init_list( &P->connections );
  init_list( &P->interfaces );
  P->timer = tm_new( p->pool );
  P->timer->data = p;
  P->timer->recurrent = 1;
  P->timer->hook = babel_timer;
  tm_start( P->timer, 2 );
  P->last_update = 0;
  DBG( "Babel: ...done\n");
  return PS_UP;
}



struct protocol proto_babel = {
  .name =		"Babel",
  .template =		"babel%d",
  .attr_class =		EAP_BABEL,
  .preference =		DEF_PREF_BABEL,
  .config_size =	sizeof(struct babel_proto_config),
  .init =		babel_init,
  .dump =		babel_dump,
  .start =		babel_start,
  .reconfigure =	babel_reconfigure,
  .copy_config =	babel_copy_config,
  .get_route_info =	babel_get_route_info,
  .get_attr =		babel_get_attr
};
