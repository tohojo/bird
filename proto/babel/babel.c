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

#include "babel.h"

#define P ((struct babel_proto *) p)
#define P_CF ((struct babel_proto_config *)p->cf)

#undef TRACE
#define TRACE(level, msg, args...) do { if (p->debug & level) { log(L_TRACE "%s: " msg, p->name , ## args); } } while(0)
#define BAD( x ) { log( L_REMOTE "%s: " x, p->name ); return 1; }




static struct babel_interface *new_iface(struct proto *p, struct iface *new,
					 unsigned long flags, struct iface_patt *patt);
static void babel_send_ihus(struct babel_interface *bif);
static void babel_hello_expiry(timer *t);
static void babel_ihu_expiry(timer *t);
static void babel_dump_entry(struct babel_entry *e);

static struct babel_entry * babel_get_entry(struct proto *p, ip_addr prefix, u8 plen)
{
  struct babel_entry *e = fib_find(&P->rtable, &prefix, plen);
  if(e) return e;
  e = fib_get(&P->rtable, &prefix, plen);
  e->p = p;
  init_list(&e->sources);
  init_list(&e->routes);
  return e;
}

static struct babel_source * babel_find_source(struct babel_entry *e, u64 router_id)
{
  struct babel_source *s;
  WALK_LIST(s, e->sources)
    if(s->router_id == router_id)
      return s;
  return NULL;
}

static struct babel_source * babel_get_source(struct babel_entry *e, u64 router_id)
{
  struct babel_source *s = babel_find_source(e, router_id);
  if(!s) return s;
  s = mb_allocz(e->p->pool, sizeof(struct babel_source));
  s->router_id = router_id;
  s->e = e;
  add_tail(&e->sources, NODE s);
  return s;
}

static struct babel_route * babel_find_route(struct babel_entry *e, struct babel_neighbor *n)
{
  struct babel_route *r;
  WALK_LIST(r, e->routes)
    if(r->neigh == n)
      return r;
  return NULL;
}
static struct babel_route * babel_get_route(struct babel_entry *e, struct babel_neighbor *n)
{
  struct babel_route *r = babel_find_route(e,n);
  if(r) return r;
  r = mb_allocz(e->p->pool, sizeof(struct babel_route));
  r->neigh = n;
  r->e = e;
  add_tail(&e->routes, NODE r);
  return r;
}


static struct babel_neighbor * babel_find_neighbor(struct babel_interface *bif, ip_addr addr)
{
  struct proto *p = bif->proto;
  neighbor *n = neigh_find2(p, &addr, bif->iface, NEF_STICKY);
  return (n->data) ? n->data : NULL;
}

static struct babel_neighbor * babel_get_neighbor(struct babel_interface *bif, ip_addr addr)
{
  struct proto *p = bif->proto;
  neighbor *n = neigh_find2(p, &addr, bif->iface, NEF_STICKY);
  if (n->data) return n->data;

  struct babel_neighbor *bn = mb_allocz(bif->pool, sizeof(struct babel_neighbor));
  bn->bif = bif;
  bn->neigh = n;
  bn->addr = n->addr;
  bn->hello_timer = tm_new(bif->pool);
  bn->hello_timer->data = bn;
  bn->hello_timer->hook = babel_hello_expiry;
  bn->ihu_timer = tm_new(bif->pool);
  bn->ihu_timer->data = bn;
  bn->ihu_timer->hook = babel_ihu_expiry;
  n->data = bn;
  init_list(&bn->routes);
  add_tail(&bif->neigh_list, NODE bn);
  ev_schedule(bif->ihu_event);
  return bn;
}


static void babel_send_ack(struct babel_interface *bif, ip_addr dest, u16 nonce)
{
  struct proto *p = bif->proto;
  struct babel_tlv_ack *tlv;
  TRACE(D_PACKETS, "Babel: Sending ACK to %I with nonce %d\n", dest, nonce);
  tlv = BABEL_NEW_PACKET(bif, struct babel_tlv_ack);
  tlv->header.type = BABEL_TYPE_ACK;
  tlv->header.length = TLV_LENGTH(struct babel_tlv_ack);
  tlv->nonce = nonce;

  babel_send_to(bif, dest);
}

static u16 babel_compute_rxcost(struct babel_neighbor *bn)
{
  struct babel_interface *bif = bn->bif;
  u8 n, missed;
  u16 map=bn->hello_map;

  if(!map) return BABEL_INFINITY;
  for(n=1;map&=map-1;n++); // number of bits set
  missed = bn->hello_n-n;

  if(bif->type == BABEL_IFACE_TYPE_WIRED) {
    DBG("Missed %d hellos from %I\n", missed, bn->addr);
    // Link is bad if more than half the expected hellos were lost
    return (missed > 0 && n/missed < 2) ? BABEL_INFINITY : bif->rxcost;
  } else if(bif->type == BABEL_IFACE_TYPE_WIRELESS) {
    double beta;
    if(!missed) return BABEL_RXCOST_WIRELESS;
    beta = 1-missed/bn->hello_n;
    return (beta > 0) ? BABEL_RXCOST_WIRELESS/beta : BABEL_RXCOST_WIRELESS;
  }
}

static u16 compute_cost(struct babel_neighbor *bn)
{
  struct babel_interface *bif = bn->bif;
  u16 rxcost = babel_compute_rxcost(bn);
  if(bif->type == BABEL_IFACE_TYPE_WIRED) {
    return (rxcost == BABEL_INFINITY) ? rxcost : bn->txcost;
  } else if(bif->type == BABEL_IFACE_TYPE_WIRELESS) {
    return (MAX(bn->txcost, 256) * rxcost)/256;
  }
}



static u16 compute_metric(struct babel_neighbor *bn, u16 metric)
{
  u16 cost = compute_cost(bn);
  return (cost == BABEL_INFINITY) ? cost : cost+metric;
}



static void babel_add_ihu(struct babel_interface *bif, struct babel_neighbor *bn)
{
  struct babel_tlv_ihu *tlv;
  tlv = BABEL_ADD_TLV_SEND(bif, struct babel_tlv_ihu, IPA_NONE);
  tlv->header.type = BABEL_TYPE_IHU;
  tlv->header.length = TLV_LENGTH(struct babel_tlv_ihu);
  babel_put_addr_ihu(&tlv->header, bn->addr);
  tlv->rxcost = babel_compute_rxcost(bn);
  tlv->interval = bif->ihu_interval*100;
}

static void babel_add_ihus(struct babel_interface *bif)
{
  struct babel_neighbor *bn;
  WALK_LIST(bn, bif->neigh_list)
    babel_add_ihu(bif,bn);
}

static void babel_send_ihus(struct babel_interface *bif)
{
  struct proto *p = bif->proto;
  TRACE(D_PACKETS, "Babel: Sending IHUs");
  babel_new_packet(bif, 0);
  babel_add_ihus(bif);
  babel_send(bif);
}

static void babel_send_hello(struct babel_interface *bif, u8 send_ihu)
{
  struct proto *p = bif->proto;
  struct babel_tlv_hello *tlv;
  TRACE(D_PACKETS, "Babel: Sending hello");
  tlv = BABEL_NEW_PACKET(bif, struct babel_tlv_hello);
  tlv->header.type = BABEL_TYPE_HELLO;
  tlv->header.length = TLV_LENGTH(struct babel_tlv_hello);
  tlv->seqno = bif->hello_seqno++;
  tlv->interval = bif->hello_interval*100;

  if(send_ihu) babel_add_ihus(bif);

  babel_send(bif);
}

static void babel_hello_timer(timer *t)
{
  struct babel_interface *bif = t->data;
  struct proto *p = bif->proto;
  TRACE(D_EVENTS, "Babel: Hello timer fired for interface %s", bif->ifname);
  babel_send_hello(bif, (bif->type == BABEL_IFACE_TYPE_WIRELESS
			 || bif->hello_seqno % BABEL_IHU_INTERVAL_FACTOR == 0));
  tm_start(t, bif->hello_interval);
}


static void babel_update_timer(timer *t)
{
  struct babel_interface *bif = t->data;
}


int babel_handle_ack_req(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ack_req *tlv = (struct babel_tlv_ack_req *)hdr;
  struct proto *p = state->proto;
  TRACE(D_PACKETS, "Received ACK req nonce %d interval %d", tlv->nonce, tlv->interval);
  if(tlv->interval) {
    babel_send_ack(state->bif, state->saddr, tlv->nonce);
  }
  return 1;
}

int babel_handle_ack(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ack *tlv = (struct babel_tlv_ack *)hdr;
  struct proto *p = state->proto;
  TRACE(D_PACKETS, "Received ACK nonce %d", tlv->nonce);
}

static void babel_flush_neighbor(struct babel_neighbor *bn)
{
  struct proto *p = bn->bif->proto;
  TRACE(D_EVENTS, "Flushing neighbor %I", bn->addr);
  tm_stop(bn->hello_timer);
  tm_stop(bn->ihu_timer);
  rfree(bn->hello_timer);
  rfree(bn->ihu_timer);
  rem_node(NODE bn);
  bn->neigh->data = NULL;
  mb_free(bn);
}

static void babel_hello_expiry(timer *t)
{
  struct babel_neighbor *bn = t->data;
  bn->hello_map <<= 1;
  if(bn->hello_n < 16) bn->hello_n++;
  if(!bn->hello_map) {
    babel_flush_neighbor(bn);
  }
}

static void babel_ihu_expiry(timer *t)
{
  struct babel_neighbor *bn = t->data;
  bn->txcost = BABEL_INFINITY;
}


/* update hello history according to Appendix A1 of the RFC */
static void update_hello_history(struct babel_neighbor *bn, u16 seqno, u16 interval)
{
  if(seqno - bn->next_hello_seqno > 16 || bn->next_hello_seqno - seqno > 16) {
    /* note state reset - flush entries */
    bn->hello_map = bn->hello_n = 0;
  } else if(seqno < bn->next_hello_seqno) {
    u8 diff = bn->next_hello_seqno - seqno;
    /* sending node increased interval; reverse history */
    bn->hello_map >>= diff;
    bn->hello_n -= MAX(bn->hello_n-diff, 0);
  } else if(seqno > bn->next_hello_seqno) {
    u8 diff = seqno - bn->next_hello_seqno;
    /* sending node decreased interval; fast-forward */
    bn->hello_map <<= seqno - bn->next_hello_seqno;
    bn->hello_n = MIN(bn->hello_n+diff, 16);
  }
  /* current entry */
  bn->hello_map = (bn->hello_map << 1) | 1;
  if(bn->hello_n < 16) bn->hello_n++;
  tm_start(bn->hello_timer, (1.5*interval)/100);
}


int babel_handle_hello(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_hello *tlv = (struct babel_tlv_hello *)hdr;
  struct proto *p = state->proto;
  struct babel_interface *bif = state->bif;
  struct babel_neighbor *bn = babel_get_neighbor(bif, state->saddr);
  TRACE(D_PACKETS, "Handling hello seqno %d interval %d", tlv->seqno,
	tlv->interval, state->saddr);
  update_hello_history(bn, tlv->seqno, tlv->interval);
  return 1;
}

int babel_handle_ihu(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ihu *tlv = (struct babel_tlv_ihu *)hdr;
  struct proto *p = state->proto;
  struct babel_interface *bif = state->bif;
  ip_addr addr = babel_get_addr(hdr, state);

  if(!ipa_equal(addr, bif->iface->addr->ip)) return 0; // not for us
  TRACE(D_PACKETS, "Handling IHU rxcost %d interval %d", tlv->rxcost,
	tlv->interval);
  struct babel_neighbor *bn = babel_get_neighbor(bif, state->saddr);
  bn->txcost = tlv->rxcost;
  tm_start(bn->ihu_timer, 1.5*(tlv->interval/100));
  return 1;
}

int babel_handle_router_id(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_router_id *tlv = (struct babel_tlv_router_id *)hdr;
  struct proto *p = state->proto;
  state->router_id = tlv->router_id;
  TRACE(D_PACKETS, "Handling router ID %016lx", state->router_id);
  return 1;
}

int babel_handle_next_hop(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_next_hop *tlv = (struct babel_tlv_next_hop *)hdr;
  state->next_hop = babel_get_addr(hdr, state);
  return 1;
}

/**
   From the RFC (section 3.5.1):

   a route advertisement carrying the quintuple (prefix, plen, router-id, seqno,
   metric) is feasible if one of the following conditions holds:

   - metric is infinite; or

   - no entry exists in the source table indexed by (id, prefix, plen); or

   - an entry (prefix, plen, router-id, seqno', metric') exists in the source
     table, and either

     - seqno' < seqno or
     - seqno = seqno' and metric < metric'.
*/
static inline int is_feasible(struct babel_source *s, u16 seqno, u16 metric)
{
  if(!s || metric == BABEL_INFINITY) return 1;
  return (seqno > s->seqno
	  || (seqno == s->seqno && metric < s->metric));
}

int babel_handle_update(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_update *tlv = (struct babel_tlv_update *)hdr;
  struct babel_interface *bif = state->bif;
  struct proto *p = state->proto;
  struct babel_neighbor *n;
  struct babel_entry *e;
  struct babel_source *s;
  struct babel_route *r;
  ip_addr prefix = babel_get_addr(hdr, state);
  TRACE(D_PACKETS, "Handling update for %I/%d with seqno %d metric %d",
	prefix, tlv->plen, tlv->seqno, tlv->metric);
  if(tlv->flags & BABEL_FLAG_DEF_PREFIX) {
    state->prefix = prefix;
  }
  if(tlv->flags & BABEL_FLAG_ROUTER_ID) {
    u64 *buf = (u64*)&prefix;
    memcpy(&state->router_id, buf+1, sizeof(u64));
  }
  n = babel_find_neighbor(bif, state->saddr);
  if(!n) {
    DBG("Haven't heard from neighbor %I; ignoring update.\n", state->saddr);
    return 0;
  }

  /* RFC section 3.5.4:

     When a Babel node receives an update (id, prefix, seqno, metric) from a
     neighbour neigh with a link cost value equal to cost, it checks whether it
     already has a routing table entry indexed by (neigh, id, prefix).

     If no such entry exists:

     o if the update is unfeasible, it is ignored;

     o if the metric is infinite (the update is a retraction), the update is
       ignored;

     o otherwise, a new route table entry is created, indexed by (neigh, id,
       prefix), with seqno equal to seqno and an advertised metric equal to the
       metric carried by the update.

     If such an entry exists:

     o if the entry is currently installed and the update is unfeasible, then
       the behaviour depends on whether the router-ids of the two entries match.
       If the router-ids are different, the update is treated as though it were
       a retraction (i.e., as though the metric were FFFF hexadecimal). If the
       router-ids are equal, the update is ignored;

     o otherwise (i.e., if either the update is feasible or the entry is not
       currently installed), then the entry's sequence number, advertised
       metric, metric, and router-id are updated and, unless the advertised
       metric is infinite, the route's expiry timer is reset to a small multiple
       of the Interval value included in the update.

*/
  e = babel_get_entry(p, prefix, tlv->plen);

  s = babel_find_source(e, state->router_id); /* for feasibility */
  r = babel_find_route(e, n); /* the route entry indexed by neighbour */

  if(!r) {

    if(!is_feasible(s, tlv->seqno, tlv->metric))
      return 0; /* first two points above. is_feasible also returns false if the
		   metric is infinite */

    r = babel_get_route(e, n);
    r->advert_metric = tlv->metric;
    r->source = s;
    r->metric = compute_metric(n, tlv->metric);
    r->next_hop = state->next_hop;
    r->updated = now;
  } else if(r->flags & BABEL_FLAG_SELECTED
       && !is_feasible(s, tlv->seqno, tlv->metric)) {

    /* route is installed and update is infeasible - check router id */

    if(state->router_id == s->router_id) return 0;
    r->metric = BABEL_INFINITY; /* retraction */
  } else {
    /* last point above - update entry */
    r->seqno = tlv->seqno;
    r->advert_metric = tlv->metric;
    r->metric = compute_metric(n, tlv->metric);
    r->source = s;
    r->next_hop = state->next_hop;
    if(tlv->metric != BABEL_INFINITY) r->expiry = now + (BABEL_EXPIRY_FACTOR*tlv->interval)/100;
  }
  babel_dump_entry(e);
}

int babel_handle_route_request(struct babel_tlv_header *hdr,
				      struct babel_parse_state *state)
{
}

int babel_handle_seqno_request(struct babel_tlv_header *hdr,
				      struct babel_parse_state *state)
{
}



/*
 * Interface to BIRD core
 */

/*
 * babel_start - initialize instance of babel
 */

static void babel_dump_source(struct babel_source *s)
{
  debug("Babel: Source router_id %0lx seqno %d metric %d\n",
	s->router_id, s->seqno, s->metric);
}

static void babel_dump_route(struct babel_route *r)
{
  debug("Babel: Route neigh %I seqno %d advert_metric %d metric %d router_id %0lx flags %d\n",
	r->neigh->addr, r->seqno, r->advert_metric,
	r->metric, r->source->router_id, r->flags);
}

static void babel_dump_entry(struct babel_entry *e)
{
  debug("Babel: Entry %I/%d:\n", e->n.prefix, e->n.pxlen);
  struct babel_souce *s; struct babel_route *r;
  WALK_LIST(s,e->sources) { debug(" "); babel_dump_source(s); }
  WALK_LIST(r,e->routes) { debug(" "); babel_dump_route(r); }
}

static void babel_dump(struct proto *p)
{
}

static void babel_tx_err( sock *s, int err )
{
  log( L_ERR ": Unexpected error at Babel transmit: %M", /*p->name,*/ err );
}


static int
babel_rx(sock *s, int size)
{
  struct babel_interface *bif = s->data;
  struct proto *p = bif->proto;
  if (! bif->iface || s->lifindex != bif->iface->index)
    return 1;

  DBG( "Babel: incoming packet: %d bytes from %I via %s\n", size, s->faddr, bif->iface ? bif->iface->name : "(dummy)" );
  if (size < sizeof(struct babel_header)) BAD( "Too small packet" );

  if (ipa_equal(bif->iface->addr->ip, s->faddr)) {
    DBG("My own packet\n");
    return 1;
  }

  if (!ipa_is_link_local(s->faddr)) { BAD("Non-link local sender"); }

  babel_process_packet((struct babel_header *) s->rbuf, size, s->faddr, s->fport, bif );
  return 1;
}

static struct babel_interface*
find_interface(struct proto *p, struct iface *what)
{
  struct babel_interface *bif;

  WALK_LIST (bif, P->interfaces)
    if (bif->iface == what)
      return bif;
  return NULL;
}

static void
kill_iface(struct babel_interface *bif)
{
  DBG( "Babel: Interface %s disappeared\n", bif->iface->name);
  struct babel_neighbor *bn;
  WALK_LIST(bn, bif->neigh_list)
    babel_flush_neighbor(bn);
  rfree(bif->pool);
  mb_free(bif);
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
    babel_send_hello(bif,0);
  } else { rfree(lock); }
}



static void
babel_if_notify(struct proto *p, unsigned c, struct iface *iface)
{
  DBG("Babel: if notify\n");
  if (iface->flags & IF_IGNORE)
    return;
  if (c & IF_CHANGE_DOWN) {
    struct babel_interface *bif;
    bif = find_interface(p, iface);
    if (bif) {
      rem_node(NODE bif);
      rfree(bif->lock);
      kill_iface(bif);
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
  bif->pool = rp_new(p->pool, bif->ifname);
  bif->iface = new;
  bif->ifname = new->name;
  bif->proto = p;
  if (PATT) {
    bif->rxcost = PATT->rxcost;
    bif->type = PATT->type;

    if(bif->type == BABEL_IFACE_TYPE_WIRED) {
      bif->hello_interval = BABEL_HELLO_INTERVAL_WIRED;
      bif->rxcost = BABEL_RXCOST_WIRED;
    } else if(bif->type == BABEL_IFACE_TYPE_WIRELESS) {
      bif->hello_interval = BABEL_HELLO_INTERVAL_WIRELESS;
      bif->rxcost = BABEL_RXCOST_WIRELESS;
    }
    if(PATT->hello_interval < BABEL_INFINITY) {
      bif->hello_interval = PATT->hello_interval;
    }
    if(PATT->rxcost < BABEL_INFINITY) {
      bif->rxcost = PATT->rxcost;
    }
    if(PATT->update_interval < BABEL_INFINITY) {
      bif->update_interval = PATT->update_interval;
    } else {
      bif->update_interval = bif->hello_interval*BABEL_UPDATE_INTERVAL_FACTOR;
    }
    bif->ihu_interval = bif->hello_interval*BABEL_IHU_INTERVAL_FACTOR;
  }
  init_list(&bif->tlv_queue);
  init_list(&bif->neigh_list);
  bif->hello_seqno = 1;
  bif->max_pkt_len = new->mtu - BABEL_OVERHEAD;

  bif->ihu_event = ev_new(bif->pool);
  bif->ihu_event->hook = babel_send_ihus;
  bif->ihu_event->data = bif;


  bif->hello_timer = tm_new(bif->pool);
  bif->hello_timer->hook = babel_hello_timer;
  bif->hello_timer->data = bif;

  bif->update_timer = tm_new(bif->pool);
  bif->update_timer->hook = babel_update_timer;
  bif->update_timer->data = bif;

  bif->sock = sk_new( bif->pool );
  bif->sock->type = SK_UDP;
  bif->sock->sport = P_CF->port;
  bif->sock->rx_hook = babel_rx;
  bif->sock->data =  bif;
  bif->sock->rbsize = 10240;
  bif->sock->iface = new;
  bif->sock->tbuf = mb_alloc( bif->pool, new->mtu);
  bif->sock->err_hook = babel_tx_err;
  bif->sock->dport = P_CF->port;
  bif->sock->daddr = IP6_BABEL_ROUTERS;

  bif->sock->tos = PATT->tx_tos;
  bif->sock->priority = PATT->tx_priority;
  bif->sock->flags = SKF_LADDR_RX;
  if (sk_open( bif->sock) < 0)
    goto err;
  if (sk_setup_multicast( bif->sock) < 0)
    goto err;
  if (sk_join_group( bif->sock,  bif->sock->daddr) < 0)
    goto err;
  TRACE(D_EVENTS, "Listening on %s, port %d, mode multicast (%I)",  bif->iface ?  bif->iface->name : "(dummy)", P_CF->port,  bif->sock->daddr );

  tm_start(bif->hello_timer, bif->hello_interval);
  tm_start(bif->update_timer, bif->update_interval);

  return bif;
 err:
  sk_log_error(bif->sock, p->name);
  log(L_ERR "%s: Cannot open socket for %s", p->name,  bif->iface ?  bif->iface->name : "(dummy)" );
  if (bif->iface) {
    rfree(bif->pool);
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
  struct babel_entry *e;


}

static void babel_neigh_notify(neighbor *n)
{
  struct proto *p = n->proto;
  struct babel_neighbor *bn = n->data;
  if(n->scope <= 0) {
    TRACE(D_EVENTS, "Babel: Neighbor lost");
  } else {
    TRACE(D_EVENTS, "Babel: Neighbor ready");
  }
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
  p->neigh_notify = babel_neigh_notify;
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
  P->update_seqno = 1;
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
