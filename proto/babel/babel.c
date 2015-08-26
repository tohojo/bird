/*  -*- c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 *	The Babel protocol
 *
 *	Copyright (c) 2015 Toke Høiland-Jørgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the main routines for handling and sending TLVs, as
 *	well as timers and interaction with the nest.
 */

/**
 * DOC: The Babel protocol
 *
 * Babel (RFC6126) is a loop-avoiding distance-vector routing protocol that is
 * robust and efficient both in ordinary wired networks and in wireless mesh
 * networks.
 *
 * The Babel protocol keeps state for each neighbour in a &babel_neighbor
 * struct, tracking received hellos and I Heard You (IHU) messages. A
 * &babel_interface struct keeps hello and update timers for each interface, and
 * a separate hello seqno is maintained for each interface.
 *
 * For each prefix, Babel keeps track of both the possible routes
 * (with next hop and router IDs), as well as the feasibility distance for each
 * prefix and router id. The prefix itself is tracked in a &babel_entry struct,
 * while the possible routes for the prefix are tracked as &babel_route entries
 * and the feasibility distance is maintained through &babel_source structures.
 *
 * The main route selection is done in babel_select_route(). This is called when
 * an update for a prefix is received, when a new prefix is received from the
 * nest, and when a prefix expiry timer fires. It performs feasibility checks on
 * the available routes for the prefix and selects the one with the lowest
 * metric.
 */

#undef LOCAL_DEBUG
#define LOCAL_DEBUG 1

#include "babel.h"


#undef TRACE
#define TRACE(level, msg, args...) do { if (p->p.debug & level) { log(L_TRACE "%s: " msg, p->p.name , ## args); } } while(0)
#define BAD( x ) { log( L_REMOTE "%s: " x, p->p.name ); return 1; }

/* computes a-b % 65535 for u16 datatypes */
static inline u16 diff_mod64k(u16 a, u16 b)
{
  return a >= b ? a-b : 0xffff-b+a;
}
/* Is one number larger than another mod 65535? Since diff_mod64k is always >=
   0, just use a simple cutoff value to determine if the difference is small
   enough that one is really larger. Since these comparisons are only made for
   values that should not differ by more than a few numbers, this should be
   safe.*/
static inline u16 ge_mod64k(u16 a, u16 b)
{
  return diff_mod64k(a,b) < 0xfff0;
}

static void babel_new_interface(struct babel_proto *p, struct iface *new,
                                unsigned long flags, struct iface_patt *patt);
static void expire_hello(struct babel_neighbor *bn);
static void expire_ihu(struct babel_neighbor *bn);
static void expire_sources(struct babel_entry *e);
static void expire_route(struct babel_route *r);
static void refresh_route(struct babel_route *r);
static void babel_dump_entry(struct babel_entry *e);
static void babel_dump_route(struct babel_route *r);
static void babel_select_route(struct babel_entry *e);
static void babel_send_route_request(struct babel_entry *e, struct babel_neighbor *n);
static int cache_seqno_request(struct babel_proto *p, ip_addr prefix, u8 plen,
			       u64 router_id, u16 seqno);


static void babel_init_entry(struct fib_node *n)
{
  struct babel_entry *e = (struct babel_entry *)n;
  e->proto = NULL;
  e->selected = NULL;
  init_list(&e->sources);
  init_list(&e->routes);
}


static inline struct babel_entry * babel_find_entry(struct babel_proto *p, ip_addr prefix, u8 plen)
{
  return fib_find(&p->rtable, &prefix, plen);
}
static struct babel_entry * babel_get_entry(struct babel_proto *p, ip_addr prefix, u8 plen)
{
  struct babel_entry *e = babel_find_entry(p, prefix, plen);
  if(e) return e;
  e = fib_get(&p->rtable, &prefix, plen);
  e->proto = p;
  return e;
}

void babel_flush_entry(struct babel_entry *e)
{
  struct babel_proto *p = e->proto;
  TRACE(D_EVENTS, "Flushing entry %I/%d", e->n.prefix, e->n.pxlen);
  rem_node(&e->garbage_node);
  if(p) fib_delete(&p->rtable, e);
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
  struct babel_proto *p = e->proto;
  struct babel_source *s = babel_find_source(e, router_id);
  if(s) return s;
  s = sl_alloc(p->source_slab);
  s->router_id = router_id;
  s->expires = now + BABEL_GARBAGE_INTERVAL;
  s->e = e;
  s->seqno = 0;
  s->metric = BABEL_INFINITY;
  add_tail(&e->sources, NODE s);
  return s;
}

static void expire_sources(struct babel_entry *e)
{
  struct babel_proto *p = e->proto;
  struct babel_source *n, *nx;
  WALK_LIST_DELSAFE(n, nx, e->sources) {
    if(n->expires && n->expires <= now) {
      rem_node(NODE n);
      sl_free(p->source_slab, n);
    }
  }
  if(EMPTY_LIST(e->sources) && EMPTY_LIST(e->routes))
    add_tail(&p->garbage, &e->garbage_node); /* to be removed later */
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
  struct babel_proto *p = e->proto;
  struct babel_route *r = babel_find_route(e,n);
  if(r) return r;
  r = sl_alloc(p->route_slab);
  memset(r, 0, sizeof(*r));
  r->neigh = n;
  r->e = e;
  if(n)
    r->expires = now + BABEL_GARBAGE_INTERVAL; /* default until we get updates to set expiry time */
  add_tail(&e->routes, NODE r);
  if(n) add_tail(&n->routes, NODE &r->neigh_route);
  return r;
}

static void babel_flush_route(struct babel_route *r)
{
  struct babel_proto *p = r->e->proto;
  DBG("Flush route %I/%d router_id %0lx neigh %I\n",
      r->e->n.prefix, r->e->n.pxlen, r->router_id, r->neigh ? r->neigh->addr : IPA_NONE);
  rem_node(NODE r);
  if(r->neigh) rem_node(&r->neigh_route);
  if(r->e->selected == r) r->e->selected = NULL;
  sl_free(p->route_slab, r);
}
static void expire_route(struct babel_route *r)
{
  struct babel_entry *e = r->e;
  struct babel_proto *p = r->e->proto;
  TRACE(D_EVENTS, "Route expiry timer for %I/%d router_id %0lx fired",
	r->e->n.prefix, r->e->n.pxlen, r->router_id);
  if(r->metric < BABEL_INFINITY) {
    r->metric = BABEL_INFINITY;
    r->expires = now + r->expiry_interval;
  } else {
    babel_flush_route(r);
  }

  babel_select_route(e);
}

static void refresh_route(struct babel_route *r)
{
  if(!r->neigh || r != r->e->selected) return;
  babel_send_route_request(r->e, r->neigh);
}

static void babel_expire_routes(struct babel_proto *p)
{
  struct babel_entry *e;
  struct babel_route *r, *rx;
  node *n;
  FIB_WALK(&p->rtable, n) {
    e = (struct babel_entry *)n;
    WALK_LIST_DELSAFE(r, rx, e->routes) {
      if(r->refresh_time && r->refresh_time <= now) {
        refresh_route(r);
        r->refresh_time = 0;
      }
      if(r->expires && r->expires <= now)
        expire_route(r);
    }
    expire_sources(e);
  } FIB_WALK_END;
  WALK_LIST_FIRST(n, p->garbage) {
    e = SKIP_BACK(struct babel_entry, garbage_node, n);
    babel_flush_entry(e);
  }
}

static struct babel_neighbor * babel_find_neighbor(struct babel_iface *bif, ip_addr addr)
{
  struct babel_neighbor *bn;
  WALK_LIST(bn, bif->neigh_list)
    if(ipa_equal(bn->addr, addr))
      return bn;
  return NULL;
}

static struct babel_neighbor * babel_get_neighbor(struct babel_iface *bif, ip_addr addr)
{
  struct babel_neighbor *bn = babel_find_neighbor(bif, addr);
  if(bn) return bn;
  bn = mb_allocz(bif->pool, sizeof(struct babel_neighbor));
  bn->bif = bif;
  bn->addr = addr;
  bn->txcost = BABEL_INFINITY;
  init_list(&bn->routes);
  add_tail(&bif->neigh_list, NODE bn);
  return bn;
}

static void babel_expire_neighbors(struct babel_proto *p)
{
  struct babel_iface *bif;
  struct babel_neighbor *bn, *bnx;
  WALK_LIST(bif, p->interfaces) {
    WALK_LIST_DELSAFE(bn, bnx, bif->neigh_list) {
      if(bn->hello_expiry && bn->hello_expiry <= now)
        expire_hello(bn);
      if(bn->ihu_expiry && bn->ihu_expiry <= now)
        expire_ihu(bn);
    }
  }
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

static u16 babel_compute_rxcost(struct babel_neighbor *bn)
{
  struct babel_iface *bif = bn->bif;
  struct babel_proto *p = bif->proto;
  u8 n, missed;
  u16 map=bn->hello_map;

  if(!map) return BABEL_INFINITY;
  n = __builtin_popcount(map); // number of bits set
  missed = bn->hello_n-n;

  if(bif->cf->type == BABEL_IFACE_TYPE_WIRED) {
    /* k-out-of-j selection - Appendix 2.1 in the RFC. */
    DBG("Missed %d hellos from %I\n", missed, bn->addr);
    /* Link is bad if more than half the expected hellos were lost */
    return (missed > 0 && n/missed < 2) ? BABEL_INFINITY : bif->cf->rxcost;
  } else if(bif->cf->type == BABEL_IFACE_TYPE_WIRELESS) {
    /* ETX - Appendix 2.2 in the RFC.

       beta = prob. of successful transmission.
       rxcost = BABEL_RXCOST_WIRELESS/beta

       Since: beta = 1-missed/bn->hello_n = n/bn->hello_n
       Then: rxcost = BABEL_RXCOST_WIRELESS * bn->hello_n / n
   */
    if(!n) return BABEL_INFINITY;
    return BABEL_RXCOST_WIRELESS * bn->hello_n / n;
  } else {
    BAD("Unknown interface type!");
  }
}


static u16 compute_cost(struct babel_neighbor *bn)
{
  struct babel_iface *bif = bn->bif;
  struct babel_proto *p = bif->proto;
  u16 rxcost = babel_compute_rxcost(bn);
  if(rxcost == BABEL_INFINITY) return rxcost;
  else if(bif->cf->type == BABEL_IFACE_TYPE_WIRED) {
    /* k-out-of-j selection - Appendix 2.1 in the RFC. */
    return bn->txcost;
  } else if(bif->cf->type == BABEL_IFACE_TYPE_WIRELESS) {
    /* ETX - Appendix 2.2 in the RFC */
    return (MAX(bn->txcost, BABEL_RXCOST_WIRELESS) * rxcost)/BABEL_RXCOST_WIRELESS;
  } else {
    BAD("Unknown interface type!");
  }
}

/* Simple additive metric - Appendix 3.1 in the RFC */
static u16 compute_metric(struct babel_neighbor *bn, u16 metric)
{
  u16 cost = compute_cost(bn);
  return (cost == BABEL_INFINITY) ? cost : cost+metric;
}

static int
babel_rte_same(struct rte *new, struct rte *old)
{
  return new->u.babel.router_id == old->u.babel.router_id;
}


static int babel_rte_better(struct rte *new, struct rte *old)
{
  return new->u.babel.metric < old->u.babel.metric;
}

static rte * babel_build_rte(struct babel_proto *p, net *n, struct babel_route *r)
{
  rta *a, A;
  rte *rte;
  memset(&A, 0, sizeof(A));
  A.src = p->p.main_source;
  A.source = RTS_BABEL;
  A.scope = SCOPE_UNIVERSE;
  A.cast = RTC_UNICAST;
  A.dest = r->metric == BABEL_INFINITY ? RTD_UNREACHABLE : RTD_ROUTER;
  A.flags = 0;
  A.gw = r->next_hop;
  if(r->neigh) {
    A.from = r->neigh->addr;
    A.iface = r->neigh->bif->iface;
  }
  a = rta_lookup(&A);
  rte = rte_get_temp(a);
  rte->u.babel.metric = r->metric;
  rte->u.babel.router_id = r->router_id;
  rte->net = n;
  rte->pflags = 0;
  return rte;
}

static void babel_send_seqno_request(struct babel_entry *e)
{
  struct babel_proto *p = e->proto;
  struct babel_route *r = e->selected;
  struct babel_source *s = babel_find_source(e, r->router_id);
  struct babel_iface *bif;
  struct babel_tlv_seqno_request *tlv;

  if(s && cache_seqno_request(p, e->n.prefix, e->n.pxlen, r->router_id, s->seqno+1)) {
    TRACE(D_EVENTS, "Sending seqno request for %I/%d router_id %0lx",
          e->n.prefix, e->n.pxlen, r->router_id);

    WALK_LIST(bif, p->interfaces) {
      tlv = babel_add_tlv_seqno_request(bif);
      tlv->plen = e->n.pxlen;
      tlv->seqno = s->seqno + 1;
      tlv->hop_count = BABEL_INITIAL_HOP_COUNT;
      tlv->router_id = r->router_id;
      babel_put_addr(&tlv->header, e->n.prefix);
    }
  }
}

static void babel_unicast_seqno_request(struct babel_route *r)
{
  struct babel_entry *e = r->e;
  struct babel_proto *p = e->proto;
  struct babel_source *s = babel_find_source(e, r->router_id);
  struct babel_iface *bif = r->neigh->bif;
  struct babel_tlv_seqno_request *tlv;
  if(s && cache_seqno_request(p, e->n.prefix, e->n.pxlen, r->router_id, s->seqno+1)) {
    TRACE(D_EVENTS, "Sending seqno request for %I/%d router_id %0lx",
          e->n.prefix, e->n.pxlen, r->router_id);
      babel_new_unicast(bif);
      tlv = babel_add_tlv_seqno_request(bif);
      tlv->plen = e->n.pxlen;
      tlv->seqno = s->seqno + 1;
      tlv->hop_count = BABEL_INITIAL_HOP_COUNT;
      tlv->router_id = r->router_id;
      babel_put_addr(&tlv->header, e->n.prefix);
      babel_send_unicast(bif, r->neigh->addr);
  }
}

static void babel_send_route_request(struct babel_entry *e, struct babel_neighbor *n)
{
  struct babel_iface *bif = n->bif;
  struct babel_proto *p = e->proto;
  struct babel_tlv_route_request *tlv;
  TRACE(D_PACKETS, "Babel: Sending route request for %I/%d to %I\n",
        e->n.prefix, e->n.pxlen, n->addr);
  babel_new_unicast(bif);
  tlv = babel_add_tlv_route_request(bif);
  babel_put_addr(&tlv->header, e->n.prefix);
  tlv->plen = e->n.pxlen;
  babel_send_unicast(bif, n->addr);
}


/**
 * babel_select_route:
 * @e: Babel entry to select the best route for.
 *
 * Select the best feasible route for a given prefix. This just selects the
 * feasible route with the lowest metric. If this results in switching upstream
 * router (identified by router id), the nest is notified of the new route.
 *
 * If no feasible route is available for a prefix that previously had a route
 * selected, a seqno request is sent to try to get a valid route. In the
 * meantime, the route is marked as infeasible in the nest (to blackhole packets
 * going to it, as per the RFC).
 *
 * If no feasible route is available, and no previous route is selected, the
 * route is removed from the nest entirely.
 */
static void babel_select_route(struct babel_entry *e)
{
  struct babel_proto *p = e->proto;
  net *n = net_get(p->p.table, e->n.prefix, e->n.pxlen);
  struct babel_route *r, *cur = e->selected;

  /* try to find the best feasible route */
  WALK_LIST(r, e->routes)
    if((!cur || r->metric < cur->metric)
       && is_feasible(babel_find_source(e, r->router_id),
		      r->seqno, r->advert_metric))
      cur = r;

  if(cur && cur->neigh && ((!e->selected && cur->metric < BABEL_INFINITY)
			   || (e->selected && cur->metric < e->selected->metric))) {
      TRACE(D_EVENTS, "Picked new route for prefix %I/%d: router id %0lx metric %d",
	    e->n.prefix, e->n.pxlen, cur->router_id, cur->metric);
      /* Notify the nest of the update. If we change router ID, we also trigger
	 a global update. */
      if(!e->selected ||
         e->selected->metric == BABEL_INFINITY ||
         e->selected->router_id != cur->router_id)

	ev_schedule(p->update_event);

      e->selected = cur;
      rte_update(&p->p, n, babel_build_rte(p, n, cur));
  } else if(!cur || cur->metric == BABEL_INFINITY) {
    /* Couldn't find a feasible route. If we have a selected route, that means
       it just became infeasible; so set it's metric to infinite and install it
       (as unreachable), then send a seqno request.

       babel_build_rte() will set the unreachable flag if the metric is BABEL_INFINITY.*/
    if(e->selected) {
      TRACE(D_EVENTS, "Lost feasible route for prefix %I/%d: sending update and seqno request",
	    e->n.prefix, e->n.pxlen);
      e->selected->metric = BABEL_INFINITY;
      rte_update(&p->p, n, babel_build_rte(p, n, e->selected));

      ev_schedule(p->update_event);
      babel_send_seqno_request(e);
    } else {
      /* No route currently selected, and no new one selected; this means we
	 don't have a route to this destination anymore (and were probably
	 called from an expiry timer). Remove the route from the nest. */
      TRACE(D_EVENTS, "Flushing route for prefix %I/%d", e->n.prefix, e->n.pxlen);
      e->selected = NULL;
      rte_update(&p->p, n, NULL);
    }
  }
}

static void babel_send_ack(struct babel_iface *bif, ip_addr dest, u16 nonce)
{
  struct babel_proto *p = bif->proto;
  struct babel_tlv_ack *tlv;
  TRACE(D_PACKETS, "Babel: Sending ACK to %I with nonce %d\n", dest, nonce);
  babel_new_unicast(bif);
  tlv = babel_add_tlv_ack(bif);
  tlv->nonce = nonce;
  babel_send_unicast(bif, dest);
}

static void babel_add_ihu(struct babel_iface *bif, struct babel_neighbor *bn)
{
  struct babel_tlv_ihu *tlv = babel_add_tlv_ihu(bif);
  babel_put_addr_ihu(&tlv->header, bn->addr);
  tlv->rxcost = babel_compute_rxcost(bn);
  tlv->interval = bif->cf->ihu_interval*100;
}

static void babel_add_ihus(struct babel_iface *bif)
{
  struct babel_neighbor *bn;
  WALK_LIST(bn, bif->neigh_list)
    babel_add_ihu(bif,bn);
}

static void babel_send_ihu(struct babel_iface *bif, struct babel_neighbor *bn)
{
  struct babel_proto *p = bif->proto;
  TRACE(D_PACKETS, "Babel: Sending IHUs");
  babel_new_unicast(bif);
  babel_add_ihu(bif, bn);
  babel_send_unicast(bif, bn->addr);
}

void babel_send_hello(struct babel_iface *bif, u8 send_ihu)
{
  struct babel_proto *p = bif->proto;
  struct babel_tlv_hello *tlv;
  TRACE(D_PACKETS, "Babel: Sending hello on interface %s", bif->ifname);
  tlv = babel_add_tlv_hello(bif);
  tlv->seqno = bif->hello_seqno++;
  tlv->interval = bif->cf->hello_interval*100;

  if(send_ihu) babel_add_ihus(bif);
}

static void babel_hello_timer(timer *t)
{
  struct babel_iface *bif = t->data;
  babel_send_hello(bif, (bif->cf->type == BABEL_IFACE_TYPE_WIRED &&
                         bif->hello_seqno % BABEL_IHU_INTERVAL_FACTOR == 0));
}

/* Function to add router_id -- a router id TLV is always followed by an update
   TLV, so add both atomically (which may send the queue), then fill in the
   router ID and return the update TLV position.

   This prevents a full queue causing a packet to be sent with a router id TLV
   as the last TLV (and so the update TLV in the next packet missing a router
   id).*/
static struct babel_tlv_update * babel_add_router_id(struct babel_iface *bif, u64 router_id)
{
  struct babel_tlv_router_id *rid;
  struct babel_tlv_update *upd;
  rid = (struct babel_tlv_router_id *) babel_add_tlv_size(bif,
                                                          BABEL_TYPE_ROUTER_ID,
                                                          (sizeof(struct babel_tlv_router_id) +
                                                           sizeof(struct babel_tlv_update)));
  rid->router_id = router_id;
  upd = (struct babel_tlv_update *)(rid+1);
  upd->header.type = BABEL_TYPE_UPDATE;
  upd->header.length = sizeof(struct babel_tlv_update) - sizeof(struct babel_tlv_header);
  return upd;
}

void babel_send_update(struct babel_iface *bif)
{
  struct babel_proto *p = bif->proto;
  struct babel_tlv_update *upd;
  struct babel_entry *e;
  struct babel_route *r;
  struct babel_source *s;
  u64 router_id = 0;
  TRACE(D_PACKETS, "Sending update on %s", bif->ifname);
  FIB_WALK(&p->rtable, n) {
    e = (struct babel_entry *)n;
    r = e->selected;
    if(!r) continue;

    if(r->router_id != router_id) {
      upd = babel_add_router_id(bif, r->router_id);
      router_id = r->router_id;
    } else {
      upd = babel_add_tlv_update(bif);
    }

    /* Our own seqno might have changed, in which case we update the routes we
       originate. */
    if(r->router_id == p->router_id && r->seqno < p->update_seqno)
      r->seqno = p->update_seqno;
    upd->plen = e->n.pxlen;
    upd->interval = bif->cf->update_interval*100;
    upd->seqno = r->seqno;
    upd->metric = r->metric;
    babel_put_addr(&upd->header, e->n.prefix);

    /* Update feasibility distance. */
    s = babel_get_source(e, r->router_id);
    s->expires = now + BABEL_GARBAGE_INTERVAL;
    if(upd->seqno > s->seqno
       || (upd->seqno == s->seqno && upd->metric < s->metric)) {
      s->seqno = upd->seqno;
      s->metric = upd->metric;
    }
  } FIB_WALK_END;
}

/* Sends and update on all interfaces. */
static void babel_global_update(void *arg)
{
  struct babel_proto *p = arg;
  struct babel_iface *bif;
  TRACE(D_EVENTS, "Sending global update. Seqno %d", p->update_seqno);
  WALK_LIST(bif, p->interfaces)
    bif->update_triggered = 1;
}

static void babel_update_timer(timer *t)
{
  struct babel_iface *bif = t->data;
  struct babel_proto *p = bif->proto;
  TRACE(D_EVENTS, "Update timer firing");
  bif->update_triggered = 1;
}


int babel_handle_ack_req(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ack_req *tlv = (struct babel_tlv_ack_req *)hdr;
  struct babel_proto *p = state->proto;
  TRACE(D_PACKETS, "Received ACK req nonce %d interval %d", tlv->nonce, tlv->interval);
  if(tlv->interval) {
    babel_send_ack(state->bif, state->saddr, tlv->nonce);
  }
  return 1;
}

int babel_handle_ack(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ack *tlv = (struct babel_tlv_ack *)hdr;
  struct babel_proto *p = state->proto;
  TRACE(D_PACKETS, "Received ACK nonce %d", tlv->nonce);
  /* We don't send any ACK requests, so no need to do anything with ACKs. */
  return 1;
}

static void babel_flush_neighbor(struct babel_neighbor *bn)
{
  struct babel_proto *p = bn->bif->proto;
  struct babel_route *r;
  node *n;
  TRACE(D_EVENTS, "Flushing neighbor %I", bn->addr);
  rem_node(NODE bn);
  WALK_LIST_FIRST(n, bn->routes) {
    r = SKIP_BACK(struct babel_route, neigh_route, n);
    babel_flush_route(r);
  }
  mb_free(bn);
}

static void expire_hello(struct babel_neighbor *bn)
{
  bn->hello_map <<= 1;
  if(bn->hello_n < 16) bn->hello_n++;
  if(!bn->hello_map) {
    babel_flush_neighbor(bn);
  }
}

static void expire_ihu(struct babel_neighbor *bn)
{
  bn->txcost = BABEL_INFINITY;
}


/* update hello history according to Appendix A1 of the RFC */
static void update_hello_history(struct babel_neighbor *bn, u16 seqno, u16 interval)
{
  u8 diff;
  if(seqno == bn->next_hello_seqno) {/* do nothing */}
  /* if the expected and seen seqnos are within 16 of each other (mod 65535),
     the modular difference is going to be less than 16 for one of the
     directions. Otherwise, the values differ too much, so just reset. */
  else if(diff_mod64k(seqno, bn->next_hello_seqno) > 16 &&
     diff_mod64k(bn->next_hello_seqno,seqno) > 16) {
    /* note state reset - flush entries */
    bn->hello_map = bn->hello_n = 0;
  } else if((diff = diff_mod64k(bn->next_hello_seqno,seqno)) <= 16) {
    /* sending node increased interval; reverse history */
    bn->hello_map >>= diff;
    bn->hello_n = (diff < bn->hello_n) ? bn->hello_n - diff : 0;
  } else if((diff = diff_mod64k(seqno,bn->next_hello_seqno)) <= 16) {
    /* sending node decreased interval; fast-forward */
    bn->hello_map <<= diff;
    bn->hello_n = MIN(bn->hello_n + diff, 16);
  }
  /* current entry */
  bn->hello_map = (bn->hello_map << 1) | 1;
  bn->next_hello_seqno = seqno+1;
  if(bn->hello_n < 16) bn->hello_n++;
  bn->hello_expiry = now + (BABEL_HELLO_EXPIRY_FACTOR*interval)/100;
}


int babel_handle_hello(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_hello *tlv = (struct babel_tlv_hello *)hdr;
  struct babel_proto *p = state->proto;
  struct babel_iface *bif = state->bif;
  struct babel_neighbor *bn = babel_get_neighbor(bif, state->saddr);
  TRACE(D_PACKETS, "Handling hello seqno %d interval %d", tlv->seqno,
	tlv->interval, state->saddr);
  update_hello_history(bn, tlv->seqno, tlv->interval);
  if(bif->cf->type == BABEL_IFACE_TYPE_WIRELESS)
    babel_send_ihu(bif, bn);
  return 0;
}

int babel_handle_ihu(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_ihu *tlv = (struct babel_tlv_ihu *)hdr;
  struct babel_proto *p = state->proto;
  struct babel_iface *bif = state->bif;
  ip_addr addr = babel_get_addr(hdr, state);

  if(!ipa_equal(addr, bif->addr)) return 1; // not for us
  TRACE(D_PACKETS, "Handling IHU rxcost %d interval %d", tlv->rxcost,
	tlv->interval);
  struct babel_neighbor *bn = babel_get_neighbor(bif, state->saddr);
  bn->txcost = tlv->rxcost;
  bn->ihu_expiry = now + 1.5*(tlv->interval/100);
  return 0;
}

int babel_handle_router_id(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_router_id *tlv = (struct babel_tlv_router_id *)hdr;
  struct babel_proto *p = state->proto;
  state->router_id = tlv->router_id;
  TRACE(D_PACKETS, "Handling router ID %016lx", state->router_id);
  return 0;
}

int babel_handle_next_hop(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  state->next_hop = babel_get_addr(hdr, state);
  return 0;
}

int babel_handle_update(struct babel_tlv_header *hdr, struct babel_parse_state *state)
{
  struct babel_tlv_update *tlv = (struct babel_tlv_update *)hdr;
  struct babel_iface *bif = state->bif;
  struct babel_proto *p = state->proto;
  struct babel_neighbor *n;
  struct babel_entry *e;
  struct babel_source *s;
  struct babel_route *r;
  ip_addr prefix = babel_get_addr(hdr, state);
  int feasible;
  TRACE(D_PACKETS, "Handling update for %I/%d with seqno %d metric %d",
	prefix, tlv->plen, tlv->seqno, tlv->metric);
  if(tlv->flags & BABEL_FLAG_DEF_PREFIX) {
    state->prefix = prefix;
  }
  if(tlv->flags & BABEL_FLAG_ROUTER_ID) {
    u64 *buf = (u64*)&prefix;
    memcpy(&state->router_id, buf+1, sizeof(u64));
  }
  if(!state->router_id)
    log(L_WARN "%s: Received update on %s with no preceding router id", p->p.name, bif->ifname);

  n = babel_find_neighbor(bif, state->saddr);
  if(!n) {
    DBG("Haven't heard from neighbor %I; ignoring update.\n", state->saddr);
    return 1;
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
  e = babel_find_entry(p, prefix, tlv->plen);
  if(!e && tlv->metric == BABEL_INFINITY)
    return 1;

  if(!e) e = babel_get_entry(p, prefix, tlv->plen);

  s = babel_find_source(e, state->router_id); /* for feasibility */
  r = babel_find_route(e, n); /* the route entry indexed by neighbour */
  feasible = is_feasible(s, tlv->seqno, tlv->metric);

  if(!r) {

    if(!feasible || tlv->metric == BABEL_INFINITY)
      return 1;

    r = babel_get_route(e, n);
    r->advert_metric = tlv->metric;
    r->router_id = state->router_id;
    r->metric = compute_metric(n, tlv->metric);
    r->next_hop = state->next_hop;
    r->seqno = tlv->seqno;
  } else if(r == r->e->selected
	    && !feasible) {

    /* route is installed and update is infeasible - we may lose the route, so
       send a unicast seqno request (section 3.8.2.2 second paragraph). */
    babel_unicast_seqno_request(r);

    if(state->router_id == s->router_id) return 1;
    r->metric = BABEL_INFINITY; /* retraction */
  } else {
    /* last point above - update entry */
    r->advert_metric = tlv->metric;
    r->metric = compute_metric(n, tlv->metric);
    r->router_id = state->router_id;
    r->next_hop = state->next_hop;
    r->seqno = tlv->seqno;
    if(tlv->metric != BABEL_INFINITY) {
      r->expiry_interval = (BABEL_ROUTE_EXPIRY_FACTOR*tlv->interval)/100;
      r->expires = now + r->expiry_interval;
      if(r->expiry_interval > BABEL_ROUTE_REFRESH_INTERVAL)
        r->refresh_time = now + r->expiry_interval - BABEL_ROUTE_REFRESH_INTERVAL;
    }
    /* If the route is not feasible at this point, it means it is from another
       neighbour than the one currently selected; so send a unicast seqno
       request to try to get a better route (section 3.8.2.2 last paragraph). */
    if(!feasible)
      babel_unicast_seqno_request(r);
  }
  babel_select_route(e);
  return 0;
}

/* A retraction is an update with an infinite metric. */
static void babel_send_retraction(struct babel_iface *bif, ip_addr prefix, int plen)
{
  struct babel_proto *p = bif->proto;
  struct babel_tlv_update *upd;
  upd = babel_add_router_id(bif, p->router_id);
  upd->plen = plen;
  upd->interval = bif->cf->update_interval*100;
  upd->seqno = p->update_seqno;
  upd->metric = BABEL_INFINITY;
  babel_put_addr(&upd->header, prefix);
}

int babel_handle_route_request(struct babel_tlv_header *hdr,
				      struct babel_parse_state *state)
{
  struct babel_tlv_route_request *tlv = (struct babel_tlv_route_request *)hdr;
  struct babel_iface *bif = state->bif;
  struct babel_proto *p = state->proto;
  ip_addr prefix = babel_get_addr(hdr, state);
  struct babel_entry *e;

  TRACE(D_PACKETS, "Handling route request for %I/%d on interface %s",
	prefix, tlv->plen, bif->ifname);

  /* Wildcard request - full update on the interface */
  if(ipa_equal(prefix,IPA_NONE)) {
    state->needs_update = 1;
    return 0;
  }
  /* Non-wildcard request - see if we have an entry for the route. If not, send
     a retraction, otherwise send an update. */
  e = babel_find_entry(p, prefix, tlv->plen);
  if(!e) {
    babel_send_retraction(bif, prefix, tlv->plen);
  } else {
    state->needs_update = 1;
  }
  return 0;
}

static void expire_seqno_requests(struct babel_seqno_request_cache *c) {
  struct babel_seqno_request *n, *nx;
  WALK_LIST_DELSAFE(n, nx, c->entries) {
    if(n->updated < now-BABEL_SEQNO_REQUEST_EXPIRY) {
      rem_node(NODE n);
      sl_free(c->slab, n);
    }
  }
}

/* Checks the seqno request cache for a matching request and returns failure if
   found. Otherwise, a new entry is stored in the cache. */
static int cache_seqno_request(struct babel_proto *p, ip_addr prefix, u8 plen,
			       u64 router_id, u16 seqno)
{
  struct babel_seqno_request_cache *c = p->seqno_cache;
  struct babel_seqno_request *r;
  WALK_LIST(r, c->entries) {
    if(ipa_equal(r->prefix, prefix) && r->plen == plen &&
       r->router_id == router_id && r->seqno == seqno)
      return 0;
  }

  /* no entries found */
  r = sl_alloc(c->slab);
  r->prefix = prefix;
  r->plen = plen;
  r->router_id = router_id;
  r->seqno = seqno;
  r->updated = now;
  add_tail(&c->entries, NODE r);
  return 1;
}

void babel_forward_seqno_request(struct babel_entry *e,
				 struct babel_tlv_seqno_request *in,
				 ip_addr sender)
{
  struct babel_proto *p = e->proto;
  struct babel_route *r;
  struct babel_iface *bif;
  struct babel_tlv_seqno_request *out;
  TRACE(D_PACKETS, "Forwarding seqno request for %I/%d router_id %0lx",
	e->n.prefix, e->n.pxlen, in->router_id);
  WALK_LIST(r, e->routes) {
    if(r->router_id == in->router_id && r->neigh
       && !ipa_equal(r->neigh->addr,sender)) {
      if(!cache_seqno_request(p, e->n.prefix, e->n.pxlen, in->router_id, in->seqno))
	return;
      bif = r->neigh->bif;
      babel_new_unicast(bif);
      out = babel_add_tlv_seqno_request(bif);
      out->plen = in->plen;
      out->seqno = in->seqno;
      out->hop_count = in->hop_count-1;
      out->router_id = in->router_id;
      babel_put_addr(&out->header, e->n.prefix);
      babel_send_unicast(bif, r->neigh->addr);
      return;
    }
  }
}

/* The RFC section 3.8.1.2 on seqno requests:

   When a node receives a seqno request for a given router-id and sequence
   number, it checks whether its routing table contains a selected entry for
   that prefix; if no such entry exists, or the entry has infinite metric, it
   ignores the request.

   If a selected route for the given prefix exists, and either the router-ids
   are different or the router-ids are equal and the entry's sequence number is
   no smaller than the requested sequence number, it MUST send an update for the
   given prefix.

   If the router-ids match but the requested seqno is larger than the route
   entry's, the node compares the router-id against its own router-id. If the
   router-id is its own, then it increases its sequence number by 1 and sends an
   update. A node MUST NOT increase its sequence number by more than 1 in
   response to a route request.

   If the requested router-id is not its own, the received request's hop count
   is 2 or more, and the node has a route (not necessarily a feasible one) for
   the requested prefix that does not use the requestor as a next hop, the node
   SHOULD forward the request. It does so by decreasing the hop count and
   sending the request in a unicast packet destined to a neighbour that
   advertises the given prefix (not necessarily the selected neighbour) and that
   is distinct from the neighbour from which the request was received.

   A node SHOULD maintain a list of recently forwarded requests and forward the
   reply in a timely manner. A node SHOULD compare every incoming request
   against its list of recently forwarded requests and avoid forwarding it if it
   is redundant.
*/
int babel_handle_seqno_request(struct babel_tlv_header *hdr,
				      struct babel_parse_state *state)
{
  struct babel_tlv_seqno_request *tlv = (struct babel_tlv_seqno_request *)hdr;
  struct babel_proto *p = state->proto;
  ip_addr prefix = babel_get_addr(hdr, state);
  struct babel_entry *e;
  struct babel_route *r;

  TRACE(D_PACKETS, "Handling seqno request for %I/%d router_id %0lx seqno %d hop count %d",
	prefix, tlv->plen, tlv->router_id, tlv->seqno, tlv->hop_count);

  e = babel_find_entry(p, prefix, tlv->plen);
  if(!e || !e->selected || e->selected->metric == BABEL_INFINITY) return 1;

  r = e->selected;
  if(r->router_id != tlv->router_id || ge_mod64k(r->seqno, tlv->seqno)) {
    state->needs_update = 1;
    return 0;
  }

  /* seqno is larger; check if we own the router id */
  if(tlv->router_id == p->router_id) {
    p->update_seqno++;
    ev_schedule(p->update_event);
    return 0;
  }

  if(tlv->hop_count > 1) {
    babel_forward_seqno_request(e, tlv, state->saddr);
  }

  return 1;

}



/*
 * Interface to BIRD core
 */

/*
 * babel_start - initialize instance of babel
 */

static void babel_dump_source(struct babel_source *s)
{
  debug("Source router_id %0lx seqno %d metric %d expires %d\n",
	s->router_id, s->seqno, s->metric, s->expires ? s->expires-now : 0);
}

static void babel_dump_route(struct babel_route *r)
{
  debug("Route neigh %I if %s seqno %d metric %d/%d router_id %0lx expires %d\n",
	r->neigh ? r->neigh->addr : IPA_NONE,
        r->neigh ? r->neigh->bif->ifname : "(none)",
        r->seqno, r->advert_metric,
	r->metric, r->router_id, r->expires ? r->expires-now : 0);
}

static void babel_dump_entry(struct babel_entry *e)
{
  debug("Babel: Entry %I/%d:\n", e->n.prefix, e->n.pxlen);
  struct babel_source *s; struct babel_route *r;
  WALK_LIST(s,e->sources) { debug(" "); babel_dump_source(s); }
  WALK_LIST(r,e->routes) { debug(r==e->selected?" * " : " "); babel_dump_route(r); }
}
static void babel_dump_neighbor(struct babel_neighbor *bn)
{
  debug("Neighbor %I txcost %d hello_map %x next seqno %d expires %d/%d\n",
	bn->addr, bn->txcost, bn->hello_map, bn->next_hello_seqno,
        bn->hello_expiry ? bn->hello_expiry - now : 0,
        bn->ihu_expiry ? bn->ihu_expiry - now : 0);
}
static void babel_dump_interface(struct babel_iface *bif)
{
  struct babel_neighbor *bn;
  debug("Babel: Interface %s addr %I rxcost %d type %d hello seqno %d intervals %d %d\n",
	bif->ifname, bif->addr, bif->cf->rxcost, bif->cf->type, bif->hello_seqno,
	bif->cf->hello_interval, bif->cf->update_interval);
  WALK_LIST(bn,bif->neigh_list) { debug(" "); babel_dump_neighbor(bn); }

}

static void babel_dump(struct proto *P)
{
  struct babel_proto *p = (struct babel_proto *) P;
  struct babel_entry *e;
  struct babel_iface *bif;
  debug("Babel: router id %0lx update seqno %d\n", p->router_id, p->update_seqno);
  WALK_LIST(bif, p->interfaces) {babel_dump_interface(bif);}
  FIB_WALK(&p->rtable, n) {
    e = (struct babel_entry *)n;
    babel_dump_entry(e);
  } FIB_WALK_END;
}


static struct babel_iface*
babel_find_interface(struct babel_proto *p, struct iface *what)
{
  struct babel_iface *bif;

  WALK_LIST (bif, p->interfaces)
    if (bif->iface == what)
      return bif;
  return NULL;
}

static void
kill_iface(struct babel_iface *bif)
{
  DBG( "Babel: Interface %s disappeared\n", bif->iface->name);
  struct babel_neighbor *bn;
  WALK_LIST_FIRST(bn, bif->neigh_list)
    babel_flush_neighbor(bn);
  rfree(bif->pool);
}



static void
babel_open_interface(struct object_lock *lock)
{
  struct babel_iface *bif = lock->data;
  struct babel_proto *p = bif->proto;

  if(!babel_open_socket(bif)) {
    log(L_ERR "%s: Cannot open socket for %s", p->p.name, bif->iface->name);
  }
}



static void
babel_if_notify(struct proto *P, unsigned c, struct iface *iface)
{
  struct babel_proto *p = (struct babel_proto *) P;
  struct babel_config *cf = (struct babel_config *) P->cf;
  DBG("Babel: if notify: %s\n", iface->name);
  if (iface->flags & IF_IGNORE)
    return;
  if (c & IF_CHANGE_UP) {
    struct iface_patt *k = iface_patt_find(&cf->iface_list, iface, iface->addr);

    /* we only speak multicast */
    if(!(iface->flags & IF_MULTICAST)) return;

    if (!k) return; /* We are not interested in this interface */

    babel_new_interface(p, iface, iface->flags, k);

  }
  struct babel_iface *bif = babel_find_interface(p, iface);

  if(!bif)
    return;

  if (c & IF_CHANGE_DOWN) {
    rem_node(NODE bif);
    rfree(bif->lock);
    kill_iface(bif);
  }
}

void babel_queue_timer(timer *t)
{
  struct babel_iface *bif = t->data;
  if(bif->update_triggered) {
    babel_send_update(bif);
    bif->update_triggered = 0;
  }
  ev_schedule(bif->send_event);
}

static void babel_new_interface(struct babel_proto *p, struct iface *new,
                                unsigned long flags, struct iface_patt *patt)
{
  struct babel_config *cf = (struct babel_config *) p->p.cf;
  struct babel_iface * bif;
  struct babel_iface_config *iface_cf = (struct babel_iface_config *) patt;
  struct object_lock *lock;
  pool *pool;
  DBG("New interface %s\n", new->name);

  if(!new) return NULL;

  pool = rp_new(p->p.pool, new->name);
  bif = mb_allocz(pool, sizeof( struct babel_iface ));
  add_tail(&p->interfaces, NODE bif);
  bif->pool = pool;
  bif->iface = new;
  bif->ifname = new->name;
  bif->proto = p;
  struct ifa* ifa;
  WALK_LIST(ifa, new->addrs)
    if(ipa_is_link_local(ifa->ip))
      bif->addr = ifa->ip;
  if (iface_cf) {
    bif->cf = iface_cf;

    if(bif->cf->type == BABEL_IFACE_TYPE_WIRED) {
      if(bif->cf->hello_interval == BABEL_INFINITY)
        bif->cf->hello_interval = BABEL_HELLO_INTERVAL_WIRED;
      if(bif->cf->rxcost == BABEL_INFINITY)
        bif->cf->rxcost = BABEL_RXCOST_WIRED;
    } else if(bif->cf->type == BABEL_IFACE_TYPE_WIRELESS) {
      if(bif->cf->hello_interval == BABEL_INFINITY)
        bif->cf->hello_interval = BABEL_HELLO_INTERVAL_WIRELESS;
      if(bif->cf->rxcost == BABEL_INFINITY)
        bif->cf->rxcost = BABEL_RXCOST_WIRELESS;
    }
    if(bif->cf->update_interval == BABEL_INFINITY) {
      bif->cf->update_interval = bif->cf->hello_interval*BABEL_UPDATE_INTERVAL_FACTOR;
    }
    bif->cf->ihu_interval = bif->cf->hello_interval*BABEL_IHU_INTERVAL_FACTOR;
  }
  init_list(&bif->neigh_list);
  bif->hello_seqno = 1;
  bif->max_pkt_len = new->mtu - BABEL_OVERHEAD;

  bif->hello_timer = tm_new_set(bif->pool, babel_hello_timer, bif, 0, bif->cf->hello_interval);
  bif->update_timer = tm_new_set(bif->pool, babel_update_timer, bif, 0, bif->cf->update_interval);
  bif->packet_timer = tm_new_set(bif->pool, babel_queue_timer, bif, BABEL_MAX_SEND_INTERVAL, 1);


  bif->tlv_buf = bif->current_buf = mb_alloc(bif->pool, new->mtu);
  babel_init_packet(bif->tlv_buf);
  bif->send_event = ev_new(bif->pool);
  bif->send_event->hook = babel_send_queue;
  bif->send_event->data = bif;

  lock = olock_new( bif->pool );
  lock->addr = IP6_BABEL_ROUTERS;
  lock->port = cf->port;
  lock->iface = bif->iface;
  lock->hook = babel_open_interface;
  lock->data = bif;
  lock->type = OBJLOCK_UDP;
  olock_acquire(lock);
}


static struct ea_list *
babel_gen_attrs(struct linpool *pool, int metric, u64 router_id)
{
  struct ea_list *l = lp_alloc(pool, sizeof(struct ea_list) + 2*sizeof(eattr));
  struct adata *rid = lp_alloc(pool, sizeof(struct adata) + sizeof(u64));
  rid->length = sizeof(u64);
  memcpy(&rid->data, &router_id, sizeof(u64));

  l->next = NULL;
  l->flags = EALF_SORTED;
  l->count = 2;
  l->attrs[0].id = EA_BABEL_METRIC;
  l->attrs[0].flags = 0;
  l->attrs[0].type = EAF_TYPE_INT | EAF_TEMP;
  l->attrs[0].u.data = metric;
  l->attrs[1].id = EA_BABEL_ROUTER_ID;
  l->attrs[1].flags = 0;
  l->attrs[1].type = EAF_TYPE_OPAQUE | EAF_TEMP;
  l->attrs[1].u.ptr = rid;
  return l;
}

static void
babel_timer(timer *t)
{
  struct babel_proto *p = t->data;
  babel_expire_routes(p);
  expire_seqno_requests(p->seqno_cache);
  babel_expire_neighbors(p);
}


static int
babel_import_control(struct proto *P, struct rte **rt, struct ea_list **attrs, struct linpool *pool)
{
  struct babel_proto *p = (struct babel_proto *)P;

  if ((*rt)->attrs->source != RTS_BABEL) {
    struct ea_list *new = babel_gen_attrs(pool, 1, p->router_id);
    new->next = *attrs;
    *attrs = new;
  }
  return 0;
}

static struct ea_list *
babel_make_tmp_attrs(struct rte *rt, struct linpool *pool)
{
  return babel_gen_attrs(pool, rt->u.babel.metric, rt->u.babel.router_id);
}

static void
babel_store_tmp_attrs(struct rte *rt, struct ea_list *attrs)
{
  eattr *rid = ea_find(attrs, EA_BABEL_ROUTER_ID);
  rt->u.babel.router_id = rid ? *((u64*) rid->u.ptr->data) : 0;
  rt->u.babel.metric = ea_get_int(attrs, EA_BABEL_METRIC, 0);
}

/*
 * babel_rt_notify - core tells us about new route (possibly our
 * own), so store it into our data structures.
 */
static void
babel_rt_notify(struct proto *P, struct rtable *table UNUSED, struct network *net,
		struct rte *new, struct rte *old, struct ea_list *attrs)
{
  struct babel_proto *p = (struct babel_proto *)P;
  struct babel_entry *e;
  struct babel_route *r;

  TRACE(D_EVENTS, "Got route from nest: %I/%d", net->n.prefix, net->n.pxlen);
  if(new) {
    e = babel_get_entry(p, net->n.prefix, net->n.pxlen);
    r = (e->selected) ? e->selected : babel_get_route(e, NULL);

    if(!r->neigh) {
      r->seqno = p->update_seqno;
      r->router_id = p->router_id;
      r->metric = 0;
      e->selected = r;
    }
  } else if(old) {
    /* route has gone away; send retraction */
    e = babel_find_entry(p, net->n.prefix, net->n.pxlen);
    if(e && e->selected && !e->selected->neigh) {
      /* no neighbour, so our route */
      e->selected->metric = BABEL_INFINITY;
      e->selected->expires = now + BABEL_HOLD_TIME;
      babel_select_route(e);
    }
  } else {
    return;
  }
  ev_schedule(p->update_event);
}

static void babel_neigh_notify(neighbor *n)
{
  struct babel_proto *p = (struct babel_proto *)n->proto;
  struct babel_neighbor *bn = n->data;
  DBG("Neighbor: bn %d scope %d flags %d\n", bn, n->scope, n->flags);
  if(n->scope <= 0) {
    TRACE(D_EVENTS, "Babel: Neighbor lost");
  } else {
    TRACE(D_EVENTS, "Babel: Neighbor ready");
  }
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

  return p;
}

void
babel_init_config(struct babel_config *c)
{
  init_list(&c->iface_list);
  c->port	= BABEL_PORT;
}

static void
babel_get_route_info(rte *rte, byte *buf, ea_list *attrs)
{
  buf += bsprintf(buf, " (%d/%0lx)", rte->u.babel.metric, rte->u.babel.router_id);
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
  return 0;
}

static void
babel_copy_config(struct proto_config *dest, struct proto_config *src)
{
  /* Shallow copy of everything */
  proto_copy_rest(dest, src, sizeof(struct babel_config));

  /* We clean up iface_list, ifaces are non-sharable */
  init_list(&((struct babel_config *) dest)->iface_list);

}

static int
babel_start(struct proto *P)
{
  struct babel_proto *p = (struct babel_proto *) P;
  struct babel_config *cf = (struct babel_config *) P->cf;
  DBG( "Babel: starting instance...\n" );
  fib_init( &p->rtable, P->pool, sizeof( struct babel_entry ), 0, babel_init_entry );
  init_list( &p->interfaces );
  init_list( &p->garbage );
  p->timer = tm_new_set(P->pool, babel_timer, p, 0, 1);
  tm_start( p->timer, 2 );
  p->update_seqno = 1;
  p->router_id = proto_get_router_id(&cf->c);
  p->update_event = ev_new(P->pool);
  p->update_event->hook = babel_global_update;
  p->update_event->data = p;

  p->entry_slab = sl_new(P->pool, sizeof(struct babel_entry));
  p->route_slab = sl_new(P->pool, sizeof(struct babel_route));
  p->source_slab = sl_new(P->pool, sizeof(struct babel_source));

  p->seqno_cache = mb_allocz(P->pool, sizeof(struct babel_seqno_request_cache));
  p->seqno_cache->slab = sl_new(P->pool, sizeof(struct babel_seqno_request));
  init_list(&p->seqno_cache->entries);
  DBG( "Babel: ...done\n");
  return PS_UP;
}



struct protocol proto_babel = {
  .name =		"Babel",
  .template =		"babel%d",
  .attr_class =		EAP_BABEL,
  .preference =		DEF_PREF_BABEL,
  .config_size =	sizeof(struct babel_config),
  .init =		babel_init,
  .dump =		babel_dump,
  .start =		babel_start,
  .reconfigure =	babel_reconfigure,
  .copy_config =	babel_copy_config,
  .get_route_info =	babel_get_route_info,
  .get_attr =		babel_get_attr
};
