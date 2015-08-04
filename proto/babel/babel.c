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

#undef TRACE
#define TRACE(level, msg, args...) do { if (p->debug & level) { log(L_TRACE "%s: " msg, p->name , ## args); } } while(0)


/*
 * Interface to BIRD core
 */

/*
 * babel_start - initialize instance of babel
 */
static int
babel_start(struct proto *p)
{
  struct babel_interface *rif;
  DBG( "Babel: starting instance...\n" );
  fib_init( &P->rtable, p->pool, sizeof( struct babel_entry ), 0, NULL );
  init_list( &P->connections );
  init_list( &P->interfaces );
  DBG( "Babel: ...done\n");
  return PS_UP;
}

static void
babel_dump(struct proto *p)
{
}

static void
babel_if_notify(struct proto *p, unsigned c, struct iface *iface)
{
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
