/*  -*- c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 *	The Babel protocol
 *
 *	Copyright (c) 2015 Toke Høiland-Jørgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the data structures used by Babel.
 */

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/locks.h"
#include "lib/resource.h"
#include "lib/lists.h"
#include "lib/socket.h"
#include "lib/string.h"
#include "lib/timer.h"

#ifndef IPV6
#error "The Babel protocol only speaks IPv6"
#endif

#define EA_BABEL_METRIC    EA_CODE(EAP_BABEL, 0)
#define EA_BABEL_ROUTER_ID EA_CODE(EAP_BABEL, 1)

#define BABEL_MAGIC    42
#define BABEL_VERSION  2
#define BABEL_PORT     6696
#define BABEL_INFINITY 0xFFFF

  /* default hello intervals in seconds */
#define BABEL_HELLO_INTERVAL_WIRED    20
#define BABEL_HELLO_INTERVAL_WIRELESS 4
#define BABEL_UPDATE_INTERVAL_FACTOR  4
#define BABEL_IHU_INTERVAL_FACTOR     3
#define BABEL_HELLO_EXPIRY_FACTOR     1.5
#define BABEL_ROUTE_EXPIRY_FACTOR     3.5
#define BABEL_ROUTE_REFRESH_INTERVAL  2  /* seconds before route expiry to send route request */
#define BABEL_HOLD_TIME               10 /* expiry time for our own routes */
#define BABEL_RXCOST_WIRED            96
#define BABEL_RXCOST_WIRELESS         256
#define BABEL_INITIAL_HOP_COUNT       255
#define BABEL_MAX_SEND_INTERVAL       5

#define BABEL_SEQNO_REQUEST_EXPIRY    60
#define BABEL_GARBAGE_INTERVAL        300

/* ip header + udp header + babel header */
#define BABEL_OVERHEAD (SIZE_OF_IP_HEADER+8+sizeof(struct babel_pkt_header))

struct babel_pkt_header {
  u8 magic;
  u8 version;
  u16 length;
};



enum babel_tlv_type {
  BABEL_TLV_PAD0             = 0,
  BABEL_TLV_PADN             = 1,
  BABEL_TLV_ACK_REQ          = 2,
  BABEL_TLV_ACK              = 3,
  BABEL_TLV_HELLO            = 4,
  BABEL_TLV_IHU              = 5,
  BABEL_TLV_ROUTER_ID        = 6,
  BABEL_TLV_NEXT_HOP         = 7,
  BABEL_TLV_UPDATE           = 8,
  BABEL_TLV_ROUTE_REQUEST    = 9,
  BABEL_TLV_SEQNO_REQUEST    = 10,
  /* extensions - not implemented
  BABEL_TLV_TS_PC            = 11,
  BABEL_TLV_HMAC             = 12,
  BABEL_TLV_SS_UPDATE        = 13,
  BABEL_TLV_SS_REQUEST       = 14,
  BABEL_TLV_SS_SEQNO_REQUEST = 15,
  */
  BABEL_TLV_MAX
};

enum babel_iface_type {
  /* In practice, UNDEF and WIRED give equivalent behaviour */
  BABEL_IFACE_TYPE_UNDEF    = 0,
  BABEL_IFACE_TYPE_WIRED    = 1,
  BABEL_IFACE_TYPE_WIRELESS = 2,
  BABEL_IFACE_TYPE_MAX
};

enum babel_ae_type {
  BABEL_AE_WILDCARD = 0,
  BABEL_AE_IP4      = 1,
  BABEL_AE_IP6      = 2,
  BABEL_AE_IP6_LL   = 3,
  BABEL_AE_MAX
};



struct babel_tlv_ack_req {
  u8 type;
  u16 nonce;
  u16 interval;
  ip_addr sender;
};

struct babel_tlv_ack {
  u8 type;
  u16 nonce;
};

struct babel_tlv_hello {
  u8 type;
  u16 seqno;
  u16 interval;
  ip_addr sender;
};

struct babel_tlv_ihu {
  u8 type;
  u8 ae;
  u16 rxcost;
  u16 interval;
  ip_addr addr;
  ip_addr sender;
};

struct babel_tlv_update {
  u8 type;
  u8 ae;
  u8 plen;
  u16 interval;
  u16 seqno;
  u16 metric;
  ip_addr prefix;
  u64 router_id;
  ip_addr next_hop;
  ip_addr sender;
};

struct babel_tlv_route_request {
  u8 type;
  u8 ae;
  u8 plen;
  ip_addr prefix;
};

struct babel_tlv_seqno_request {
  u8 type;
  u8 ae;
  u8 plen;
  u16 seqno;
  u8 hop_count;
  u64 router_id;
  ip_addr prefix;
  ip_addr sender;
};

union babel_tlv {
  u8 type;
  struct babel_tlv_ack_req ack_req;
  struct babel_tlv_ack ack;
  struct babel_tlv_hello hello;
  struct babel_tlv_ihu ihu;
  struct babel_tlv_update update;
  struct babel_tlv_route_request route_request;
  struct babel_tlv_seqno_request seqno_request;
};



/* Stores forwarded seqno requests for duplicate suppression. */
struct babel_seqno_request {
  node n;
  ip_addr prefix;
  u8  plen;
  u64 router_id;
  u16 seqno;
  bird_clock_t updated;
};


struct babel_iface {
  node n;

  struct babel_proto *proto;
  struct iface *iface;
  struct object_lock *lock;

  struct babel_iface_config *cf;

  u8 up;

  pool *pool;
  char *ifname;
  sock *sock;
  ip_addr addr;
  int max_pkt_len;
  list neigh_list; /* List of neighbors seen on this iface (struct babel_neighbor) */
  list tlv_queue;

  u16 hello_seqno;              /* To be increased on each hello */

  bird_clock_t next_hello;
  bird_clock_t next_regular;
  bird_clock_t next_triggered;
  bird_clock_t want_triggered;

  timer *timer;
  event *send_event;

};

struct babel_iface_config {
  struct iface_patt i;

  u16 rxcost;
  int type;
  int tx_tos;
  int tx_priority;
  int port;
  u16 hello_interval;
  u16 ihu_interval;
  u16 update_interval;
};

struct babel_neighbor {
  node n;
  struct babel_iface *ifa;

  ip_addr addr;
  u16 txcost;
  u8 hello_cnt;
  u16 hello_map;
  u16 next_hello_seqno;
  /* expiry timers */
  bird_clock_t hello_expiry;
  bird_clock_t ihu_expiry;

  list routes;  /* Routes this neighbour has sent us (struct babel_route) */
};

struct babel_entry;

struct babel_source {
  node n;

  u64 router_id;
  u16 seqno;
  u16 metric;
  bird_clock_t expires;
};

struct babel_route {
  node n;
  node neigh_route;
  struct babel_entry    *e;
  struct babel_neighbor *neigh;

  u16 seqno;
  u16 advert_metric;
  u16 metric;
  u64 router_id;
  ip_addr next_hop;
  bird_clock_t refresh_time;
  bird_clock_t expires;
  u16 expiry_interval;
};


struct babel_entry {
  struct fib_node n;
  struct babel_proto *proto;
  struct babel_route *selected;

  bird_clock_t updated;

  list sources;   /* Source table entries for this prefix (struct babel_source). */
  list routes;    /* Routes for this prefix (struct babel_route). */
};



struct babel_config {
  struct proto_config c;

  list iface_list;              /* Patterns configured -- keep it first; see babel_reconfigure why */
};

struct babel_proto {
  struct proto p;
  timer *timer;
  struct fib rtable;
  list interfaces;     /* Interfaces we really know about (struct babel_iface) */
  u16 update_seqno;   /* To be increased on request */
  u64 router_id;
  u8 triggered;   /* For triggering global updates */

  slab *entry_slab;
  slab *route_slab;
  slab *source_slab;
  slab *tlv_slab;

  slab *seqno_slab;
  list seqno_cache;  /* Seqno requests in the cache (struct babel_seqno_request) */
};



void babel_init_config(struct babel_config *c);

/* Handlers */

void babel_handle_ack_req(union babel_tlv *tlv, struct babel_iface *ifa);
void babel_handle_ack(union babel_tlv *tlv, struct babel_iface *ifa);
void babel_handle_hello(union babel_tlv *tlv, struct babel_iface *ifa);
void babel_handle_ihu(union babel_tlv *tlv, struct babel_iface *ifa);
void babel_handle_router_id(union babel_tlv *tlv, struct babel_iface *ifa);
void babel_handle_update(union babel_tlv *tlv, struct babel_iface *ifa);
void babel_handle_route_request(union babel_tlv *tlv, struct babel_iface *ifa);
void babel_handle_seqno_request(union babel_tlv *tlv, struct babel_iface *ifa);


/* Packet mangling code - packet.c */
struct babel_tlv_node {
  node n;
  union babel_tlv tlv;
};

void babel_enqueue(union babel_tlv *tlv, struct babel_iface *ifa);

void babel_send_hello(struct babel_iface *ifa, u8 send_ihu);
void babel_send_unicast(union babel_tlv *tlv, struct babel_iface *ifa, ip_addr dest);
void babel_send_queue(void *arg);
void babel_send_update(struct babel_iface *ifa, bird_clock_t changed);
void babel_init_packet(void *buf);
int babel_open_socket(struct babel_iface *ifa);
void babel_iface_start(struct babel_iface *ifa);
