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
#define BABEL_OVERHEAD (SIZE_OF_IP_HEADER+8+sizeof(struct babel_header))

struct babel_header {
  u8 magic;
  u8 version;
  u16 length;
};

enum babel_tlv_type {
  BABEL_TYPE_PAD0             = 0,
  BABEL_TYPE_PADN             = 1,
  BABEL_TYPE_ACK_REQ          = 2,
  BABEL_TYPE_ACK              = 3,
  BABEL_TYPE_HELLO            = 4,
  BABEL_TYPE_IHU              = 5,
  BABEL_TYPE_ROUTER_ID        = 6,
  BABEL_TYPE_NEXT_HOP         = 7,
  BABEL_TYPE_UPDATE           = 8,
  BABEL_TYPE_ROUTE_REQUEST    = 9,
  BABEL_TYPE_SEQNO_REQUEST    = 10,
  /* extensions - not implemented
  BABEL_TYPE_TS_PC            = 11,
  BABEL_TYPE_HMAC             = 12,
  BABEL_TYPE_SS_UPDATE        = 13,
  BABEL_TYPE_SS_REQUEST       = 14,
  BABEL_TYPE_SS_SEQNO_REQUEST = 15,
  */
  BABEL_TYPE_MAX
};

enum babel_iface_type {
  BABEL_IFACE_TYPE_WIRED,
  BABEL_IFACE_TYPE_WIRELESS,
  BABEL_IFACE_TYPE_MAX
};

enum babel_ae_type {
  BABEL_AE_WILDCARD = 0,
  BABEL_AE_IP4      = 1,
  BABEL_AE_IP6      = 2,
  BABEL_AE_IP6_LL   = 3,
  BABEL_AE_MAX
};


struct babel_parse_state {
  struct babel_proto *proto;
  struct babel_iface *bif;
  ip_addr saddr;
  u64 router_id;
  /* A router_id may be 0, so we need a separate variable to track whether we
     have seen a router_id */
  u8 router_id_seen;
  ip_addr prefix;
  ip_addr next_hop;
  u8 needs_update;
};




struct babel_tlv_header {
  u8 type;
  u8 length;
};

struct babel_tlv_ack_req {
  struct babel_tlv_header header;
  u16 reserved;
  u16 nonce;
  u16 interval;
};

struct babel_tlv_ack {
  struct babel_tlv_header header;
  u16 nonce;
};

struct babel_tlv_hello {
  struct babel_tlv_header header;
  u16 reserved;
  u16 seqno;
  u16 interval;
};

struct babel_tlv_ihu {
  struct babel_tlv_header header;
  u8 ae;
  u8 reserved;
  u16 rxcost;
  u16 interval;
  ip_addr addr __attribute__((packed));
};

struct babel_tlv_router_id {
  struct babel_tlv_header header;
  u16 reserved;
  u64 router_id __attribute__((packed));
};

struct babel_tlv_next_hop {
  struct babel_tlv_header header;
  u8 ae;
  u8 reserved;
  ip_addr addr __attribute__((packed));
};

struct babel_tlv_update {
  struct babel_tlv_header header;
  u8 ae;
#define BABEL_FLAG_DEF_PREFIX 0x80
#define BABEL_FLAG_ROUTER_ID 0x40
  u8 flags;
  u8 plen;
  u8 omitted;
  u16 interval;
  u16 seqno;
  u16 metric;
  ip_addr addr __attribute__((packed));
  /* below attributes are not on the wire */
  u64 router_id;
};

struct babel_tlv_route_request {
  struct babel_tlv_header header;
  u8 ae;
  u8 plen;
  ip_addr addr __attribute__((packed));
};

struct babel_tlv_seqno_request {
  struct babel_tlv_header header;
  u8 ae;
  u8 plen;
  u16 seqno;
  u8 hop_count;
  u8 reserved;
  u64 router_id __attribute__((packed));
  ip_addr addr __attribute__((packed));
};

union babel_tlv {
  struct babel_tlv_header header;
  struct babel_tlv_ack_req ack_req;
  struct babel_tlv_ack ack;
  struct babel_tlv_hello hello;
  struct babel_tlv_ihu ihu;
  struct babel_tlv_router_id router_id;
  struct babel_tlv_next_hop next_hop;
  struct babel_tlv_update update;
  struct babel_tlv_route_request route_request;
  struct babel_tlv_seqno_request seqno_request;
};

struct babel_tlv_node {
  node n;
  union babel_tlv tlv;
};

/* Handlers */

int babel_validate_length(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_ack_req(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_ack(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_hello(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_ihu(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_validate_ihu(struct babel_tlv_header *hdr, struct babel_parse_state *state);
int babel_handle_router_id(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_next_hop(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_validate_next_hop(struct babel_tlv_header *hdr, struct babel_parse_state *state);
int babel_handle_update(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_validate_update(struct babel_tlv_header *hdr, struct babel_parse_state *state);
int babel_handle_route_request(struct babel_tlv_header *tlv,
                               struct babel_parse_state *state);
int babel_validate_request(struct babel_tlv_header *hdr, struct babel_parse_state *state);
int babel_handle_seqno_request(struct babel_tlv_header *tlv,
                               struct babel_parse_state *state);

/* Stores forwarded seqno requests for duplicate suppression. */
struct babel_seqno_request {
  node n;
  ip_addr prefix;
  u8  plen;
  u64 router_id;
  u16 seqno;
  bird_clock_t updated;
};

struct babel_seqno_request_cache {
  slab *slab;
  list entries;  /* Seqno requests in the cache (struct babel_seqno_request) */
};


struct babel_iface {
  node n;

  struct babel_proto *proto;
  struct iface *iface;
  struct object_lock *lock;

  struct babel_iface_config *cf;

  pool *pool;
  char *ifname;
  sock *sock;
  ip_addr addr;
  int max_pkt_len;
  list neigh_list; /* List of neighbors seen on this iface (struct babel_neighbor) */
  list tlv_queue;

  void *tlv_buf;
  void *current_buf;
  int update_triggered;

  u16 hello_seqno;              /* To be increased on each hello */

  timer *hello_timer;
  timer *update_timer;
  timer *packet_timer;
  event *send_event;

};

struct babel_iface_config {
  struct iface_patt i;

  u16 rxcost;
  int type;
  int tx_tos;
  int tx_priority;
  u16 hello_interval;
  u16 ihu_interval;
  u16 update_interval;
};

struct babel_neighbor {
  node n;
  struct babel_iface *bif;

  ip_addr addr;
  u16 txcost;
  u8 hello_n;
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
  struct babel_entry *e;

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
  node garbage_node;
  struct babel_proto *proto;
  struct babel_route *selected;

  list sources;   /* Source table entries for this prefix (struct babel_source). */
  list routes;    /* Routes for this prefix (struct babel_route). */
};



struct babel_config {
  struct proto_config c;

  list iface_list;              /* Patterns configured -- keep it first; see babel_reconfigure why */
  int port;
};

struct babel_proto {
  struct proto p;
  timer *timer;
  struct fib rtable;
  list garbage;        /* Entries to be garbage collected (struct babel_entry) */
  list interfaces;     /* Interfaces we really know about (struct babel_iface) */
  u16 update_seqno;   /* To be increased on request */
  u64 router_id;
  event  *update_event;   /* For triggering global updates */

  slab *entry_slab;
  slab *route_slab;
  slab *source_slab;
  slab *tlv_slab;

  struct babel_seqno_request_cache *seqno_cache;
};



void babel_init_config(struct babel_config *c);

/* Packet mangling code - packet.c */
void babel_send_hello(struct babel_iface *bif, u8 send_ihu);
void babel_send_unicast( struct babel_iface *bif, ip_addr dest );
void babel_send_queue(void *arg);
void babel_send_update(struct babel_iface *bif);
void babel_init_packet(void *buf);
int babel_open_socket(struct babel_iface *bif);
int babel_process_packet(struct babel_header *pkt, int size,
                         ip_addr saddr, int port, struct babel_iface *bif);
ip_addr babel_get_addr(struct babel_tlv_header *hdr, struct babel_parse_state *state);
void babel_put_addr(struct babel_tlv_header *hdr, ip_addr addr);
void babel_new_unicast(struct babel_iface *bif);
struct babel_tlv_header * babel_add_tlv_size(struct babel_iface *bif, u16 type, int size);
struct babel_tlv_header * babel_add_tlv(struct babel_iface *bif, u16 len);
#define BABEL_ADD_TLV_SEND(tlv,bif,func,addr) do {                      \
    tlv=func(bif);                                                      \
    if(!tlv) {                                                          \
      babel_send_to(bif,addr);                                          \
      babel_new_packet(bif);                                            \
      tlv=func(bif);                                                    \
    }} while (0);

inline struct babel_tlv_ack_req * babel_add_tlv_ack_req(struct babel_iface *bif)
{
  return (struct babel_tlv_ack_req *) babel_add_tlv(bif, BABEL_TYPE_ACK_REQ);
}
inline struct babel_tlv_ack * babel_add_tlv_ack(struct babel_iface *bif)
{
  return (struct babel_tlv_ack *) babel_add_tlv(bif, BABEL_TYPE_ACK);
}
inline struct babel_tlv_hello * babel_add_tlv_hello(struct babel_iface *bif)
{
  return (struct babel_tlv_hello *) babel_add_tlv(bif, BABEL_TYPE_HELLO);
}
inline struct babel_tlv_ihu * babel_add_tlv_ihu(struct babel_iface *bif)
{
  return (struct babel_tlv_ihu *) babel_add_tlv(bif, BABEL_TYPE_IHU);
}
inline struct babel_tlv_router_id * babel_add_tlv_router_id(struct babel_iface *bif)
{
  return (struct babel_tlv_router_id *) babel_add_tlv(bif, BABEL_TYPE_ROUTER_ID);
}
inline struct babel_tlv_next_hop * babel_add_tlv_next_hop(struct babel_iface *bif)
{
  return (struct babel_tlv_next_hop *) babel_add_tlv(bif, BABEL_TYPE_NEXT_HOP);
}
inline struct babel_tlv_update * babel_add_tlv_update(struct babel_iface *bif)
{
  return (struct babel_tlv_update *) babel_add_tlv(bif, BABEL_TYPE_UPDATE);
}
inline struct babel_tlv_route_request * babel_add_tlv_route_request(struct babel_iface *bif)
{
  return (struct babel_tlv_route_request *) babel_add_tlv(bif, BABEL_TYPE_ROUTE_REQUEST);
}
inline struct babel_tlv_seqno_request * babel_add_tlv_seqno_request(struct babel_iface *bif)
{
  return (struct babel_tlv_seqno_request *) babel_add_tlv(bif, BABEL_TYPE_SEQNO_REQUEST);
}
