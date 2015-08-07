/*
 * Structures for the Babel protocol
 *
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

#define EA_BABEL_METRIC	EA_CODE(EAP_BABEL, 0)

#define PACKET_MAX	25
#define PACKET_MD5_MAX	18	/* FIXME */


#define BABEL_MAGIC	42
#define BABEL_VERSION	2
#define BABEL_PORT	6696
#define BABEL_DEFAULT_METRIC	1   /* default metric */
#define BABEL_HELLO_INTERVAL	10  /* default hello interval in seconds */
#define BABEL_UPDATE_INTERVAL	10  /* default update interval in seconds */

#define TLV_LENGTH(t) (sizeof(t)-sizeof(struct babel_tlv_header))

struct babel_header {
  u8 magic;
  u8 version;
  u16 length;
};

struct babel_parse_state {
  struct proto *proto;
  ip_addr whotoldme;
  struct babel_interface *bif;
  u64 router_id;
};


enum babel_tlv_type_t {
  BABEL_TYPE_PAD0	   = 0,
  BABEL_TYPE_PADN	   = 1,
  BABEL_TYPE_ACK_REQ	   = 2,
  BABEL_TYPE_ACK	   = 3,
  BABEL_TYPE_HELLO	   = 4,
  BABEL_TYPE_IHU	   = 5,
  BABEL_TYPE_ROUTER_ID	   = 6,
  BABEL_TYPE_NEXT_HOP	   = 7,
  BABEL_TYPE_UPDATE	   = 8,
  BABEL_TYPE_ROUTE_REQUEST = 9,
  BABEL_TYPE_SEQNO_REQUEST = 10,
  BABEL_TYPE_MAX
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

void babel_hton_ack_req(struct babel_tlv_header *tlv);
void babel_ntoh_ack_req(struct babel_tlv_header *tlv);

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

void babel_hton_hello(struct babel_tlv_header *tlv);
void babel_ntoh_hello(struct babel_tlv_header *tlv);


struct babel_tlv_ihu {
  struct babel_tlv_header header;
  u8 addr_enc;
  u8 reserved;
  u16 rxcost;
  u16 interval;
  /*addr...*/
};
void babel_hton_ihu(struct babel_tlv_header *tlv);
void babel_ntoh_ihu(struct babel_tlv_header *tlv);

struct babel_tlv_router_id {
  struct babel_tlv_header header;
  u16 reserved;
  u64 router_id;
};

struct babel_tlv_next_hop {
  struct babel_tlv_header header;
  u8 addr_enc;
  u8 reserved;
  /*next -hop*/
};

struct babel_tlv_update {
  struct babel_tlv_header header;
  u8 addr_enc;
  u8 flags;
  u8 plen;
  u8 omitted;
  u16 interval;
  u16 seqno;
  u16 metric;
  /*prefixes*/
};
void babel_hton_update(struct babel_tlv_header *tlv);
void babel_ntoh_update(struct babel_tlv_header *tlv);

struct babel_tlv_route_request {
  struct babel_tlv_header header;
  u8 addr_enc;
  u8 plen;
  /*prefixes*/
};

struct babel_tlv_seqno_request {
  struct babel_tlv_header header;
  u8 addr_enc;
  u8 plen;
  u16 seqno;
  u8 hop_count;
  u8 reserved;
  u64 router_id;
  /*prefixes*/
};
void babel_hton_seqno_request(struct babel_tlv_header *tlv);
void babel_ntoh_seqno_request(struct babel_tlv_header *tlv);

struct babel_entry {
  struct fib_node n;

  ip_addr whotoldme;
  ip_addr nexthop;
  int metric;
  u16 tag;

  bird_clock_t updated, changed;
  int flags;
};

struct babel_packet {
  struct babel_header header;
};


struct babel_interface {
  node n;
  struct proto *proto;
  struct iface *iface;
  char *ifname;
  sock *sock;
  int metric;
  struct object_lock *lock;
  list tlv_queue;
  list neigh_list;
  u16 hello_seqno;		/* To be increased on each hello */
  bird_clock_t last_hello;
};

struct babel_patt {
  struct iface_patt i;

  int metric;
  int tx_tos;
  int tx_priority;
};

struct babel_neighbor {
  node n;
  struct babel_interface *bif;
  neighbor *neigh;
  ip_addr addr;
  u16 txcost;
  u16 hello_map;
  u16 hello_seqno;
  bird_clock_t hello_exp;
  bird_clock_t ihu_exp;
};



struct babel_proto_config {
  struct proto_config c;
  list iface_list;	/* Patterns configured -- keep it first; see babel_reconfigure why */
  int port;
  u16 update_seqno;		/* To be increased on request */
  int hello_interval;
  int update_interval;
};

struct babel_proto {
  struct proto inherited;
  timer *timer;
  list connections;
  struct fib rtable;
  list garbage;
  list interfaces;	/* Interfaces we really know about */
  bird_clock_t last_update;
};



void babel_init_config(struct babel_proto_config *c);
void babel_send( struct babel_interface *bif );
void babel_send_to( struct babel_interface *bif, ip_addr dest );
int babel_process_packet(struct babel_header *pkt, int size,
			 ip_addr whotoldme, int port, struct babel_interface *bif);
void * babel_new_packet(sock *s, u16 len);

int babel_handle_ack_req(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_ack(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_hello(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_ihu(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_router_id(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_next_hop(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_update(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_route_request(struct babel_tlv_header *tlv,
				      struct babel_parse_state *state);
int babel_handle_seqno_request(struct babel_tlv_header *tlv,
				      struct babel_parse_state *state);
