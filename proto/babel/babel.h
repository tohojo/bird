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

/* ip header + udp header + babel header */
#define BABEL_OVERHEAD (SIZE_OF_IP_HEADER+8+sizeof(struct babel_header))
#define BABEL_INFINITY 0xFFFF
#define BABEL_AE_WILDCARD 0
#define BABEL_AE_IP4 1
#define BABEL_AE_IP6 2
#define BABEL_AE_IP6_LL 3

#define TLV_LENGTH(t) (sizeof(t)-sizeof(struct babel_tlv_header))

struct babel_header {
  u8 magic;
  u8 version;
  u16 length;
};

struct babel_parse_state {
  struct proto *proto;
  ip_addr saddr;
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
  u8 ae;
  u8 reserved;
  u16 rxcost;
  u16 interval;
  u32 addr[2];
};
void babel_hton_ihu(struct babel_tlv_header *tlv);
void babel_ntoh_ihu(struct babel_tlv_header *tlv);
ip_addr babel_get_addr_ihu(struct babel_tlv_header *tlv, struct babel_parse_state *state);
void babel_put_addr_ihu(struct babel_tlv_header *tlv, ip_addr addr);

struct babel_tlv_router_id {
  struct babel_tlv_header header;
  u16 reserved;
  u64 router_id;
};

struct babel_tlv_next_hop {
  struct babel_tlv_header header;
  u8 ae;
  u8 reserved;
  u32 addr[2];
};
ip_addr babel_get_addr_next_hop(struct babel_tlv_header *tlv, struct babel_parse_state *state);
void babel_put_addr_next_hop(struct babel_tlv_header *tlv, ip_addr addr);

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
  u32 addr[4];
};
void babel_hton_update(struct babel_tlv_header *tlv);
void babel_ntoh_update(struct babel_tlv_header *tlv);
ip_addr babel_get_addr_update(struct babel_tlv_header *tlv, struct babel_parse_state *state);
void babel_put_addr_update(struct babel_tlv_header *tlv, ip_addr addr);

struct babel_tlv_route_request {
  struct babel_tlv_header header;
  u8 ae;
  u8 plen;
  u32 addr[4];
};
ip_addr babel_get_addr_route_request(struct babel_tlv_header *tlv,
				     struct babel_parse_state *state);
void babel_put_addr_route_request(struct babel_tlv_header *tlv, ip_addr addr);

struct babel_tlv_seqno_request {
  struct babel_tlv_header header;
  u8 ae;
  u8 plen;
  u16 seqno;
  u8 hop_count;
  u8 reserved;
  u64 router_id;
  /* optionally prefix */
};
void babel_hton_seqno_request(struct babel_tlv_header *tlv);
void babel_ntoh_seqno_request(struct babel_tlv_header *tlv);
ip_addr babel_get_addr_seqno_request(struct babel_tlv_header *tlv,
				     struct babel_parse_state *state);
void babel_put_addr_seqno_request(struct babel_tlv_header *tlv, ip_addr addr);


/* Handlers */

int babel_validate_length(struct babel_tlv_header *tlv);
int babel_handle_ack_req(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_ack(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_hello(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_ihu(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_validate_ihu(struct babel_tlv_header *hdr);
int babel_handle_router_id(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_handle_next_hop(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_validate_next_hop(struct babel_tlv_header *hdr);
int babel_handle_update(struct babel_tlv_header *tlv, struct babel_parse_state *state);
int babel_validate_update(struct babel_tlv_header *hdr);
int babel_handle_route_request(struct babel_tlv_header *tlv,
				      struct babel_parse_state *state);
int babel_validate_route_request(struct babel_tlv_header *hdr);
int babel_handle_seqno_request(struct babel_tlv_header *tlv,
				      struct babel_parse_state *state);
int babel_validate_seqno_request(struct babel_tlv_header *hdr);


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
  pool *pool;
  char *ifname;
  sock *sock;
  int max_pkt_len;
  int metric;
  int type;
  struct object_lock *lock;
  list tlv_queue;
  list neigh_list;
  u16 hello_seqno;		/* To be increased on each hello */
  bird_clock_t last_hello;
};

struct babel_patt {
  struct iface_patt i;

  int metric;
#define BABEL_TYPE_WIRED 1
#define BABEL_TYPE_WIRELESS 2
  int type;
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
  u16 next_hello_seqno;
  timer *hello_timer;
  timer *ihu_timer;
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

/* Packet mangling code - packet.c */
void babel_send( struct babel_interface *bif );
void babel_send_to( struct babel_interface *bif, ip_addr dest );
int babel_process_packet(struct babel_header *pkt, int size,
			 ip_addr saddr, int port, struct babel_interface *bif);
ip_addr babel_get_addr(struct babel_tlv_header *hdr, struct babel_parse_state *state);

#define BABEL_NEW_PACKET(bif,t) ((t *)babel_new_packet(bif,sizeof(t)))
struct babel_tlv_header * babel_new_packet(struct babel_interface *bif, u16 len);
#define BABEL_ADD_TLV(bif,t) ((t *)babel_add_tlv(bif,sizeof(t)))
struct babel_tlv_header * babel_add_tlv(struct babel_interface *bif, u16 len);
