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
  /* default hello intervals in seconds */
#define BABEL_HELLO_INTERVAL_WIRED	20
#define BABEL_HELLO_INTERVAL_WIRELESS	4
#define BABEL_UPDATE_INTERVAL_FACTOR	4
#define BABEL_IHU_INTERVAL_FACTOR	3
#define BABEL_EXPIRY_FACTOR	3.5
#define BABEL_RXCOST_WIRED	96
#define BABEL_RXCOST_WIRELESS	256

/* ip header + udp header + babel header */
#define BABEL_OVERHEAD (SIZE_OF_IP_HEADER+8+sizeof(struct babel_header))
#define BABEL_INFINITY 0xFFFF

struct babel_header {
  u8 magic;
  u8 version;
  u16 length;
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
  /* extensions - not implemented
  BABEL_TYPE_TS_PC = 11,
  BABEL_TYPE_HMAC = 12,
  BABEL_TYPE_SS_UPDATE = 13,
  BABEL_TYPE_SS_REQUEST = 14,
  BABEL_TYPE_SS_SEQNO_REQUEST = 15,
  */
  BABEL_TYPE_MAX
};

enum babel_iface_type_t {
  BABEL_IFACE_TYPE_WIRED,
  BABEL_IFACE_TYPE_WIRELESS,
  BABEL_IFACE_TYPE_MAX
};

enum babel_ae_type_t {
  BABEL_AE_WILDCARD = 0,
  BABEL_AE_IP4 = 1,
  BABEL_AE_IP6 = 2,
  BABEL_AE_IP6_LL = 3,
  BABEL_AE_MAX
};


struct babel_parse_state {
  struct proto *proto;
  ip_addr saddr;
  struct babel_interface *bif;
  u64 router_id;
  ip_addr prefix;
  ip_addr next_hop;
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
  u64 router_id __attribute__((packed));
};
void babel_hton_router_id(struct babel_tlv_header *tlv);
void babel_ntoh_router_id(struct babel_tlv_header *tlv);

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
  u64 router_id __attribute__((packed));
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

struct babel_packet {
  struct babel_header header;
};


struct babel_interface {
  node n;
  struct proto *proto;
  struct iface *iface;
  ip_addr addr;
  pool *pool;
  char *ifname;
  sock *sock;
  int max_pkt_len;
  int rxcost;
  int type;
  struct object_lock *lock;
  list tlv_queue;
  list neigh_list;
  u16 hello_seqno;		/* To be increased on each hello */
  u16 hello_interval;
  u16 ihu_interval;
  u16 update_interval;
  timer * hello_timer;
  timer * update_timer;
  event * ihu_event;
};

struct babel_patt {
  struct iface_patt i;

  int rxcost;
  int type;
  int tx_tos;
  int tx_priority;
  int hello_interval;
  int update_interval;
};

struct babel_neighbor {
  node n;
  struct babel_interface *bif;
  neighbor *neigh;
  ip_addr addr;
  u16 txcost;
  u8 hello_n;
  u16 hello_map;
  u16 next_hello_seqno;
  /* expiry timers */
  timer *hello_timer;
  timer *ihu_timer;

  list routes;
};

struct babel_entry;

struct babel_source {
  node n;
  struct babel_entry *e;
  u64 router_id;
  u16 seqno;
  u16 metric;
  bird_clock_t updated;
};

struct babel_route {
  node n;
  struct babel_entry *e;
  struct babel_neighbor *neigh;
  u16 seqno;
  u16 advert_metric;
  u16 metric;
  u64 router_id;
  ip_addr next_hop;

  bird_clock_t updated, expiry;
#define BABEL_FLAG_SELECTED 1
  u8 flags;
};


struct babel_entry {
  struct fib_node n;
  struct proto *proto;
  struct babel_route *selected;
  list sources;
  list routes;
};



struct babel_proto_config {
  struct proto_config c;
  list iface_list;	/* Patterns configured -- keep it first; see babel_reconfigure why */
  int port;
};

struct babel_proto {
  struct proto inherited;
  timer *timer;
  list connections;
  struct fib rtable;
  list garbage;
  list interfaces;	/* Interfaces we really know about */
  u16 update_seqno;		/* To be increased on request */
  event *update_event;  /* For triggering global updates */
};



void babel_init_config(struct babel_proto_config *c);

/* Packet mangling code - packet.c */
void babel_send( struct babel_interface *bif );
void babel_send_to( struct babel_interface *bif, ip_addr dest );
int babel_process_packet(struct babel_header *pkt, int size,
			 ip_addr saddr, int port, struct babel_interface *bif);
ip_addr babel_get_addr(struct babel_tlv_header *hdr, struct babel_parse_state *state);
void babel_put_addr(struct babel_tlv_header *hdr, ip_addr addr);
void babel_new_packet(struct babel_interface *bif);
struct babel_tlv_header * babel_add_tlv(struct babel_interface *bif, u16 len);
#define BABEL_ADD_TLV_SEND(tlv,bif,func,addr) do {			\
    tlv=func(bif);							\
    if(!tlv) {								\
      babel_send_to(bif,addr);						\
      babel_new_packet(bif);						\
      tlv=func(bif);							\
    }} while (0);

inline struct babel_tlv_ack_req * babel_add_tlv_ack_req(struct babel_interface *bif)
{
  return (struct babel_tlv_ack_req *) babel_add_tlv(bif, BABEL_TYPE_ACK_REQ);
}
inline struct babel_tlv_ack * babel_add_tlv_ack(struct babel_interface *bif)
{
  return (struct babel_tlv_ack *) babel_add_tlv(bif, BABEL_TYPE_ACK);
}
inline struct babel_tlv_hello * babel_add_tlv_hello(struct babel_interface *bif)
{
  return (struct babel_tlv_hello *) babel_add_tlv(bif, BABEL_TYPE_HELLO);
}
inline struct babel_tlv_ihu * babel_add_tlv_ihu(struct babel_interface *bif)
{
  return (struct babel_tlv_ihu *) babel_add_tlv(bif, BABEL_TYPE_IHU);
}
inline struct babel_tlv_router_id * babel_add_tlv_router_id(struct babel_interface *bif)
{
  return (struct babel_tlv_router_id *) babel_add_tlv(bif, BABEL_TYPE_ROUTER_ID);
}
inline struct babel_tlv_next_hop * babel_add_tlv_next_hop(struct babel_interface *bif)
{
  return (struct babel_tlv_next_hop *) babel_add_tlv(bif, BABEL_TYPE_NEXT_HOP);
}
inline struct babel_tlv_update * babel_add_tlv_update(struct babel_interface *bif)
{
  return (struct babel_tlv_update *) babel_add_tlv(bif, BABEL_TYPE_UPDATE);
}
inline struct babel_tlv_route_request * babel_add_tlv_route_request(struct babel_interface *bif)
{
  return (struct babel_tlv_route_request *) babel_add_tlv(bif, BABEL_TYPE_ROUTE_REQUEST);
}
inline struct babel_tlv_seqno_request * babel_add_tlv_seqno_request(struct babel_interface *bif)
{
  return (struct babel_tlv_seqno_request *) babel_add_tlv(bif, BABEL_TYPE_SEQNO_REQUEST);
}