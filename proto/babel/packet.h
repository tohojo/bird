/*  -*- c-file-style: "gnu"; indent-tabs-mode: nil; -*-
 *
 *	The Babel protocol
 *
 *	Copyright (c) 2015 Toke Høiland-Jørgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the on-wire data structures (i.e. TLVs and packet
 *	format) used by the Babel protocol.
 */

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

enum parse_result {
  PARSE_SUCCESS,
  PARSE_ERROR,
  PARSE_IGNORE,
};

struct babel_write_state {
  u64 router_id;
  u8 router_id_seen;
  ip_addr next_hop;
};

struct babel_pkt_tlv_header {
  u8 type;
  u8 length;
};

struct babel_pkt_tlv_ack_req {
  struct babel_pkt_tlv_header header;
  u16 reserved;
  u16 nonce;
  u16 interval;
};

struct babel_pkt_tlv_ack {
  struct babel_pkt_tlv_header header;
  u16 nonce;
};

struct babel_pkt_tlv_hello {
  struct babel_pkt_tlv_header header;
  u16 reserved;
  u16 seqno;
  u16 interval;
};

struct babel_pkt_tlv_ihu {
  struct babel_pkt_tlv_header header;
  u8 ae;
  u8 reserved;
  u16 rxcost;
  u16 interval;
  u8 addr[0];
} __attribute__((packed));

struct babel_pkt_tlv_router_id {
  struct babel_pkt_tlv_header header;
  u16 reserved;
  u64 router_id;
} __attribute__((packed));

struct babel_pkt_tlv_next_hop {
  struct babel_pkt_tlv_header header;
  u8 ae;
  u8 reserved;
  u8 addr[0];
} __attribute__((packed));

struct babel_pkt_tlv_update {
  struct babel_pkt_tlv_header header;
  u8 ae;
#define BABEL_FLAG_DEF_PREFIX 0x80
#define BABEL_FLAG_ROUTER_ID 0x40
  u8 flags;
  u8 plen;
  u8 omitted;
  u16 interval;
  u16 seqno;
  u16 metric;
  u8 addr[0];
} __attribute__((packed));

struct babel_pkt_tlv_route_request {
  struct babel_pkt_tlv_header header;
  u8 ae;
  u8 plen;
  u8 addr[0];
} __attribute__((packed));

struct babel_pkt_tlv_seqno_request {
  struct babel_pkt_tlv_header header;
  u8 ae;
  u8 plen;
  u16 seqno;
  u8 hop_count;
  u8 reserved;
  u64 router_id;
  u8 addr[0];
} __attribute__((packed));

union babel_pkt_tlv {
  struct babel_pkt_tlv_header header;
  struct babel_pkt_tlv_ack_req ack_req;
  struct babel_pkt_tlv_ack ack;
  struct babel_pkt_tlv_hello hello;
  struct babel_pkt_tlv_ihu ihu;
  struct babel_pkt_tlv_router_id router_id;
  struct babel_pkt_tlv_next_hop next_hop;
  struct babel_pkt_tlv_update update;
  struct babel_pkt_tlv_route_request route_request;
  struct babel_pkt_tlv_seqno_request seqno_request;
};
