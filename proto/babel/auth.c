/*
 *	BIRD -- The Babel protocol
 *
 *	Copyright (c) 2020 Toke Hoiland-Jorgensen
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	This file contains the authentication code for the Babel protocol
 */

#include "nest/bird.h"
#include "lib/mac.h"
#include "babel.h"
#include "packets.h"

struct babel_tlv_pc {
  u8 type;
  u8 length;
  u32 pc;
  u8 index[0];
} PACKED;

struct babel_tlv_mac {
  u8 type;
  u8 length;
  u8 mac[0];
} PACKED;

struct babel_tlv_challenge {
  u8 type;
  u8 length;
  u8 nonce[0];
} PACKED;

struct babel_mac_pseudohdr {
  u8 src_addr[16];
  u16 src_port;
  u8 dst_addr[16];
  u16 dst_port;
} PACKED;

struct babel_auth_state {
  struct babel_read_state rstate;
  u32 pc;
  u8 pc_seen;
  u8 index_len;
  u8 *index;
  u8 challenge_reply_seen;
  u8 challenge_reply[BABEL_AUTH_NONCE_LEN];
  u8 challenge_seen;
  u8 challenge_len;
  u8 challenge[BABEL_AUTH_MAX_NONCE_LEN];
  u8 is_unicast;
};

#define LOG_PKT_AUTH(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_AUTH "%s: " msg, p->p.name, args)

#define TO_AUTH_STATE(_s,_r) struct babel_auth_state *_s = ((struct babel_auth_state *)_r)

static int
babel_read_pc(struct babel_tlv *hdr, union babel_msg *m UNUSED,
              struct babel_read_state *rstate)
{
  struct babel_tlv_pc *tlv = (void *) hdr;
  TO_AUTH_STATE(state, rstate);

  if (!state->pc_seen)
  {
    state->pc_seen = 1;
    state->pc = get_u32(&tlv->pc);
    state->index_len = TLV_OPT_LENGTH(tlv);
    state->index = tlv->index;
  }

  return PARSE_IGNORE;
}

static const struct babel_tlv_data pc_tlv_data = {
  .min_length = sizeof(struct babel_tlv_pc),
  .read_tlv = &babel_read_pc
};

static int
babel_read_challenge_req(struct babel_tlv *hdr, union babel_msg *m UNUSED,
			 struct babel_read_state *rstate)
{
  struct babel_tlv_challenge *tlv = (void *) hdr;
  TO_AUTH_STATE(state, rstate);

  if (!state->is_unicast)
  {
    DBG("Ignoring non-unicast challenge request from %I\n", state->rstate.saddr);
    return PARSE_IGNORE;
  }

  if (tlv->length > BABEL_AUTH_MAX_NONCE_LEN)
    return PARSE_IGNORE;

  state->challenge_len = tlv->length;
  if (state->challenge_len)
    memcpy(state->challenge, tlv->nonce, state->challenge_len);
  state->challenge_seen = 1;

  return PARSE_IGNORE;
}

static const struct babel_tlv_data challenge_req_tlv_data = {
  .min_length = sizeof(struct babel_tlv_challenge),
  .read_tlv = &babel_read_challenge_req,
};

static int
babel_read_challenge_reply(struct babel_tlv *hdr, union babel_msg *m UNUSED,
                           struct babel_read_state *rstate)
{
  struct babel_tlv_challenge *tlv = (void *) hdr;
  TO_AUTH_STATE(state, rstate);

  if (tlv->length != BABEL_AUTH_NONCE_LEN || state->challenge_reply_seen)
    return PARSE_IGNORE;

  state->challenge_reply_seen = 1;
  memcpy(state->challenge_reply, tlv->nonce, BABEL_AUTH_NONCE_LEN);

  return PARSE_IGNORE;
}

static const struct babel_tlv_data challenge_reply_tlv_data = {
  .min_length = sizeof(struct babel_tlv_challenge),
  .read_tlv = &babel_read_challenge_reply,
};

static const struct babel_tlv_data *
get_auth_tlv_data(u8 type)
{
  switch(type)
  {
  case BABEL_TLV_PC:
    return &pc_tlv_data;
  case BABEL_TLV_CHALLENGE_REQ:
    return &challenge_req_tlv_data;
  case BABEL_TLV_CHALLENGE_REPLY:
    return &challenge_reply_tlv_data;
  default:
    return NULL;
  }
}

uint
babel_auth_write_challenge(struct babel_tlv *hdr, union babel_msg *m,
                           struct babel_write_state *state UNUSED,uint max_len)
{
  struct babel_tlv_challenge *tlv = (void *) hdr;
  struct babel_msg_challenge *msg = &m->challenge;

  uint len = sizeof(struct babel_tlv_challenge) + msg->nonce_len;

  if (len > max_len)
    return 0;

  TLV_HDR(tlv, msg->type, len);
  memcpy(tlv->nonce, msg->nonce, msg->nonce_len);

  return len;
}

static void
babel_auth_send_challenge(struct babel_iface *ifa, struct babel_neighbor *n)
{
  struct babel_proto *p = ifa->proto;
  union babel_msg msg = {};

  TRACE(D_PACKETS, "Sending AUTH challenge to %I on %s",
	n->addr, ifa->ifname);

  random_bytes(n->auth_nonce, BABEL_AUTH_NONCE_LEN);
  n->auth_nonce_expiry = current_time() + BABEL_AUTH_CHALLENGE_TIMEOUT;
  n->auth_next_challenge = current_time() + BABEL_AUTH_CHALLENGE_INTERVAL;

  msg.type = BABEL_TLV_CHALLENGE_REQ;
  msg.challenge.nonce_len = BABEL_AUTH_NONCE_LEN;
  msg.challenge.nonce = n->auth_nonce;

  babel_send_unicast(&msg, ifa, n->addr);
}

static int
babel_mac_hash(struct password_item *pass,
               struct babel_mac_pseudohdr *phdr,
               byte *pkt, uint pkt_len,
               byte *buf, uint *buf_len)
{
  struct mac_context ctx;

  if (mac_type_length(pass->alg) > *buf_len)
    return 1;

  mac_init(&ctx, pass->alg, pass->password, pass->length);
  mac_update(&ctx, (byte *)phdr, sizeof(*phdr));
  mac_update(&ctx, (byte *)pkt, pkt_len);

  *buf_len = mac_get_length(&ctx);
  memcpy(buf, mac_final(&ctx), *buf_len);

  mac_cleanup(&ctx);

  return 0;
}

static void
babel_mac_build_phdr(struct babel_mac_pseudohdr *phdr,
                     ip_addr saddr, u16 sport,
                     ip_addr daddr, u16 dport)
{
  memset(phdr, 0, sizeof(*phdr));
  put_ip6(phdr->src_addr, saddr);
  put_u16(&phdr->src_port, sport);
  put_ip6(phdr->dst_addr, daddr);
  put_u16(&phdr->dst_port, dport);
  DBG("MAC pseudo-header: %I %d %I %d\n", saddr, sport, daddr, dport);
}

static int
babel_auth_check_mac(struct babel_iface *ifa, byte *pkt,
                     byte *trailer, uint trailer_len,
                     ip_addr saddr, u16 sport,
                     ip_addr daddr, u16 dport)
{
  uint hash_len = (uint)(trailer - pkt);
  struct babel_proto *p = ifa->proto;
  byte *end = trailer + trailer_len;
  btime now_ = current_real_time();
  struct babel_mac_pseudohdr phdr;
  struct password_item *pass;
  struct babel_tlv *tlv;

  if (trailer_len < sizeof(*tlv))
  {
    LOG_PKT_AUTH("No MAC signature on packet from %I on %s",
                 saddr, ifa->ifname);
    return 1;
  }

  babel_mac_build_phdr(&phdr, saddr, sport, daddr, dport);

  WALK_LIST(pass, *ifa->cf->passwords)
  {
    byte mac_res[MAX_HASH_SIZE];
    uint mac_len = MAX_HASH_SIZE;

    if (pass->accfrom > now_ || pass->accto < now_)
      continue;

    if (babel_mac_hash(pass, &phdr,
                       pkt, hash_len,
                       mac_res, &mac_len))
      continue;

    WALK_TLVS(trailer, end, tlv, saddr, ifa->ifname)
    {
      struct babel_tlv_mac *mac = (void *)tlv;

      if (tlv->type != BABEL_TLV_MAC)
	continue;

      if (tlv->length == mac_len && !memcmp(mac->mac, mac_res, mac_len))
        return 0;

      DBG("MAC mismatch key id %d pos %d len %d/%d\n",
	  pass->id, (byte *)tlv - (byte *)pkt, mac_len, tlv->length);
    }
    WALK_TLVS_END;
  }

  LOG_PKT_AUTH("No MAC key matching packet from %I found on %s",
               saddr, ifa->ifname);
  return 1;

frame_err:
  DBG("MAC trailer TLV framing error\n");
  return 1;
}

static int
babel_auth_check_pc(struct babel_iface *ifa, struct babel_auth_state *state)
{
  struct babel_proto *p = ifa->proto;
  struct babel_neighbor *n;

  TRACE(D_PACKETS, "Handling MAC check from %I on %s",
        state->rstate.saddr,  ifa->ifname);

  /* We create the neighbour entry at this point because it makes it easier to
   * rate limit challenge replies; this is explicitly allowed by the spec (see
   *  Section 4.3).
   */
  n = babel_get_neighbor(ifa, state->rstate.saddr);

  if (state->challenge_seen && n->auth_next_challenge_reply <= current_time())
  {
    union babel_msg resp = {};
    TRACE(D_PACKETS, "Sending MAC challenge response to %I", state->rstate.saddr);
    resp.type = BABEL_TLV_CHALLENGE_REPLY;
    resp.challenge.nonce_len = state->challenge_len;
    resp.challenge.nonce = state->challenge;
    n->auth_next_challenge_reply = current_time() + BABEL_AUTH_CHALLENGE_INTERVAL;
    babel_send_unicast(&resp, ifa, state->rstate.saddr);
  }

  if (state->index_len > BABEL_AUTH_INDEX_LEN || !state->pc_seen)
  {
    LOG_PKT_AUTH("Invalid index or no PC from %I on %s",
                 state->rstate.saddr, ifa->ifname);
    return 1;
  }

  /* On successful challenge, update PC and index to current values */
  if (state->challenge_reply_seen &&
      n->auth_nonce_expiry &&
      n->auth_nonce_expiry >= current_time() &&
      !memcmp(state->challenge_reply, n->auth_nonce, BABEL_AUTH_NONCE_LEN))
  {
    n->auth_index_len = state->index_len;
    memcpy(n->auth_index, state->index, state->index_len);
    n->auth_pc = state->pc;
  }

  /* If index differs, send challenge */
  if ((n->auth_index_len != state->index_len ||
      memcmp(n->auth_index, state->index, state->index_len)) &&
      n->auth_next_challenge <= current_time())
  {
    LOG_PKT_AUTH("Index mismatch from %I on %s; sending challenge",
                 state->rstate.saddr, ifa->ifname);
    babel_auth_send_challenge(ifa, n);
    return 1;
  }

  /* Index matches; only accept if PC is greater than last */
  if (n->auth_pc >= state->pc)
  {
    LOG_PKT_AUTH("Packet counter too low from %I on %s",
                 state->rstate.saddr, ifa->ifname);
    return 1;
  }

  n->auth_pc = state->pc;
  n->auth_expiry = current_time() + BABEL_AUTH_NEIGHBOR_TIMEOUT;
  n->auth_passed = 1;
  return 0;
}

/**
 * babel_auth_check - Check authentication for a packet
 * @ifa: Interface holding the transmission buffer
 * @saddr: Source address the packet was received from
 * @sport: Source port the packet was received from
 * @daddr: Destination address the packet was sent to
 * @dport: Destination port the packet was sent to
 * @pkt: Pointer to start of the packet data
 * @trailer: Pointer to the packet trailer
 * @trailer_len: Length of the packet trailer
 *
 * This function performs any necessary authentication checks on a packet and
 * returns 0 if the packet should be accepted (either because it has been
 * successfully authenticated or because authentication is disabled or
 * configured in permissive mode), or 1 if the packet should be dropped without
 * further processing.
 */
int
babel_auth_check(struct babel_iface *ifa,
                 ip_addr saddr, u16 sport,
                 ip_addr daddr, u16 dport,
                 struct babel_pkt_header *pkt,
                 byte *trailer, uint trailer_len)
{
  struct babel_proto *p = ifa->proto;
  struct babel_tlv *tlv;

  struct babel_auth_state state = {
    .rstate = {
      .get_tlv_data = &get_auth_tlv_data,
      .proto        = p,
      .ifa          = ifa,
      .saddr        = saddr,
    },
    .is_unicast     = !(ipa_classify(daddr) & IADDR_MULTICAST),
  };

  if (ifa->cf->auth_type == BABEL_AUTH_NONE)
    return 0;

  TRACE(D_PACKETS, "Checking packet authentication signature");

  if (babel_auth_check_mac(ifa, (byte *)pkt,
                           trailer, trailer_len,
                           saddr, sport,
                           daddr, dport))
    goto fail;

  /* MAC verified; parse packet to check packet counter and challenge */
  WALK_TLVS(FIRST_TLV(pkt), trailer, tlv, saddr, ifa->iface->name)
  {
    union babel_msg msg;
    enum parse_result res;

    res = babel_read_tlv(tlv, &msg, &state.rstate);
    if (res == PARSE_ERROR)
    {
      LOG_PKT_AUTH("Bad TLV from %I via %s type %d pos %d - parse error",
                   saddr, ifa->iface->name, tlv->type, (byte *)tlv - (byte *)pkt);
      goto fail;
    }
  }
  WALK_TLVS_END;

frame_err:

  if (babel_auth_check_pc(ifa, &state))
    goto fail;

  TRACE(D_PACKETS, "Packet from %I via %s authenticated successfully",
        saddr, ifa->ifname);
  return 0;

fail:
  LOG_PKT_AUTH("Packet from %I via %s failed authentication%s",
               saddr, ifa->ifname,
               ifa->cf->auth_permissive ? " but accepted in permissive mode" : "");

  return !ifa->cf->auth_permissive;
}

/**
 * babel_auth_add_tlvs - Add authentication-related TLVs to a packet
 * @ifa: Interface holding the transmission buffer
 * @tlv: Pointer to the place where any new TLVs should be added
 * @max_len: Maximum length available for adding new TLVs
 *
 * This function adds any new TLVs required by the authentication mode to a
 * packet before it is shipped out. For MAC authentication, this is the packet
 * counter TLV that must be included in every packet.
 */
int
babel_auth_add_tlvs(struct babel_iface *ifa, struct babel_tlv *tlv, int max_len)
{
  struct babel_proto *p = ifa->proto;
  struct babel_tlv_pc *msg;
  int len;

  if (ifa->cf->auth_type == BABEL_AUTH_NONE)
    return 0;

  msg = (void *)tlv;
  len = sizeof(*msg) + BABEL_AUTH_INDEX_LEN;
  max_len += ifa->auth_tx_overhead;

  if (len > max_len)
  {
    LOG_WARN("Insufficient space to add MAC seqno TLV on iface %s: %d < %d",
             ifa->ifname, max_len, len);
    return 0;
  }

  msg->type = BABEL_TLV_PC;
  msg->length = len - sizeof(struct babel_tlv);
  put_u32(&msg->pc, ifa->auth_pc++);
  memcpy(msg->index, ifa->auth_index, BABEL_AUTH_INDEX_LEN);

  /* Reset index on overflow to 0 */
  if (!ifa->auth_pc)
    babel_auth_reset_index(ifa);

  return len;
}

/**
 * babel_auth_sign - Sign an outgoing packet before transmission
 * @ifa: Interface holding the transmission buffer
 * @dest: Destination address of the packet
 *
 * This function adds authentication signature(s) to the packet trailer for each
 * of the configured authentication keys on the interface.
 */
int
babel_auth_sign(struct babel_iface *ifa, ip_addr dest)
{
  struct babel_proto *p = ifa->proto;
  struct babel_mac_pseudohdr phdr;
  struct babel_pkt_header *hdr;
  struct password_item *pass;
  int tot_len = 0, i = 0;
  struct babel_tlv *tlv;
  sock *sk = ifa->sk;
  byte *pos, *end;
  btime now_;
  int len;

  if (ifa->cf->auth_type == BABEL_AUTH_NONE)
    return 0;

  hdr = (void *) sk->tbuf;
  len = get_u16(&hdr->length) + sizeof(struct babel_pkt_header);

  pos = (byte *)hdr + len;
  end = (byte *)hdr + ifa->tx_length + ifa->auth_tx_overhead;
  tlv = (void *)pos;
  now_ = current_real_time();

  babel_mac_build_phdr(&phdr, sk->saddr, sk->fport, dest, sk->dport);

  WALK_LIST(pass, *ifa->cf->passwords)
  {
    struct babel_tlv_mac *msg = (void *)tlv;
    uint buf_len = (uint) (end - (byte *)msg - sizeof(*msg));

    if (pass->genfrom > now_ || pass->gento < now_)
      continue;

    if (babel_mac_hash(pass, &phdr,
                       (byte *)hdr, len,
                       msg->mac, &buf_len))
    {
      LOG_WARN("Insufficient space for MAC signatures on iface %s dest %I",
               ifa->ifname, dest);
      break;
    }

    msg->type = BABEL_TLV_MAC;
    msg->length = buf_len;

    tlv = NEXT_TLV(tlv);
    tot_len += buf_len + sizeof(*msg);
    i++;
  }

  DBG("Added %d MAC signatures (%d bytes) on ifa %s for dest %I\n",
      i, tot_len, ifa->ifname, dest);

  return tot_len;
}

/**
 * babel_auth_reset_index - Reset authentication index on interface
 * @ifa: Interface to reset
 *
 * This function resets the authentication index and packet counter for an
 * interface, and should be called on interface configuration, or when the
 * packet counter overflows.
 */
void
babel_auth_reset_index(struct babel_iface *ifa)
{
  random_bytes(ifa->auth_index, BABEL_AUTH_INDEX_LEN);
  ifa->auth_pc = 1;
}

/**
 * babel_auth_set_tx_overhead - Set interface TX overhead for authentication
 * @ifa: Interface to configure
 *
 * This function sets the TX overhead for an interface based on its
 * authentication configuration.
 */
void
babel_auth_set_tx_overhead(struct babel_iface *ifa)
{
  if (ifa->cf->auth_type == BABEL_AUTH_NONE)
  {
    ifa->auth_tx_overhead = 0;
    return;
  }

  ifa->auth_tx_overhead = (sizeof(struct babel_tlv_pc) +
                           sizeof(struct babel_tlv_mac) * ifa->cf->mac_num_keys +
                           ifa->cf->mac_total_len);
  ifa->tx_length -= ifa->auth_tx_overhead;
}

/**
 * babel_auth_init_neighbor - Initialise authentication data for neighbor
 * @n: Neighbor to initialise
 *
 * This function initialises the authentication-related state for a new neighbor
 * that has just been created.
 */
void
babel_auth_init_neighbor(struct babel_neighbor *n)
{
  if (n->ifa->cf->auth_type != BABEL_AUTH_NONE)
    n->auth_expiry = current_time() + BABEL_AUTH_NEIGHBOR_TIMEOUT;
}
