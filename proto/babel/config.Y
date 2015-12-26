/*
 *	BIRD -- Babel Configuration
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */



CF_HDR

#include "proto/babel/babel.h"
#include "nest/iface.h"

CF_DEFINES

#define BABEL_CFG ((struct babel_config *) this_proto)
#define BABEL_IFACE_CFG ((struct babel_iface_config *) this_ipatt)

CF_DECLS

CF_KEYWORDS(BABEL, METRIC, RXCOST, HELLO_INTERVAL, UPDATE_INTERVAL, PORT, WIRED,
WIRELESS, BABEL_METRIC)

CF_GRAMMAR

CF_ADDTO(proto, babel_cfg '}' { } )

babel_cfg_start: proto_start BABEL {
     this_proto = proto_config_new(&proto_babel, $1);
     babel_init_config(BABEL_CFG);
   }
 ;

babel_cfg:
   babel_cfg_start proto_name '{'
 | babel_cfg proto_item ';'
 | babel_cfg INTERFACE babel_iface ';'
 ;


babel_iface_item:
 | PORT expr { BABEL_IFACE_CFG->port = $2; }
 | RXCOST expr { BABEL_IFACE_CFG->rxcost = $2; }
 | TX tos { BABEL_IFACE_CFG->tx_tos = $2; }
 | TX PRIORITY expr { BABEL_IFACE_CFG->tx_priority = $3; }
 | TYPE WIRED { BABEL_IFACE_CFG->type = BABEL_IFACE_TYPE_WIRED; }
 | TYPE WIRELESS { BABEL_IFACE_CFG->type = BABEL_IFACE_TYPE_WIRELESS; }
 | HELLO_INTERVAL expr { BABEL_IFACE_CFG->hello_interval = $2; }
 | UPDATE_INTERVAL expr { BABEL_IFACE_CFG->update_interval = $2; }
 ;

babel_iface_opts:
   /* empty */
 | babel_iface_opts babel_iface_item ';'
 ;

babel_iface_opt_list:
   /* empty */
 | '{' babel_iface_opts '}'
 ;

babel_iface_init:
   /* EMPTY */ {
     this_ipatt = cfg_allocz(sizeof(struct babel_iface_config));
     add_tail(&BABEL_CFG->iface_list, NODE this_ipatt);
     init_list(&this_ipatt->ipn_list);
     BABEL_IFACE_CFG->port = BABEL_PORT;
     BABEL_IFACE_CFG->rxcost = BABEL_INFINITY;
     BABEL_IFACE_CFG->type = BABEL_IFACE_TYPE_WIRED;
     BABEL_IFACE_CFG->tx_tos = IP_PREC_INTERNET_CONTROL;
     BABEL_IFACE_CFG->tx_priority = sk_priority_control;
     BABEL_IFACE_CFG->hello_interval = BABEL_INFINITY;
     BABEL_IFACE_CFG->update_interval = BABEL_INFINITY;
   }
 ;

babel_iface:	/* TODO: switch to iface_patt_list_nopx */
   babel_iface_init iface_patt_list babel_iface_opt_list
 ;

CF_ADDTO(dynamic_attr, BABEL_METRIC { $$ = f_new_dynamic_attr(EAF_TYPE_INT | EAF_TEMP, T_INT, EA_BABEL_METRIC); })

CF_CODE

CF_END
