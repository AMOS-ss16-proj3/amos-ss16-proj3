
#ifndef __PACKET_DOIP_H
#define __PACKET_DOIP_H

#include "config.h"

#include <epan/packet.h>

static void
dissect_doip_tcp(tvbuff_t *, packet_info *, proto_tree *);

static void
dissect_doip_udp(tvbuff_t *, packet_info *, proto_tree *);

static void
register_udp_test_equipment_messages(proto_tree *);

#endif // __PACKET_DOIP_H
