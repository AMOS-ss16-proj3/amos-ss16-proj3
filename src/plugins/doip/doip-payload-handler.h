
#ifndef __DOIP_PAYLOAD_HANDLER_H
#define __DOIP_PAYLOAD_HANDLER_H

#include "config.h"
#include <epan/packet.h>

#include "doip-header.h"

typedef
void (*payload_handler)(doip_header *, packet_info *, proto_tree *);

payload_handler
find_matching_payload_handler(doip_header *);



#endif /* __DOIP_PAYLOAD_HANDLER_H */


