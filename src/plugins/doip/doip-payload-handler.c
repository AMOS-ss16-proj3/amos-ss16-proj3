
#include "doip-payload-handler.h"

#include "doip-header.h"

#include "doip-payload-0000.h"

payload_handler
find_matching_handler(doip_header *header)
{
    return dissect_payload_0000;
    /*
    payload_handler *handler = dissect_payload_0000;
    return payload_handler;
    */
}


