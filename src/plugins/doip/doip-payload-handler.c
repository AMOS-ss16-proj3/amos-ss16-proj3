
#include "doip-payload-handler.h"

#include "doip-header.h"
#include "doip-payload-0000.h"

payload_handler
find_matching_payload_handler(doip_header *header)
{
    payload_handler handler = NULL;
    if(header)
    {
        switch(header->payload_type)
        {
            case 0x0000:
                handler = dissect_payload_0000;
                break;

            default:
                break;
        }
    }
    return handler;
}


