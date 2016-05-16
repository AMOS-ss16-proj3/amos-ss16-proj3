
#include "doip-payload-0000.h"

void
dissect_payload_0000(doip_header *header, packet_info *pinfo, proto_tree *tree)
{
    if(header)
    {
        header = NULL;
    }
    if(pinfo)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "payload type 0x0000");
        pinfo = NULL;
    }
    if(tree)
    {
        tree = NULL;
    }
}




