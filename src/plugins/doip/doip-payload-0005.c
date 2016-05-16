
#include "doip-payload-0005.h"

void
dissect_payload_0005(doip_header *header, packet_info *pinfo, proto_tree *tree)
{
    if(header)
    {
        header = NULL;
    }
    if(pinfo)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "payload type 0x0005");
        pinfo = NULL;
    }
    if(tree)
    {
        tree = NULL;
    }
}




