/**
* Copyright 2016 The Open Source Research Group,
*                University of Erlangen-Nürnberg
*
* Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     https://www.gnu.org/licenses/gpl.html
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


#include "config.h"
#include <epan/proto.h>

#include "doip-header.h"
#include "doip-payload-4001.h"

static const gchar *description = "DoIP status request";

/* values which will be displayed for payload type in proto_tree */
void
register_proto_doip_payload_4001(gint proto_doip)
{

    /** According to ISO 13400-2:2012(E) (page 40, table 36) 
     * payload type 0x4001 does not contain any other data
     * besides the doip-header.
     * Therefore there is this payload-handler doesn't have to
     * display anything
    */

    /* suppress compiler warning */
    if(proto_doip)
    {
        proto_doip = 0;
    }
}

void
dissect_payload_4001(doip_header *header, proto_item *pitem, packet_info *pinfo)
{
    /** See comment at register_proto_doip_payload_4001()
    */

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);


    /* suppress compiler warning */
    if(header && pitem)
    {
        header = NULL;
        pitem = NULL;
    }
}


