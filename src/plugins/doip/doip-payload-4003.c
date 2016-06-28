/**
* Copyright 2017 The Open Source Research Group,
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
#include "doip-helper.h"
#include "doip-payload-4003.h"

static const gchar *description = "Diagnostic power mode information request";

/* values which will be displayed for payload type 4003 in proto_tree */
void
register_proto_doip_payload_4003(gint proto_doip)
{
    /* suppress compiler warning */
    if(proto_doip)
    {
        proto_doip = 0;
    }
}

/* After a doip row is selected in Wireshark */
void
dissect_payload_4003(doip_header *header, proto_item *pitem, packet_info *pinfo)
{
    if(pinfo)
    {
        /* set info column to description */
        col_set_str(pinfo->cinfo, COL_INFO, description);
    }
    
    /* suppress compiler warning */
    if(header && pitem)
    {
        header = NULL;
    }

}


