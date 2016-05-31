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
#include "doip-payload-0001.h"

static gint hf_doip_payload_eid = -1;
static gint hf_doip_payload_vin = -1;

/* values which will be displayed for payload type in proto_tree */
void
register_proto_doip_payload_0001(gint proto_doip)
{
    /* nothing to do here */

    /* avoid compiler errors: */
    if(proto_doip)
    {
        proto_doip = 0;
    }
}

void
dissect_payload_0001(doip_header *header, proto_item *pitem, gint proto_doip)
{
    if(header && tree)
    {

    }
}


