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
    static hf_register_info hf[] = 
    {
        /* prepare info for version */
        {
            &hf_doip_payload_eid,
            {
                "Entity Id",
                "doip.payload.eid",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                "A DoIP entities unique ID (e.g. network interface's MAC address) that shall respond to the vehicle identification request message",
                HFILL
            }
        },
        {
            &hf_doip_payload_vin,
            {
                "Vehicle identification number",
                "doip.payload.vin",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "A vehicle's identification number as specified in ISO 3779. This parameter is only present if the external test equipment intends to identify the DoIP entities of an individual vehicle, the VIN of which is known to the test external test equipment.",
                HFILL
            }
        }
    };
           
    /*
    static gint *ett[] = 
    {
        &ett_doip
    };

    proto_register_field_array(proto_doip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    */
}

void
dissect_payload_0001(doip_header *header, proto_tree *tree, gint proto_doip)
{
    if(header && tree)
    {

    }
}


