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
#include "doip-helper.h"
#include "doip-payload-0002.h"

/* Entity identification */
static gint hf_eid = -1;

static gint ett_vehicle_identification_request_eid = -1;

static void
fill_tree(proto_tree *tree, tvbuff_t *tvb);

static const gchar *description = "Vehicle identification request message with Entity Identification (EID)";


/* values which will be displayed for payload type 0002 in proto_tree */
void
register_proto_doip_payload_0002(gint proto_doip)
{
    static hf_register_info hf[] =
    {
        /* prepare info for the header field based on ISO 13400-2:2012(E) */
        {
            &hf_eid,
            {
                "Entity identification",
                "doip.payload.eid",
                FT_ETHER,
                BASE_NONE,
                NULL,
                0x0,
				"The DoIP entity's unique ID (e.g. network interface's MAC address) \
                that shall respond to the vehicle identification request message.",
                HFILL
            }
        }
    };


    static gint *ett[] = 
    {
		&ett_vehicle_identification_request_eid
    };

	/* one-time registration after Wireshark is started */
    proto_register_field_array(proto_doip, hf, array_length(hf));  
    proto_register_subtree_array(ett, array_length(ett));
}

/* After a doip row is selected in Wireshark */
void
dissect_payload_0002(doip_header *header, proto_item *pitem, packet_info *pinfo)   	
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
	doip_tree = proto_item_add_subtree(pitem, ett_vehicle_identification_request_eid);

    /* check for a valid tvbuff_t */
    if(doip_tree && tvb)
    {
        fill_tree(doip_tree, tvb);
    }
}

static void
fill_tree(proto_tree *tree, tvbuff_t *tvb)
{
    /* Values taken from ISO 13400-2:2012(E) page 32
    *
    * Constants starting with prefix "REL_" indicate a relative
    * offset to a doip-messages payload.
    * In order to get the absolute offset starting from the very
    * first doip-header byte we have to calculate the
    * absolute position
    */
    const gint REL_EID_POS = 0;
    const gint EID_LEN = 6;

	insert_item_to_tree(tree, hf_eid, tvb, REL_EID_POS, EID_LEN, ENC_NA);
}





