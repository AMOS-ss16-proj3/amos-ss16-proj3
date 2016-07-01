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
#include "doip-payload-0003.h"

/* Vehicle identification number */
static gint hf_vin = -1;

static gint ett_vehicle_identification_request_vin = -1;

static void
fill_tree(proto_tree *tree, tvbuff_t *tvb);

static const gchar *description = "Vehicle identification request message with vehicle identification number (VIN)";


/* values which will be displayed for payload type 0003 in proto_tree */
void
register_proto_doip_payload_0003(gint proto_doip)
{
    static hf_register_info hf[] =
    {
	/* prepare info for the header field based on ISO 13400-2:2012(E) */
	{
	    &hf_vin,
	    {
		"Vehicle identification number",
		"doip.vin",
		FT_STRING,
		STR_ASCII,
		NULL,
		0x0,
		"The vehicle's vehicle identification number (VIN) as specified in ISO 3779.",
		HFILL
	    }
	}
    };


    static gint *ett[] = 
    {
		&ett_vehicle_identification_request_vin
    };

/* one-time registration after Wireshark is started */
    proto_register_field_array(proto_doip, hf, array_length(hf));  
    proto_register_subtree_array(ett, array_length(ett));
}

/* After a doip row is selected in Wireshark */
void
dissect_payload_0003(doip_header *header, proto_item *pitem, packet_info *pinfo)   	
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
	doip_tree = proto_item_add_subtree(pitem, ett_vehicle_identification_request_vin);

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
    const gint REL_VIN_POS = 0;
    const gint VIN_LEN = 17;

	insert_item_to_tree(tree, hf_vin, tvb, REL_VIN_POS, VIN_LEN, ENC_ASCII);
}





