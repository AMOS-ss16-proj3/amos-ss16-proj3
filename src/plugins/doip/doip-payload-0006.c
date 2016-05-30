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
#include "doip-payload-0006.h"

/*
static const char *description = "routing activation response";
*/

static gint hf_test_equipment_address = -1;
static gint hf_doip_entity_address = -1;
/*static gint response_code = -1;*/

static gint ett_routing_activation_response = -1;

void
register_proto_doip_payload_0006(gint proto_doip)
{
    
    static hf_register_info hf[] = 
    {
        /* prepare info for version */
        {
            /** Even though ISO 13400-2:2012(E), Table 39
             * gives a overview over logical addresses 
             * we will simply display the address value
             * instead of a string describing who reserved the
             * corresponding field
            */
            &hf_test_equipment_address,
            {
                "Logical address of external test equipment",
                "doip.payload.routing.activation.response",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_doip_entity_address,
            {
                "Logical address of doip entity",
                "doip.payload.routing.activation.response",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        }
    };

    static gint *ett[] = 
    {
        &ett_routing_activation_response,
    };

    proto_register_field_array(proto_doip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
dissect_payload_0006(doip_header *header, proto_tree *tree, gint proto_doip)
{
    tvbuff_t *tvb;
    proto_item *ti;
    proto_tree *doip_tree;

    tvb = retrieve_tvbuff(header);

    if(proto_doip > 0)
    {
        proto_doip = 1;
    }

    if(header && tree && tvb)
    {
        ti = proto_tree_add_item(tree, proto_doip, tvb, 8, -1, ENC_NA);
        doip_tree = proto_item_add_subtree(ti, ett_routing_activation_response);

        proto_tree_add_item(doip_tree, hf_test_equipment_address, tvb, 8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_entity_address, tvb, 10, 2, ENC_BIG_ENDIAN);

        /*
        doip_rar = proto_tree_add_item(tree, proto_amin, tvb, 0, -1, FALSE);
        amin_tree = proto_item_add_subtree(amin_item, ett_amin);
        */




        
    }
}













