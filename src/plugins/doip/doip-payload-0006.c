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
static gint hf_response_code = -1;
static gint hf_iso_reserved = -1;
static gint hf_oem_reserved = -1;

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
                "doip.payload.routing.entity.address",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_response_code,
            {
                "Routing activation response code",
                "doip.payload.routing.response.code",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                "Response by the DoIP gateway. Routing activation denial will result in the TCP_DATA connection being reseted by DoIP gateway. Successful routing activation implies that diagnostic messages can now be routed over the TCP_DATA connection",
                HFILL
            }
        },
        {
            &hf_iso_reserved,
            {
                "Reserved by ISO 13400",
                "doip.payload.routing.iso.reserved",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                "Reserved for future standardization use.",
                HFILL
            }
        },
        {
            &hf_oem_reserved,
            {
                "Reserved for OEM-specific use",
                "doip.payload.routing.oem-reserved",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                "Available for additional OEM-specific use",
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
dissect_payload_0006(doip_header *header, proto_item *pitem)
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    tvb = retrieve_tvbuff(header);

    if(header && tvb)
    {
        doip_tree = proto_item_add_subtree(pitem, ett_routing_activation_response);

        proto_tree_add_item(doip_tree, hf_test_equipment_address, tvb, 8, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_entity_address, tvb, 10, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_response_code, tvb, 12, 1, ENC_BIG_ENDIAN);
        
        proto_tree_add_item(doip_tree, hf_iso_reserved, tvb, 13, 4, ENC_NA);
        proto_tree_add_item(doip_tree, hf_oem_reserved, tvb, 17, 4, ENC_NA);

    }
}













