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
#include "doip-payload-0006.h"


static gint hf_test_equipment_addr = -1;
static gint hf_doip_entity_addr = -1;
static gint hf_response_code = -1;
static gint hf_iso_reserved = -1;
static gint hf_oem_reserved = -1;

static gint ett_routing_activation_response = -1;

static const gchar *description = "Routing activation response";


/* helper function for filling the proto_tree
 * structure / displaying stuff
*/
static gboolean
fill_tree(proto_tree *, tvbuff_t *);


void
register_proto_doip_payload_0006(gint proto_doip)
{
    /** All "DoIP payload 0x0006" items are described at
     * ISO 13400-2:2012(E) Table 24
    */
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
            &hf_test_equipment_addr,
            {
                "Logical address of external test equipment",
                "doip.routingaddr.testequip",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_doip_entity_addr,
            {
                "Logical address of doip entity",
                "doip.routingaddr.doipentity",
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
                "doip.routing.response.code",
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
                "doip.routing.iso.reserved",
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
                "doip.routing.oem-reserved",
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
dissect_payload_0006(doip_header *header, proto_item *pitem, packet_info *pinfo)
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
    doip_tree = proto_item_add_subtree(pitem, ett_routing_activation_response);

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);

    /* check for a valid tvbuff_t */
    if(doip_tree && tvb)
    {
        fill_tree(doip_tree, tvb);
    }
}

static gboolean 
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
    const gint REL_TEST_EQUIP_ADDR_POS = 0;
    const gint TEST_EQUIP_ADDR_LEN = 2;

    const gint REL_DOIP_ENTITY_ADDR_POS = 2;
    const gint DOIP_ENTITY_ADDR_LEN = 2;

    const gint REL_RESPONSE_CODE_POS = 4;
    const gint RESPONSE_CODE_LEN = 1;

    const gint REL_ISO_RESERVED_POS = 5;
    const gint ISO_RESERVED_LEN = 4;

    const gint REL_OEM_RESERVED_POS = 9;
    const gint OEM_RESERVED_POS = 4;

    gboolean error;


    /* execute everything with a logical OR for
     * stopping evaluation automatically as soon
     * as one of the calls fails
    */
    error = 
        insert_item_to_tree(tree, hf_test_equipment_addr, tvb, REL_TEST_EQUIP_ADDR_POS, TEST_EQUIP_ADDR_LEN, ENC_BIG_ENDIAN)
        || insert_item_to_tree(tree, hf_doip_entity_addr, tvb, REL_DOIP_ENTITY_ADDR_POS, DOIP_ENTITY_ADDR_LEN, ENC_BIG_ENDIAN)
        || insert_item_to_tree(tree, hf_response_code, tvb, REL_RESPONSE_CODE_POS, RESPONSE_CODE_LEN, ENC_BIG_ENDIAN)
        || insert_item_to_tree(tree, hf_iso_reserved, tvb, REL_ISO_RESERVED_POS, ISO_RESERVED_LEN, ENC_NA)
        || insert_item_to_tree(tree, hf_oem_reserved, tvb, REL_OEM_RESERVED_POS, OEM_RESERVED_POS, ENC_NA)
    ;

    return error;
}




