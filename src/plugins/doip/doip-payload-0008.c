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
#include "doip-payload-0008.h"

/* Source address */
static gint hf_doip_payload_sa = -1; 

static gint ett_alive_check_response = -1;

static void
fill_tree(proto_tree *tree, tvbuff_t *tvb);

static const gchar *description = "Alive check response";

static const range_string source_address_values[] = {
    { 0x0000, 0x0000, "ISO/SAE reserved" },
    { 0x0001, 0x0DFF, "Vehicle manufacturer specific" },
    { 0x0E00, 0x0FFF, "Reserved for addresses of external test equipment" },
    { 0x0E00, 0x0E7F, "External legislated diagnostics test equipment (e.g. for emissions test scan-tool use)" },
    { 0x0E80, 0x0EFF, "External vehicle-manufacturer-/aftermarket-enhanced diagnostics test equipment" },
    { 0x0F00, 0x0F7F, "Internal data collection/on-board diagnostic equipment (for vehicle-manufacturer use only)" },
    { 0x0F80, 0x0FFF, "External prolonged data collection equipment (vehicle data recorders and loggers, e.g. used by insurance companies or to collect vehicle fleet data)" },
    { 0x1000, 0x7FFF, "Vehicle manufacturer specific" },
    { 0x8000, 0xCFFF, "ISO/SAE reserved" },
    { 0xD000, 0xDFFF, "Reserved for SAE Truck & Bus Control and Communication Committee" },
    { 0xE000, 0xE3FF, "ISO/SAE-reserved functional group addresses" },
    { 0xE000, 0xE000, "ISO 27145 WWH-OBD functional group address" },
    { 0xE001, 0xE3FF, "ISO/SAE reserved" },
    { 0xE400, 0xEFFF, "Vehicle-manufacturer-defined functional group logical addresses" },
    { 0xF000, 0xFFFF, "ISO/SAE reserved" },
    { 0x0000, 0x0000, NULL }
};




/* values which will be displayed for payload type 0008 in proto_tree */
void
register_proto_doip_payload_0008(gint proto_doip)
{
    static hf_register_info hf[] =
    {
        /* prepare info for the header field based on ISO 13400-2:2012(E) */
        {
            &hf_doip_payload_sa,
            {
                "Source address",
                "doip.payload.sa",
                FT_UINT16,
                BASE_HEX | BASE_RANGE_STRING,
                RVALS(source_address_values),
                0x0,
                "Contains the logical address of the external test equipment that is currently active on this TCP_DATA socket.",
                HFILL
            }
        }
    };


    static gint *ett[] = 
    {
        &ett_alive_check_response
    };

    /* one-time registration after Wireshark is started */
    proto_register_field_array(proto_doip, hf, array_length(hf));  
    proto_register_subtree_array(ett, array_length(ett));
}

/* After a doip row is selected in Wireshark */
void
dissect_payload_0008(doip_header *header, proto_item *pitem, packet_info *pinfo)
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
    doip_tree = proto_item_add_subtree(pitem, ett_alive_check_response);

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
    const gint REL_SOURCE_ADDR_POS = 0;
    const gint SOURCE_ADDR_LEN = 2;

    insert_item_to_tree(tree, hf_doip_payload_sa, tvb, REL_SOURCE_ADDR_POS, SOURCE_ADDR_LEN, ENC_BIG_ENDIAN);
}





