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
#include "doip-payload-0005.h"

static gint hf_doip_payload_sa = -1; /* Source address */
static gint hf_doip_payload_at = -1; /* Activation type */
static gint hf_doip_payload_iso = -1; /* Reserved by this part of ISO 13400 */
static gint hf_doip_payload_oem = -1; /* Reserved for OEM-specific use */

static gint ett_routing_activation_request = -1;

static gboolean
fill_tree(proto_tree *tree, tvbuff_t *tvb);

/* values which will be displayed for payload type 0005 in proto_tree */
void
register_proto_doip_payload_0005(gint proto_doip)
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
                BASE_HEX,
                NULL,
                0x0,
                "A address of the external test equipment that requests routing activation. This is the same address that is used by the external test equipment when sending diagnostic messages on the same TCP_DATA socket",
                HFILL
            }
        },
        {
            &hf_doip_payload_at,
            {
                "Activation type",
                "doip.payload.at",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                "Specific type of routing activation that may require different types of authentication and/or confirmation",
                HFILL
            }
        },
        {
            &hf_doip_payload_iso,
            {
                "Reserved by ISO",
                "doip.payload.iso",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "Reserved for future standardization use",
                HFILL
            }
        },
        {
            &hf_doip_payload_oem,
            {
                "Reserved for OEM",
                "doip.payload.oem",
                FT_UINT32,
                BASE_HEX,
                NULL,
                0x0,
                "Available for additional OEM-specific use",
                HFILL
            }
        }
    };


    static gint *ett[] = 
    {
        &ett_routing_activation_request 
    };

    proto_register_field_array(proto_doip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
dissect_payload_0005(doip_header *header, proto_item *pitem)
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
    doip_tree = proto_item_add_subtree(pitem, ett_routing_activation_request);

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
    const gint REL_SOURCE_ADDR_POS = 0;
    const gint SOURCE_ADDR_LEN = 2;

    /*
    const gint REL_ACT_TYPE_POS = 2;
    const gint ACT_TYPE_LEN = 1;

    const gint REL_ISO_RESERVED_POS = 3;
    const gint ISO_RESERVED_LEN = 4;

    const gint REL_OEM_RESERVED_POS = 7;
    const gint OEM_RESERVED_LEN = 4;
    */

    gboolean error;

    error = 
        insert_item_to_tree(tree, hf_doip_payload_sa, tvb, REL_SOURCE_ADDR_POS, SOURCE_ADDR_LEN, ENC_BIG_ENDIAN);

    return error;
}





