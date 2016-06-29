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
#include "doip-payload-8003.h"

/* Source address */
static gint hf_src_addr = -1; 

/* Target address */
static gint hf_target_addr = -1; 

/* Ack code */
static gint hf_nack_code = -1;

/* Previous diagnostic message data */
static gint hf_prev_diag_msg_data = -1;

static gint ett_diag_msg_pos_resp = -1;

/** Possible values for negative acknoledges
 * Values taken and description from ISO 13400-2:2012(E)
 * page 38 table 31.
*/
static const range_string nack_codes[] = 
{
    {0x00, 0x01, "Reserved by this part of ISO 13400"},
    {0x02, 0x02, "Invalid source address"},
    {0x02, 0x02, "Invalid source address"},
    {0x03, 0x03, "Unknown target address"},
    {0x04, 0x04, "Diagnostic message too large"},
    {0x05, 0x05, "Out of memory"},
    {0x06, 0x06, "Target unreachable"},
    {0x07, 0x07, "Unknown network"},
    {0x08, 0x08, "Transport protocol error"},
    {0x09, 0xFF, "Reserved by this part of ISO 13400"},
    {0x00, 0x00, NULL}
};

static void
fill_tree(doip_header *, proto_tree *tree, tvbuff_t *tvb);

static const gchar *description = "Diagnostic message negative acknowledge";

void
register_proto_doip_payload_8003(gint proto_doip)
{
    static hf_register_info hf[] =
    {
        /* prepare info for the header field
         * based on ISO 13400-2:2012(E) page 37, table 30
        */
        {
            &hf_src_addr,
            {
                "Source address",
                "doip.payload.sa",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                "Contains the logical address of the (intended) \
                receiver of the previous diagnostic message (e.g. \
                a specific ECU on the vehicle’s networks).",
                HFILL
            }
        },
        {
            &hf_target_addr,
            {
                "Target address",
                "doip.payload.ta",
                FT_UINT16,
                BASE_HEX,
                NULL,
                0x0,
                "Contains the logical address of the sender of the \
previous diagnostic message (i.e. the external \
test equipment address).",
                HFILL
            }
        },
        {
            &hf_nack_code,
            {
                "NACK code",
                "doip.payload.nack",
                FT_UINT8,  
                BASE_HEX | BASE_RANGE_STRING,
                RVALS(nack_codes),
                0x0,
                "Contains the diagnostic message negative acknowledge code.",
                HFILL
            }
        },
        {
            &hf_prev_diag_msg_data,
            {
                "Previous diagnostic message data",
                "doip.payload.ackcode",
                FT_BYTES,  
                BASE_NONE,
                NULL,
                0x0,
                "Currently acknowledged diagnostic message",
                HFILL
            }
        }
    };


    static gint *ett[] = 
    {
        &ett_diag_msg_pos_resp 
    };

	/* one-time registration after Wireshark is started */
    proto_register_field_array(proto_doip, hf, array_length(hf));  
    proto_register_subtree_array(ett, array_length(ett));
}

/* After a doip row is selected in Wireshark */
void
dissect_payload_8003(doip_header *header, proto_item *pitem, packet_info *pinfo)   	
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
    doip_tree = proto_item_add_subtree(pitem, ett_diag_msg_pos_resp);

    /* check for a valid tvbuff_t */
    if(doip_tree && tvb)
    {
        fill_tree(header, doip_tree, tvb);
    }
}

static void
fill_tree(doip_header *header, proto_tree *tree, tvbuff_t *tvb)
{
    /* Values taken from ISO 13400-2:2012(E) page 37 table 30
    *
    * Constants starting with prefix "REL_" indicate a relative
    * offset to a doip-messages payload.
    * In order to get the absolute offset starting from the very
    * first doip-header byte we have to calculate the
    * absolute position
    */
    const gint REL_SRC_ADDR_POS = 0;
    const gint SRC_ADDR_LEN = 2;

    const gint REL_TARGET_ADDR_POS = 2;
    const gint TARGET_ADDR_LEN = 2;

    const gint REL_NACK_CODE_POS = 4;
    const gint NACK_CODE_LEN = 1;

    const gint REL_PREV_DIAG_MSG_POS = 5;

    gint payload_len;
    gboolean has_prev_diag_msg;
    gint prev_diag_msg_len;

    payload_len = header->payload.length;
    has_prev_diag_msg = payload_len > REL_PREV_DIAG_MSG_POS;

    insert_item_to_tree(tree, hf_src_addr, tvb, REL_SRC_ADDR_POS, SRC_ADDR_LEN, ENC_BIG_ENDIAN);
    insert_item_to_tree(tree, hf_target_addr, tvb, REL_TARGET_ADDR_POS, TARGET_ADDR_LEN, ENC_BIG_ENDIAN);
    insert_item_to_tree(tree, hf_nack_code, tvb, REL_NACK_CODE_POS, NACK_CODE_LEN, ENC_BIG_ENDIAN);

    if(has_prev_diag_msg)
    {
        prev_diag_msg_len = payload_len - REL_PREV_DIAG_MSG_POS;
        insert_item_to_tree(tree, hf_prev_diag_msg_data, tvb, REL_PREV_DIAG_MSG_POS, prev_diag_msg_len, ENC_NA);
    }
}

