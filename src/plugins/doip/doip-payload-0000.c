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
#include <epan/column-utils.h>
#include <epan/proto.h>

#include "doip-header.h"
#include "doip-helper.h"
#include "doip-payload-0000.h"

/* Generic DoIP header NACK code */
static gint hf_nc = -1; 

static gint ett_nack_codes = -1;

static void
fill_tree(proto_tree *tree, tvbuff_t *tvb);

static const gchar *description = "Generic DoIP header NACK code";
static const gchar *description_format = "Generic DoIP header NACK code [NACK: %#x]";


/** Values are defined in ISO 13400-2:2012(E)
 * on table 14
*/
static const range_string nack_codes[] = {
    { 0x00, 0x00, "Incorrect pattern format" },
    { 0x01, 0x01, "Unknown payload type" },
    { 0x02, 0x02, "Message too large" },
    { 0x03, 0x03, "Out of memory" },
    { 0x04, 0x04, "Invalid payload lenght" },
    { 0x05, 0xFF, "Reserved by this part of ISO 13400"}    
};


/* values which will be displayed for payload type 0000 in proto_tree */
void
register_proto_doip_payload_0000(gint proto_doip)
{
    static hf_register_info hf[] =
    {
        /* prepare info for the header field based on ISO 13400-2:2012(E) table 13 */
        {
            &hf_nc,
            {
                "Generic DoIP header NACK code",
                "doip.nack",
                FT_UINT8,
                BASE_HEX | BASE_RANGE_STRING,
                RVALS(nack_codes),
                0x0,
                "The generic header negative acknoledge code indicates the specific error that was detected in the generic DoIP header or it indicates an unsupported payload or a memory overload condition",
                HFILL
            }
        }
    };

    static gint *ett[] = 
    {
        &ett_nack_codes 
    };

    /* one-time registration after Wireshark is started */
    proto_register_field_array(proto_doip, hf, array_length(hf));  
    proto_register_subtree_array(ett, array_length(ett));
}

/* After a doip row is selected in Wireshark */
void
dissect_payload_0000(doip_header *header, proto_item *pitem, packet_info *pinfo)       
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    guint8 nack_code;

    /* set info column to description */
    if(get_guint8_from_message(header, &nack_code, 0))
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, description_format, nack_code);
    }
    else
    {
        col_set_str(pinfo->cinfo, COL_INFO, description);
    }

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
    doip_tree = proto_item_add_subtree(pitem, ett_nack_codes);

    /* check for a valid tvbuff_t */
    if(doip_tree && tvb)
    {
        fill_tree(doip_tree, tvb);
    }
}

static void
fill_tree(proto_tree *tree, tvbuff_t *tvb)
{
    /* Values taken from ISO 13400-2:2012(E) table 13
    *
    * Constants starting with prefix "REL_" indicate a relative
    * offset to a doip-messages payload.
    * In order to get the absolute offset starting from the very
    * first doip-header byte we have to calculate the
    * absolute position
    */
    const gint REL_HEADER_NACK_CODE_POS = 0;
    const gint HEADER_NACK_LEN = 1;

    insert_item_to_tree(tree, hf_nc, tvb, REL_HEADER_NACK_CODE_POS, HEADER_NACK_LEN, ENC_BIG_ENDIAN);
}





