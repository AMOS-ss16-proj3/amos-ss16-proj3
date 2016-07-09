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
#include "doip-payload-0006.h"

/** Logical address of external test equipment*/
static gint hf_tea = -1;
/** Logical address of DoIP entity*/
static gint hf_ea = -1;
/** Routing activation response code*/
static gint hf_rc = -1;
/** Reserved by this part of ISO 13400*/
static gint hf_iso = -1;
/** Reserved for OEM-specific use*/
static gint hf_oem = -1;

static gint ett_routing_activation_response = -1;

static const gchar *description = "Routing activation response";

/** Values are defined in ISO 13400-2:2012(E)
* on table 25
*/
static const range_string routing_actvation_response_codes[] = {
    {0x00, 0x00, "Routing activation denied due to unknown source address."},
    {0x01, 0x01, "Routing activation denied because all concurrently supported TCP_DATA sockets are registered and active."},
    {0x02, 0x02, "Routing activation denied because an SA different from the table connection entry was received on the already activated TCP_DATA socket."},
    {0x03, 0x03, "Routing activation denied because the SA is already registered and active on a different TCP_DATA socket."},
    {0x04, 0x04, "Routing activation denied due to missing authentication."},
    {0x05, 0x05, "Routing activation denied due to rejected confirmation."},
    {0x06, 0x06, "Routing activation denied due to unsupported routing activation type."},

    {0x07, 0x0F, "Reserved by this part of ISO 13400."},

    {0x10, 0x10, "Routing successfully activated."},
    {0x11, 0x11, "Routing will be activated; confirmation required."},

    {0x12, 0xDF, "Reserved by this part of ISO 13400."},

    {0xE0, 0xFE, "Vehicle-manufacturer specific."},

    {0xFF, 0xFF, "Reserved by this part of ISO 13400."},

    {0x00, 0x00, NULL}
};

/** Values are defined in ISO 13400-2:2012(E)
* on table 39
*/
static const range_string address_values[] = {
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

/* helper function for filling the proto_tree
 * structure / displaying stuff
*/
static void
fill_tree(proto_tree *, tvbuff_t *, guint32);

/* values which will be displayed for payload type 0006 in proto_tree */
void
register_proto_doip_payload_0006(gint proto_doip)
{
    static hf_register_info hf[] = 
    {
        /* prepare info for the header field based on ISO 13400-2:2012(E) table 24 */
        {
            /** Even though ISO 13400-2:2012(E), Table 39
             * gives a overview over logical addresses 
             * we will simply display the address value
             * instead of a string describing who reserved the
             * corresponding field
            */
            &hf_tea,
            {
                "Logical address of external test equipment",
                "doip.tea",
                FT_UINT16,
         BASE_HEX | BASE_RANGE_STRING,
         RVALS(address_values),
                0x0,
                "The logical address of the external test euqipment that requested routing activation.",
                HFILL
            }
        },
        {
            &hf_ea,
            {
                "Logical address of doip entity",
                "doip.ea",
                FT_UINT16,
         BASE_HEX | BASE_RANGE_STRING,
         RVALS(address_values),
                0x0,
                "The logical address of the responding DoIP entity.",
                HFILL
            }
        },
        {
            &hf_rc,
            {
                "Routing activation response code",
                "doip.rc",
                FT_UINT8,
                BASE_HEX | BASE_RANGE_STRING,
                RVALS(routing_actvation_response_codes),
                0x0,
                "Response by the DoIP gateway. Routing activation denial will result in the TCP_DATA connection being reseted by DoIP gateway. Successful routing activation implies that diagnostic messages can now be routed over the TCP_DATA connection",
                HFILL
            }
        },
        {
            &hf_iso,
            {
                "Reserved by ISO 13400",
                "doip.iso",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                "Reserved for future standardization use.",
                HFILL
            }
        },
        {
            &hf_oem,
            {
                "Reserved for OEM-specific use",
                "doip.oem",
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
    guint32 payloadLength;

    tvb = retrieve_tvbuff(header);
    /* attach a new tree to proto_item pitem */
    doip_tree = proto_item_add_subtree(pitem, ett_routing_activation_response);

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);

    payloadLength = header->payload.length;

    /* check for a valid tvbuff_t */
    if(doip_tree && tvb)
    {
        fill_tree(doip_tree, tvb, payloadLength);
    }
}

static void
fill_tree(proto_tree *tree, tvbuff_t *tvb, guint32 payloadLength)
{
    /* Values taken from ISO 13400-2:2012(E) table 24
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
    const gint OEM_RESERVED_LEN = 4;

    gboolean oemReservedIsPresent = ((gint) payloadLength) >= (REL_OEM_RESERVED_POS + OEM_RESERVED_LEN);

    insert_item_to_tree(tree, hf_tea, tvb, REL_TEST_EQUIP_ADDR_POS, TEST_EQUIP_ADDR_LEN, ENC_BIG_ENDIAN);
    insert_item_to_tree(tree, hf_ea, tvb, REL_DOIP_ENTITY_ADDR_POS, DOIP_ENTITY_ADDR_LEN, ENC_BIG_ENDIAN);
    insert_item_to_tree(tree, hf_rc, tvb, REL_RESPONSE_CODE_POS, RESPONSE_CODE_LEN, ENC_BIG_ENDIAN);
    insert_item_to_tree(tree, hf_iso, tvb, REL_ISO_RESERVED_POS, ISO_RESERVED_LEN, ENC_NA);
    if(oemReservedIsPresent)
    {
        insert_item_to_tree(tree, hf_oem, tvb, REL_OEM_RESERVED_POS, OEM_RESERVED_LEN, ENC_NA);
    }
}




