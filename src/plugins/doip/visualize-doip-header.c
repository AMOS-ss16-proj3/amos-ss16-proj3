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
#include "visualize-doip-header.h"

/* TEST */
static gint hf_test_equipment_address = -1;
static gint ett_test_equipment_address = -1;

/* constants describing various header-fields */
static const gint VERSION_POSITION = 0;
static const gint VERSION_LENGTH = 1;

static const gint INVERSE_VERSION_POSITION = 1;
static const gint INVERSE_VERSION_LENGTH = 1;

static const gint PAYLOAD_TYPE_POSITION = 2;
static const gint PAYLOAD_TYPE_LENGTH = 2;

static const gint PAYLOAD_LENGTH_POSITION = 4;
static const gint PAYLOAD_LENGTH_LENGTH = 4;


/* variables required for proto_tree */
static gint hf_doip_version = -1;
static gint hf_doip_inverse_version = -1;
static gint hf_doip_payload_type = -1;
static gint hf_doip_payload_length = -1;

static gint ett_doip = -1;


/* value_strings which will be displayed for version in proto_tree */
static const range_string doip_version_names[] = {
    { 0x00, 0x00, "Reserved"},
    { 0x01, 0x01, "DoIP ISO/DIS 13400-2:2010"},
    { 0x02, 0x02, "DoIP ISO 13400-2:2012"},
    { 0x03, 0xFE, "Reserved by ISO 13400"},
    { 0xFF, 0xFF, "Default value for vehicle identification request messages"},
    { 0x00, 0x00, NULL}
};

/* values which will be displayed for payload type in proto_tree */
static const range_string packet_type_names[] = {
    { 0x0000, 0x0000, "Generic DoIP header negative acknowledge" },
    { 0x0001, 0x0001, "Vehicle identification request message" },
    { 0x0002, 0x0002, "Vehicle identification request message with EID" },
    { 0x0003, 0x0003, "Vehicle identification request message with VID" },
    { 0x0004, 0x0004, "Vehicle announcement message/vehicle identification response message" },
    { 0x0005, 0x0005, "Routing activation request" },
    { 0x0006, 0x0006, "Routing activation response" },
    { 0x0007, 0x0007, "Alive check request" },
    { 0x0008, 0x0008, "Alive check response" },

    { 0x0009, 0x4000, "Reserved by this part of ISO 13400" },

    { 0x4001, 0x4001, "DoIP entity status request" },
    { 0x4002, 0x4002, "DoIP entity status response" },
    { 0x4003, 0x4003, "Diagnostic power mode activation request" },
    { 0x4004, 0x4004, "Diagnostic power mode activation response" },

    { 0x4005, 0x8000, "Reserved by this part of ISO 13400"},

    { 0x8001, 0x8001, "Diagnostic message" },
    { 0x8002, 0x8002, "Diagnostic message positive acknowledgement" },
    { 0x8003, 0x8003, "Diagnostic message negative acknowledgement" },
    { 0x8004, 0xEFFF, "Reserved by this part of ISO 13400"},
    { 0xF000, 0xFFFF, "Reserved for manufacturer-specific use"},
    { 0x0000, 0x0000, NULL }
};

void
register_proto_doip_header(gint proto_doip)
{
    static hf_register_info hf[] = 
    {
        /* prepare info for version */
        {
            &hf_doip_version,
            {
                "Version",
                "doip.version",
                FT_UINT8,
                BASE_DEC | BASE_RANGE_STRING,
                RVALS(doip_version_names),
                0x0,
                NULL,
                HFILL
            }
        },
        /* prepare info for inverse version */
        {
            &hf_doip_inverse_version,
            {
                "Inverse Version",
                "doip.iversion",
                FT_UINT8,
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        /* prepare info for payload type */
        {
            &hf_doip_payload_type,
            {
                "Payload Type",
                "doip.type",
                FT_UINT16,
                BASE_HEX | BASE_RANGE_STRING,
                RVALS(packet_type_names),
                0x0,
                NULL,
                HFILL
            }
        },
        /* prepare info for payload length */
        {
            &hf_doip_payload_length,
            {
                "Payload Length", 
                "doip.payload.length",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        }
    };


    static hf_register_info hf2[] = 
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
        }
    };

    static gint *ett[] = 
    {
        &ett_doip
    };

    static gint *ett2[] = 
    {
        &ett_test_equipment_address
    };

    proto_register_field_array(proto_doip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    proto_register_field_array(proto_doip, hf2, array_length(hf2));
    proto_register_subtree_array(ett2, array_length(ett2));

}



void
visualize_doip_header(doip_header *header, proto_item *pitem)
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    tvb = retrieve_tvbuff(header);

    if(header && tvb)
    {
        doip_tree = proto_item_add_subtree(pitem, ett_doip);

        proto_tree_add_item(doip_tree, hf_doip_version, tvb, VERSION_POSITION, VERSION_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_inverse_version, tvb, INVERSE_VERSION_POSITION, INVERSE_VERSION_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_payload_type, tvb, PAYLOAD_TYPE_POSITION, PAYLOAD_TYPE_LENGTH, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_payload_length, tvb, PAYLOAD_LENGTH_POSITION, PAYLOAD_LENGTH_LENGTH, ENC_BIG_ENDIAN);

    }
}

