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
#include "visualize-doip-header.h"



static gint hf_doip_version = -1;
static gint hf_doip_inverse_version = -1;
static gint hf_doip_payload_type = -1;
static gint hf_doip_payload_length = -1;
static gint ett_doip = -1;


static const value_string doip_version_names[] = {
    { 0x00, "Reserved"},
    { 0x01, "DoIP ISO/DIS 13400-2:2010"},
    { 0x02, "DoIP ISO 13400-2:2012"},
    { 0xFF, "Default value for vehicle identification request messages"}
};

static const value_string packet_type_names[] = {
    { 0x0000, "Generic DoIP header negative acknowledge" },
    { 0x0001, "Vehicle identification request message" },
    { 0x0002, "Vehicle identification request message with EID" },
    { 0x0003, "Vehicle identification request message with VID" },
    { 0x0004, "Vehicle announcement message/vehicle identification response message" },
    { 0x0005, "Routing activation request" },
    { 0x0006, "Routing activation response" },
    { 0x0007, "Alive check request" },
    { 0x0008, "Alive check response" },

    { 0x4001, "DoIP entity status request" },
    { 0x4002, "DoIP entity status response" },
    { 0x4003, "Diagnostic power mode activation request" },
    { 0x4004, "Diagnostic power mode activation response" },

    { 0x8001, "Diagnostic message" },
    { 0x8002, "Diagnostic message positive acknowledgement" },
    { 0x8003, "Diagnostic message negative acknowledgement" },
    { 0, NULL }
};

void
register_proto_doip_header(gint proto_doip)
{
    static hf_register_info hf[] = 
    {
        {
            &hf_doip_version,
            {
                "Version", "doip.version",
                FT_UINT8, BASE_DEC,
                VALS(doip_version_names), 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_doip_inverse_version,
            {
                "Inverse Version", "doip.iversion",
                FT_UINT8, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_doip_payload_type,
            {
                "Payload Type", "doip.payload.type",
                FT_UINT16, BASE_HEX,
                VALS(packet_type_names), 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_doip_payload_length,
            {
                "Payload Length", "doip.payload.length",
                FT_UINT32, BASE_DEC,
                NULL, 0x0,
                NULL, HFILL
            }
        }
    };

    static gint *ett[] = 
    {
        &ett_doip
    };

    proto_register_field_array(proto_doip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}


void
visualize_doip_header(doip_header *header, proto_tree *tree, gint proto_doip)
{
    proto_tree *doip_tree;
    gint doip_length;
    proto_item *ti;
    tvbuff_t *tvb;

    if(header && tree)
    {
        tvb = retrieve_tvbuff(header);
        doip_length = get_total_doip_package_length(header);

        ti = proto_tree_add_item(tree, proto_doip, tvb, 0, doip_length, ENC_NA);
        doip_tree = proto_item_add_subtree(ti, ett_doip);
        proto_tree_add_item(doip_tree, hf_doip_version, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_inverse_version, tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_payload_type, tvb, 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(doip_tree, hf_doip_payload_length, tvb, 4, 4, ENC_BIG_ENDIAN);
    }
}

