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
#include "doip-payload-0004.h"

/* Vehicle identification number */
static gint hf_vin = -1;  

/* Logical Address */
static gint hf_log_addr = -1;

/* Entity identification */
static gint hf_eid = -1;

/* Group identification */
static gint hf_gid = -1;

/* Further action required */
static gint hf_further_action_req = -1;

/* VIN/GID sync. status */
static gint hf_vin_gid_sync = -1;

static gint ett_vehicle_announce_id_msg = -1;

static gboolean
fill_tree(proto_tree *tree, tvbuff_t *tvb);

static const gchar *description = "Vehicle announcement message / vehicle identification response message";


/** Values are defined in ISO 13400-2:2012(E)
 * on table 20
*/
static const range_string further_action_values[] = {
	{ 0x00, 0x00, "No further action required" },
	{ 0x01, 0x0F, "Reserved by this part of ISO 13400" },
	{ 0x10, 0x10, "Routing activation required to initiate central security." },
	{ 0x11, 0xFF, "Available for additional OEM-specific use." },
	{ 0x00, 0x00, NULL}	
};

/** Values are defined in ISO 13400-2:2012(E)
* on table 21
*/
static const range_string vin_gid_sync_values[] = {
	{ 0x00, 0x00, "VIN and/or GID are synchronized" },
	{ 0x01, 0x0F, "Reserved by this part of ISO 13400" },
	{ 0x10, 0x10, "Incomplete: VIN and GID are NOT synchronized." },
	{ 0x11, 0xFF, "Reserved by this part of ISO 13400" },
	{ 0x00, 0x00, NULL }
};

/** Values are defined in ISO 13400-2:2012(E)
* on table 39
*/
static const range_string log_addr_values[] = {
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

/* values which will be displayed for payload type 0004 in proto_tree */
void
register_proto_doip_payload_0004(gint proto_doip)
{
    static hf_register_info hf[] =
    {
        /* prepare info for the header field based on ISO 13400-2:2012(E) */
        {
            &hf_vin,
            {
                "Vehicle identification number",
                "doip.payload.vin",
                FT_UINT_STRING,
                STR_ASCII,
                NULL, // TO DO: Use values of table 40 if the vid is not configured at the time of transmission of the message
                0x0,
                "The vehicle's vehicle identification number (VIN) as specified in ISO 3779.",
                HFILL
            }
        },
		{
			&hf_log_addr,
			{
				"Logical Address",
				"doip.payload.la",
				FT_UINT16,
				BASE_HEX,
				log_addr_values,
				0x0,
				"The logical address that is assigned to the responding DoIP entity. It can be used, for example, to address diagnostic requests directly to the DoIP entity.",
				HFILL
			}
		},
		{
			&hf_eid,
			{
				"Entity identification",
				"doip.payload.eid",
				FT_ETHER,
				BASE_NONE,
				NULL,
				0x0,
				"The unique identification of the DoIP entities in order to separate their responses even before the VIN is programmed to or recognized by the DoIP devices (e.g. during the vehicle assembly process).",
				HFILL
			}
		},
        {
            &hf_gid,
            {
                "Group identification",
                "doip.payload.gid",
                FT_ETHER,
                BASE_NONE,
                NULL, // TO DO: Use values of table 40 if the gid is not available
                0x0,
                "The unique identification of a group of DoIP entities within the same vehicle in the case that a VIN is not configured for that vehicle.",
                HFILL
            }
        },
        {
			&hf_further_action_req,
            {
                "Further action required",
                "doip.payload.far",
				FT_UINT8,
				BASE_HEX,
				further_action_values,
                0x0,
                "The additional information to notify the external test equipment that there are either DoIP entities with no initial connectivity or that a centralized security approach is used.",
                HFILL
            }
        },
        {
			&hf_vin_gid_sync,
            {
                "VIN/GID sync. status",
                "doip.payload.vgss",
				FT_UINT8,
				BASE_HEX,
				vin_gid_sync_values,
                0x0,
                "The additional information to notify the external test equipment that all DoIP entities have synchronized their information about the VIN or GID of the vehicle.",
                HFILL
            }
        }
    };


    static gint *ett[] = 
    {
		&ett_vehicle_announce_id_msg
    };

	/* one-time registration after Wireshark is started */
    proto_register_field_array(proto_doip, hf, array_length(hf));  
    proto_register_subtree_array(ett, array_length(ett));
}

/* After a doip row is selected in Wireshark */
void
dissect_payload_0004(doip_header *header, proto_item *pitem, packet_info *pinfo)   	
{
    tvbuff_t *tvb;
    proto_tree *doip_tree;

    /* set info column to description */
    col_set_str(pinfo->cinfo, COL_INFO, description);

    tvb = retrieve_tvbuff(header);

    /* attach a new tree to proto_item pitem */
	doip_tree = proto_item_add_subtree(pitem, ett_vehicle_announce_id_msg);

    /* check for a valid tvbuff_t */
    if(doip_tree && tvb)
    {
        fill_tree(doip_tree, tvb);
    }
}

static gboolean
fill_tree(proto_tree *tree, tvbuff_t *tvb)
{
    /* Values taken from ISO 13400-2:2012(E) table 19
    *
    * Constants starting with prefix "REL_" indicate a relative
    * offset to a doip-messages payload.
    * In order to get the absolute offset starting from the very
    * first doip-header byte we have to calculate the
    * absolute position
    */
    const gint REL_VIN_POS = 0;
    const gint VIN_LEN = 17;

    const gint REL_LOG_ADDR_POS = 17;
	const gint LOG_ADDR_LEN = 2;

	const gint REL_EID_POS = 19;
	const gint EID_LEN = 6;

	const gint REL_GID_POS = 25;
	const gint GID_LEN = 6;

	const gint REL_FURTHER_ACTION_REQ_POS = 31;
	const gint FURTHER_ACTION_REQ_LEN = 1;

	const gint REL_VIN_GID_SYNC = 32;
	const gint VIN_GID_SYNC_LEN = 1;

    gboolean error;

    error = 
		insert_item_to_tree(tree, hf_vin, tvb, REL_VIN_POS, VIN_LEN, ENC_ASCII)
		|| insert_item_to_tree(tree, hf_log_addr, tvb, REL_LOG_ADDR_POS, LOG_ADDR_LEN, ENC_BIG_ENDIAN)
		|| insert_item_to_tree(tree, hf_eid, tvb, REL_EID_POS, EID_LEN, ENC_NA)
		|| insert_item_to_tree(tree, hf_gid, tvb, REL_GID_POS, GID_LEN, ENC_NA)
		|| insert_item_to_tree(tree, hf_further_action_req, tvb, REL_FURTHER_ACTION_REQ_POS, FURTHER_ACTION_REQ_LEN, ENC_BIG_ENDIAN)
		|| insert_item_to_tree(tree, hf_vin_gid_sync, tvb, REL_VIN_GID_SYNC, VIN_GID_SYNC_LEN, ENC_BIG_ENDIAN)
    ;

    return error;
}





