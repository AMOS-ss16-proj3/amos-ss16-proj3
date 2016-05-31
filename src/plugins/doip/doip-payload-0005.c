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
#include "doip-payload-0005.h"

static const char *description = "routing activation request";
static gint hf_doip_payload_sa = -1; // Source address
static gint hf_doip_payload_at = -1; // Activation type
static gint hf_doip_payload_iso = -1; // Reserved by this part of ISO 13400
static gint hf_doip_payload_oem = -1; // Reserved for OEM-specific use



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
}

void
dissect_payload_0005(doip_header *header, proto_tree *tree, gint proto_doip)
{
    const guint TEST_STR_SIZE = 20;
    char *test_str;
    guint32 test;

    test_str = (char *) malloc(sizeof(char) * TEST_STR_SIZE);


    if(header && pinfo && tree && test_str)
    {
        if(get_guint32_from_message(header, &test, 0))
        {
            snprintf(test_str, TEST_STR_SIZE, "%d", test);

            col_set_str(pinfo->cinfo, COL_INFO, test_str);
        }
        else{
            col_set_str(pinfo->cinfo, COL_INFO, description);
        }
    }
}













