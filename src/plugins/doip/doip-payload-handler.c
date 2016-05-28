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

#include "doip-header.h"
#include "visualize-doip-header.h"

/* TODO not fully implemented yet
*/
#include "doip-payload-0001.h"

#include "doip-payload-handler.h"

payload_handler
find_matching_payload_handler(doip_header *header)
{
    payload_handler handler = NULL;

    if(header)
    {
        switch(header->payload.type)
        {
            case 0x0001:
                handler = dissect_payload_0001;
                break;
            /** TODO dissect_payload_type is not fully implemented yet
            */
            default:
                handler = NULL;
                break;
        }
    }
    return handler;
}

void
register_proto_doip_payload(gint proto_doip)
{
    /* prepare proto entries for header */
    register_proto_doip_header(proto_doip);

    /* prepare proto entries for payload type 0000 */
    register_proto_doip_payload_0001(proto_doip);
    /* TODO not fully implemented yet
    */
}


