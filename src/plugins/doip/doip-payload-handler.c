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

#include "doip-payload-0000.h"
#include "doip-payload-0001.h"
#include "doip-payload-0002.h"
#include "doip-payload-0003.h"
#include "doip-payload-0004.h"
#include "doip-payload-0005.h"
#include "doip-payload-0006.h"
#include "doip-payload-0007.h"
#include "doip-payload-0008.h"
#include "doip-payload-4001.h"
#include "doip-payload-8001.h"
#include "doip-payload-8002.h"
#include "doip-payload-8003.h"

#include "doip-payload-handler.h"

payload_handler
find_matching_payload_handler(doip_header *header)
{
    payload_handler handler = NULL;

    if(header)
    {
        switch(header->payload.type)
        {
            case 0x0000:
                handler = dissect_payload_0000;
                break;
            case 0x0001:
                handler = dissect_payload_0001;
                break;
            case 0x0002:
                handler = dissect_payload_0002;
                break;
            case 0x0003:
                handler = dissect_payload_0003;
                break;
            case 0x0004:
                handler = dissect_payload_0004;
                break;
            case 0x0005:
                handler = dissect_payload_0005;
                break;
            case 0x0006:
                handler = dissect_payload_0006;
                break;
            case 0x0007:
                handler = dissect_payload_0007;
                break;
            case 0x0008:
                handler = dissect_payload_0008;
                break;
            case 0x4001:
                handler = dissect_payload_4001;
                break;
            case 0x8001:
                handler = dissect_payload_8001;
                break;
            case 0x8002:
                handler = dissect_payload_8002;
                break;
            case 0x8003:
                handler = dissect_payload_8003;
                break;
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

    /* prepare proto entries for payload type 0x0000 */
    register_proto_doip_payload_0000(proto_doip);
    
    /* prepare proto entries for payload type 0x0001 */
    register_proto_doip_payload_0001(proto_doip);

    /* prepare proto entries for payload type 0x0002 */
    register_proto_doip_payload_0002(proto_doip);

    /* prepare proto entries for payload type 0x0003 */
    register_proto_doip_payload_0003(proto_doip);

    /* prepare proto entries for payload type 0x0004 */
    register_proto_doip_payload_0004(proto_doip);

    /* prepare proto entries for payload type 0x0005 */
    register_proto_doip_payload_0005(proto_doip);

    /* prepare proto entries for payload type 0x0006 */
    register_proto_doip_payload_0006(proto_doip);

    /* prepare proto entries for payload type 0x0007 */
    register_proto_doip_payload_0007(proto_doip);

    /* prepare proto entries for payload type 0x0008 */
    register_proto_doip_payload_0008(proto_doip);

    /* prepare proto entries for payload type 0x4001 */
    register_proto_doip_payload_4001(proto_doip);

    /* prepare proto entries for payload type 0x8001 */
    register_proto_doip_payload_8001(proto_doip);

    /* prepare proto entries for payload type 0x8002 */
    register_proto_doip_payload_8002(proto_doip);

    /* prepare proto entries for payload type 0x8003 */
    register_proto_doip_payload_8003(proto_doip);
}


