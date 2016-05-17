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

#include "doip-payload-0000.h"
#include "doip-payload-0005.h"

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
            case 0x0005:
                handler = dissect_payload_0005;
                break;

            default:
                break;
        }
    }
    return handler;
}


