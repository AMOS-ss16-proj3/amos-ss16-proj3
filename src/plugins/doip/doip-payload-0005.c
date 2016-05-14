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

#include "doip-payload-0005.h"

void
dissect_payload_0005(doip_header *header, packet_info *pinfo, proto_tree *tree)
{
    if(header)
    {
        header = NULL;
    }
    if(pinfo)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "payload type 0x0005");
        pinfo = NULL;
    }
    if(tree)
    {
        tree = NULL;
    }
}




