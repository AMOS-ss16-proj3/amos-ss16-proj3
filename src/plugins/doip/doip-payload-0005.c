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

static const char *description = "routing activation request";

void
dissect_payload_0005(doip_header *header, packet_info *pinfo, proto_tree *tree)
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













