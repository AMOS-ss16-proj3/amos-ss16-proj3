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

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <epan/tvbuff.h>
#include "tvb-mock.h"

#include "doip-header.h"

int
test()
{
    tvbuff_t *tvb;
    guint8 buffer[] = {1,2,3,0xFF, 0x00};
    int i;
    
    tvb = create_tvb_mock(buffer, sizeof(buffer));
    if(tvb)
    {
        for(i = 0; i < sizeof(buffer); i += 1)
        {
            printf("%d\n", tvb_get_bits8(tvb, i, 8));
        }

        printf("%d\n", tvb_get_bits16(tvb, 0, 0, 0));
    } 
    else
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;;
}


int
main()
{
    guint8 doip_buffer[] = {
        0x02, /* protocol version */
        0xFD, /* inverse protocol version */
        0x00, 0x01, /* payload type */
        0x00, 0x00, 0x00, 0x00 /* payload length */
    };
    tvbuff_t *tvb;
    doip_header header;

    tvb = create_tvb_mock(doip_buffer, sizeof(doip_buffer));
    if(tvb)
    {
        fill_doip_header(&header, tvb);

        print_doip_header(stdout, &header);
    }

    return EXIT_SUCCESS;
}

