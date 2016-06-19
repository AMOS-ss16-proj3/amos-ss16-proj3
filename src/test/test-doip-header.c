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

#include <stdio.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <CUnit/Console.h>
#include <CUnit/Automated.h>

#include "tvb-mock.h"
#include "epan/tvbuff.h"

#include "../plugins/doip/doip-header.h"

#include "test-doip-header.h"



static int
init_suite_doip_header(void)
{
    return 0;
}

static int
clean_suite_doip_header(void)
{
    return 0;
}

static void
all_header_fields_are_set_correctly(void)
{
    guint8 doip_header_buffer[] = {
        0x02, /* proto_version */
        0xFD, /* inverse proto_version */
        0x43, 0x21, /* payload type == 0x4321 */
        0x12, 0x34, 0x56, 0x78 /* payload length == 0x12345678 */
    };

    doip_header header;
    tvbuff_t *tvb;

    tvb = create_tvb_mock(doip_header_buffer, sizeof(doip_header_buffer));

    gboolean success = fill_doip_header(&header, tvb);

    CU_ASSERT(success == TRUE);
    CU_ASSERT(header.proto_version == 0x02);
    CU_ASSERT(header.inverse_proto_version == 0xFD);
    CU_ASSERT(header.payload.type == 0x4321);
    CU_ASSERT(header.payload.length == 0x12345678);

    destroy_tvb_mock(tvb);
}

static void
fill_doip_header_indicates_error_by_return(void)
{
    const gint BUFFER_SIZE = 8;
    guint8 doip_header_buffer[][8] =
    {
        /* protocol version and inverse proto version do not match */
        {0x02, 0x00, 0x43, 0x21, 0x12, 0x34, 0x56, 0x78},
        {0x01, 0xFD, 0x43, 0x21, 0x12, 0x34, 0x56, 0x78}
    };
    doip_header header;
    tvbuff_t *tvb;
    gint i;

    for(i = 0; i < sizeof(doip_header_buffer) / BUFFER_SIZE; i += 1)
    {
        tvb = create_tvb_mock(doip_header_buffer[i], BUFFER_SIZE);

        gboolean success = fill_doip_header(&header, tvb);

        CU_ASSERT(success == FALSE);

        destroy_tvb_mock(tvb);
    }
}


CU_pSuite
add_doip_header_suite(void)
{
    CU_pSuite pSuite = NULL;
    
    /* initialize the CUnit test registry */
    if(CUE_SUCCESS != CU_initialize_registry())
    {
        return NULL;
    }

    /* add a suite to the registry */
    pSuite = CU_add_suite("doip-header suite", init_suite_doip_header, clean_suite_doip_header);
    if(!pSuite)
    {
        CU_cleanup_registry();
        return NULL;
    }


    /* add the tests to the suite */
    if(!CU_add_test(pSuite, "test of doip_header", all_header_fields_are_set_correctly)
        || !CU_add_test(pSuite, "fill doip header indicates error by return", fill_doip_header_indicates_error_by_return))
    {
        CU_cleanup_registry();
        return NULL;
    }

    return pSuite;
}

