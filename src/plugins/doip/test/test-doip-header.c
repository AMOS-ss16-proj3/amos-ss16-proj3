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

#include "tvb-mock.h"

#include "doip-header.h"


static tvbuff_t *tvb;

static guint8 doip_header_buffer[] = {
    0x02, /* proto_version */
    0xFD, /* inverse proto_version */
    0x43, 0x21, /* payload type == 0x4321 */
    0x12, 0x34, 0x56, 0x78 /* payload length == 0x12345678 */
};

int
init_suite_doip_header(void)
{
    printf("\ninit_suite()\n");
    return 0;
}

int
clean_suite_doip_header(void)
{
    printf("\nclean_suite()\n");
    return 0;
}

void
all_header_fields_are_set_correctly(void)
{
    doip_header header;
    tvbuff_t *tvb;

    tvb = create_tvb_mock(doip_header_buffer, sizeof(doip_header_buffer));

    fill_doip_header(&header, tvb);

    /*
    printf("proto_version value: %#2x\n", header.proto_version);
    printf("inverse_proto_version: %#2x\n", header.inverse_proto_version);
    printf("payload type: %#4x\n", header.payload.type);
    printf("payload length: %#8x\n", header.payload.length);
    */

    CU_ASSERT(header.proto_version == 0x02);
    CU_ASSERT(header.inverse_proto_version == 0xFD);
    CU_ASSERT(header.payload.type == 0x4321);
    CU_ASSERT(header.payload.length == 0x12345678);

    destroy_tvb_mock(tvb);
}


int
main(void)
{
    CU_pSuite pSuite = NULL;
    
    /* initialize the CUnit test registry */
    if(CUE_SUCCESS != CU_initialize_registry())
    {
        return CU_get_error();
    }

    /* add a suite to the registry */
    pSuite = CU_add_suite("doip-header suite", init_suite_doip_header, clean_suite_doip_header);
    if(!pSuite)
    {
        CU_cleanup_registry();
        return CU_get_error();
    }


    /* add the tests to the suite */
    if(!CU_add_test(pSuite, "test of doip_header", all_header_fields_are_set_correctly))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    /* Run all tests using the CUnit Basic interface */
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return CU_get_error();
}







