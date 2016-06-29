/**
* Copyright 2016 The Open Source Research Group,
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

#include "test-doip-header.h"



int
main(void)
{
    CU_BasicRunMode brm = CU_BRM_VERBOSE;

    CU_pSuite (*test_functions[])(void) =
    {
        add_doip_header_suite
    };

    int no_failures = 0;

    int i;
    for(i = 0; i < sizeof(test_functions) / sizeof(test_functions[0]); i += 1)
    {
        /* initialize the CUnit test registry */
        if(CUE_SUCCESS != CU_initialize_registry())
        {
            return CU_get_error();
        }

        test_functions[i]();

        /* Run all tests using the CUnit Basic interface */
        CU_basic_set_mode(brm);
        CU_basic_run_tests();

        no_failures += CU_get_number_of_failures();

        CU_cleanup_registry();
    }



    return no_failures;
}


