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

#include <stdlib.h>
#include <epan/tvbuff.h>

#include "tvb-mock.h"

tvbuff_t *
create_tvb_mock(guint8 buffer[], guint len)
{
    tvbuff_t *tvb;

    if((tvb = (tvbuff_t *) malloc(sizeof(tvbuff_t))))
    {
        tvb->buffer = buffer;
        tvb->length = len;
    }

    return tvb;
}

void
destroy_tvb_mock(tvbuff_t *tvb)
{
    if(tvb)
    {
        free(tvb);
    }
}
