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


#include "doip-header.h"
#include "doip-helper.h"

#include "config.h"
#include <assert.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

#ifdef NDEBUG

    #define RANGE_CHECK(pos, length, tvb) {}

#else

    #define RANGE_CHECK_END_POS(pos,length) (pos + length)
    #define RANGE_CHECK_TVB_LENGTH(tvb)  (tvb_reported_length(tvb))

    #define RANGE_CHECK(pos, length, tvb) { \
        /* Check for an int overflow */ \
        assert(RANGE_CHECK_END_POS(pos,length) > pos); \
        /* Check whether the item is within a given tvb-boundary */ \
        assert(RANGE_CHECK_END_POS(pos,length) <= (gint) RANGE_CHECK_TVB_LENGTH(tvb)); \
    }
#endif /* NDEBUG */

/*
static void
item_is_in_tvb_range(const gint pos, const gint length, tvbuff_t *tvb);
*/

void
insert_item_to_tree(proto_tree *tree, const gint hf, tvbuff_t *tvb, gint rel_pos, gint length, const guint enc)
{
    gint abs_pos;

    abs_pos = payload_offset_to_abs_offset(rel_pos);

    /*
    item_is_in_tvb_range(abs_pos, length, tvb);
    */
    RANGE_CHECK(abs_pos, length, tvb);
        
    proto_tree_add_item(tree, hf, tvb, abs_pos, length, enc);
}

/*
static void
item_is_in_tvb_range(const gint pos, const gint length, tvbuff_t *tvb)
{
    #define tvb_len tvb_reported_length(tvb);
    #define end_pos pos + length;

    / Check for an int overflow /
    assert(end_pos > pos);

    / check whether the item is within a given tvb-boundary /
    assert(end_pos <= (gint) tvb_len);
}
*/





