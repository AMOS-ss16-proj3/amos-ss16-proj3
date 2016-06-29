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



#ifndef __DOIP_HELPER_H
#define __DOIP_HELPER_H

#include "epan/proto.h"
#include <epan/packet.h>
#include <epan/tvbuff.h>


/* helper function inserts a value
 * to a specific field
 * @param[in] proto_tree *, the tree in which the values will be inserted
 * @param[in] gint hf, the header fields id
 * @param[in] gint rel_pos, the values position on a doip-payload
 * @param[in] gint length, number of bytes which represent the value
 * @param[in] const guint encoding, encoding used for displaying
*/
void
insert_item_to_tree(proto_tree *tree, const gint hf, tvbuff_t *tvb, gint rel_pos, gint length, const guint enc);

#endif /* __DOIP_HELPER_H */

