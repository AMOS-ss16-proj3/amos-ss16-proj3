

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
gboolean
insert_item_to_tree(proto_tree *tree, const gint hf, tvbuff_t *tvb, gint rel_pos, gint length, const guint enc);

#endif /* __DOIP_HELPER_H */

