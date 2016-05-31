

#include "doip-header.h"
#include "doip-helper.h"

#include "config.h"
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

gboolean
insert_item_to_tree(proto_tree *tree, const gint hf, tvbuff_t *tvb, gint rel_pos, gint length, const guint enc)
{
    gint abs_pos;
    gboolean overflow;
    gboolean error;

    abs_pos = payload_offset_to_abs_offset(rel_pos);
        
    overflow = abs_pos + length < abs_pos;

    error = overflow;

    if(!error)
    {
        proto_tree_add_item(tree, hf, tvb, abs_pos, length, enc);
    }
    return error;
}
