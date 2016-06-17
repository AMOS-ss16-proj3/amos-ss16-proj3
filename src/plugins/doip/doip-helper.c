

#include "doip-header.h"
#include "doip-helper.h"

#include "config.h"
#include <assert.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>

static void
item_is_in_tvb_range(const gint pos, const gint length, tvbuff_t *tvb);

void
insert_item_to_tree(proto_tree *tree, const gint hf, tvbuff_t *tvb, gint rel_pos, gint length, const guint enc)
{
    gint abs_pos;

    abs_pos = payload_offset_to_abs_offset(rel_pos);

    item_is_in_tvb_range(abs_pos, length, tvb);
        
    proto_tree_add_item(tree, hf, tvb, abs_pos, length, enc);
}

static void
item_is_in_tvb_range(const gint pos, const gint length, tvbuff_t *tvb)
{
    guint tvb_len = tvb_reported_length(tvb);
    gint end_pos = pos + length;

    /* Check for an int overflow */
    assert(end_pos > pos);

    /* check whether the item is within a given tvb-boundary */
    assert(end_pos <= (gint) tvb_len);
}





